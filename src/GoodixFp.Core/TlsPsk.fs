namespace GoodixFp.Core

open System
open System.IO
open System.Security.Cryptography
open System.Text
open Org.BouncyCastle.Tls
open Org.BouncyCastle.Tls.Crypto.Impl.BC
open Org.BouncyCastle.Security

// ============================================================================
// TLS-PSK Tunnel Interface
// ============================================================================

type ITlsPskTunnel =
    inherit IDisposable
    abstract member IsHandshakeComplete: bool
    abstract member HandleHandshake: clientRecordBytes: byte[] -> Result<byte[] option, DriverError>
    abstract member DecryptApplicationData: recordBytes: byte[] -> Result<byte[], DriverError>
    abstract member Reset: unit -> unit

// ============================================================================
// Variant 1: 100% Pure F# RFC 4279 / RFC 5246 TLS 1.2 PSK Server
// ============================================================================

module private PureTlsCrypto =

    let pHash (secret: byte[]) (seed: byte[]) (length: int) : byte[] =
        let result = Array.zeroCreate<byte> length
        let mutable bytesGenerated = 0
        let mutable a = HMACSHA256.HashData(secret, seed)
        while bytesGenerated < length do
            let toHash = Array.concat [ a; seed ]
            let chunk = HMACSHA256.HashData(secret, toHash)
            let copyLen = min chunk.Length (length - bytesGenerated)
            Buffer.BlockCopy(chunk, 0, result, bytesGenerated, copyLen)
            bytesGenerated <- bytesGenerated + copyLen
            a <- HMACSHA256.HashData(secret, a)
        result

    let prf (secret: byte[]) (label: string) (seed: byte[]) (length: int) : byte[] =
        let labelBytes = Encoding.ASCII.GetBytes(label)
        let combinedSeed = Array.concat [ labelBytes; seed ]
        pHash secret combinedSeed length

    let u64Be (v: uint64) : byte[] =
        [|
            byte (v >>> 56)
            byte (v >>> 48)
            byte (v >>> 40)
            byte (v >>> 32)
            byte (v >>> 24)
            byte (v >>> 16)
            byte (v >>> 8)
            byte v
        |]

    let u16Be (v: int) : byte[] =
        [| byte (v >>> 8); byte (v &&& 0xff) |]

    let sha256 (data: byte[]) : byte[] =
        SHA256.HashData(data)

    let computeMac (macKey: byte[]) (seqNum: uint64) (recType: byte) (content: byte[]) : byte[] =
        let header = Array.concat [
            u64Be seqNum
            [| recType; 0x03uy; 0x03uy |]
            u16Be content.Length
        ]
        HMACSHA256.HashData(macKey, Array.concat [ header; content ])

    let findTlsStartOffset (recordBytes: byte[]) : int option =
        if isNull recordBytes || recordBytes.Length < 5 then None
        elif recordBytes.[0] = 0x17uy && recordBytes.Length >= 3 && recordBytes.[1] = 0x03uy && recordBytes.[2] = 0x03uy then
            Some 0
        elif recordBytes.[0] = Protocol.FlagsTransportLayerSecurityData then
            // Check if 4-byte MessagePack header (0xb2 <len_lo> <len_hi> <csum>) followed by 9-byte Goodix metadata -> offset 13 (4 + 9)
            if recordBytes.Length >= 16 && recordBytes.[13] = 0x17uy && recordBytes.[14] = 0x03uy && recordBytes.[15] = 0x03uy then
                Some 13
            // Check if 4-byte MessagePack header was already stripped and only 9-byte Goodix metadata is present -> offset 9
            elif recordBytes.Length >= 12 && recordBytes.[9] = 0x17uy && recordBytes.[10] = 0x03uy && recordBytes.[11] = 0x03uy then
                Some 9
            else
                // Fallback search within first 32 bytes
                let mutable found = None
                let maxSearch = min 32 (recordBytes.Length - 3)
                let mutable i = 0
                while i <= maxSearch && found.IsNone do
                    if recordBytes.[i] = 0x17uy && recordBytes.[i + 1] = 0x03uy && recordBytes.[i + 2] = 0x03uy then
                        found <- Some i
                    i <- i + 1
                found
        else
            let mutable found = None
            let maxSearch = min 32 (recordBytes.Length - 3)
            let mutable i = 0
            while i <= maxSearch && found.IsNone do
                if recordBytes.[i] = 0x17uy && recordBytes.[i + 1] = 0x03uy && recordBytes.[i + 2] = 0x03uy then
                    found <- Some i
                i <- i + 1
            found

type PureFSharpTlsPskTunnel(psk: byte[]) =
    let pskBytes = if isNull psk then Array.zeroCreate 32 else Array.copy psk
    let aes = Aes.Create()

    let mutable clientRandom: byte[] = [||]
    let mutable serverRandom: byte[] = [||]
    let mutable masterSecret: byte[] = [||]
    let mutable clientWriteMacKey: byte[] = [||]
    let mutable serverWriteMacKey: byte[] = [||]
    let mutable clientWriteKey: byte[] = [||]
    let mutable serverWriteKey: byte[] = [||]
    let mutable handshakeMessages = ResizeArray<byte>()
    let mutable clientSeqNum: uint64 = 0UL
    let mutable serverSeqNum: uint64 = 0UL
    let mutable hasReceivedCke: bool = false
    let mutable hasReceivedCcs: bool = false
    let mutable hasReceivedFin: bool = false
    let mutable isConnected: bool = false
    let mutable isDisposed: bool = false

    new() = new PureFSharpTlsPskTunnel(Array.zeroCreate 32)

    member this.ResetInternal() =
        clientRandom <- [||]
        serverRandom <- [||]
        masterSecret <- [||]
        clientWriteMacKey <- [||]
        serverWriteMacKey <- [||]
        clientWriteKey <- [||]
        serverWriteKey <- [||]
        handshakeMessages.Clear()
        clientSeqNum <- 0UL
        serverSeqNum <- 0UL
        hasReceivedCke <- false
        hasReceivedCcs <- false
        hasReceivedFin <- false
        isConnected <- false

    member this.ResetClientSeqNum(?seqNum: uint64) = clientSeqNum <- defaultArg seqNum 1UL

    interface ITlsPskTunnel with
        member this.IsHandshakeComplete = isConnected

        member this.Reset() = this.ResetInternal()

        member this.HandleHandshake(clientRecordBytes: byte[]) : Result<byte[] option, DriverError> =
            if isNull clientRecordBytes || clientRecordBytes.Length < 4 then
                Error (TlsHandshakeFailed "Handshake record buffer too short")
            else
                try
                    // Strip outer 4-byte MessagePack 0xb0 header if present
                    let raw =
                        if clientRecordBytes.Length >= 4 && clientRecordBytes.[0] = Protocol.FlagsTransportLayerSecurity && (clientRecordBytes.[4] = 0x16uy || clientRecordBytes.[4] = 0x14uy) then
                            Array.sub clientRecordBytes 4 (clientRecordBytes.Length - 4)
                        else
                            clientRecordBytes

                    let recType = raw.[0]
                    if recType = 0x16uy && raw.Length > 5 && raw.[5] = 0x01uy && not isConnected then
                        // 1. ClientHello
                        let hsMsg = Array.sub raw 5 (raw.Length - 5)
                        handshakeMessages.AddRange(hsMsg)
                        clientRandom <- Array.sub hsMsg 6 32

                        serverRandom <- Array.zeroCreate 32
                        RandomNumberGenerator.Fill(serverRandom.AsSpan())

                        // RFC 5746 renegotiation_info extension
                        let extensions = [|
                            0x00uy; 0x05uy
                            0xffuy; 0x01uy
                            0x00uy; 0x01uy
                            0x00uy
                        |]

                        let shBody = Array.concat [
                            [| 0x03uy; 0x03uy |]
                            serverRandom
                            [| 0x00uy |] // session ID length 0
                            [| 0x00uy; 0xaeuy |] // TLS_PSK_WITH_AES_128_CBC_SHA256
                            [| 0x00uy |] // compression null
                            extensions
                        ]
                        let shHs = Array.concat [
                            [| 0x02uy; 0x00uy; byte (shBody.Length >>> 8); byte (shBody.Length &&& 0xff) |]
                            shBody
                        ]
                        handshakeMessages.AddRange(shHs)

                        let shdHs = [| 0x0euy; 0x00uy; 0x00uy; 0x00uy |]
                        handshakeMessages.AddRange(shdHs)

                        let bothHs = Array.concat [ shHs; shdHs ]
                        let serverRecord = Array.concat [
                            [| 0x16uy; 0x03uy; 0x03uy; byte (bothHs.Length >>> 8); byte (bothHs.Length &&& 0xff) |]
                            bothHs
                        ]
                        Ok (Some serverRecord)

                    else
                        // 2. ClientKeyExchange, ChangeCipherSpec, and Finished flight
                        // May arrive concatenated in a single buffer OR across multiple consecutive HandleHandshake calls
                        let mutable offset = 0
                        while offset + 5 <= raw.Length do
                            let curType = raw.[offset]
                            let curLen = (int raw.[offset + 3] <<< 8) ||| int raw.[offset + 4]
                            if offset + 5 + curLen > raw.Length then
                                failwith $"Truncated handshake record at offset {offset}: length {curLen}, available {raw.Length - offset - 5}"
                            let curPayload = Array.sub raw (offset + 5) curLen
                            offset <- offset + 5 + curLen

                            match curType with
                            | 0x16uy when not hasReceivedCcs ->
                                // ClientKeyExchange
                                handshakeMessages.AddRange(curPayload)
                                let pskLen = pskBytes.Length
                                let pms = Array.concat [
                                    [| 0x00uy; byte pskLen |]
                                    Array.zeroCreate pskLen
                                    [| 0x00uy; byte pskLen |]
                                    pskBytes
                                ]
                                let seed = Array.concat [ clientRandom; serverRandom ]
                                masterSecret <- PureTlsCrypto.prf pms "master secret" seed 48

                                let kbSeed = Array.concat [ serverRandom; clientRandom ]
                                let kb = PureTlsCrypto.prf masterSecret "key expansion" kbSeed 96
                                clientWriteMacKey <- Array.sub kb 0 32
                                serverWriteMacKey <- Array.sub kb 32 32
                                clientWriteKey <- Array.sub kb 64 16
                                serverWriteKey <- Array.sub kb 80 16
                                hasReceivedCke <- true

                            | 0x14uy ->
                                // ChangeCipherSpec
                                hasReceivedCcs <- true

                            | 0x16uy when hasReceivedCcs ->
                                // Encrypted Client Finished
                                let iv = Array.sub curPayload 0 16
                                let cipher = Array.sub curPayload 16 (curPayload.Length - 16)
                                aes.Key <- clientWriteKey
                                let decrypted = aes.DecryptCbc(ReadOnlySpan cipher, ReadOnlySpan iv, PaddingMode.None)
                                let padLen = int decrypted.[decrypted.Length - 1]
                                let contentAndMacLen = decrypted.Length - 1 - padLen
                                let contentLen = contentAndMacLen - 32
                                if contentLen < 0 then
                                    failwith $"Invalid Finished record padding: padLen={padLen}, decryptedLen={decrypted.Length}"
                                let content = Array.sub decrypted 0 contentLen
                                let mac = Array.sub decrypted contentLen 32

                                let expectedMac = PureTlsCrypto.computeMac clientWriteMacKey clientSeqNum 0x16uy content
                                clientSeqNum <- clientSeqNum + 1UL
                                if mac <> expectedMac then
                                    failwith "Client Finished HMAC verification failed"

                                let clientVerifyData = Array.sub content 4 12
                                let hsHash = PureTlsCrypto.sha256 (handshakeMessages.ToArray())
                                let expectedVerifyData = PureTlsCrypto.prf masterSecret "client finished" hsHash 12
                                if clientVerifyData <> expectedVerifyData then
                                    failwith "Client Finished verify_data mismatch"

                                handshakeMessages.AddRange(content)
                                hasReceivedFin <- true

                            | unexpected ->
                                failwith $"Unexpected handshake record type 0x{unexpected:x2}"

                        // Only generate and return Some (ccsRecord + finRecord) once encrypted Finished (0x16 after ChangeCipherSpec) has been processed
                        if hasReceivedFin then
                            let ccsRecord = [| 0x14uy; 0x03uy; 0x03uy; 0x00uy; 0x01uy; 0x01uy |]

                            let hsHash2 = PureTlsCrypto.sha256 (handshakeMessages.ToArray())
                            let serverVerifyData = PureTlsCrypto.prf masterSecret "server finished" hsHash2 12
                            let serverFinishedContent = Array.concat [
                                [| 0x14uy; 0x00uy; 0x00uy; 0x0cuy |]
                                serverVerifyData
                            ]
                            let sMac = PureTlsCrypto.computeMac serverWriteMacKey serverSeqNum 0x16uy serverFinishedContent
                            serverSeqNum <- serverSeqNum + 1UL

                            let contentAndMac = Array.concat [ serverFinishedContent; sMac ]
                            let rem = contentAndMac.Length % 16
                            let padLen = 16 - rem - 1 + (if rem = 15 then 16 else 0)
                            let padding = Array.create (padLen + 1) (byte padLen)
                            let plain = Array.concat [ contentAndMac; padding ]

                            let sIv = Array.zeroCreate 16
                            RandomNumberGenerator.Fill(sIv.AsSpan())
                            aes.Key <- serverWriteKey
                            let sCipher = aes.EncryptCbc(ReadOnlySpan plain, ReadOnlySpan sIv, PaddingMode.None)
                            let finPayload = Array.concat [ sIv; sCipher ]
                            let finRecord = Array.concat [
                                [| 0x16uy; 0x03uy; 0x03uy; byte (finPayload.Length >>> 8); byte (finPayload.Length &&& 0xff) |]
                                finPayload
                            ]

                            isConnected <- true
                            Ok (Some (Array.concat [ ccsRecord; finRecord ]))
                        else
                            Ok None
                with ex ->
                    Error (TlsHandshakeFailed ex.Message)

        member this.DecryptApplicationData(recordBytes: byte[]) : Result<byte[], DriverError> =
            if isNull recordBytes || recordBytes.Length < 5 then
                Error (TlsDecryptionFailed "Application data record too short")
            elif not isConnected then
                Error (TlsDecryptionFailed "TLS handshake has not completed")
            else
                try
                    match PureTlsCrypto.findTlsStartOffset recordBytes with
                    | None ->
                        Error (TlsDecryptionFailed "No TLS ApplicationData record found in buffer")
                    | Some startOffset ->
                        let decryptedChunks = ResizeArray<byte[]>()
                        let mutable offset = startOffset
                        while offset + 5 <= recordBytes.Length && recordBytes.[offset] = 0x17uy do
                            let recType = recordBytes.[offset]
                            let recLen = (int recordBytes.[offset + 3] <<< 8) ||| int recordBytes.[offset + 4]
                            if offset + 5 + recLen > recordBytes.Length then
                                failwith $"Truncated TLS record at offset {offset}: length {recLen}, available {recordBytes.Length - offset - 5}"
                            let payload = Array.sub recordBytes (offset + 5) recLen
                            offset <- offset + 5 + recLen

                            let iv = Array.sub payload 0 16
                            let cipher = Array.sub payload 16 (payload.Length - 16)

                            aes.Key <- clientWriteKey
                            let plain = aes.DecryptCbc(ReadOnlySpan cipher, ReadOnlySpan iv, PaddingMode.None)

                            let padLen = int plain.[plain.Length - 1]
                            let contentAndMacLen = plain.Length - 1 - padLen
                            let contentLen = contentAndMacLen - 32
                            if contentLen < 0 then
                                failwith "Invalid padding or truncated TLS record content"
                            let content = Array.sub plain 0 contentLen
                            let mac = Array.sub plain contentLen 32

                            let expectedMac = PureTlsCrypto.computeMac clientWriteMacKey clientSeqNum recType content
                            clientSeqNum <- clientSeqNum + 1UL
                            if mac <> expectedMac then
                                failwith "Application data HMAC verification failed"

                            decryptedChunks.Add(content)

                        if decryptedChunks.Count = 0 then
                            Error (TlsDecryptionFailed "No ApplicationData records decrypted")
                        elif decryptedChunks.Count = 1 then
                            Ok decryptedChunks.[0]
                        else
                            let totalLen = decryptedChunks |> Seq.sumBy (fun c -> c.Length)
                            let totalPlain = Array.zeroCreate<byte> totalLen
                            let mutable curDst = 0
                            for chunk in decryptedChunks do
                                Buffer.BlockCopy(chunk, 0, totalPlain, curDst, chunk.Length)
                                curDst <- curDst + chunk.Length
                            Ok totalPlain
                with ex ->
                    Error (TlsDecryptionFailed ex.Message)

        member this.Dispose() =
            if not isDisposed then
                isDisposed <- true
                (aes :> IDisposable).Dispose()
                this.ResetInternal()

// ============================================================================
// Variant 2: In-Memory TLS 1.2 PSK Server built on Org.BouncyCastle.Tls
// ============================================================================

type GoodixBcPskTlsServer(psk: byte[]) =
    inherit PskTlsServer(
        BcTlsCrypto(SecureRandom()),
        { new TlsPskIdentityManager with
            member _.GetHint() = [||]
            member _.GetPsk(id) = psk
        }
    )
    override this.GetSupportedCipherSuites() =
        [| CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256 |]
    override this.GetSupportedVersions() =
        ProtocolVersion.TLSv12.DownTo(ProtocolVersion.TLSv12)

type BouncyCastleTlsPskTunnel(psk: byte[]) =
    let pskBytes = if isNull psk then Array.zeroCreate 32 else Array.copy psk
    let mutable serverProtocol: TlsServerProtocol = null
    let mutable isDisposed: bool = false

    let initServer () =
        serverProtocol <- new TlsServerProtocol()
        serverProtocol.Accept(GoodixBcPskTlsServer(pskBytes))

    do initServer ()

    new() = new BouncyCastleTlsPskTunnel(Array.zeroCreate 32)

    member this.ResetInternal() =
        if not (isNull serverProtocol) then
            try serverProtocol.Close() with _ -> ()
        initServer ()

    interface ITlsPskTunnel with
        member this.IsHandshakeComplete =
            not (isNull serverProtocol) && serverProtocol.IsConnected

        member this.Reset() = this.ResetInternal()

        member this.HandleHandshake(clientRecordBytes: byte[]) : Result<byte[] option, DriverError> =
            if isNull clientRecordBytes || clientRecordBytes.Length = 0 then
                Error (TlsHandshakeFailed "Empty handshake record")
            else
                try
                    serverProtocol.OfferInput(clientRecordBytes)
                    let avail = serverProtocol.GetAvailableOutputBytes()
                    if avail > 0 then
                        let resp = Array.zeroCreate<byte> avail
                        serverProtocol.ReadOutput(resp, 0, avail) |> ignore
                        Ok (Some resp)
                    else
                        Ok None
                with ex ->
                    Error (TlsHandshakeFailed ex.Message)

        member this.DecryptApplicationData(recordBytes: byte[]) : Result<byte[], DriverError> =
            if isNull recordBytes || recordBytes.Length < 5 then
                Error (TlsDecryptionFailed "Application data record too short")
            else
                try
                    match PureTlsCrypto.findTlsStartOffset recordBytes with
                    | None ->
                        Error (TlsDecryptionFailed "No TLS ApplicationData record found in buffer")
                    | Some startOffset ->
                        let data =
                            if startOffset = 0 then recordBytes
                            else Array.sub recordBytes startOffset (recordBytes.Length - startOffset)

                        serverProtocol.OfferInput(data)
                        let avail = serverProtocol.GetAvailableInputBytes()
                        if avail > 0 then
                            let plain = Array.zeroCreate<byte> avail
                            serverProtocol.ReadApplicationData(plain, 0, avail) |> ignore
                            Ok plain
                        else
                            Error (TlsDecryptionFailed "No decrypted application data available")
                with ex ->
                    Error (TlsDecryptionFailed ex.Message)

        member this.Dispose() =
            if not isDisposed then
                isDisposed <- true
                if not (isNull serverProtocol) then
                    try serverProtocol.Close() with _ -> ()

// ============================================================================
// TLS-PSK Client Helper (for unit tests, integration tests & benchmarks)
// ============================================================================

type TestPskTlsClient(psk: byte[]) =
    inherit PskTlsClient(BcTlsCrypto(SecureRandom()), BasicTlsPskIdentity("Client_identity", psk))
    override this.GetSupportedCipherSuites() =
        [| CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256 |]
    override this.GetSupportedVersions() =
        ProtocolVersion.TLSv12.DownTo(ProtocolVersion.TLSv12)
