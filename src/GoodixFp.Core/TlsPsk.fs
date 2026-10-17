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
        use hmac = new HMACSHA256(secret)
        let result = Array.zeroCreate<byte> length
        let mutable bytesGenerated = 0
        let mutable a = hmac.ComputeHash(seed)
        while bytesGenerated < length do
            let toHash = Array.concat [ a; seed ]
            let chunk = hmac.ComputeHash(toHash)
            let copyLen = min chunk.Length (length - bytesGenerated)
            Buffer.BlockCopy(chunk, 0, result, bytesGenerated, copyLen)
            bytesGenerated <- bytesGenerated + copyLen
            a <- hmac.ComputeHash(a)
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
        use s = SHA256.Create()
        s.ComputeHash(data)

    let aesDecryptCbc (key: byte[]) (iv: byte[]) (cipher: byte[]) : byte[] =
        use aes = Aes.Create()
        aes.Key <- key
        aes.IV <- iv
        aes.Mode <- CipherMode.CBC
        aes.Padding <- PaddingMode.None
        use decryptor = aes.CreateDecryptor()
        decryptor.TransformFinalBlock(cipher, 0, cipher.Length)

    let aesEncryptCbc (key: byte[]) (iv: byte[]) (plain: byte[]) : byte[] =
        use aes = Aes.Create()
        aes.Key <- key
        aes.IV <- iv
        aes.Mode <- CipherMode.CBC
        aes.Padding <- PaddingMode.None
        use encryptor = aes.CreateEncryptor()
        encryptor.TransformFinalBlock(plain, 0, plain.Length)

    let computeMac (macKey: byte[]) (seqNum: uint64) (recType: byte) (content: byte[]) : byte[] =
        use hmac = new HMACSHA256(macKey)
        let header = Array.concat [
            u64Be seqNum
            [| recType; 0x03uy; 0x03uy |]
            u16Be content.Length
        ]
        hmac.ComputeHash(Array.concat [ header; content ])

type PureFSharpTlsPskTunnel(psk: byte[]) =
    let pskBytes = if isNull psk then Array.zeroCreate 32 else Array.copy psk

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
        isConnected <- false

    interface ITlsPskTunnel with
        member this.IsHandshakeComplete = isConnected

        member this.Reset() = this.ResetInternal()

        member this.HandleHandshake(clientRecordBytes: byte[]) : Result<byte[] option, DriverError> =
            if isNull clientRecordBytes || clientRecordBytes.Length < 5 then
                Error (TlsHandshakeFailed "Handshake record buffer too short")
            else
                try
                    let recType = clientRecordBytes.[0]
                    if recType = 0x16uy && clientRecordBytes.Length > 5 && clientRecordBytes.[5] = 0x01uy && not isConnected then
                        // 1. ClientHello
                        let hsMsg = Array.sub clientRecordBytes 5 (clientRecordBytes.Length - 5)
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
                        // 2. ClientKeyExchange + ChangeCipherSpec + Finished flight
                        let mutable offset = 0
                        while offset < clientRecordBytes.Length do
                            let curType = clientRecordBytes.[offset]
                            let curLen = (int clientRecordBytes.[offset + 3] <<< 8) ||| int clientRecordBytes.[offset + 4]
                            let curPayload = Array.sub clientRecordBytes (offset + 5) curLen
                            offset <- offset + 5 + curLen

                            match curType with
                            | 0x16uy when masterSecret.Length = 0 ->
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

                            | 0x14uy ->
                                // ChangeCipherSpec
                                ()

                            | 0x16uy ->
                                // Encrypted Client Finished
                                let iv = Array.sub curPayload 0 16
                                let cipher = Array.sub curPayload 16 (curPayload.Length - 16)
                                let decrypted = PureTlsCrypto.aesDecryptCbc clientWriteKey iv cipher
                                let padLen = int decrypted.[decrypted.Length - 1]
                                let contentAndMacLen = decrypted.Length - 1 - padLen
                                let contentLen = contentAndMacLen - 32
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

                            | unexpected ->
                                failwith $"Unexpected handshake record type 0x{unexpected:x2}"

                        // Server Flight: ChangeCipherSpec + Finished
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
                        let sCipher = PureTlsCrypto.aesEncryptCbc serverWriteKey sIv plain
                        let finPayload = Array.concat [ sIv; sCipher ]
                        let finRecord = Array.concat [
                            [| 0x16uy; 0x03uy; 0x03uy; byte (finPayload.Length >>> 8); byte (finPayload.Length &&& 0xff) |]
                            finPayload
                        ]

                        isConnected <- true
                        Ok (Some (Array.concat [ ccsRecord; finRecord ]))
                with ex ->
                    Error (TlsHandshakeFailed ex.Message)

        member this.DecryptApplicationData(recordBytes: byte[]) : Result<byte[], DriverError> =
            if isNull recordBytes || recordBytes.Length < 5 then
                Error (TlsDecryptionFailed "Application data record too short")
            elif not isConnected then
                Error (TlsDecryptionFailed "TLS handshake has not completed")
            else
                try
                    // Strip 9-byte Goodix 0xb2 header if present
                    let data =
                        if recordBytes.Length >= 9 && recordBytes.[0] = Protocol.FlagsTransportLayerSecurityData then
                            Array.sub recordBytes 9 (recordBytes.Length - 9)
                        else
                            recordBytes

                    let recType = data.[0]
                    let recLen = (int data.[3] <<< 8) ||| int data.[4]
                    let payload = Array.sub data 5 recLen

                    let iv = Array.sub payload 0 16
                    let cipher = Array.sub payload 16 (payload.Length - 16)
                    let plain = PureTlsCrypto.aesDecryptCbc clientWriteKey iv cipher

                    let padLen = int plain.[plain.Length - 1]
                    let contentAndMacLen = plain.Length - 1 - padLen
                    let contentLen = contentAndMacLen - 32
                    let content = Array.sub plain 0 contentLen
                    let mac = Array.sub plain contentLen 32

                    let expectedMac = PureTlsCrypto.computeMac clientWriteMacKey clientSeqNum recType content
                    clientSeqNum <- clientSeqNum + 1UL
                    if mac <> expectedMac then
                        Error (TlsDecryptionFailed "Application data HMAC verification failed")
                    else
                        Ok content
                with ex ->
                    Error (TlsDecryptionFailed ex.Message)

        member this.Dispose() =
            if not isDisposed then
                isDisposed <- true
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
            if isNull recordBytes || recordBytes.Length = 0 then
                Error (TlsDecryptionFailed "Empty application data record")
            else
                try
                    // Strip 9-byte Goodix 0xb2 header if present
                    let data =
                        if recordBytes.Length >= 9 && recordBytes.[0] = Protocol.FlagsTransportLayerSecurityData then
                            Array.sub recordBytes 9 (recordBytes.Length - 9)
                        else
                            recordBytes

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
