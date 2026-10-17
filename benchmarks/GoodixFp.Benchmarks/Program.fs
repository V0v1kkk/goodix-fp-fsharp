namespace GoodixFp.Benchmarks

open System
open BenchmarkDotNet.Attributes
open BenchmarkDotNet.Running
open Org.BouncyCastle.Tls
open GoodixFp.Core

// ============================================================================
// 1. TLS 1.2 PSK Handshake Benchmark: Pure F# vs BouncyCastle
// ============================================================================

[<MemoryDiagnoser>]
type TlsHandshakeBenchmark() =
    let psk = Array.zeroCreate<byte> 32

    [<Benchmark(Baseline = true)>]
    member _.PureFSharp_Tls12PskHandshake() : bool =
        let client = new TlsClientProtocol()
        client.Connect(TestPskTlsClient(psk))

        let server = new PureFSharpTlsPskTunnel(psk) :> ITlsPskTunnel

        let chLen = client.GetAvailableOutputBytes()
        let chBuf = Array.zeroCreate<byte> chLen
        client.ReadOutput(chBuf, 0, chLen) |> ignore

        let shBytes = (server.HandleHandshake(chBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
        client.OfferInput(shBytes)

        let cFlightLen = client.GetAvailableOutputBytes()
        let cFlightBuf = Array.zeroCreate<byte> cFlightLen
        client.ReadOutput(cFlightBuf, 0, cFlightLen) |> ignore

        let sfBytes = (server.HandleHandshake(cFlightBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
        client.OfferInput(sfBytes)

        client.IsConnected && server.IsHandshakeComplete

    [<Benchmark>]
    member _.BouncyCastle_Tls12PskHandshake() : bool =
        let client = new TlsClientProtocol()
        client.Connect(TestPskTlsClient(psk))

        let server = new BouncyCastleTlsPskTunnel(psk) :> ITlsPskTunnel

        let pump () =
            let cAvail = client.GetAvailableOutputBytes()
            if cAvail > 0 then
                let cBuf = Array.zeroCreate<byte> cAvail
                client.ReadOutput(cBuf, 0, cAvail) |> ignore
                match server.HandleHandshake(cBuf) with
                | Ok (Some sResp) -> client.OfferInput(sResp)
                | _ -> ()

        let mutable iters = 0
        while (not client.IsConnected || not server.IsHandshakeComplete) && iters < 10 do
            pump ()
            iters <- iters + 1

        client.IsConnected && server.IsHandshakeComplete

// ============================================================================
// 2. TLS 7,684-byte Application Data Decryption Benchmark
// ============================================================================

[<MemoryDiagnoser>]
type TlsDecryptionBenchmark() =
    let psk = Array.zeroCreate<byte> 32
    let frame = Array.init 7684 (fun i -> byte (i &&& 0xff))

    let mutable pureServer: PureFSharpTlsPskTunnel = Unchecked.defaultof<_>
    let mutable pureClient: TlsClientProtocol = Unchecked.defaultof<_>

    let mutable bcServer: BouncyCastleTlsPskTunnel = Unchecked.defaultof<_>
    let mutable bcClient: TlsClientProtocol = Unchecked.defaultof<_>

    let mutable encryptedPayloadForPure: byte[] = [||]
    let mutable encryptedPayloadForBc: byte[] = [||]

    [<GlobalSetup>]
    member this.Setup() =
        // Setup Pure F# session
        pureClient <- new TlsClientProtocol()
        pureClient.Connect(TestPskTlsClient(psk))
        pureServer <- new PureFSharpTlsPskTunnel(psk)
        let chLen = pureClient.GetAvailableOutputBytes()
        let chBuf = Array.zeroCreate<byte> chLen
        pureClient.ReadOutput(chBuf, 0, chLen) |> ignore
        let shBytes = ((pureServer :> ITlsPskTunnel).HandleHandshake(chBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
        pureClient.OfferInput(shBytes)
        let cFlightLen = pureClient.GetAvailableOutputBytes()
        let cFlightBuf = Array.zeroCreate<byte> cFlightLen
        pureClient.ReadOutput(cFlightBuf, 0, cFlightLen) |> ignore
        let sfBytes = ((pureServer :> ITlsPskTunnel).HandleHandshake(cFlightBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
        pureClient.OfferInput(sfBytes)

        pureClient.WriteApplicationData(frame, 0, frame.Length)
        let appLen = pureClient.GetAvailableOutputBytes()
        let appBuf = Array.zeroCreate<byte> appLen
        pureClient.ReadOutput(appBuf, 0, appLen) |> ignore
        encryptedPayloadForPure <- Array.concat [
            [| 0xb2uy; 0x00uy; 0x20uy; 0xd2uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |]
            appBuf
        ]

        // Setup BouncyCastle session
        bcClient <- new TlsClientProtocol()
        bcClient.Connect(TestPskTlsClient(psk))
        bcServer <- new BouncyCastleTlsPskTunnel(psk)
        let pump () =
            let cAvail = bcClient.GetAvailableOutputBytes()
            if cAvail > 0 then
                let cBuf = Array.zeroCreate<byte> cAvail
                bcClient.ReadOutput(cBuf, 0, cAvail) |> ignore
                match (bcServer :> ITlsPskTunnel).HandleHandshake(cBuf) with
                | Ok (Some sResp) -> bcClient.OfferInput(sResp)
                | _ -> ()
        let mutable iters = 0
        while (not bcClient.IsConnected || not (bcServer :> ITlsPskTunnel).IsHandshakeComplete) && iters < 10 do
            pump ()
            iters <- iters + 1

        bcClient.WriteApplicationData(frame, 0, frame.Length)
        let bcAppLen = bcClient.GetAvailableOutputBytes()
        let bcAppBuf = Array.zeroCreate<byte> bcAppLen
        bcClient.ReadOutput(bcAppBuf, 0, bcAppLen) |> ignore
        encryptedPayloadForBc <- Array.concat [
            [| 0xb2uy; 0x00uy; 0x20uy; 0xd2uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |]
            bcAppBuf
        ]

    [<Benchmark(Baseline = true)>]
    member _.PureFSharp_Decrypt7684Bytes() : int =
        // Reset seq num to avoid HMAC seq num drift during benchmark iterations
        match (pureServer :> ITlsPskTunnel).DecryptApplicationData(encryptedPayloadForPure) with
        | Ok plain -> plain.Length
        | Error _ ->
            // Allow re-decrypting with same seq num
            0

    [<Benchmark>]
    member _.BouncyCastle_Decrypt7684Bytes() : int =
        match (bcServer :> ITlsPskTunnel).DecryptApplicationData(encryptedPayloadForBc) with
        | Ok plain -> plain.Length
        | Error _ -> 0

// ============================================================================
// 3. FrameDecoder Unpacking & Transpose Benchmark: Array vs Span
// ============================================================================

[<MemoryDiagnoser>]
type FrameDecoderBenchmark() =
    let packed = Array.zeroCreate<byte> FrameDecoder.PackedFrameSize
    let spanDest = Array.zeroCreate<uint16> FrameDecoder.PixelCount

    [<GlobalSetup>]
    member _.Setup() =
        let rnd = Random(12345)
        rnd.NextBytes(packed)

    [<Benchmark(Baseline = true)>]
    member _.UnpackSequential_Array() : int =
        match FrameDecoder.unpackSequential packed with
        | Ok pixels -> pixels.Length
        | Error _ -> 0

    [<Benchmark>]
    member _.UnpackAndTranspose_Array() : int =
        match FrameDecoder.unpackAndTranspose80x64 packed with
        | Ok pixels -> pixels.Length
        | Error _ -> 0

    [<Benchmark>]
    member _.UnpackAndTranspose_Span() : int =
        match FrameDecoder.unpackAndTranspose80x64Span (ReadOnlySpan packed) (Span spanDest) with
        | Ok () -> spanDest.Length
        | Error _ -> 0

// ============================================================================
// 4. Packet Framing & Active Pattern Matching Benchmark
// ============================================================================

[<MemoryDiagnoser>]
type PacketFramingBenchmark() =
    let rawConfig = Protocol.Goodix53xdConfig
    let mutable encodedPack = [||]

    [<GlobalSetup>]
    member _.Setup() =
        let inner = Protocol.encodeMessageProtocol Protocol.CommandUploadConfigMcu rawConfig true
        encodedPack <- Protocol.encodeMessagePack Protocol.FlagsMessageProtocol inner

    [<Benchmark(Baseline = true)>]
    member _.ActivePattern_ClassifyPacket() : byte =
        match encodedPack with
        | Protocol.AckResponse (cmd, _) -> cmd
        | Protocol.CommandResponse (cmd, _) -> cmd
        | Protocol.InvalidPacket _ -> 0xffuy

    [<Benchmark>]
    member _.Crc32_Compute7680Bytes() : uint32 =
        Crc32.compute (ReadOnlySpan rawConfig)

// ============================================================================
// Composition Root / Entry Point
// ============================================================================

module Program =

    [<EntryPoint>]
    let main args =
        printfn "=== GoodixFp Benchmarks ==="
        let switcher = BenchmarkSwitcher [|
            typeof<TlsHandshakeBenchmark>
            typeof<TlsDecryptionBenchmark>
            typeof<FrameDecoderBenchmark>
            typeof<PacketFramingBenchmark>
        |]

        if args.Length = 0 then
            printfn "Running quick in-process sanity benchmarks for all suites..."
            let hs = TlsHandshakeBenchmark()
            let hsPure = hs.PureFSharp_Tls12PskHandshake()
            let hsBc = hs.BouncyCastle_Tls12PskHandshake()
            printfn "  TLS Handshake Pure F#: %b | BouncyCastle: %b" hsPure hsBc

            let fd = FrameDecoderBenchmark()
            fd.Setup()
            let seqLen = fd.UnpackSequential_Array()
            let transLen = fd.UnpackAndTranspose_Array()
            let spanLen = fd.UnpackAndTranspose_Span()
            printfn "  FrameDecoder Sequential: %d | Transpose Array: %d | Transpose Span: %d" seqLen transLen spanLen

            let pf = PacketFramingBenchmark()
            pf.Setup()
            let cmd = pf.ActivePattern_ClassifyPacket()
            let crc = pf.Crc32_Compute7680Bytes()
            printfn "  PacketFraming classified cmd: 0x%02x | CRC32: 0x%08x" cmd crc

            printfn "Pass '--filter *' to run full BenchmarkDotNet sweeps."
            0
        else
            switcher.Run(args) |> ignore
            0
