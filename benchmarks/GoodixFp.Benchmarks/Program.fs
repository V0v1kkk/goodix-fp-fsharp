namespace GoodixFp.Benchmarks

open System
open BenchmarkDotNet.Attributes
open BenchmarkDotNet.Running
open GoodixFp.Core
open GoodixFp.NativeMatcher
open System.IO

// ============================================================================
// 1. TLS 1.2 PSK Handshake Benchmark: Pure F# RFC 4279 / RFC 5246
// ============================================================================

[<MemoryDiagnoser>]
type TlsHandshakeBenchmark() =
    let psk = Array.zeroCreate<byte> 32

    [<Benchmark>]
    member _.PureFSharp_Tls12PskHandshake() : bool =
        let client = new PureTlsPskClient(psk)
        use server = new PureFSharpTlsPskTunnel(psk) :> ITlsPskTunnel

        let ch = client.CreateClientHello()
        let sh = (server.HandleHandshake(ch) |> Result.defaultWith (fun e -> failwith (string e))).Value
        let cFlight = client.ProcessServerHello(sh)
        let sf = (server.HandleHandshake(cFlight) |> Result.defaultWith (fun e -> failwith (string e))).Value
        let finOk = client.ProcessServerFinished(sf)

        finOk && client.IsConnected && server.IsHandshakeComplete

// ============================================================================
// 2. TLS 7,684-byte Application Data Decryption Benchmark
// ============================================================================

[<MemoryDiagnoser>]
type TlsDecryptionBenchmark() =
    let psk = Array.zeroCreate<byte> 32
    let frame = Array.init 7684 (fun i -> byte (i &&& 0xff))

    let mutable pureServer: PureFSharpTlsPskTunnel = Unchecked.defaultof<_>
    let mutable pureClient: PureTlsPskClient = Unchecked.defaultof<_>
    let mutable encryptedPayloadForPure: byte[] = [||]

    [<GlobalSetup>]
    member this.Setup() =
        pureClient <- new PureTlsPskClient(psk)
        pureServer <- new PureFSharpTlsPskTunnel(psk)
        let ch = pureClient.CreateClientHello()
        let sh = ((pureServer :> ITlsPskTunnel).HandleHandshake(ch) |> Result.defaultWith (fun e -> failwith (string e))).Value
        let cFlight = pureClient.ProcessServerHello(sh)
        let sf = ((pureServer :> ITlsPskTunnel).HandleHandshake(cFlight) |> Result.defaultWith (fun e -> failwith (string e))).Value
        pureClient.ProcessServerFinished(sf) |> ignore

        let appBuf = pureClient.EncryptApplicationData(frame)
        encryptedPayloadForPure <- Array.concat [
            [| 0xb2uy; 0x00uy; 0x20uy; 0xd2uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |]
            appBuf
        ]

    [<Benchmark>]
    member _.PureFSharp_Decrypt7684Bytes() : int =
        pureServer.ResetClientSeqNum()
        match (pureServer :> ITlsPskTunnel).DecryptApplicationData(encryptedPayloadForPure) with
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
// 5. Goodix TOD Native Matcher Benchmark: Preprocess & Identify Probe
// ============================================================================

[<MemoryDiagnoser>]
type GoodixTodMatcherBenchmark() =
    let mutable matcher: GoodixTodMatcher = Unchecked.defaultof<_>
    let mutable testFrame: uint16[] = [||]
    let mutable enrolledTemplates: (FingerId * TemplateBlob) list = []

    static member GenerateSyntheticRidgeFrame(shiftX: float, shiftY: float, noise: float) : uint16[] =
        let width = 80
        let height = 64
        let cx = 40.0 + shiftX
        let cy = 32.0 + shiftY
        let pixels = Array.zeroCreate<uint16> (width * height)
        for y in 0 .. height - 1 do
            for x in 0 .. width - 1 do
                let dx = float x - cx
                let dy = float y - cy
                let r = Math.Sqrt(dx * dx + dy * dy)
                let theta = Math.Atan2(dy, dx)
                let ridge = Math.Cos(r * 0.8 + 2.0 * theta)
                let rawVal = 1500.0 + 350.0 * ridge + noise * (float ((x * 17 + y * 31) % 10) - 5.0)
                let clamped = Math.Clamp(rawVal, 0.0, 4095.0)
                pixels.[y * width + x] <- uint16 clamped
        pixels

    [<GlobalSetup>]
    member this.Setup() =
        let home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
        let candidatePaths = [
            Path.Combine(home, ".local/share/goodix-fp/libgoodix_tod_53xc.so")
            "/tmp/libgoodix_standalone.so"
        ]
        match candidatePaths |> List.tryFind File.Exists with
        | None -> failwith "Goodix native library not found for benchmarks"
        | Some pathStr ->
            let libPath = LibraryPath.create pathStr |> Result.defaultWith (fun e -> failwith (string e))
            matcher <- GoodixTodMatcher.Create(customPath = libPath.Value) |> Result.defaultWith (fun e -> failwith (string e))

            testFrame <- GoodixTodMatcherBenchmark.GenerateSyntheticRidgeFrame(0.5, 0.5, 1.0)

            matcher.StartEnroll() |> ignore
            for i in 0 .. 11 do
                let sx = float (i % 3 - 1) * 1.5
                let sy = float (i / 3 - 2) * 1.5
                let sample = GoodixTodMatcherBenchmark.GenerateSyntheticRidgeFrame(sx, sy, 1.0)
                matcher.MergeSample(sample) |> ignore

            let fid = FingerId.createUnsafe "bench_finger"
            let blob = matcher.CommitTemplate(fid) |> Result.defaultWith (fun e -> failwith (string e))
            enrolledTemplates <- [ (fid, blob) ]

    [<Benchmark(Baseline = true)>]
    member this.Preprocess_80x64Frame() : PreprocessedFrame =
        matcher.Preprocess(testFrame) |> Result.defaultWith (fun e -> failwith (string e))

    [<Benchmark>]
    member this.Verify_ProbeAgainstTemplate() : bool =
        match matcher.IdentifyProbe(testFrame, enrolledTemplates) with
        | Ok (Some _) -> true
        | _ -> false

    [<GlobalCleanup>]
    member this.Cleanup() =
        if not (isNull (box matcher)) then
            (matcher :> IDisposable).Dispose()

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
            typeof<GoodixTodMatcherBenchmark>
        |]

        if args.Length = 0 then
            printfn "Running quick in-process sanity benchmarks for all suites..."
            let hs = TlsHandshakeBenchmark()
            let hsPure = hs.PureFSharp_Tls12PskHandshake()
            printfn $"  TLS Handshake Pure F#: {hsPure}"

            let fd = FrameDecoderBenchmark()
            fd.Setup()
            let seqLen = fd.UnpackSequential_Array()
            let transLen = fd.UnpackAndTranspose_Array()
            let spanLen = fd.UnpackAndTranspose_Span()
            printfn $"  FrameDecoder Sequential: {seqLen} | Transpose Array: {transLen} | Transpose Span: {spanLen}"

            let pf = PacketFramingBenchmark()
            pf.Setup()
            let cmd = pf.ActivePattern_ClassifyPacket()
            let crc = pf.Crc32_Compute7680Bytes()
            printfn $"  PacketFraming classified cmd: 0x{cmd:X2} | CRC32: 0x{crc:X8}"

            let m = GoodixTodMatcherBenchmark()
            m.Setup()
            let prep = m.Preprocess_80x64Frame()
            let matchOk = m.Verify_ProbeAgainstTemplate()
            m.Cleanup()
            printfn $"  GoodixTodMatcher Preprocess Quality: {prep.Quality.Value} | Verify Matched: {matchOk}"

            printfn "Pass '--filter *' to run full BenchmarkDotNet sweeps."
            0
        else
            switcher.Run(args) |> ignore
            0
