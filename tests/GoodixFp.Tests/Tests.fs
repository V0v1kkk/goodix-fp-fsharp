module GoodixFp.Tests

open System
open System.IO
open System.Threading.Tasks
open Xunit
open Org.BouncyCastle.Tls
open GoodixFp.Core
open GoodixFp.NativeMatcher

// ============================================================================
// Types & Domain DU Discipline Tests
// ============================================================================

[<Fact>]
let ``UsbVid create rejects zero and accepts valid VID`` () =
    match UsbVid.create 0us with
    | Error msg -> Assert.Contains("non-zero", msg)
    | Ok _ -> Assert.Fail("Expected error for 0us")

    match UsbVid.create 0x27c6us with
    | Ok vid ->
        Assert.Equal(0x27c6us, vid.Value)
        Assert.Equal(0x27c6us, UsbVid.value vid)
    | Error err -> Assert.Fail(err)

[<Fact>]
let ``UsbPid create rejects zero and accepts valid PID`` () =
    match UsbPid.create 0us with
    | Error msg -> Assert.Contains("non-zero", msg)
    | Ok _ -> Assert.Fail("Expected error for 0us")

    match UsbPid.create 0x538dus with
    | Ok pid -> Assert.Equal(0x538dus, pid.Value)
    | Error err -> Assert.Fail(err)

[<Fact>]
let ``FirmwareVersion rejects empty string and trims whitespace`` () =
    match FirmwareVersion.create "   " with
    | Error msg -> Assert.Contains("empty", msg)
    | Ok _ -> Assert.Fail("Expected error for whitespace")

    match FirmwareVersion.create "  GF5298_GM168SEC_APP_13016 \n" with
    | Ok fw -> Assert.Equal("GF5298_GM168SEC_APP_13016", fw.Value)
    | Error err -> Assert.Fail(err)

[<Fact>]
let ``PskHash requires exactly 32 bytes`` () =
    match PskHash.create (Array.zeroCreate 16) with
    | Error msg -> Assert.Contains("32 bytes", msg)
    | Ok _ -> Assert.Fail("Expected error for 16-byte hash")

    let validBytes = Array.init 32 (fun i -> byte i)
    match PskHash.create validBytes with
    | Ok hash -> Assert.Equal<byte seq>(validBytes, hash.Value)
    | Error err -> Assert.Fail(err)

[<Fact>]
let ``QualityScore and CoverageScore enforce 0 to 100 range`` () =
    Assert.True(QualityScore.create -1 |> Result.isError)
    Assert.True(QualityScore.create 101 |> Result.isError)
    Assert.True(QualityScore.create 85 |> Result.isOk)

    Assert.True(CoverageScore.create -5 |> Result.isError)
    Assert.True(CoverageScore.create 105 |> Result.isError)
    Assert.True(CoverageScore.create 92 |> Result.isOk)

[<Fact>]
let ``SensorOtp parses DacH, DacL and FdtDac correctly`` () =
    let raw = Array.zeroCreate 64
    raw.[26] <- 0x28uy // DacH
    raw.[45] <- 0x24uy // DacL
    raw.[33] <- 0x91uy // FdtDac[0]
    raw.[41] <- 0x8buy // FdtDac[1]
    raw.[42] <- 0x96uy // FdtDac[2]
    raw.[43] <- 0x92uy // FdtDac[3]

    match SensorOtp.parse raw with
    | Ok otp ->
        Assert.Equal(0x28uy, otp.DacH)
        Assert.Equal(0x24uy, otp.DacL)
        Assert.Equal<byte seq>([| 0x91uy; 0x8buy; 0x96uy; 0x92uy |], otp.FdtDac)
        Assert.Equal(64, otp.Raw.Length)
    | Error err -> Assert.Fail(string err)

[<Fact>]
let ``SensorOtp rejects truncated buffer`` () =
    let truncated = Array.zeroCreate 32
    match SensorOtp.parse truncated with
    | Error (ValidationError ("SensorOtp", _)) -> ()
    | res -> Assert.Fail($"Expected ValidationError, got {res}")

// ============================================================================
// CRC32 Tests
// ============================================================================

[<Fact>]
let ``Standard CRC32 matches IEEE 802.3 test vectors`` () =
    // Empty input: 0x00000000
    Assert.Equal(0x00000000u, Crc32.compute (ReadOnlySpan [||]))

    // Standard ASCII "123456789": 0xCBF43926
    let vector = System.Text.Encoding.ASCII.GetBytes("123456789")
    Assert.Equal(0xCBF43926u, Crc32.compute (ReadOnlySpan vector))

[<Fact>]
let ``GoodixFrameCrc correctly verifies valid and corrupted frame`` () =
    let data = Array.init GoodixFrameCrc.FrameDataLength (fun i -> byte (i &&& 0xff))
    let crc = Crc32.compute (ReadOnlySpan data)
    let crcBytesBe = [|
        byte (crc >>> 24)
        byte (crc >>> 16)
        byte (crc >>> 8)
        byte crc
    |]
    let validFrame = Array.concat [ data; crcBytesBe ]

    match GoodixFrameCrc.verify (ReadOnlySpan validFrame) with
    | Ok () -> ()
    | Error err -> Assert.Fail($"Valid frame verification failed: {err}")

    // Corrupt one data byte
    validFrame.[100] <- validFrame.[100] ^^^ 0xffuy
    match GoodixFrameCrc.verify (ReadOnlySpan validFrame) with
    | Error (ChecksumMismatch _) -> ()
    | res -> Assert.Fail($"Expected ChecksumMismatch, got {res}")

// ============================================================================
// Protocol Packet & Active Pattern Tests
// ============================================================================

[<Fact>]
let ``MessagePack encode and decode roundtrip`` () =
    let payload = [| 0x01uy; 0x02uy; 0x03uy; 0x04uy |]
    let packed = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol payload

    match Protocol.decodeMessagePack packed with
    | Ok (flags, decPayload) ->
        Assert.Equal(Protocol.FlagsMessageProtocol, flags)
        Assert.Equal<byte seq>(payload, decPayload)
    | Error err -> Assert.Fail(string err)

[<Fact>]
let ``MessagePack rejects invalid checksum`` () =
    let payload = [| 0x01uy; 0x02uy |]
    let packed = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol payload
    packed.[3] <- packed.[3] ^^^ 0x55uy // corrupt checksum

    match Protocol.decodeMessagePack packed with
    | Error (InvalidPacket msg) -> Assert.Contains("checksum mismatch", msg)
    | res -> Assert.Fail($"Expected checksum mismatch error, got {res}")

[<Fact>]
let ``MessageProtocol encode and decode with checksum roundtrip`` () =
    let payload = [| 0x10uy; 0x20uy; 0x30uy |]
    let encoded = Protocol.encodeMessageProtocol Protocol.CommandMcuGetImage payload true

    match Protocol.decodeMessageProtocol encoded true with
    | Ok (cmd, decPayload) ->
        Assert.Equal(Protocol.CommandMcuGetImage, cmd)
        Assert.Equal<byte seq>(payload, decPayload)
    | Error err -> Assert.Fail(string err)

[<Fact>]
let ``Active pattern AckResponse correctly identifies ACK packet`` () =
    let ackPayload = [| Protocol.CommandReset; 0x03uy |] // command = Reset, success bit 1 set
    let inner = Protocol.encodeMessageProtocol Protocol.CommandAck ackPayload true
    let packet = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol inner

    match packet with
    | Protocol.AckResponse (cmd, success) ->
        Assert.Equal(Protocol.CommandReset, cmd)
        Assert.True(success)
    | other -> Assert.Fail($"Expected AckResponse, got {other}")

// ============================================================================
// FrameDecoder Tests
// ============================================================================

[<Fact>]
let ``UnpackSequential and UnpackAndTranspose80x64 unpack 7680 bytes to 5120 pixels`` () =
    // Create synthetic 6-byte chunk:
    // chunk: [b0; b1; b2; b3; b4; b5]
    // p0 = ((b0 & 0xf) << 8) | b1
    // p1 = (b3 << 4) | (b0 >> 4)
    // p2 = ((b5 & 0xf) << 8) | b2
    // p3 = (b4 << 4) | (b5 >> 4)
    let packed = Array.zeroCreate FrameDecoder.PackedFrameSize
    for chunkIdx in 0 .. 1279 do
        let off = chunkIdx * 6
        packed.[off] <- 0x12uy
        packed.[off + 1] <- 0x34uy
        packed.[off + 2] <- 0x56uy
        packed.[off + 3] <- 0x78uy
        packed.[off + 4] <- 0x9auy
        packed.[off + 5] <- 0xbcuy

    match FrameDecoder.unpackSequential packed with
    | Ok pixels ->
        Assert.Equal(5120, pixels.Length)
        // Check first 4 pixels
        // p0 = ((0x12 & 0xf) << 8) | 0x34 = 0x234 = 564
        // p1 = (0x78 << 4) | (0x12 >> 4) = 0x781 = 1921
        // p2 = ((0xbc & 0xf) << 8) | 0x56 = 0xc56 = 3158
        // p3 = (0x9a << 4) | (0xbc >> 4) = 0x9ab = 2475
        Assert.Equal(564us, pixels.[0])
        Assert.Equal(1921us, pixels.[1])
        Assert.Equal(3158us, pixels.[2])
        Assert.Equal(2475us, pixels.[3])
    | Error err -> Assert.Fail(string err)

[<Fact>]
let ``Span-based unpack and transpose matches array-based implementation exactly`` () =
    let rnd = Random(42)
    let packed = Array.zeroCreate FrameDecoder.PackedFrameSize
    rnd.NextBytes(packed)

    let expected =
        match FrameDecoder.unpackAndTranspose80x64 packed with
        | Ok arr -> arr
        | Error err -> failwith (string err)

    let spanOutput = Array.zeroCreate<uint16> FrameDecoder.PixelCount
    match FrameDecoder.unpackAndTranspose80x64Span (ReadOnlySpan packed) (Span spanOutput) with
    | Ok () ->
        Assert.Equal<uint16 seq>(expected, spanOutput)
    | Error err -> Assert.Fail(string err)

[<Fact>]
let ``PGM and PPM export generate valid headers and byte counts`` () =
    let pixels = Array.init 5120 (fun i -> uint16 (i % 4096))
    let pgm12 = FrameDecoder.toPgm12Bit pixels 80 64
    let expectedHeader12 = "P5\n80 64\n4095\n"
    let str12 = System.Text.Encoding.ASCII.GetString(pgm12)
    Assert.StartsWith(expectedHeader12, str12)
    Assert.Equal(expectedHeader12.Length + (80 * 64 * 2), pgm12.Length)

    let squashed = FrameDecoder.squash12To8Bit pixels
    let pgm8 = FrameDecoder.toPgm8Bit squashed 80 64
    let expectedHeader8 = "P5\n80 64\n255\n"
    let str8 = System.Text.Encoding.ASCII.GetString(pgm8)
    Assert.StartsWith(expectedHeader8, str8)
    Assert.Equal(expectedHeader8.Length + (80 * 64), pgm8.Length)

    let ppm8 = FrameDecoder.toPpm8Bit squashed 80 64
    let expectedHeaderPpm = "P6\n80 64\n255\n"
    let strPpm = System.Text.Encoding.ASCII.GetString(ppm8)
    Assert.StartsWith(expectedHeaderPpm, strPpm)
    Assert.Equal(expectedHeaderPpm.Length + (80 * 64 * 3), ppm8.Length)

// ============================================================================
// TLS 1.2 PSK Handshake & Decryption Tests (Both Servers)
// ============================================================================

[<Fact>]
let ``PureFSharpTlsPskTunnel completes handshake with client and decrypts 7684 byte frame`` () =
    let psk = Array.zeroCreate<byte> 32
    let client = new TlsClientProtocol()
    client.Connect(TestPskTlsClient(psk))

    use server = new PureFSharpTlsPskTunnel(psk) :> ITlsPskTunnel

    // 1. ClientHello
    let chLen = client.GetAvailableOutputBytes()
    let chBuf = Array.zeroCreate<byte> chLen
    client.ReadOutput(chBuf, 0, chLen) |> ignore

    // 2. ServerHello + ServerHelloDone
    match server.HandleHandshake(chBuf) with
    | Ok (Some shBytes) ->
        client.OfferInput(shBytes)
    | other -> Assert.Fail($"Expected ServerHello flight, got {other}")

    // 3. ClientKeyExchange + ChangeCipherSpec + Finished
    let cFlightLen = client.GetAvailableOutputBytes()
    let cFlightBuf = Array.zeroCreate<byte> cFlightLen
    client.ReadOutput(cFlightBuf, 0, cFlightLen) |> ignore

    // 4. Server ChangeCipherSpec + Finished
    match server.HandleHandshake(cFlightBuf) with
    | Ok (Some sfBytes) ->
        client.OfferInput(sfBytes)
    | other -> Assert.Fail($"Expected Server finished flight, got {other}")

    Assert.True(client.IsConnected, "Client is connected")
    Assert.True(server.IsHandshakeComplete, "Pure F# server handshake complete")

    // 5. Encrypt 7684-byte frame from client
    let frame = Array.init 7684 (fun i -> byte (i &&& 0xff))
    client.WriteApplicationData(frame, 0, frame.Length)
    let appLen = client.GetAvailableOutputBytes()
    let appBuf = Array.zeroCreate<byte> appLen
    client.ReadOutput(appBuf, 0, appLen) |> ignore

    // Test decryption both with and without 9-byte 0xb2 Goodix header
    match server.DecryptApplicationData(appBuf) with
    | Ok decryptedBare ->
        Assert.Equal<byte seq>(frame, decryptedBare)
    | Error err -> Assert.Fail($"Bare application data decryption failed: {err}")

    // Wrap in 9-byte 0xb2 Goodix header
    let goodixWrapped = Array.concat [
        [| 0xb2uy; 0x00uy; 0x20uy; 0xd2uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |]
        appBuf
    ]

    // Reset sequence number or re-test
    // Note: since sequence number incremented for bare record, we test wrapped with fresh tunnel
    let serverWrapped = new PureFSharpTlsPskTunnel(psk) :> ITlsPskTunnel
    let client2 = new TlsClientProtocol()
    client2.Connect(TestPskTlsClient(psk))

    let chLen2 = client2.GetAvailableOutputBytes()
    let chBuf2 = Array.zeroCreate<byte> chLen2
    client2.ReadOutput(chBuf2, 0, chLen2) |> ignore
    let shBytes2 = (serverWrapped.HandleHandshake(chBuf2) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client2.OfferInput(shBytes2)

    let cFlightLen2 = client2.GetAvailableOutputBytes()
    let cFlightBuf2 = Array.zeroCreate<byte> cFlightLen2
    client2.ReadOutput(cFlightBuf2, 0, cFlightLen2) |> ignore
    let sfBytes2 = (serverWrapped.HandleHandshake(cFlightBuf2) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client2.OfferInput(sfBytes2)

    client2.WriteApplicationData(frame, 0, frame.Length)
    let appLen2 = client2.GetAvailableOutputBytes()
    let appBuf2 = Array.zeroCreate<byte> appLen2
    client2.ReadOutput(appBuf2, 0, appLen2) |> ignore

    let goodixWrapped2 = Array.concat [
        [| 0xb2uy; 0x00uy; 0x20uy; 0xd2uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |]
        appBuf2
    ]

    match serverWrapped.DecryptApplicationData(goodixWrapped2) with
    | Ok decryptedWrapped ->
        Assert.Equal<byte seq>(frame, decryptedWrapped)
    | Error err -> Assert.Fail($"0xb2-wrapped application data decryption failed: {err}")

[<Fact>]
let ``BouncyCastleTlsPskTunnel completes handshake with client and decrypts 7684 byte frame`` () =
    let psk = Array.zeroCreate<byte> 32
    let client = new TlsClientProtocol()
    client.Connect(TestPskTlsClient(psk))

    use server = new BouncyCastleTlsPskTunnel(psk) :> ITlsPskTunnel

    let pump () =
        let cAvail = client.GetAvailableOutputBytes()
        if cAvail > 0 then
            let cBuf = Array.zeroCreate<byte> cAvail
            client.ReadOutput(cBuf, 0, cAvail) |> ignore
            match server.HandleHandshake(cBuf) with
            | Ok (Some sResp) -> client.OfferInput(sResp)
            | Ok None -> ()
            | Error err -> failwith $"Server handshake error: {err}"

    let mutable iters = 0
    while (not client.IsConnected || not server.IsHandshakeComplete) && iters < 10 do
        pump ()
        iters <- iters + 1

    Assert.True(client.IsConnected, "BC Client connected")
    Assert.True(server.IsHandshakeComplete, "BC Server connected")

    // Send 7684-byte frame
    let frame = Array.init 7684 (fun i -> byte (i &&& 0xff))
    client.WriteApplicationData(frame, 0, frame.Length)

    let appAvail = client.GetAvailableOutputBytes()
    let appBuf = Array.zeroCreate<byte> appAvail
    client.ReadOutput(appBuf, 0, appAvail) |> ignore

    let goodixWrapped = Array.concat [
        [| 0xb2uy; 0x00uy; 0x20uy; 0xd2uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |]
        appBuf
    ]

    match server.DecryptApplicationData(goodixWrapped) with
    | Ok decrypted ->
        Assert.Equal<byte seq>(frame, decrypted)
    | Error err -> Assert.Fail($"BC DecryptApplicationData failed: {err}")

// ============================================================================
// High-Level Device53xd Driver Workflow Tests (Mock Transport)
// ============================================================================

type MockUsbTransport() =
    let responses = System.Collections.Generic.Queue<byte[]>()
    let written = ResizeArray<byte[]>()

    member _.EnqueueResponse(data: byte[]) = responses.Enqueue(data)
    member _.WrittenPackets = written.ToArray()

    interface IUsbTransport with
        member _.Write(data) =
            written.Add(Array.copy data)
            Ok ()
        member _.Read(length, timeoutMs) =
            if responses.Count > 0 then
                Ok (responses.Dequeue())
            else
                Error (Timeout "Mock transport queue empty")
        member _.Dispose() = ()

[<Fact>]
let ``Goodix53xdDevice ProbeInfo correctly queries firmware, chip ID, and OTP`` () =
    task {
        let mockTransport = new MockUsbTransport()

        // 1. NOP -> ACK
        let ackNop = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandNop; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackNop)

        // 2. FirmwareVersion -> ACK, then CommandResponse
        let ackFw = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandFirmwareVersion; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackFw)
        let respFw = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandFirmwareVersion (System.Text.Encoding.ASCII.GetBytes("GF5298_GM168SEC_APP_13016\u0000")) true)
        mockTransport.EnqueueResponse(respFw)

        // 3. EnableChip -> ACK
        let ackEnableChip = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandEnableChip; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackEnableChip)

        // 4. Reset -> ACK, then CommandResponse
        let ackReset = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandReset; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackReset)
        let respReset = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandReset [| 0x01uy; 0x00uy |] true)
        mockTransport.EnqueueResponse(respReset)

        // 5. ReadSensorRegister -> ACK, then CommandResponse (Chip ID payload on 27c6:538d is [0f a6 00 22])
        let ackChip = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandReadSensorRegister; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackChip)
        let respChip = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandReadSensorRegister [| 0x0fuy; 0xa6uy; 0x00uy; 0x22uy |] true)
        mockTransport.EnqueueResponse(respChip)

        // 6. ReadOtp -> ACK, then CommandResponse (64 bytes OTP)
        let ackOtp = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandReadOtp; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackOtp)
        let rawOtp = Array.zeroCreate 64
        rawOtp.[26] <- 0x28uy
        rawOtp.[45] <- 0x24uy
        let respOtp = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandReadOtp rawOtp true)
        mockTransport.EnqueueResponse(respOtp)

        use dev = new Goodix53xdDevice(mockTransport)
        let! probeResult = dev.ProbeInfo()

        match probeResult with
        | Ok info ->
            Assert.Equal("GF5298_GM168SEC_APP_13016", info.Firmware.Value)
            Assert.Equal(0x00a6us, info.Chip.Value)
            Assert.Equal(0x28uy, info.Otp.DacH)
            Assert.Equal(0x24uy, info.Otp.DacL)
        | Error err -> Assert.Fail($"ProbeInfo failed: {err}")
    }

[<Fact>]
let ``Goodix53xdDevice Sleep sends sleep command and receives ACK`` () =
    task {
        let mockTransport = new MockUsbTransport()
        let ackSleep = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandMcuSwitchToSleepMode; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackSleep)

        use dev = new Goodix53xdDevice(mockTransport)
        let! sleepResult = dev.Sleep()

        match sleepResult with
        | Ok () ->
            Assert.True(mockTransport.WrittenPackets.Length > 0)
        | Error err -> Assert.Fail($"Sleep failed: {err}")
    }

// ============================================================================
// NativeMatcher Types & Domain Discipline Tests
// ============================================================================

[<Fact>]
let ``LibraryPath rejects whitespace and empty strings`` () =
    Assert.True(LibraryPath.create "" |> Result.isError)
    Assert.True(LibraryPath.create "   " |> Result.isError)
    let tempFile = Path.GetTempFileName()
    try
        match LibraryPath.create tempFile with
        | Ok p -> Assert.Equal(tempFile, p.Value)
        | Error err -> Assert.Fail(string err)
    finally
        if File.Exists tempFile then File.Delete tempFile

[<Fact>]
let ``FingerId rejects whitespace and empty strings`` () =
    Assert.True(FingerId.create "" |> Result.isError)
    Assert.True(FingerId.create "   " |> Result.isError)
    match FingerId.create "finger1" with
    | Ok fid -> Assert.Equal("finger1", fid.Value)
    | Error err -> Assert.Fail(string err)

[<Fact>]
let ``TemplateBlob validates non-empty and minimum header length`` () =
    Assert.True(TemplateBlob.create [||] |> Result.isError)
    Assert.True(TemplateBlob.create [| 0x54uy; 0x47uy |] |> Result.isError)
    let validBlob = Array.create 65649 0uy
    validBlob.[0] <- 0x54uy // 'T'
    validBlob.[1] <- 0x47uy // 'G'
    validBlob.[2] <- 0x4cuy // 'L'
    validBlob.[3] <- 0x41uy // 'A'
    match TemplateBlob.create validBlob with
    | Ok tb ->
        Assert.Equal(65649, tb.Length)
        Assert.Equal<byte seq>(validBlob, tb.Value)
    | Error err -> Assert.Fail(string err)

// ============================================================================
// NativeMatcher E2E Matching & Preprocessing Tests
// ============================================================================

let private generateSyntheticRidgeFrame (shiftX: float) (shiftY: float) (noise: float) =
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
            let ridge = Math.Sin(r * 0.8 - theta * 3.0)
            let rawVal = 2048.0 + 800.0 * ridge + noise * (float ((x * 17 + y * 31) % 50) - 25.0)
            let clamped = Math.Clamp(rawVal, 0.0, 4095.0)
            pixels.[y * width + x] <- uint16 clamped
    pixels

[<Fact>]
let ``GoodixTodMatcher E2E enrolls 12 samples, exports 65KB TGLA template, matches genuine and rejects impostor`` () =
    let home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
    let candidatePaths = [
        Path.Combine(home, ".local/share/goodix-fp/libgoodix_tod_53xc.so")
        "/tmp/libgoodix_standalone.so"
    ]
    let libPathOpt = candidatePaths |> List.tryFind File.Exists
    match libPathOpt with
    | None ->
        // In environments without native lib, skip gracefully
        ()
    | Some pathStr ->
        let libPath = LibraryPath.create pathStr |> Result.defaultWith (fun e -> failwith (string e))
        use matcher = GoodixTodMatcher.create libPath |> Result.defaultWith (fun e -> failwith $"Failed to create matcher: {e}")

        // 1. Verify preprocessing
        let testFrame = generateSyntheticRidgeFrame 0.0 0.0 0.0
        match matcher.Preprocess(testFrame) with
        | Error err -> Assert.Fail($"Preprocess failed: {err}")
        | Ok prep ->
            Assert.True(prep.Quality.Value > 0, "Quality score should be > 0")
            Assert.True(prep.Coverage.Value > 0, "Coverage score should be > 0")
            Assert.Equal(80 * 64, prep.NormalizedPixels.Length)

        // 2. Start enrollment
        match matcher.StartEnroll() with
        | Error err -> Assert.Fail($"StartEnroll failed: {err}")
        | Ok () -> ()

        // 3. Merge 12 synthetic samples
        for i in 0 .. 11 do
            let sx = float (i % 3 - 1) * 1.5
            let sy = float (i / 3 - 2) * 1.5
            let sample = generateSyntheticRidgeFrame sx sy 1.0
            match matcher.MergeSample(sample) with
            | Error err -> Assert.Fail($"MergeSample {i + 1} failed: {err}")
            | Ok progress ->
                Assert.Equal(i + 1, progress)

        // 4. Commit template
        let fingerId = FingerId.create "finger1" |> Result.defaultWith (fun e -> failwith (string e))
        let templateBlob =
            match matcher.CommitTemplate(fingerId) with
            | Error err -> failwith $"CommitTemplate failed: {err}"
            | Ok blob ->
                Assert.True(blob.Length > 50000, $"Expected template size > 50KB, got {blob.Length}")
                // Verify "TGLA" magic header
                Assert.Equal(0x54uy, blob.Value.[0]) // 'T'
                Assert.Equal(0x47uy, blob.Value.[1]) // 'G'
                Assert.Equal(0x4cuy, blob.Value.[2]) // 'L'
                Assert.Equal(0x41uy, blob.Value.[3]) // 'A'
                blob

        let enrolledTemplates = [ (fingerId, templateBlob) ]

        // 5. Genuine probe match
        let genuineProbe = generateSyntheticRidgeFrame 0.5 0.5 1.0
        match matcher.IdentifyProbe(genuineProbe, enrolledTemplates) with
        | Error err -> Assert.Fail($"IdentifyProbe failed: {err}")
        | Ok None -> Assert.Fail("Expected genuine probe to match template, but got None")
        | Ok (Some matchedId) ->
            Assert.Equal("finger1", matchedId.Value)

        // 6. Impostor probe rejection
        let impostorProbe = Array.init (80 * 64) (fun idx -> uint16 (1800 + (idx * 47) % 800))
        match matcher.IdentifyProbe(impostorProbe, enrolledTemplates) with
        | Error err -> Assert.Fail($"IdentifyProbe impostor failed: {err}")
        | Ok (Some matchedId) ->
            Assert.Fail($"Expected impostor probe to be rejected, but matched {matchedId.Value}")
        | Ok None ->
            // Impostor successfully rejected
            ()

// ============================================================================
// Multi-record flights & TLS Decryption Offset Tests
// ============================================================================

[<Fact>]
let ``PureFSharpTlsPskTunnel handles ClientKeyExchange, ChangeCipherSpec, and Finished across 3 separate calls`` () =
    let psk = Array.zeroCreate<byte> 32
    let client = new TlsClientProtocol()
    client.Connect(TestPskTlsClient(psk))

    use server = new PureFSharpTlsPskTunnel(psk) :> ITlsPskTunnel

    // 1. ClientHello
    let chLen = client.GetAvailableOutputBytes()
    let chBuf = Array.zeroCreate<byte> chLen
    client.ReadOutput(chBuf, 0, chLen) |> ignore

    let shBytes = (server.HandleHandshake(chBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client.OfferInput(shBytes)

    // 2. Client sends flight: extract individual TLS records
    let cFlightLen = client.GetAvailableOutputBytes()
    let cFlightBuf = Array.zeroCreate<byte> cFlightLen
    client.ReadOutput(cFlightBuf, 0, cFlightLen) |> ignore

    // Split concatenated cFlightBuf into separate TLS records
    let records = ResizeArray<byte[]>()
    let mutable offset = 0
    while offset + 5 <= cFlightBuf.Length do
        let curLen = (int cFlightBuf.[offset + 3] <<< 8) ||| int cFlightBuf.[offset + 4]
        let recBytes = Array.sub cFlightBuf offset (5 + curLen)
        records.Add(recBytes)
        offset <- offset + 5 + curLen

    Assert.Equal(3, records.Count) // CKE, CCS, Finished

    // Call 1: ClientKeyExchange -> returns Ok None
    match server.HandleHandshake(records.[0]) with
    | Ok None -> ()
    | other -> Assert.Fail($"Expected Ok None for CKE, got {other}")
    Assert.False(server.IsHandshakeComplete)

    // Call 2: ChangeCipherSpec -> returns Ok None
    match server.HandleHandshake(records.[1]) with
    | Ok None -> ()
    | other -> Assert.Fail($"Expected Ok None for CCS, got {other}")
    Assert.False(server.IsHandshakeComplete)

    // Call 3: Encrypted Finished -> returns Ok (Some serverFlight)
    match server.HandleHandshake(records.[2]) with
    | Ok (Some sfBytes) ->
        client.OfferInput(sfBytes)
    | other -> Assert.Fail($"Expected Ok (Some serverFlight) for Finished, got {other}")

    Assert.True(server.IsHandshakeComplete)
    Assert.True(client.IsConnected)

[<Fact>]
let ``PureFSharpTlsPskTunnel and BouncyCastle decrypt concatenated multi-record frames across 0, 9, and 13 offsets`` () =
    let psk = Array.zeroCreate<byte> 32

    // Setup Pure F# session
    let client = new TlsClientProtocol()
    client.Connect(TestPskTlsClient(psk))
    use pureServer = new PureFSharpTlsPskTunnel(psk) :> ITlsPskTunnel

    let chLen = client.GetAvailableOutputBytes()
    let chBuf = Array.zeroCreate<byte> chLen
    client.ReadOutput(chBuf, 0, chLen) |> ignore
    let shBytes = (pureServer.HandleHandshake(chBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client.OfferInput(shBytes)

    let cFlightLen = client.GetAvailableOutputBytes()
    let cFlightBuf = Array.zeroCreate<byte> cFlightLen
    client.ReadOutput(cFlightBuf, 0, cFlightLen) |> ignore
    let sfBytes = (pureServer.HandleHandshake(cFlightBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client.OfferInput(sfBytes)

    // Write chunk 1 (100 bytes) and chunk 2 (200 bytes)
    let chunk1 = Array.init 100 (fun i -> byte (i &&& 0xff))
    let chunk2 = Array.init 200 (fun i -> byte ((i + 100) &&& 0xff))
    client.WriteApplicationData(chunk1, 0, chunk1.Length)
    let rec1Len = client.GetAvailableOutputBytes()
    let rec1Bytes = Array.zeroCreate<byte> rec1Len
    client.ReadOutput(rec1Bytes, 0, rec1Len) |> ignore

    client.WriteApplicationData(chunk2, 0, chunk2.Length)
    let rec2Len = client.GetAvailableOutputBytes()
    let rec2Bytes = Array.zeroCreate<byte> rec2Len
    client.ReadOutput(rec2Bytes, 0, rec2Len) |> ignore

    // Concatenate two TLS records into one buffer
    let multiRecordTls = Array.concat [ rec1Bytes; rec2Bytes ]
    let expectedPlain = Array.concat [ chunk1; chunk2 ]

    // 1. Decrypt raw TLS multi-record (offset 0)
    match pureServer.DecryptApplicationData(multiRecordTls) with
    | Ok decrypted -> Assert.Equal<byte seq>(expectedPlain, decrypted)
    | Error err -> Assert.Fail($"Multi-record raw TLS decryption failed: {err}")

    // Reset sequence number and test with 9-byte Goodix header
    pureServer.Reset()
    let client2 = new TlsClientProtocol()
    client2.Connect(TestPskTlsClient(psk))
    let chLen2 = client2.GetAvailableOutputBytes()
    let chBuf2 = Array.zeroCreate<byte> chLen2
    client2.ReadOutput(chBuf2, 0, chLen2) |> ignore
    let shBytes2 = (pureServer.HandleHandshake(chBuf2) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client2.OfferInput(shBytes2)
    let cFlightLen2 = client2.GetAvailableOutputBytes()
    let cFlightBuf2 = Array.zeroCreate<byte> cFlightLen2
    client2.ReadOutput(cFlightBuf2, 0, cFlightLen2) |> ignore
    let sfBytes2 = (pureServer.HandleHandshake(cFlightBuf2) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client2.OfferInput(sfBytes2)

    client2.WriteApplicationData(chunk1, 0, chunk1.Length)
    let rec1Len2 = client2.GetAvailableOutputBytes()
    let rec1Bytes2 = Array.zeroCreate<byte> rec1Len2
    client2.ReadOutput(rec1Bytes2, 0, rec1Len2) |> ignore

    // 9-byte Goodix header (0xb2 + 8 metadata bytes) -> offset 9
    let goodixHeader9 = [| 0xb2uy; 0x00uy; 0x20uy; 0xd2uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |]
    let wrapped9 = Array.concat [ goodixHeader9; rec1Bytes2 ]

    match pureServer.DecryptApplicationData(wrapped9) with
    | Ok decrypted -> Assert.Equal<byte seq>(chunk1, decrypted)
    | Error err -> Assert.Fail($"9-byte Goodix wrapped decryption failed: {err}")

    // Test with 4-byte outer MessagePack header + 9-byte Goodix header (offset 13)
    pureServer.Reset()
    let client3 = new TlsClientProtocol()
    client3.Connect(TestPskTlsClient(psk))
    let chLen3 = client3.GetAvailableOutputBytes()
    let chBuf3 = Array.zeroCreate<byte> chLen3
    client3.ReadOutput(chBuf3, 0, chLen3) |> ignore
    let shBytes3 = (pureServer.HandleHandshake(chBuf3) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client3.OfferInput(shBytes3)
    let cFlightLen3 = client3.GetAvailableOutputBytes()
    let cFlightBuf3 = Array.zeroCreate<byte> cFlightLen3
    client3.ReadOutput(cFlightBuf3, 0, cFlightLen3) |> ignore
    let sfBytes3 = (pureServer.HandleHandshake(cFlightBuf3) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client3.OfferInput(sfBytes3)

    client3.WriteApplicationData(chunk1, 0, chunk1.Length)
    let rec1Len3 = client3.GetAvailableOutputBytes()
    let rec1Bytes3 = Array.zeroCreate<byte> rec1Len3
    client3.ReadOutput(rec1Bytes3, 0, rec1Len3) |> ignore

    // 4-byte MessagePack header (0xb2, len_lo, len_hi, csum) + 9-byte metadata
    let mpHeader = [| 0xb2uy; 0x80uy; 0x00uy; 0x32uy |]
    let wrapped13 = Array.concat [ mpHeader; goodixHeader9; rec1Bytes3 ]

    match pureServer.DecryptApplicationData(wrapped13) with
    | Ok decrypted -> Assert.Equal<byte seq>(chunk1, decrypted)
    | Error err -> Assert.Fail($"13-byte wrapped decryption failed: {err}")

[<Fact>]
let ``Goodix53xdDevice ProvisionZeroPsk validates PMK_HASH and writes PSK White-Box when needed`` () =
    task {
        let mockTransport = new MockUsbTransport()

        // 1. Initial PSK read returns invalid (all zeros, not matching PmkHashZero)
        let ackRead = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandPresetPskReadR; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackRead)
        let unprovPskPayload = Array.zeroCreate 45 // status=0, flags=0, hash=all zeros
        let respRead = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandPresetPskReadR unprovPskPayload true)
        mockTransport.EnqueueResponse(respRead)

        // 2. Write PSK White-Box -> ACK, then CommandResponse (status=0)
        let ackWrite = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandPresetPskWriteR; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackWrite)
        let respWrite = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandPresetPskWriteR [| 0x00uy |] true)
        mockTransport.EnqueueResponse(respWrite)

        // 3. Re-read PSK status -> ACK, then CommandResponse with valid PmkHashZero at [9..40]
        mockTransport.EnqueueResponse(ackRead)
        let validPskPayload = Array.zeroCreate 45
        validPskPayload.[0] <- 0x00uy
        Array.Copy(Protocol.PmkHashZero, 0, validPskPayload, 9, 32)
        let respValidRead = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandPresetPskReadR validPskPayload true)
        mockTransport.EnqueueResponse(respValidRead)

        use dev = new Goodix53xdDevice(mockTransport)
        let! provRes = dev.ProvisionZeroPsk()

        match provRes with
        | Ok () ->
            // Verify that writePacket was sent with CommandPresetPskWriteR
            Assert.True(mockTransport.WrittenPackets.Length >= 2)
        | Error err -> Assert.Fail($"ProvisionZeroPsk failed: {err}")
    }


