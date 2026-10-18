module GoodixFp.Tests

open System
open System.IO
open System.Threading.Tasks
open Xunit
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

[<Fact>]
let ``GoodixFrameCrc verifies live Goodix hardware word-swapped MPEG2 frame CRC`` () =
    let data = Array.init GoodixFrameCrc.FrameDataLength (fun i -> byte (i &&& 0xff))
    let crc = Crc32.goodixCrc32 data
    let b0 = byte (crc >>> 8)
    let b1 = byte crc
    let b2 = byte (crc >>> 24)
    let b3 = byte (crc >>> 16)
    let frame = Array.concat [ data; [| b0; b1; b2; b3 |] ]
    match GoodixFrameCrc.verify (ReadOnlySpan frame) with
    | Ok () -> ()
    | Error err -> Assert.Fail($"Goodix hardware frame verification failed: {err}")

    // Corrupt one byte
    frame.[0] <- frame.[0] ^^^ 0x01uy
    match GoodixFrameCrc.verify (ReadOnlySpan frame) with
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
// TLS 1.2 PSK Handshake & Decryption Tests (Pure F# RFC 4279 / RFC 5246)
// ============================================================================

[<Fact>]
let ``PureFSharpTlsPskTunnel completes handshake with client and decrypts 7684 byte frame`` () =
    let psk = Array.zeroCreate<byte> 32
    use client = new PureTlsPskClient(psk)
    use server = new PureFSharpTlsPskTunnel(psk) :> ITlsPskTunnel

    // 1. ClientHello
    let ch = client.CreateClientHello()

    // 2. ServerHello + ServerHelloDone
    match server.HandleHandshake(ch) with
    | Ok (Some shBytes) ->
        // 3. ClientKeyExchange + ChangeCipherSpec + Finished
        let cFlight = client.ProcessServerHello(shBytes)

        // 4. Server ChangeCipherSpec + Finished
        match server.HandleHandshake(cFlight) with
        | Ok (Some sfBytes) ->
            let clientFinishedOk = client.ProcessServerFinished(sfBytes)
            Assert.True(clientFinishedOk, "Client processed server finished")
        | other -> Assert.Fail($"Expected Server finished flight, got {other}")
    | other -> Assert.Fail($"Expected ServerHello flight, got {other}")

    Assert.True(client.IsConnected, "Client is connected")
    Assert.True(server.IsHandshakeComplete, "Pure F# server handshake complete")

    // 5. Encrypt 7684-byte frame from client
    let frame = Array.init 7684 (fun i -> byte (i &&& 0xff))
    let appBuf = client.EncryptApplicationData(frame)

    // Test decryption both with and without 9-byte 0xb2 Goodix header
    match server.DecryptApplicationData(appBuf) with
    | Ok decryptedBare ->
        Assert.Equal<byte seq>(frame, decryptedBare)
    | Error err -> Assert.Fail($"Bare application data decryption failed: {err}")

    // Wrap in 9-byte 0xb2 Goodix header with fresh tunnel
    use serverWrapped = new PureFSharpTlsPskTunnel(psk) :> ITlsPskTunnel
    use client2 = new PureTlsPskClient(psk)

    let ch2 = client2.CreateClientHello()
    let shBytes2 = (serverWrapped.HandleHandshake(ch2) |> Result.defaultWith (fun e -> failwith (string e))).Value
    let cFlight2 = client2.ProcessServerHello(shBytes2)
    let sfBytes2 = (serverWrapped.HandleHandshake(cFlight2) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client2.ProcessServerFinished(sfBytes2) |> ignore

    let appBuf2 = client2.EncryptApplicationData(frame)
    let goodixWrapped2 = Array.concat [
        [| 0xb2uy; 0x00uy; 0x20uy; 0xd2uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |]
        appBuf2
    ]

    match serverWrapped.DecryptApplicationData(goodixWrapped2) with
    | Ok decryptedWrapped ->
        Assert.Equal<byte seq>(frame, decryptedWrapped)
    | Error err -> Assert.Fail($"0xb2-wrapped application data decryption failed: {err}")

[<Fact>]
let ``PureTlsCrypto verifies RFC 5246 PRF and HMAC vectors and start offset detection`` () =
    // Verify PRF test vector with known secret and seed
    let secret = Array.init 32 (fun i -> byte i)
    let seed = Array.init 32 (fun i -> byte (i + 32))
    let prfOutput = PureTlsCrypto.prf secret "test label" seed 48
    Assert.Equal(48, prfOutput.Length)

    // Verify HMAC-SHA256 record MAC computation
    let macKey = Array.init 32 (fun i -> byte (i * 3))
    let payload = Array.init 100 (fun i -> byte (i * 7))
    let mac = PureTlsCrypto.computeMac macKey 1UL 0x17uy payload
    Assert.Equal(32, mac.Length)

    // Verify findTlsStartOffset across bare (0), Goodix 9-byte (9), and MessagePack 13-byte (13) headers
    let bareTls = [| 0x17uy; 0x03uy; 0x03uy; 0x00uy; 0x10uy |]
    Assert.Equal(Some 0, PureTlsCrypto.findTlsStartOffset bareTls)

    let goodix9 = Array.concat [
        [| 0xb2uy; 0x00uy; 0x20uy; 0xd2uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |]
        bareTls
    ]
    Assert.Equal(Some 9, PureTlsCrypto.findTlsStartOffset goodix9)

    let goodix13 = Array.concat [
        [| 0xb2uy; 0x80uy; 0x00uy; 0x32uy |]
        goodix9
    ]
    Assert.Equal(Some 13, PureTlsCrypto.findTlsStartOffset goodix13)

// ============================================================================
// High-Level Device53xd Driver Workflow Tests (Mock Transport)
// ============================================================================

type MockUsbTransport() =
    let responses = System.Collections.Generic.Queue<Result<byte[], DriverError>>()
    let written = ResizeArray<byte[]>()

    member _.EnqueueResponse(data: byte[]) = responses.Enqueue(Ok data)
    member _.EnqueueError(err: DriverError) = responses.Enqueue(Error err)
    member _.WrittenPackets = written.ToArray()

    interface IUsbTransport with
        member _.Write(data) =
            written.Add(Array.copy data)
            Ok ()
        member _.Read(length, timeoutMs) =
            if responses.Count > 0 then
                responses.Dequeue()
            else
                Error (Timeout "Mock transport queue empty")
        member _.DrainBuffer(?timeoutMs: int) = ()
        member _.ResetConnection() = Ok ()
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
            let ridge = Math.Cos(r * 0.8 + 2.0 * theta)
            let rawVal = 1500.0 + 350.0 * ridge + noise * (float ((x * 17 + y * 31) % 10) - 5.0)
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

[<Fact>]
let ``GoodixTodMatcher with baseline frame accepts real saved laptop touches 1 to 12 and identifies touch 14`` () =
    let home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
    let candidatePaths = [
        Path.Combine(home, ".local/share/goodix-fp/libgoodix_tod_53xc.so")
        "/tmp/libgoodix_standalone.so"
    ]
    let libPathOpt = candidatePaths |> List.tryFind File.Exists
    let calibPgmPath = "/tmp/goodix-fp/calib-baseline16.pgm"
    let touch1PgmPath = "/tmp/goodix-fp/enroll-sample1-touch1-raw16.pgm"

    match libPathOpt with
    | Some pathStr when File.Exists calibPgmPath && File.Exists touch1PgmPath ->
        let libPath = LibraryPath.create pathStr |> Result.defaultWith (fun e -> failwith (string e))
        let calibBytes = File.ReadAllBytes calibPgmPath
        let calibPixels = FrameDecoder.fromPgm12Bit calibBytes
        let baseline = RawFrame12Bit.create calibPixels |> Result.toOption
        use matcher = GoodixTodMatcher.Create(customPath = libPath.Value, ?baseline = baseline) |> Result.defaultWith (fun e -> failwith $"Failed to create matcher: {e}")

        // Start enrollment
        match matcher.StartEnroll() with
        | Error err -> Assert.Fail($"StartEnroll failed: {err}")
        | Ok () -> ()

        // Merge all available touches 1..12
        for i in 1 .. 12 do
            let touchPath = $"/tmp/goodix-fp/enroll-sample1-touch{i}-raw16.pgm"
            if File.Exists touchPath then
                let touchBytes = File.ReadAllBytes touchPath
                let touchPixels = FrameDecoder.fromPgm12Bit touchBytes
                match matcher.MergeSample(touchPixels) with
                | Error err -> Assert.Fail($"MergeSample touch {i} failed: {err}")
                | Ok progress ->
                    Assert.Equal(i, progress)

        let fingerId = FingerId.create "finger1" |> Result.defaultWith (fun e -> failwith (string e))
        let templateBlob =
            match matcher.CommitTemplate(fingerId) with
            | Error err -> failwith $"CommitTemplate failed: {err}"
            | Ok blob ->
                Assert.True(blob.Length > 50000, $"Expected template size > 50000, got {blob.Length}")
                blob

        let enrolledTemplates = [ (fingerId, templateBlob) ]

        // Test touch 14 if exists
        let touch14Path = "/tmp/goodix-fp/enroll-sample1-touch14-raw16.pgm"
        if File.Exists touch14Path then
            let t14Bytes = File.ReadAllBytes touch14Path
            let t14Pixels = FrameDecoder.fromPgm12Bit t14Bytes
            match matcher.IdentifyProbe(t14Pixels, enrolledTemplates) with
            | Error err -> Assert.Fail($"IdentifyProbe failed: {err}")
            | Ok None -> Assert.Fail("Expected touch 14 to match enrolled template")
            | Ok (Some matchedId) ->
                Assert.Equal("finger1", matchedId.Value)
    | _ -> ()

// ============================================================================
// Multi-record flights & TLS Decryption Offset Tests
// ============================================================================

[<Fact>]
let ``PureFSharpTlsPskTunnel handles ClientKeyExchange, ChangeCipherSpec, and Finished across 3 separate calls`` () =
    let psk = Array.zeroCreate<byte> 32
    use client = new PureTlsPskClient(psk)
    use server = new PureFSharpTlsPskTunnel(psk) :> ITlsPskTunnel

    // 1. ClientHello
    let ch = client.CreateClientHello()
    let shBytes = (server.HandleHandshake(ch) |> Result.defaultWith (fun e -> failwith (string e))).Value

    // 2. Client sends flight: extract individual TLS records
    let cFlightBuf = client.ProcessServerHello(shBytes)

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
        let clientFinishedOk = client.ProcessServerFinished(sfBytes)
        Assert.True(clientFinishedOk, "Client processed server finished")
    | other -> Assert.Fail($"Expected Ok (Some serverFlight) for Finished, got {other}")

    Assert.True(server.IsHandshakeComplete)
    Assert.True(client.IsConnected)

[<Fact>]
let ``PureFSharpTlsPskTunnel decrypts concatenated multi-record frames across 0, 9, and 13 offsets`` () =
    let psk = Array.zeroCreate<byte> 32

    // Setup Pure F# session
    use client = new PureTlsPskClient(psk)
    use pureServer = new PureFSharpTlsPskTunnel(psk) :> ITlsPskTunnel

    let ch = client.CreateClientHello()
    let shBytes = (pureServer.HandleHandshake(ch) |> Result.defaultWith (fun e -> failwith (string e))).Value
    let cFlight = client.ProcessServerHello(shBytes)
    let sfBytes = (pureServer.HandleHandshake(cFlight) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client.ProcessServerFinished(sfBytes) |> ignore

    // Write chunk 1 (100 bytes) and chunk 2 (200 bytes)
    let chunk1 = Array.init 100 (fun i -> byte (i &&& 0xff))
    let chunk2 = Array.init 200 (fun i -> byte ((i + 100) &&& 0xff))
    let rec1Bytes = client.EncryptApplicationData(chunk1)
    let rec2Bytes = client.EncryptApplicationData(chunk2)

    // Concatenate two TLS records into one buffer
    let multiRecordTls = Array.concat [ rec1Bytes; rec2Bytes ]
    let expectedPlain = Array.concat [ chunk1; chunk2 ]

    // 1. Decrypt raw TLS multi-record (offset 0)
    match pureServer.DecryptApplicationData(multiRecordTls) with
    | Ok decrypted -> Assert.Equal<byte seq>(expectedPlain, decrypted)
    | Error err -> Assert.Fail($"Multi-record raw TLS decryption failed: {err}")

    // Reset sequence number and test with 9-byte Goodix header
    pureServer.Reset()
    use client2 = new PureTlsPskClient(psk)
    let ch2 = client2.CreateClientHello()
    let shBytes2 = (pureServer.HandleHandshake(ch2) |> Result.defaultWith (fun e -> failwith (string e))).Value
    let cFlight2 = client2.ProcessServerHello(shBytes2)
    let sfBytes2 = (pureServer.HandleHandshake(cFlight2) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client2.ProcessServerFinished(sfBytes2) |> ignore

    let rec1Bytes2 = client2.EncryptApplicationData(chunk1)

    // 9-byte Goodix header (0xb2 + 8 metadata bytes) -> offset 9
    let goodixHeader9 = [| 0xb2uy; 0x00uy; 0x20uy; 0xd2uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |]
    let wrapped9 = Array.concat [ goodixHeader9; rec1Bytes2 ]

    match pureServer.DecryptApplicationData(wrapped9) with
    | Ok decrypted -> Assert.Equal<byte seq>(chunk1, decrypted)
    | Error err -> Assert.Fail($"9-byte Goodix wrapped decryption failed: {err}")

    // Test with 4-byte outer MessagePack header + 9-byte Goodix header (offset 13)
    pureServer.Reset()
    use client3 = new PureTlsPskClient(psk)
    let ch3 = client3.CreateClientHello()
    let shBytes3 = (pureServer.HandleHandshake(ch3) |> Result.defaultWith (fun e -> failwith (string e))).Value
    let cFlight3 = client3.ProcessServerHello(shBytes3)
    let sfBytes3 = (pureServer.HandleHandshake(cFlight3) |> Result.defaultWith (fun e -> failwith (string e))).Value
    client3.ProcessServerFinished(sfBytes3) |> ignore

    let rec1Bytes3 = client3.EncryptApplicationData(chunk1)

    // 4-byte MessagePack header (0xb2, len_lo, len_hi, csum) + 9-byte metadata
    let mpHeader = [| 0xb2uy; 0x80uy; 0x00uy; 0x32uy |]
    let wrapped13 = Array.concat [ mpHeader; goodixHeader9; rec1Bytes3 ]

    match pureServer.DecryptApplicationData(wrapped13) with
    | Ok decrypted -> Assert.Equal<byte seq>(chunk1, decrypted)
    | Error err -> Assert.Fail($"13-byte wrapped decryption failed: {err}")

let private createValidTestFirmware () : byte[] =
    let payload = Array.init 24256 (fun i -> byte (i &&& 0xff))
    let codeCrc = Crc32.goodixCrc32 payload
    let hdrTail = Array.concat [ BitConverter.GetBytes(24256u); BitConverter.GetBytes(codeCrc) ]
    let hdrCrc = Crc32.goodixCrc32 hdrTail
    Array.concat [ BitConverter.GetBytes(hdrCrc); hdrTail; payload ]

[<Fact>]
let ``Protocol verifyFirmwareImage validates header and payload Goodix CRC32 correctly`` () =
    let fw = createValidTestFirmware ()
    match Protocol.verifyFirmwareImage fw with
    | Ok () -> ()
    | Error err -> Assert.Fail($"Valid firmware failed verification: {err}")

    // Truncated firmware
    let shortFw = Array.zeroCreate 100
    match Protocol.verifyFirmwareImage shortFw with
    | Error (ValidationError ("FirmwareImage", _)) -> ()
    | other -> Assert.Fail($"Expected ValidationError for short firmware, got: {other}")

    // Corrupted header CRC
    let badHdrCrc = Array.copy fw
    badHdrCrc.[0] <- badHdrCrc.[0] ^^^ 0xffuy
    match Protocol.verifyFirmwareImage badHdrCrc with
    | Error (ChecksumMismatch _) -> ()
    | other -> Assert.Fail($"Expected ChecksumMismatch for corrupted header CRC, got: {other}")

    // Corrupted payload length
    let badLen = Array.copy fw
    badLen.[4] <- badLen.[4] ^^^ 0x01uy
    // Recompute header CRC over corrupted 4..11 so we reach payload length check
    let newHdrCrc = Crc32.goodixCrc32 badLen.[4..11]
    Array.Copy(BitConverter.GetBytes(newHdrCrc), 0, badLen, 0, 4)
    match Protocol.verifyFirmwareImage badLen with
    | Error (ValidationError ("FirmwarePayloadLength", _)) -> ()
    | other -> Assert.Fail($"Expected ValidationError for corrupted payload length, got: {other}")

    // Corrupted code CRC
    let badCodeCrc = Array.copy fw
    badCodeCrc.[8] <- badCodeCrc.[8] ^^^ 0xffuy
    let newHdrCrc2 = Crc32.goodixCrc32 badCodeCrc.[4..11]
    Array.Copy(BitConverter.GetBytes(newHdrCrc2), 0, badCodeCrc, 0, 4)
    match Protocol.verifyFirmwareImage badCodeCrc with
    | Error (ChecksumMismatch _) -> ()
    | other -> Assert.Fail($"Expected ChecksumMismatch for corrupted code CRC, got: {other}")

[<Fact>]
let ``Protocol packMcuEraseApp, packWriteFirmware, packCheckFirmware produce correct packets`` () =
    // 1. packMcuEraseApp
    let erasePacket = Protocol.packMcuEraseApp 50uy
    match erasePacket with
    | Protocol.MessagePack (flags, inner) ->
        Assert.Equal(Protocol.FlagsMessageProtocol, flags)
        match inner with
        | Protocol.MessageProtocol (cmd, payload) ->
            Assert.Equal(Protocol.CommandMcuEraseApp, cmd)
            Assert.Equal<byte seq>([| 0x00uy; 50uy |], payload)
        | _ -> Assert.Fail("Failed to decode inner MessageProtocol for McuEraseApp")
    | _ -> Assert.Fail("Failed to decode MessagePack for McuEraseApp")

    // 2. packWriteFirmware
    let payload = [| 0x11uy; 0x22uy; 0x33uy; 0x44uy |]
    let writePacket = Protocol.packWriteFirmware 512u payload 2u
    match writePacket with
    | Protocol.MessagePack (flags, inner) ->
        Assert.Equal(Protocol.FlagsMessageProtocol, flags)
        match inner with
        | Protocol.MessageProtocol (cmd, innerPayload) ->
            Assert.Equal(Protocol.CommandWriteFirmware, cmd)
            Assert.Equal(16, innerPayload.Length) // 4B offset + 4B len + 4B number + 4B payload
            Assert.Equal(512u, BitConverter.ToUInt32(innerPayload, 0))
            Assert.Equal(4u, BitConverter.ToUInt32(innerPayload, 4))
            Assert.Equal(2u, BitConverter.ToUInt32(innerPayload, 8))
            Assert.Equal<byte seq>(payload, Array.sub innerPayload 12 4)
        | _ -> Assert.Fail("Failed to decode inner MessageProtocol for WriteFirmware")
    | _ -> Assert.Fail("Failed to decode MessagePack for WriteFirmware")

    // 3. packCheckFirmware
    let hmac = Array.zeroCreate 32
    let checkPacket = Protocol.packCheckFirmware hmac
    match checkPacket with
    | Protocol.MessagePack (flags, inner) ->
        Assert.Equal(Protocol.FlagsMessageProtocol, flags)
        match inner with
        | Protocol.MessageProtocol (cmd, innerPayload) ->
            Assert.Equal(Protocol.CommandCheckFirmware, cmd)
            Assert.Equal<byte seq>(hmac, innerPayload)
        | _ -> Assert.Fail("Failed to decode inner MessageProtocol for CheckFirmware")
    | _ -> Assert.Fail("Failed to decode MessagePack for CheckFirmware")

[<Fact>]
let ``Protocol computeFirmwareHmac produces valid 32-byte HMAC for zero PSK`` () =
    let psk = Protocol.ZeroPsk
    let fwBytes = createValidTestFirmware ()
    let hmac = Protocol.computeFirmwareHmac psk fwBytes
    Assert.Equal(32, hmac.Length)
    Assert.False(Array.forall ((=) 0uy) hmac)

[<Fact>]
let ``Goodix53xdDevice ProvisionZeroPsk returns Ok immediately when already in APP mode with zero PSK`` () =
    task {
        let mockTransport = new MockUsbTransport()
        let fwBytes = createValidTestFirmware ()

        let enqueueAckAndResp (cmd: byte) (payload: byte[]) =
            let ack = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| cmd; 0x03uy |] true)
            let resp = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol cmd payload true)
            mockTransport.EnqueueResponse(ack)
            mockTransport.EnqueueResponse(resp)

        // 1. NOP ACK
        let ackNop = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandNop; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackNop)

        // 2. ReadFirmwareVersion -> APP firmware
        enqueueAckAndResp Protocol.CommandFirmwareVersion (System.Text.Encoding.ASCII.GetBytes("GF5298_GM168SEC_APP_13016\u0000"))

        // 3. PresetPskRead -> PmkHashZero
        let validPskPayload = Array.zeroCreate 45
        validPskPayload.[0] <- 0x00uy
        Array.Copy(BitConverter.GetBytes(0xbb020001u), 0, validPskPayload, 1, 4)
        Array.Copy(BitConverter.GetBytes(32), 0, validPskPayload, 5, 4)
        Array.Copy(Protocol.PmkHashZero, 0, validPskPayload, 9, 32)
        enqueueAckAndResp Protocol.CommandPresetPskRead validPskPayload

        use dev = new Goodix53xdDevice(mockTransport)
        let! provRes = dev.ProvisionZeroPsk(fwBytes)

        match provRes with
        | Ok () ->
            // Ensure no McuEraseApp or WriteFirmware packets were sent!
            let commands =
                mockTransport.WrittenPackets
                |> Array.choose (fun p ->
                    match p with
                    | Protocol.MessagePack (_, inner) ->
                        match inner with
                        | Protocol.MessageProtocol (cmd, _) -> Some cmd
                        | _ -> None
                    | _ -> None)
            Assert.DoesNotContain(Protocol.CommandMcuEraseApp, commands)
            Assert.DoesNotContain(Protocol.CommandWriteFirmware, commands)
        | Error err -> Assert.Fail($"ProvisionZeroPsk failed: {err}")
    }

[<Fact>]
let ``Goodix53xdDevice ProvisionZeroPsk executes full IAP -> PSK write -> Firmware write -> APP boot sequence`` () =
    task {
        let mockTransport = new MockUsbTransport()
        let fwBytes = createValidTestFirmware ()

        let enqueueAckAndResp (cmd: byte) (payload: byte[]) =
            let ack = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| cmd; 0x03uy |] true)
            let resp = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol cmd payload true)
            mockTransport.EnqueueResponse(ack)
            mockTransport.EnqueueResponse(resp)

        let enqueueAckOnly (cmd: byte) =
            let ack = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| cmd; 0x03uy |] true)
            mockTransport.EnqueueResponse(ack)

        // 1. NOP ACK
        let ackNop = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandNop; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackNop)

        // 2. ReadFirmwareVersion (initial check: in APP mode)
        enqueueAckAndResp Protocol.CommandFirmwareVersion (System.Text.Encoding.ASCII.GetBytes("GF5298_GM168SEC_APP_13016\u0000"))

        // 3. PresetPskRead (initial check: non-zero factory hash)
        let nonZeroPskPayload = Array.zeroCreate 45
        nonZeroPskPayload.[0] <- 0x00uy
        Array.Copy(BitConverter.GetBytes(0xbb020001u), 0, nonZeroPskPayload, 1, 4)
        Array.Copy(BitConverter.GetBytes(32), 0, nonZeroPskPayload, 5, 4)
        Array.Copy(Array.create 32 0x77uy, 0, nonZeroPskPayload, 9, 32)
        enqueueAckAndResp Protocol.CommandPresetPskRead nonZeroPskPayload

        // 4. McuEraseApp (0xa4) -> ACK, then response [0x01]
        enqueueAckAndResp Protocol.CommandMcuEraseApp [| 0x01uy |]

        // 5. ReadFirmwareVersion (after erase: in IAP mode)
        enqueueAckAndResp Protocol.CommandFirmwareVersion (System.Text.Encoding.ASCII.GetBytes("MILAN_GM168SEC_IAP_10007\u0000"))

        // 6. PresetPskWrite (0xe0) -> ACK, then response [0x00]
        enqueueAckAndResp Protocol.CommandPresetPskWrite [| 0x00uy |]

        // 7. PresetPskRead (verify zero PSK in IAP mode)
        let zeroPskPayload = Array.zeroCreate 45
        zeroPskPayload.[0] <- 0x00uy
        Array.Copy(BitConverter.GetBytes(0xbb020001u), 0, zeroPskPayload, 1, 4)
        Array.Copy(BitConverter.GetBytes(32), 0, zeroPskPayload, 5, 4)
        Array.Copy(Protocol.PmkHashZero, 0, zeroPskPayload, 9, 32)
        enqueueAckAndResp Protocol.CommandPresetPskRead zeroPskPayload

        // 8. UpdateFirmware: 95 chunks of WriteFirmware (0xf0)
        let totalChunks = (fwBytes.Length + 255) / 256
        for _ in 1 .. totalChunks do
            enqueueAckAndResp Protocol.CommandWriteFirmware [| 0x00uy |]

        // 9. CheckFirmware (0xf4) -> ACK, then response [0x00]
        enqueueAckAndResp Protocol.CommandCheckFirmware [| 0x00uy |]

        // 10. Reset (0xa2) -> ACK only
        enqueueAckOnly Protocol.CommandReset

        // 11. ReadFirmwareVersion (after reset: back in APP mode)
        enqueueAckAndResp Protocol.CommandFirmwareVersion (System.Text.Encoding.ASCII.GetBytes("GF5298_GM168SEC_APP_13016\u0000"))

        use dev = new Goodix53xdDevice(mockTransport)
        let! provRes = dev.ProvisionZeroPsk(fwBytes)

        match provRes with
        | Ok () ->
            let commands =
                mockTransport.WrittenPackets
                |> Array.choose (fun p ->
                    match p with
                    | Protocol.MessagePack (_, inner) ->
                        match inner with
                        | Protocol.MessageProtocol (cmd, _) -> Some cmd
                        | _ -> None
                    | _ -> None)
            Assert.Contains(Protocol.CommandMcuEraseApp, commands)
            Assert.Contains(Protocol.CommandPresetPskWrite, commands)
            Assert.Contains(Protocol.CommandWriteFirmware, commands)
            Assert.Contains(Protocol.CommandCheckFirmware, commands)
            Assert.Contains(Protocol.CommandReset, commands)
        | Error err -> Assert.Fail($"ProvisionZeroPsk full sequence failed: {err}")
    }

[<Fact>]
let ``FdtCalculations calcFdtDownBase transforms 16-byte raw baseline correctly`` () =
    // Create 16 bytes representing 8 words: 0x0122, 0x0124, 0x0116, 0x0116, 0x012c, 0x012c, 0x0122, 0x0122
    let rawFdt = [|
        0x22uy; 0x01uy // 0x0122 -> w>>>1 = 0x91 -> [0x80; 0x91]
        0x24uy; 0x01uy // 0x0124 -> w>>>1 = 0x92 -> [0x80; 0x92]
        0x16uy; 0x01uy // 0x0116 -> w>>>1 = 0x8b -> [0x80; 0x8b]
        0x16uy; 0x01uy // 0x0116 -> w>>>1 = 0x8b -> [0x80; 0x8b]
        0x2cuy; 0x01uy // 0x012c -> w>>>1 = 0x96 -> [0x80; 0x96]
        0x2cuy; 0x01uy // 0x012c -> w>>>1 = 0x96 -> [0x80; 0x96]
        0x22uy; 0x01uy // 0x0122 -> w>>>1 = 0x91 -> [0x80; 0x91]
        0x22uy; 0x01uy // 0x0122 -> w>>>1 = 0x91 -> [0x80; 0x91]
    |]
    let downBase = FdtCalculations.calcFdtDownBase rawFdt
    Assert.Equal(16, downBase.Length)
    Assert.Equal<byte seq>(
        [|
            0x80uy; 0x91uy
            0x80uy; 0x92uy
            0x80uy; 0x8buy
            0x80uy; 0x8buy
            0x80uy; 0x96uy
            0x80uy; 0x96uy
            0x80uy; 0x91uy
            0x80uy; 0x91uy
        |],
        downBase
    )

[<Fact>]
let ``FdtCalculations calcFdtDownBase returns fallback for null or short input`` () =
    let fallback = FdtCalculations.calcFdtDownBase null
    Assert.Equal(16, fallback.Length)
    Assert.Equal(0x91uy, fallback.[0])
    Assert.Equal(0x91uy, fallback.[1])

    let fallbackShort = FdtCalculations.calcFdtDownBase [| 0x01uy; 0x02uy |]
    Assert.Equal(16, fallbackShort.Length)

[<Fact>]
let ``FdtCalculations calcFdtUpBase transforms raw baseline with touch flags correctly`` () =
    // 8 words: 0x0122, 0x0124, 0x0116, 0x0116, 0x012c, 0x012c, 0x0122, 0x0122
    // w >>> 1: 0x91,   0x92,   0x8b,   0x8b,   0x96,   0x96,   0x91,   0x91
    // with diff = 0x15 (21):
    // elevated: 0xa6,   0xa7,   0xa0,   0xa0,   0xab,   0xab,   0xa6,   0xa6
    // untouched (diff - 2): 0x13
    let rawFdt = [|
        0x22uy; 0x01uy
        0x24uy; 0x01uy
        0x16uy; 0x01uy
        0x16uy; 0x01uy
        0x2cuy; 0x01uy
        0x2cuy; 0x01uy
        0x22uy; 0x01uy
        0x22uy; 0x01uy
    |]

    // Scenario 1: touchFlag = 0x00FF (all 8 areas touched)
    let upBaseAll = FdtCalculations.calcFdtUpBase 0x00FFus rawFdt (Some 0x15s)
    Assert.Equal<byte seq>(
        [|
            0x80uy; 0xa6uy
            0x80uy; 0xa7uy
            0x80uy; 0xa0uy
            0x80uy; 0xa0uy
            0x80uy; 0xabuy
            0x80uy; 0xabuy
            0x80uy; 0xa6uy
            0x80uy; 0xa6uy
        |],
        upBaseAll
    )

    // Scenario 2: touchFlag = 0x0003 (only areas 0 and 1 touched, areas 2..7 untouched)
    let upBasePartial = FdtCalculations.calcFdtUpBase 0x0003us rawFdt (Some 0x15s)
    Assert.Equal<byte seq>(
        [|
            0x80uy; 0xa6uy
            0x80uy; 0xa7uy
            0x80uy; 0x13uy
            0x80uy; 0x13uy
            0x80uy; 0x13uy
            0x80uy; 0x13uy
            0x80uy; 0x13uy
            0x80uy; 0x13uy
        |],
        upBasePartial
    )

[<Fact>]
let ``FdtCalculations calcFdtUpBase returns fallback for null or short input`` () =
    let fallback = FdtCalculations.calcFdtUpBase 0x00FFus null None
    Assert.Equal(16, fallback.Length)
    Assert.Equal(0x91uy, fallback.[0])
    Assert.Equal(0x91uy, fallback.[1])

    let fallbackShort = FdtCalculations.calcFdtUpBase 0x00FFus [| 0x01uy; 0x02uy |] None
    Assert.Equal(16, fallbackShort.Length)

[<Fact>]
let ``FdtCalculations calcFdtUpBase treats touchFlag 0 as all areas touched`` () =
    let rawFdt = [|
        0x22uy; 0x01uy; 0x24uy; 0x01uy; 0x16uy; 0x01uy; 0x16uy; 0x01uy
        0x2cuy; 0x01uy; 0x2cuy; 0x01uy; 0x22uy; 0x01uy; 0x22uy; 0x01uy
    |]
    let upBaseZeroFlag = FdtCalculations.calcFdtUpBase 0x0000us rawFdt (Some 0x15s)
    Assert.Equal<byte seq>(
        [|
            0x80uy; 0xa6uy
            0x80uy; 0xa7uy
            0x80uy; 0xa0uy
            0x80uy; 0xa0uy
            0x80uy; 0xabuy
            0x80uy; 0xabuy
            0x80uy; 0xa6uy
            0x80uy; 0xa6uy
        |],
        upBaseZeroFlag
    )

[<Fact>]
let ``Goodix53xdDevice ReadFdtManual sends mode 0x0d and returns decoded 8 words`` () =
    task {
        let mockTransport = new MockUsbTransport()

        // 1. ACK for fdt0dNoReply
        let ack0 = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandMcuSwitchToFdtMode; 0x03uy |] true)
        mockTransport.EnqueueResponse(ack0)

        // 2. ACK for fdt0dWait
        let ack1 = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandMcuSwitchToFdtMode; 0x03uy |] true)
        mockTransport.EnqueueResponse(ack1)

        // 3. Response for fdt0dWait: 20 bytes (4 header + 16 data)
        let respPayload = Array.zeroCreate<byte> 20
        let testWords = [| 290us; 292us; 278us; 278us; 300us; 300us; 290us; 290us |]
        for i in 0 .. 7 do
            respPayload.[4 + 2 * i] <- byte (testWords.[i] &&& 0xffus)
            respPayload.[4 + 2 * i + 1] <- byte (testWords.[i] >>> 8)

        let respPack = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandMcuSwitchToFdtMode respPayload true)
        mockTransport.EnqueueResponse(respPack)

        use dev = new Goodix53xdDevice(mockTransport)
        let! wordsRes = dev.ReadFdtManual()
        match wordsRes with
        | Ok words ->
            Assert.Equal<uint16 seq>(testWords, words)
        | Error err -> Assert.Fail($"ReadFdtManual failed: {err}")
    }

[<Fact>]
let ``FdtCalculations isFingerLifted correctly distinguishes idle, touched, and lifted states`` () =
    let idle = [| 260us; 250us; 286us; 283us; 296us; 288us; 294us; 286us |]

    // 1. Exact idle returns lifted
    let (lifted1, delta1) = FdtCalculations.isFingerLifted idle idle
    Assert.True(lifted1)
    Assert.Equal(0.0, delta1, 1)

    // 2. Normal idle jitter (noise +- 2) returns lifted
    let noisyIdle = [| 259us; 249us; 286us; 283us; 296us; 288us; 293us; 285us |]
    let (lifted2, delta2) = FdtCalculations.isFingerLifted noisyIdle idle
    Assert.True(lifted2)
    Assert.True(delta2 > -30.0)

    // 3. Live finger-down readings from hardware (~ -212 delta) return NOT lifted (finger present)
    let fingerDown = [| 48us; 45us; 73us; 73us; 80us; 72us; 75us; 74us |]
    let (lifted3, delta3) = FdtCalculations.isFingerLifted fingerDown idle
    Assert.False(lifted3)
    Assert.True(delta3 < -80.0)

    // 4. All channels within 40 counts return lifted even if mean delta is slightly negative
    let slightlyNegative = [| 240us; 230us; 266us; 263us; 276us; 268us; 274us; 266us |] // all diffs = -20
    let (lifted4, delta4) = FdtCalculations.isFingerLifted slightlyNegative idle
    Assert.True(lifted4)
    Assert.Equal(-20.0, delta4, 1)

[<Fact>]
let ``Goodix53xdDevice WaitForFingerUpRobust detects finger lift with pure FDT manual polling`` () =
    task {
        let mockTransport = new MockUsbTransport()

        let ackMode0 = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandMcuSwitchToFdtMode; 0x03uy |] true)
        let ackMode1 = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandMcuSwitchToFdtMode; 0x03uy |] true)

        let respPayload1 = Array.zeroCreate<byte> 20
        let clearWords1 = [| 290us; 290us; 278us; 278us; 300us; 300us; 290us; 290us |]
        for i in 0 .. 7 do
            respPayload1.[4 + 2 * i] <- byte (clearWords1.[i] &&& 0xffus)
            respPayload1.[4 + 2 * i + 1] <- byte (clearWords1.[i] >>> 8)
        let respPack1 = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandMcuSwitchToFdtMode respPayload1 true)

        // 1. Initial idle read (when sessionIdle is None)
        mockTransport.EnqueueResponse(ackMode0)
        mockTransport.EnqueueResponse(ackMode1)
        mockTransport.EnqueueResponse(respPack1)

        // 2. Poll 1: ReadFdtManual (consecutive clear sample 1)
        mockTransport.EnqueueResponse(ackMode0)
        mockTransport.EnqueueResponse(ackMode1)
        mockTransport.EnqueueResponse(respPack1)

        // 3. Poll 2: ReadFdtManual (consecutive clear sample 2)
        mockTransport.EnqueueResponse(ackMode0)
        mockTransport.EnqueueResponse(ackMode1)
        mockTransport.EnqueueResponse(respPack1)

        // 4. Sleep command ACK (0x60)
        let ackSleep = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandMcuSwitchToSleepMode; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackSleep)

        use dev = new Goodix53xdDevice(mockTransport)
        let! upRes = dev.WaitForFingerUpRobust(timeoutMs = 5000)
        match upRes with
        | Ok () -> ()
        | Error err -> Assert.Fail($"WaitForFingerUpRobust failed: {err}")
    }

// ============================================================================
// Storage & Privilege-Separated Template Resolution Tests
// ============================================================================

[<Fact>]
let ``Storage tryGetHomeFromPasswdFile parses passwd entries correctly`` () =
    let tempPasswd = Path.GetTempFileName()
    try
        File.WriteAllLines(tempPasswd, [
            "root:x:0:0:root:/root:/bin/bash"
            "vladimir:x:1000:1000:Vladimir Rogozhin:/home/vladimir:/bin/zsh"
            "service:x:999:999::/var/lib/service:/sbin/nologin"
        ])

        Assert.Equal(Some "/root", Storage.tryGetHomeFromPasswdFile tempPasswd "root")
        Assert.Equal(Some "/home/vladimir", Storage.tryGetHomeFromPasswdFile tempPasswd "vladimir")
        Assert.Equal(Some "/var/lib/service", Storage.tryGetHomeFromPasswdFile tempPasswd "service")
        Assert.Equal(None, Storage.tryGetHomeFromPasswdFile tempPasswd "nonexistent")
    finally
        if File.Exists tempPasswd then File.Delete tempPasswd

[<Fact>]
let ``Storage resolveUserHomeWith falls back to /home/user when passwd misses`` () =
    let mockPasswd (user: string) =
        if user = "alice" then Some "/custom/alice" else None

    let mockDirExists (path: string) =
        path = "/custom/alice" || path = "/home/bob"

    Assert.Equal(Some "/custom/alice", Storage.resolveUserHomeWith mockPasswd mockDirExists "alice")
    Assert.Equal(Some "/home/bob", Storage.resolveUserHomeWith mockPasswd mockDirExists "bob")
    Assert.Equal(None, Storage.resolveUserHomeWith mockPasswd mockDirExists "charlie")

[<Fact>]
let ``Storage resolveInvokingUserWith prioritizes explicit user over PAM_USER and SUDO_USER`` () =
    let mockEnv = function
        | "PAM_USER" -> Some "pam_alice"
        | "SUDO_USER" -> Some "sudo_bob"
        | _ -> None

    // Explicit user takes highest priority
    Assert.Equal(Some "target_user", Storage.resolveInvokingUserWith mockEnv (Some "target_user"))

    // Falls back to PAM_USER if no explicit user
    Assert.Equal(Some "pam_alice", Storage.resolveInvokingUserWith mockEnv None)

    // Falls back to SUDO_USER if PAM_USER is absent or root
    let mockEnvNoPam = function
        | "PAM_USER" -> Some "root"
        | "SUDO_USER" -> Some "sudo_bob"
        | _ -> None
    Assert.Equal(Some "sudo_bob", Storage.resolveInvokingUserWith mockEnvNoPam None)

    // Returns None if all are root or absent
    let mockEnvRoot = function
        | "PAM_USER" -> Some "root"
        | "SUDO_USER" -> Some "root"
        | _ -> None
    Assert.Equal(None, Storage.resolveInvokingUserWith mockEnvRoot None)

[<Fact>]
let ``Storage resolveTemplateDirectoryWith resolves XDG_DATA_HOME for regular user`` () =
    let mockEnv = function
        | "XDG_DATA_HOME" -> Some "/custom/xdg/share"
        | "HOME" -> Some "/home/user"
        | _ -> None
    let isRoot () = false
    let getUserHome _ = Some "/home/user"
    let dirExists _ = true

    let result = Storage.resolveTemplateDirectoryWith isRoot mockEnv getUserHome dirExists None None
    Assert.Equal(Path.Combine("/custom/xdg/share", "goodix-fp", "templates"), result)

[<Fact>]
let ``Storage resolveTemplateDirectoryWith resolves ~/.local/share for regular user without XDG`` () =
    let mockEnv = function
        | "HOME" -> Some "/home/alice"
        | _ -> None
    let isRoot () = false
    let getUserHome _ = Some "/home/alice"
    let dirExists _ = true

    let result = Storage.resolveTemplateDirectoryWith isRoot mockEnv getUserHome dirExists None None
    Assert.Equal(Path.Combine("/home/alice", ".local", "share", "goodix-fp", "templates"), result)

[<Fact>]
let ``Storage resolveTemplateDirectoryWith resolves user home when run as root via sudo or PAM`` () =
    let mockEnv = function
        | "SUDO_USER" -> Some "vladimir"
        | _ -> None
    let isRoot () = true
    let getUserHome (u: string) = if u = "vladimir" then Some "/home/vladimir" else None
    let dirExists (p: string) = p = Path.Combine("/home/vladimir", ".local", "share", "goodix-fp", "templates")

    let result = Storage.resolveTemplateDirectoryWith isRoot mockEnv getUserHome dirExists None None
    Assert.Equal(Path.Combine("/home/vladimir", ".local", "share", "goodix-fp", "templates"), result)

[<Fact>]
let ``Storage resolveTemplateDirectoryWith falls back to system dirs when root has no user templates`` () =
    let mockEnv = function
        | "PAM_USER" -> Some "bob"
        | _ -> None
    let isRoot () = true
    let getUserHome (u: string) = if u = "bob" then Some "/home/bob" else None
    // Bob's templates don't exist yet, but /var/lib/goodix-fp/templates exists
    let dirExists (p: string) = p = "/var/lib/goodix-fp/templates"

    let result = Storage.resolveTemplateDirectoryWith isRoot mockEnv getUserHome dirExists None None
    Assert.Equal("/var/lib/goodix-fp/templates", result)

[<Fact>]
let ``Storage resolveTemplateDirectoryWith falls back to /etc when /var/lib missing`` () =
    let mockEnv = function
        | "PAM_USER" -> Some "bob"
        | _ -> None
    let isRoot () = true
    let getUserHome (u: string) = if u = "bob" then Some "/home/bob" else None
    let dirExists (p: string) = p = "/etc/goodix-fp/templates"

    let result = Storage.resolveTemplateDirectoryWith isRoot mockEnv getUserHome dirExists None None
    Assert.Equal("/etc/goodix-fp/templates", result)

[<Fact>]
let ``Storage resolveTemplateDirectoryWith falls back to system dir for direct root run`` () =
    let mockEnv _ = None
    let isRoot () = true
    let getUserHome _ = None
    let dirExists (p: string) = p = "/var/lib/goodix-fp/templates"

    let result = Storage.resolveTemplateDirectoryWith isRoot mockEnv getUserHome dirExists None None
    Assert.Equal("/var/lib/goodix-fp/templates", result)

[<Fact>]
let ``Storage resolveTemplateDirectoryWith respects explicit customDir override`` () =
    let mockEnv _ = Some "/ignored"
    let isRoot () = true
    let getUserHome _ = Some "/ignored"
    let dirExists _ = true

    let result = Storage.resolveTemplateDirectoryWith isRoot mockEnv getUserHome dirExists (Some "/custom/override/dir") None
    Assert.Equal("/custom/override/dir", result)




