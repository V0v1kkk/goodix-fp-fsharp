module GoodixFp.Tests

open System
open System.IO
open System.Threading.Tasks
open Xunit
open Org.BouncyCastle.Tls
open GoodixFp.Core

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

        // 3. ReadSensorRegister -> ACK, then CommandResponse (Chip ID 0x00a6)
        let ackChip = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandAck [| Protocol.CommandReadSensorRegister; 0x03uy |] true)
        mockTransport.EnqueueResponse(ackChip)
        let respChip = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol Protocol.CommandReadSensorRegister [| 0xa6uy; 0x00uy; 0x00uy; 0x00uy |] true)
        mockTransport.EnqueueResponse(respChip)

        // 4. ReadOtp -> ACK, then CommandResponse (64 bytes OTP)
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
