namespace GoodixFp.Core

open System
open System.Diagnostics
open System.Threading.Tasks
open FsToolkit.ErrorHandling

// ============================================================================
// Device Probe Info
// ============================================================================

type DeviceInfo = {
    Firmware: FirmwareVersion
    Chip: ChipId
    Otp: SensorOtp
}

module FdtCalculations =
    /// Computes FDT down base from 16 bytes (8 uint16 little-endian words) of MCU baseline readings.
    /// Matches MilanFSerCalcFdtDownBase from libfprint-tod-goodix-53xc:
    /// For each word w, down_word = ((w >>> 1) <<< 8) ||| 0x80us
    /// In little-endian bytes: byte[2*i] = 0x80uy, byte[2*i + 1] = byte ((w >>> 1) &&& 0xff).
    let calcFdtDownBase (fdtData: byte[]) : byte[] =
        if isNull fdtData || fdtData.Length < 16 then
            [|
                0x91uy; 0x91uy; 0x8buy; 0x8buy
                0x96uy; 0x96uy; 0x91uy; 0x91uy
                0x98uy; 0x98uy; 0x90uy; 0x90uy
                0x92uy; 0x92uy; 0x88uy; 0x88uy
            |]
        else
            let downBase = Array.zeroCreate<byte> 16
            for i in 0 .. 7 do
                let w = uint16 fdtData.[2 * i] ||| (uint16 fdtData.[2 * i + 1] <<< 8)
                let wShift = (int w) >>> 1
                downBase.[2 * i] <- 0x80uy
                downBase.[2 * i + 1] <- byte (wShift &&& 0xff)
            downBase

    /// Computes FDT up base from 16 bytes (8 uint16 little-endian words) of MCU touch readings,
    /// touchFlag, and optional diff.
    /// Matches MilanFSerCalcFdtUpBase from libfprint-tod-goodix-53xc:
    /// Loop 1: For each word w at index i (0..7):
    ///   val = (w >>> 1) + diff  (default diff is 0x15)
    ///   upBase.[2*i] <- 0x80uy
    ///   upBase.[2*i + 1] <- byte (val &&& 0xff)
    /// Loop 2: For each bit i (0..7) in touchFlag:
    ///   if (touchFlag &&& (1us <<< i)) = 0us then (area was NOT touched)
    ///     let untVal = if diff <> 0 then diff - 2 else 0x13
    ///     upBase.[2*i] <- 0x80uy
    ///     upBase.[2*i + 1] <- byte (untVal &&& 0xff)
    let calcFdtUpBase (touchFlag: uint16) (fdtData: byte[]) (fdtDiff: int16 option) : byte[] =
        let diff = defaultArg fdtDiff 0x15s
        let diffVal = int diff
        if isNull fdtData || fdtData.Length < 16 then
            [|
                0x91uy; 0x91uy; 0x8buy; 0x8buy
                0x96uy; 0x96uy; 0x91uy; 0x91uy
                0x98uy; 0x98uy; 0x90uy; 0x90uy
                0x92uy; 0x92uy; 0x88uy; 0x88uy
            |]
        else
            let effectiveFlag = if touchFlag = 0us then 0x00FFus else touchFlag
            let upBase = Array.zeroCreate<byte> 16
            for i in 0 .. 7 do
                let w = uint16 fdtData.[2 * i] ||| (uint16 fdtData.[2 * i + 1] <<< 8)
                let wShift = (int w) >>> 1
                let upVal = (wShift + diffVal) &&& 0xff
                upBase.[2 * i] <- 0x80uy
                upBase.[2 * i + 1] <- byte upVal

            for i in 0 .. 7 do
                if (effectiveFlag &&& (1us <<< i)) = 0us then
                    let untVal = (if diffVal <> 0 then diffVal - 2 else 0x13) &&& 0xff
                    upBase.[2 * i] <- 0x80uy
                    upBase.[2 * i + 1] <- byte untVal
            upBase

    /// Checks whether an FDT reading sample indicates the finger has been lifted.
    /// Finger considered PRESENT if mean(delta) < -80;
    /// LIFTED if every channel is within 40 counts of sessionIdle (or mean(delta) > -30).
    let isFingerLifted (sample: uint16[]) (sessionIdle: uint16[]) : bool * float =
        if isNull sample || isNull sessionIdle || sample.Length < 8 || sessionIdle.Length < 8 then
            false, 0.0
        else
            let mutable allWithin40 = true
            let mutable sumDelta = 0
            for i in 0 .. 7 do
                let diff = int sample.[i] - int sessionIdle.[i]
                sumDelta <- sumDelta + diff
                if abs diff > 40 then
                    allWithin40 <- false
            let meanDelta = float sumDelta / 8.0
            let isLifted = allWithin40 || meanDelta > -30.0
            isLifted, meanDelta

module private DeviceDebug =
    let logBaselineIdle (idleWords: uint16[]) =
        let v = Environment.GetEnvironmentVariable("GOODIX_DEBUG")
        if v = "1" || String.Equals(v, "true", StringComparison.OrdinalIgnoreCase) then
            let idleStr = idleWords |> Array.map (fun v -> (int v).ToString().PadLeft(4)) |> String.concat " "
            eprintfn $"[DEBUG][ActivateSession] Baseline idle: [ {idleStr} ]"

    let logFingerDown (downPayload: byte[]) (sessionIdle: uint16[] option) (currentFdtIdle: uint16[] option) =
        let v = Environment.GetEnvironmentVariable("GOODIX_DEBUG")
        if (v = "1" || String.Equals(v, "true", StringComparison.OrdinalIgnoreCase)) && downPayload.Length >= 20 then
            let refIdle = sessionIdle |> Option.orElse currentFdtIdle
            match refIdle with
            | Some idle when idle.Length >= 8 ->
                let touchFlag = uint16 downPayload.[2] ||| (uint16 downPayload.[3] <<< 8)
                let fdtData = Array.sub downPayload 4 16
                let downWords = [| for i in 0 .. 7 -> uint16 fdtData.[2 * i] ||| (uint16 fdtData.[2 * i + 1] <<< 8) |]
                let fdtStr = downWords |> Array.map (fun v -> (int v).ToString().PadLeft(4)) |> String.concat " "
                let deltaStr =
                    Array.map2 (fun curr baseVal ->
                        let diff = int curr - int baseVal
                        let sign = if diff >= 0 then "+" else ""
                        (sign + diff.ToString()).PadLeft(5)
                    ) downWords idle
                    |> String.concat " "
                let meanDelta = (float (Array.sumBy (fun i -> int downWords.[i] - int idle.[i]) [| 0 .. 7 |])) / 8.0
                eprintfn $"[DEBUG][FingerDown] 0x32 event! flag=0x{touchFlag:X4} FDT: [ {fdtStr} ] | delta: [ {deltaStr} ] (mean={meanDelta,6:F1})"
            | _ -> ()

    let logPostTouch (postTouchResp: byte[]) (sessionIdle: uint16[] option) (currentFdtIdle: uint16[] option) =
        let v = Environment.GetEnvironmentVariable("GOODIX_DEBUG")
        if (v = "1" || String.Equals(v, "true", StringComparison.OrdinalIgnoreCase)) && postTouchResp.Length >= 20 then
            let refIdle = sessionIdle |> Option.orElse currentFdtIdle
            match refIdle with
            | Some idle when idle.Length >= 8 ->
                let rawFdt = Array.sub postTouchResp 4 16
                let postWords = [| for i in 0 .. 7 -> uint16 rawFdt.[2 * i] ||| (uint16 rawFdt.[2 * i + 1] <<< 8) |]
                let fdtStr = postWords |> Array.map (fun v -> (int v).ToString().PadLeft(4)) |> String.concat " "
                let deltaStr =
                    Array.map2 (fun curr baseVal ->
                        let diff = int curr - int baseVal
                        let sign = if diff >= 0 then "+" else ""
                        (sign + diff.ToString()).PadLeft(5)
                    ) postWords idle
                    |> String.concat " "
                let meanDelta = (float (Array.sumBy (fun i -> int postWords.[i] - int idle.[i]) [| 0 .. 7 |])) / 8.0
                eprintfn $"[DEBUG][FingerDown] Post-touch 0x36: FDT: [ {fdtStr} ] | delta: [ {deltaStr} ] (mean={meanDelta,6:F1})"
            | _ -> ()

// ============================================================================
// High-Level Goodix 53xd Driver
// ============================================================================

type Goodix53xdDevice(transport: IUsbTransport, tlsTunnel: ITlsPskTunnel) =

    let mutable currentOtp: SensorOtp option = None
    let mutable baselineFrame: RawFrame12Bit option = None
    let mutable lastFdtUpBase: byte[] option = None
    let mutable currentFdtDownBase: byte[] option = None
    let mutable currentFdtIdle: uint16[] option = None
    let mutable sessionIdle: uint16[] option = None

    new(transport: IUsbTransport) =
        new Goodix53xdDevice(transport, new PureFSharpTlsPskTunnel())

    member this.Transport = transport
    member this.TlsTunnel = tlsTunnel
    member this.CurrentOtp = currentOtp
    member this.BaselineFrame = baselineFrame
    member this.LastFdtUpBase = lastFdtUpBase
    member this.CurrentFdtDownBase = currentFdtDownBase
    member this.CurrentFdtIdle = currentFdtIdle
    member this.SessionIdle = sessionIdle

    // ------------------------------------------------------------------------
    // Low-Level Packet Exchange Helpers
    // ------------------------------------------------------------------------

    member this.SendAndExpectAck(packet: byte[], expectedCommand: byte, ?timeoutMs: int) : Result<unit, DriverError> =
        result {
            let timeout = defaultArg timeoutMs 2000
            do! transport.Write(packet)
            let! response =
                transport.Read(64, timeout)
                |> Result.mapError (fun e ->
                    match e with
                    | UsbError (_, code) -> UsbError ($"Bulk transfer in timed out waiting for ACK 0x{expectedCommand:x2}", code)
                    | other -> other)
            match response with
            | Protocol.AckResponse (cmd, _) when cmd = expectedCommand ->
                return ()
            | Protocol.CommandResponse (cmd, _) when cmd = expectedCommand ->
                return ()
            | Protocol.AckResponse (cmd, _) ->
                return! Error (ProtocolError $"Expected ACK for command 0x{expectedCommand:x2}, got 0x{cmd:x2} (raw: {Convert.ToHexString(response)})")
            | Protocol.InvalidPacket reason ->
                return! Error (InvalidPacket $"Invalid packet (raw: {Convert.ToHexString(response)}): {reason}")
            | Protocol.CommandResponse (cmd, _) ->
                return! Error (ProtocolError $"Unexpected command response 0x{cmd:x2} while expecting ACK for 0x{expectedCommand:x2} (raw: {Convert.ToHexString(response)})")
        }

    member this.ReadCommandResponse(expectedCommand: byte, ?timeoutMs: int) : Result<byte[], DriverError> =
        result {
            let timeout = defaultArg timeoutMs 3000
            let! response =
                transport.Read(1024, timeout)
                |> Result.mapError (fun e ->
                    match e with
                    | UsbError (_, code) -> UsbError ($"Bulk transfer in timed out waiting for response 0x{expectedCommand:x2}", code)
                    | other -> other)
            match response with
            | Protocol.CommandResponse (cmd, payload) when cmd = expectedCommand ->
                return payload
            | Protocol.CommandResponse (cmd, _) ->
                return! Error (ProtocolError $"Expected response for command 0x{expectedCommand:x2}, got 0x{cmd:x2} (raw: {Convert.ToHexString(response)})")
            | Protocol.AckResponse (cmd, _) ->
                return! Error (ProtocolError $"Unexpected ACK for command 0x{cmd:x2} while expecting response (raw: {Convert.ToHexString(response)})")
            | Protocol.InvalidPacket reason ->
                return! Error (InvalidPacket $"Invalid packet (raw: {Convert.ToHexString(response)}): {reason}")
        }

    member this.SendAndReceive(packet: byte[], expectedCommand: byte, ?timeoutMs: int) : Result<byte[], DriverError> =
        result {
            let timeout = defaultArg timeoutMs 3000
            do! transport.Write(packet)
            let! firstResponse =
                transport.Read(1024, timeout)
                |> Result.mapError (fun e ->
                    match e with
                    | UsbError (_, code) -> UsbError ($"Bulk transfer in timed out waiting for response 0x{expectedCommand:x2}", code)
                    | other -> other)
            match firstResponse with
            | Protocol.CommandResponse (cmd, payload) when cmd = expectedCommand ->
                return payload
            | Protocol.AckResponse (cmd, _) when cmd = expectedCommand ->
                return! this.ReadCommandResponse(expectedCommand, timeout)
            | Protocol.AckResponse (cmd, _) ->
                return! Error (ProtocolError $"Expected ACK or response for command 0x{expectedCommand:x2}, got ACK for 0x{cmd:x2} (raw: {Convert.ToHexString(firstResponse)})")
            | Protocol.CommandResponse (cmd, _) ->
                return! Error (ProtocolError $"Expected response for command 0x{expectedCommand:x2}, got 0x{cmd:x2} (raw: {Convert.ToHexString(firstResponse)})")
            | Protocol.InvalidPacket reason ->
                return! Error (InvalidPacket $"Invalid packet (raw: {Convert.ToHexString(firstResponse)}): {reason}")
        }

    member this.ReadFirmwareVersion() : Result<string, DriverError> =
        result {
            let! fwPayload = this.SendAndReceive(Protocol.packFirmwareVersion(), Protocol.CommandFirmwareVersion)
            let nullIdx = Array.IndexOf(fwPayload, 0x00uy)
            let strBytes = if nullIdx >= 0 then Array.sub fwPayload 0 nullIdx else fwPayload
            return System.Text.Encoding.ASCII.GetString(strBytes)
        }


    member private this.SendNopWakeup() : Result<unit, DriverError> =
        result {
            transport.DrainBuffer(20)
            do! transport.Write(Protocol.packNop())
            // Best effort: read response if device sends ACK, but ignore timeout if waking up
            match transport.Read(64, 150) with
            | Ok _ -> ()
            | Error (Timeout _) | Error (UsbError (_, -7)) -> ()
            | Error err -> return! Error err
            System.Threading.Thread.Sleep(50)
            transport.DrainBuffer(50)
        }

    // ------------------------------------------------------------------------
    // Workflow 1: Probe Device Information
    // ------------------------------------------------------------------------

    member this.ProbeInfo() : Task<Result<DeviceInfo, DriverError>> = taskResult {
        // 1. Send NOP wakeup
        do! this.SendNopWakeup()

        // 2. Query Firmware Version
        let! fwPayload = this.SendAndReceive(Protocol.packFirmwareVersion(), Protocol.CommandFirmwareVersion)
        let fwStr =
            let nullIdx = Array.IndexOf(fwPayload, 0x00uy)
            let strBytes = if nullIdx >= 0 then Array.sub fwPayload 0 nullIdx else fwPayload
            System.Text.Encoding.ASCII.GetString(strBytes)
        let! fw = FirmwareVersion.create fwStr |> Result.mapError (fun err -> ValidationError ("FirmwareVersion", err))

        // 3. Wake sensor chip before reading Chip ID
        do! this.SendAndExpectAck(Protocol.packEnableChip true, Protocol.CommandEnableChip)

        let resetPacket = Protocol.packReset true false 20uy
        do! this.SendAndExpectAck(resetPacket, Protocol.CommandReset)
        let! resetPayload = transport.Read(64, 2000)
        let! _ =
            match resetPayload with
            | Protocol.CommandResponse (Protocol.CommandReset, payload) when payload.Length >= 1 && payload.[0] = 0x01uy ->
                Ok ()
            | _ ->
                Error (ResetFailed "Reset response invalid or rejected")

        // 4. Query Chip ID (Sensor Register 0x0000, 4 bytes)
        // On 27c6:538d, payload is [0f a6 00 22] -> bytes [1..2] = 0x00a6. If byte 0 is not 0x0f or [1..2] is 0, fallback to [0..1].
        let! chipPayload = this.SendAndReceive(Protocol.packReadSensorRegister 0x0000us 4uy, Protocol.CommandReadSensorRegister)
        let chipRaw =
            if chipPayload.Length >= 3 && chipPayload.[0] = 0x0fuy then
                uint16 chipPayload.[1] ||| (uint16 chipPayload.[2] <<< 8)
            elif chipPayload.Length >= 3 && (uint16 chipPayload.[1] ||| (uint16 chipPayload.[2] <<< 8)) <> 0us then
                uint16 chipPayload.[1] ||| (uint16 chipPayload.[2] <<< 8)
            elif chipPayload.Length >= 2 then
                uint16 chipPayload.[0] ||| (uint16 chipPayload.[1] <<< 8)
            else
                0us
        let! chip = ChipId.create chipRaw |> Result.mapError (fun err -> ValidationError ("ChipId", err))

        // 5. Query OTP
        let! otpPayload = this.SendAndReceive(Protocol.packReadOtp(), Protocol.CommandReadOtp)
        let! otp = SensorOtp.parse otpPayload
        currentOtp <- Some otp

        return {
            Firmware = fw
            Chip = chip
            Otp = otp
        }
    }

    // ------------------------------------------------------------------------
    // Workflow 2: Provision Zero PSK & Firmware Restore
    // ------------------------------------------------------------------------

    member this.PresetPskRead(flags: uint32, length: int, offset: int) : Result<byte[], DriverError> =
        result {
            let packet = Protocol.packPresetPskRead flags length offset
            let! pskPayload = this.SendAndReceive(packet, Protocol.CommandPresetPskRead)
            if pskPayload.Length < 9 then
                return! Error (ProtocolError $"PresetPskRead response too short: {pskPayload.Length} bytes")
            elif pskPayload.[0] <> 0x00uy then
                return! Error (ProtocolError $"PresetPskRead error status: 0x{pskPayload.[0]:x2}")
            else
                let payloadLen = BitConverter.ToInt32(pskPayload, 5)
                if payloadLen > 0 && pskPayload.Length >= 9 + payloadLen then
                    return Array.sub pskPayload 9 payloadLen
                elif pskPayload.Length >= 41 then
                    return Array.sub pskPayload 9 32
                else
                    return Array.sub pskPayload 9 (pskPayload.Length - 9)
        }

    member this.ReadPresetPsk(flags: uint32, length: int, offset: int) : Task<Result<byte[], DriverError>> = task {
        return this.PresetPskRead(flags, length, offset)
    }

    member this.ReadPresetPsk(flags: uint32) : Task<Result<byte[], DriverError>> =
        this.ReadPresetPsk(flags, 0, 0)

    member this.UpdateFirmware(firmwareBytes: byte[], ?psk: byte[]) : Task<Result<unit, DriverError>> = taskResult {
        let pskBytes = defaultArg psk Protocol.ZeroPsk
        // Validate firmware integrity
        do! Protocol.verifyFirmwareImage firmwareBytes

        // 1. Loop offset from 0 to firmwareBytes.Length in chunks of 256 bytes
        let chunkSize = 256
        let mutable offset = 0
        while offset < firmwareBytes.Length do
            let chunkLen = min chunkSize (firmwareBytes.Length - offset)
            let chunk = Array.sub firmwareBytes offset chunkLen
            let writePacket = Protocol.packWriteFirmware (uint32 offset) chunk 2u
            do! this.SendAndExpectAck(writePacket, Protocol.CommandWriteFirmware)
            let! writeResp = this.ReadCommandResponse(Protocol.CommandWriteFirmware, 2000)
            if writeResp.Length = 0 || (writeResp.[0] <> 0x01uy && writeResp.[0] <> 0x00uy) then
                return! Error (ProtocolError $"CommandWriteFirmware failed at offset {offset}: status 0x{(if writeResp.Length > 0 then writeResp.[0] else 0xffuy):x2}")
            offset <- offset + chunkLen

        // 2. Send CheckFirmware with computed firmware HMAC
        let fwHmac = Protocol.computeFirmwareHmac pskBytes firmwareBytes
        let checkPacket = Protocol.packCheckFirmware fwHmac
        do! this.SendAndExpectAck(checkPacket, Protocol.CommandCheckFirmware)
        let! checkResp = this.ReadCommandResponse(Protocol.CommandCheckFirmware, 3000)
        if checkResp.Length = 0 || (checkResp.[0] <> 0x01uy && checkResp.[0] <> 0x00uy) then
            return! Error (ProtocolError $"CommandCheckFirmware failed: status 0x{(if checkResp.Length > 0 then checkResp.[0] else 0xffuy):x2}")

        // 3. Send Reset to boot the newly written APP firmware from IAP mode
        let resetPacket = Protocol.packReset false true 50uy
        do! this.SendAndExpectAck(resetPacket, Protocol.CommandReset)

        // 4. Reset USB transport since MCU reboot causes USB re-enumeration
        System.Threading.Thread.Sleep(1500)
        do! transport.ResetConnection()

        // 5. Query FirmwareVersion to confirm back in GF5298_GM168SEC_APP_13016
        let! newFw = this.ReadFirmwareVersion()
        if not (newFw.StartsWith("GF5298_GM168SEC_APP_13016")) then
            return! Error (FirmwareMismatch ("GF5298_GM168SEC_APP_13016", newFw))
        else
            return ()
    }

    member this.ProvisionZeroPsk(firmwareBytes: byte[]) : Task<Result<unit, DriverError>> = taskResult {
        // Step 1: First validate Protocol.verifyFirmwareImage firmwareBytes
        do! Protocol.verifyFirmwareImage firmwareBytes

        // Step 2: Read FirmwareVersion (0xa8) and PresetPskRead(0xbb020001u, 0, 0) (0xe4)
        // Best effort NOP wakeup (only needed if in APP mode)
        let _ = this.SendNopWakeup()
        let! currentFw = this.ReadFirmwareVersion()
        let pskHashResult = this.PresetPskRead(0xbb020001u, 0, 0)
        let isZeroPsk =
            match pskHashResult with
            | Ok pskHash when pskHash = Protocol.PmkHashZero -> true
            | _ -> false

        // Step 3: If FirmwareVersion starts with "GF5298_GM168SEC_APP" AND pskHash = Protocol.PmkHashZero, return Ok ()
        if currentFw.StartsWith("GF5298_GM168SEC_APP") && isZeroPsk then
            return ()
        else
            // Step 4: If FirmwareVersion is NOT "MILAN_GM168SEC_IAP_10007" (i.e. it is in APP mode), transition to IAP mode
            if not (currentFw.StartsWith("MILAN_GM168SEC_IAP")) then
                do! this.SendAndExpectAck(Protocol.packMcuEraseApp 50uy, Protocol.CommandMcuEraseApp)
                let! eraseResp = this.ReadCommandResponse(Protocol.CommandMcuEraseApp, 2000)
                System.Threading.Thread.Sleep(1000)

                let! iapFw = this.ReadFirmwareVersion()
                if not (iapFw.StartsWith("MILAN_GM168SEC_IAP")) then
                    return! Error (FirmwareMismatch ("MILAN_GM168SEC_IAP", iapFw))

            // Step 5: In IAP mode, write the zero PSK if not already provisioned
            if not isZeroPsk then
                let writePskPacket = Protocol.packPresetPskWrite 0xbb010003u Protocol.PskWhiteBox 114 0 Protocol.PreFlagsPresetPskWrite
                do! this.SendAndExpectAck(writePskPacket, Protocol.CommandPresetPskWrite)
                let! writeResp = this.ReadCommandResponse(Protocol.CommandPresetPskWrite, 2000)
                if writeResp.Length = 0 || writeResp.[0] <> 0x00uy then
                    return! Error (ProtocolError $"PresetPskWrite failed with status: 0x{(if writeResp.Length > 0 then writeResp.[0] else 0xffuy):x2}")

                let! verifiedPskHash = this.PresetPskRead(0xbb020001u, 0, 0)
                if verifiedPskHash <> Protocol.PmkHashZero then
                    return! Error (ProtocolError $"PSK verification failed after writing PSK White-Box in IAP mode. Hash: {Convert.ToHexString(verifiedPskHash)}")

            // Step 6: Restore the APP firmware
            do! this.UpdateFirmware(firmwareBytes, Protocol.ZeroPsk)
            return ()
    }

    // ------------------------------------------------------------------------
    // Workflow 3: Activate Session (Init + TLS Handshake)
    // ------------------------------------------------------------------------

    member this.ActivateSession() : Task<Result<SensorOtp, DriverError>> = taskResult {
        // 1. Send NOP wakeup & query firmware version to verify MCU is awake and ready in APP mode
        do! this.SendNopWakeup()
        let! fw = this.ReadFirmwareVersion()
        if not (fw.StartsWith("GF5298_GM168SEC_APP")) then
            do! Error (FirmwareMismatch ("GF5298_GM168SEC_APP_13016", fw))

        // 2. Enable chip before reset
        do! this.SendAndExpectAck(Protocol.packEnableChip true, Protocol.CommandEnableChip)

        // 3. Reset device (sensor reset only, never soft-reset MCU)
        let resetPacket = Protocol.packReset true false 20uy
        do! this.SendAndExpectAck(resetPacket, Protocol.CommandReset)
        let! resetPayload = transport.Read(64, 2000)
        let! _ =
            match resetPayload with
            | Protocol.CommandResponse (Protocol.CommandReset, payload) when payload.Length >= 1 && payload.[0] = 0x01uy ->
                Ok ()
            | _ ->
                Error (ResetFailed "Reset response invalid or rejected")

        // 4. Read Chip ID (Sensor Register 0x0000, 4 bytes)
        let! _ = this.SendAndReceive(Protocol.packReadSensorRegister 0x0000us 4uy, Protocol.CommandReadSensorRegister)

        // 5. Read OTP
        let! otpPayload = this.SendAndReceive(Protocol.packReadOtp(), Protocol.CommandReadOtp)
        let! otp = SensorOtp.parse otpPayload
        currentOtp <- Some otp

        // 6. Initiate TLS handshake BEFORE UploadConfigMcu (matching driver_53xd.py)
        do! this.SendAndExpectAck(Protocol.packRequestTlsConnection(), Protocol.CommandRequestTlsConnection)
        let! clientHelloPack = transport.Read(1024, 2000)
        let! clientHelloBytes =
            match clientHelloPack with
            | Protocol.MessagePack (Protocol.FlagsTransportLayerSecurity, bytes) -> Ok bytes
            | _ -> Error (TlsHandshakeFailed "Unexpected packet while expecting TLS ClientHello")

        tlsTunnel.Reset()
        let! serverHelloFlight = tlsTunnel.HandleHandshake(clientHelloBytes)
        let! shBytes =
            match serverHelloFlight with
            | Some bytes -> Ok bytes
            | None -> Error (TlsHandshakeFailed "ServerHello generation returned None")

        // Send ServerHello + ServerHelloDone to device
        let shPack = Protocol.encodeMessagePack Protocol.FlagsTransportLayerSecurity shBytes
        do! transport.Write(shPack)

        // Loop reading 0xb0 packs and feeding to tlsTunnel until server finished flight is produced
        // (MCU may send ClientKeyExchange, ChangeCipherSpec, and Finished in 1, 2, or 3 separate 0xb0 MessagePacks)
        let mutable serverFlightBytes: byte[] option = None
        let mutable handshakeAttempts = 0
        let maxAttempts = 5

        while serverFlightBytes.IsNone && handshakeAttempts < maxAttempts do
            handshakeAttempts <- handshakeAttempts + 1
            let! clientFlightPack = transport.Read(1024, 2000)
            let! clientPayload =
                match clientFlightPack with
                | Protocol.MessagePack (Protocol.FlagsTransportLayerSecurity, bytes) -> Ok bytes
                | _ -> Error (TlsHandshakeFailed "Unexpected packet while expecting TLS handshake flight (FlagsTransportLayerSecurity)")
            let! hsRes = tlsTunnel.HandleHandshake(clientPayload)
            match hsRes with
            | Some sfBytes ->
                serverFlightBytes <- Some sfBytes
            | None ->
                ()

        let! sfBytes =
            match serverFlightBytes with
            | Some bytes -> Ok bytes
            | None -> Error (TlsHandshakeFailed "Handshake did not complete after reading client flight packets")

        // Send Server ChangeCipherSpec + Finished to device
        let sfPack = Protocol.encodeMessagePack Protocol.FlagsTransportLayerSecurity sfBytes
        do! transport.Write(sfPack)

        // Notify TLS established
        do! this.SendAndExpectAck(Protocol.packTlsSuccessfullyEstablished(), Protocol.CommandTlsSuccessfullyEstablished)

        // 7. Upload MCU config (after TLS connection established)
        let! uploadResp = this.SendAndReceive(Protocol.packUploadConfig Protocol.Goodix53xdConfig, Protocol.CommandUploadConfigMcu)
        if uploadResp.Length = 0 || uploadResp.[0] <> 0x01uy then
            do! Error (ProtocolError "Failed to upload MCU config")

        // 8. FDT Baseline Calibration sequence (matching driver_53xd.py / Milan TOD)
        let dacBytes = [|
            otp.FdtDac.[0]; 0x01uy
            otp.FdtDac.[1]; 0x01uy
            otp.FdtDac.[2]; 0x01uy
            otp.FdtDac.[3]; 0x01uy
        |]
        let dacBytesMinus15 = [|
            byte (max 0 (int otp.FdtDac.[0] - 15)); 0x01uy
            byte (max 0 (int otp.FdtDac.[1] - 15)); 0x01uy
            byte (max 0 (int otp.FdtDac.[2] - 15)); 0x01uy
            byte (max 0 (int otp.FdtDac.[3] - 15)); 0x01uy
        |]
        let zeros16 = Array.zeroCreate<byte> 16

        let makeFdtModePacket (modeByte: byte) (reply: bool) =
            let replyByte = if reply then 0x01uy else 0x00uy
            Array.concat [| [| modeByte; 0x01uy |]; dacBytes; zeros16; [| replyByte |] |]

        // 8.1: mcu_switch_to_fdt_mode(0x0d... 0, false)
        let fdt0dNoReply = makeFdtModePacket 0x0duy false
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtMode fdt0dNoReply, Protocol.CommandMcuSwitchToFdtMode)

        // 8.2: mcu_switch_to_fdt_mode(0x0d... 1, true)
        let fdt0dWait = makeFdtModePacket 0x0duy true
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtMode fdt0dWait, Protocol.CommandMcuSwitchToFdtMode)
        let! fdtResp0 = this.ReadCommandResponse(Protocol.CommandMcuSwitchToFdtMode, 2000)
        if fdtResp0.Length >= 20 && currentFdtDownBase.IsNone then
            let rawFdt = Array.sub fdtResp0 4 16
            let idleWords = [| for i in 0 .. 7 -> uint16 rawFdt.[2 * i] ||| (uint16 rawFdt.[2 * i + 1] <<< 8) |]
            currentFdtIdle <- Some idleWords
            sessionIdle <- Some idleWords
            let downBase = FdtCalculations.calcFdtDownBase rawFdt
            currentFdtDownBase <- Some downBase

        // 8.3: write_sensor_register 0x022c = [0x0a, 0x03]
        do! this.SendAndExpectAck(Protocol.packWriteSensorRegister 0x022cus [| 0x0auy; 0x03uy |], Protocol.CommandWriteSensorRegister)

        // 8.4: get_image clear-0 ([0x01, 0x03, dacBytes])
        let imgClear0 = Array.concat [| [| 0x01uy; 0x03uy |]; dacBytes |]
        let! _clear0 = this.CaptureRawFrameInternal(imgClear0)

        // 8.5: write_sensor_register 0x022c = [0x0a, 0x02]
        do! this.SendAndExpectAck(Protocol.packWriteSensorRegister 0x022cus [| 0x0auy; 0x02uy |], Protocol.CommandWriteSensorRegister)

        // 8.6: write_sensor_register 0x022c = [0x0a, 0x03]
        do! this.SendAndExpectAck(Protocol.packWriteSensorRegister 0x022cus [| 0x0auy; 0x03uy |], Protocol.CommandWriteSensorRegister)

        // 8.7: get_image clear-1 ([0x81, 0x03, dacBytes])
        let imgClear1 = Array.concat [| [| 0x81uy; 0x03uy |]; dacBytes |]
        let! _clear1 = this.CaptureRawFrameInternal(imgClear1)

        // 8.8: write_sensor_register 0x022c = [0x0a, 0x02]
        do! this.SendAndExpectAck(Protocol.packWriteSensorRegister 0x022cus [| 0x0auy; 0x02uy |], Protocol.CommandWriteSensorRegister)

        // 8.9: write_sensor_register 0x022c = [0x0a, 0x03]
        do! this.SendAndExpectAck(Protocol.packWriteSensorRegister 0x022cus [| 0x0auy; 0x03uy |], Protocol.CommandWriteSensorRegister)

        // 8.10: get_image clear-2 ([0x81, 0x03, dacBytesMinus15])
        let imgClear2 = Array.concat [| [| 0x81uy; 0x03uy |]; dacBytesMinus15 |]
        let! _clear2 = this.CaptureRawFrameInternal(imgClear2)

        // 8.11: write_sensor_register 0x022c = [0x0a, 0x02]
        do! this.SendAndExpectAck(Protocol.packWriteSensorRegister 0x022cus [| 0x0auy; 0x02uy |], Protocol.CommandWriteSensorRegister)

        // 8.12: mcu_switch_to_fdt_mode(0x8d... 0, false)
        let fdt8dNoReply = makeFdtModePacket 0x8duy false
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtMode fdt8dNoReply, Protocol.CommandMcuSwitchToFdtMode)

        // 8.13: mcu_switch_to_fdt_mode(0x8d... 1, true)
        let fdt8dWait = makeFdtModePacket 0x8duy true
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtMode fdt8dWait, Protocol.CommandMcuSwitchToFdtMode)
        let! _ = this.ReadCommandResponse(Protocol.CommandMcuSwitchToFdtMode, 2000)

        // 8.14: write_sensor_register 0x022c = [0x0a, 0x03]
        do! this.SendAndExpectAck(Protocol.packWriteSensorRegister 0x022cus [| 0x0auy; 0x03uy |], Protocol.CommandWriteSensorRegister)

        // 8.15: get_image clear-3 ([0x81, 0x03, dacBytes]) -> baseline dark frame
        let imgClear3 = Array.concat [| [| 0x81uy; 0x03uy |]; dacBytes |]
        let! clear3 = this.CaptureRawFrameInternal(imgClear3)
        baselineFrame <- Some clear3

        // 8.16: write_sensor_register 0x022c = [0x0a, 0x02]
        do! this.SendAndExpectAck(Protocol.packWriteSensorRegister 0x022cus [| 0x0auy; 0x02uy |], Protocol.CommandWriteSensorRegister)

        // 8.17: mcu_switch_to_fdt_mode(0x0d... 0, false)
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtMode fdt0dNoReply, Protocol.CommandMcuSwitchToFdtMode)

        // 8.18: mcu_switch_to_fdt_mode(0x0d... 1, true)
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtMode fdt0dWait, Protocol.CommandMcuSwitchToFdtMode)
        let! fdtResp = this.ReadCommandResponse(Protocol.CommandMcuSwitchToFdtMode, 2000)
        if fdtResp.Length >= 20 then
            let rawFdt = Array.sub fdtResp 4 16
            let idleWords = [| for i in 0 .. 7 -> uint16 rawFdt.[2 * i] ||| (uint16 rawFdt.[2 * i + 1] <<< 8) |]
            currentFdtIdle <- Some idleWords
            sessionIdle <- Some idleWords
            let downBase = FdtCalculations.calcFdtDownBase rawFdt
            currentFdtDownBase <- Some downBase
            DeviceDebug.logBaselineIdle idleWords

        // 8.19: mcu_switch_to_sleep_mode
        do! this.SendAndExpectAck(Protocol.packSwitchToSleepMode(), Protocol.CommandMcuSwitchToSleepMode)

        // 8.20: query_mcu_state([0x01, 0x01, 0x01])
        do! this.SendAndExpectAck(Protocol.packQueryMcuState [| 0x01uy; 0x01uy; 0x01uy |], Protocol.CommandQueryMcuState)

        return otp
    }

    // ------------------------------------------------------------------------
    // Internal Frame Capture Helper
    // ------------------------------------------------------------------------

    member private this.CaptureRawFrameInternal(imgPayload: byte[]) : Task<Result<RawFrame12Bit, DriverError>> = taskResult {
        let imgReq = Protocol.packGetImage imgPayload Protocol.FlagsTransportLayerSecurityData
        do! this.SendAndExpectAck(imgReq, Protocol.CommandMcuGetImage)

        // Read encrypted application data (7684 frame payload + TLS record wrapping)
        let! encryptedPack = transport.Read(8192, 5000)

        // Decrypt application data via TLS-PSK tunnel
        let! decrypted = tlsTunnel.DecryptApplicationData(encryptedPack)

        // Verify CRC32
        do! GoodixFrameCrc.verify (ReadOnlySpan decrypted)

        // Unpack and transpose pixels into 80x64
        let! pixels = FrameDecoder.unpackAndTranspose80x64 (Array.take FrameDecoder.PackedFrameSize decrypted)
        return! RawFrame12Bit.create pixels
    }

    // ------------------------------------------------------------------------
    // Workflow 4: Wait for Finger Down Event
    // ------------------------------------------------------------------------

    member this.WaitForFingerDown(?timeoutMs: int) : Task<Result<unit, DriverError>> = taskResult {
        let timeout = defaultArg timeoutMs 10000

        let otp =
            match currentOtp with
            | Some o -> o
            | None -> { Raw = Array.zeroCreate 64; DacH = 0x28uy; DacL = 0x24uy; FdtDac = [| 0x91uy; 0x8buy; 0x96uy; 0x91uy |] }

        let dacBytes = [|
            otp.FdtDac.[0]; 0x01uy
            otp.FdtDac.[1]; 0x01uy
            otp.FdtDac.[2]; 0x01uy
            otp.FdtDac.[3]; 0x01uy
        |]
        let downThresholds =
            match currentFdtDownBase with
            | Some b when b.Length = 16 -> b
            | _ ->
                [|
                    0x91uy; 0x91uy; 0x8buy; 0x8buy
                    0x96uy; 0x96uy; 0x91uy; 0x91uy
                    0x98uy; 0x98uy; 0x90uy; 0x90uy
                    0x92uy; 0x92uy; 0x88uy; 0x88uy
                |]

        // 1. Send 0x32 with reply = false
        let fdtDownNoReply = Array.concat [| [| 0x8cuy; 0x01uy |]; dacBytes; downThresholds; [| 0x00uy |] |]
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtDown fdtDownNoReply, Protocol.CommandMcuSwitchToFdtDown)

        // 2. Send 0x32 with reply = true and wait for touch event
        let fdtDownWait = Array.concat [| [| 0x8cuy; 0x01uy |]; dacBytes; downThresholds; [| 0x01uy |] |]
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtDown fdtDownWait, Protocol.CommandMcuSwitchToFdtDown)
        let! downPayload = this.ReadCommandResponse(Protocol.CommandMcuSwitchToFdtDown, timeout)

        // 3. Extract FDT baseline up data if present in payload (offset 2..3: touch_flag, offset 4..19: 16 bytes = 8 words)
        if downPayload.Length >= 20 then
            let touchFlag = uint16 downPayload.[2] ||| (uint16 downPayload.[3] <<< 8)
            let fdtData = Array.sub downPayload 4 16
            let upBase = FdtCalculations.calcFdtUpBase touchFlag fdtData None
            lastFdtUpBase <- Some upBase
            DeviceDebug.logFingerDown downPayload sessionIdle currentFdtIdle

        // 4. Immediately perform post-touch 0x36 mode switch (matching driver_53xd.py lines 242-252)
        let fdt0dPostNoReply = Array.concat [| [| 0x0duy; 0x01uy |]; dacBytes; downThresholds; [| 0x00uy |] |]
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtMode fdt0dPostNoReply, Protocol.CommandMcuSwitchToFdtMode)

        let fdt0dPostWait = Array.concat [| [| 0x0duy; 0x01uy |]; dacBytes; downThresholds; [| 0x01uy |] |]
        let! postTouchResp = this.SendAndReceive(Protocol.packSwitchToFdtMode fdt0dPostWait, Protocol.CommandMcuSwitchToFdtMode)

        DeviceDebug.logPostTouch postTouchResp sessionIdle currentFdtIdle

        return ()
    }

    // ------------------------------------------------------------------------
    // Workflow 5: Capture Frame
    // ------------------------------------------------------------------------

    member this.CaptureFrame() : Task<Result<RawFrame12Bit, DriverError>> = taskResult {
        let otp =
            match currentOtp with
            | Some o -> o
            | None -> { Raw = Array.zeroCreate 64; DacH = 0x28uy; DacL = 0x24uy; FdtDac = [| 0x91uy; 0x8buy; 0x96uy; 0x91uy |] }

        // Setup sensor gain/exposure register
        do! this.SendAndExpectAck(Protocol.packWriteSensorRegister 0x022cus [| 0x05uy; 0x03uy |], Protocol.CommandWriteSensorRegister)

        // Request image from sensor
        let imgPayload = [|
            0x41uy; 0x03uy
            otp.DacH; 0x00uy; otp.DacH - 6uy; 0x00uy
            otp.DacL; 0x00uy; otp.DacL - 4uy; 0x00uy
        |]
        let! rawFrame = this.CaptureRawFrameInternal(imgPayload)

        // Reset sensor register 0x022c back to FDT mode [0x0a; 0x02] (matching Milan TOD / ActivateSession steps 8.11, 8.16)
        do! this.SendAndExpectAck(Protocol.packWriteSensorRegister 0x022cus [| 0x0auy; 0x02uy |], Protocol.CommandWriteSensorRegister)

        return rawFrame
    }

    // ------------------------------------------------------------------------
    // Workflow 6: FDT Manual Reading & Finger Up Detection
    // ------------------------------------------------------------------------

    /// Performs an on-demand manual FDT reading (0x36) and returns the 8 decoded 16-bit FDT words.
    member this.ReadFdtManual(?timeoutMs: int) : Task<Result<uint16[], DriverError>> = taskResult {
        let timeout = defaultArg timeoutMs 2000
        let otp =
            match currentOtp with
            | Some o -> o
            | None -> { Raw = Array.zeroCreate 64; DacH = 0x28uy; DacL = 0x24uy; FdtDac = [| 0x91uy; 0x8buy; 0x96uy; 0x91uy |] }

        let dacBytes = [|
            otp.FdtDac.[0]; 0x01uy
            otp.FdtDac.[1]; 0x01uy
            otp.FdtDac.[2]; 0x01uy
            otp.FdtDac.[3]; 0x01uy
        |]
        let zeros16 = Array.zeroCreate<byte> 16
        let fdt0dNoReply = Array.concat [| [| 0x0duy; 0x01uy |]; dacBytes; zeros16; [| 0x00uy |] |]
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtMode fdt0dNoReply, Protocol.CommandMcuSwitchToFdtMode, timeoutMs = timeout)

        let fdt0dWait = Array.concat [| [| 0x0duy; 0x01uy |]; dacBytes; zeros16; [| 0x01uy |] |]
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtMode fdt0dWait, Protocol.CommandMcuSwitchToFdtMode, timeoutMs = timeout)
        let! fdtResp = this.ReadCommandResponse(Protocol.CommandMcuSwitchToFdtMode, timeoutMs = timeout)
        if fdtResp.Length >= 20 then
            let rawFdt = Array.sub fdtResp 4 16
            let words = [| for i in 0 .. 7 -> uint16 rawFdt.[2 * i] ||| (uint16 rawFdt.[2 * i + 1] <<< 8) |]
            return words
        else
            return! Error (ProtocolError $"FDT manual response too short ({fdtResp.Length} bytes)")
    }

    member this.WaitForFingerUp(?timeoutMs: int) : Task<Result<unit, DriverError>> = taskResult {
        let timeout = defaultArg timeoutMs 5000
        let otp =
            match currentOtp with
            | Some o -> o
            | None -> { Raw = Array.zeroCreate 64; DacH = 0x28uy; DacL = 0x24uy; FdtDac = [| 0x91uy; 0x8buy; 0x96uy; 0x91uy |] }

        let dacBytes = [|
            otp.FdtDac.[0]; 0x01uy
            otp.FdtDac.[1]; 0x01uy
            otp.FdtDac.[2]; 0x01uy
            otp.FdtDac.[3]; 0x01uy
        |]
        let upThresholds =
            match lastFdtUpBase with
            | Some b when b.Length = 16 -> b
            | _ ->
                [|
                    0x91uy; 0x91uy; 0x8buy; 0x8buy
                    0x96uy; 0x96uy; 0x91uy; 0x91uy
                    0x98uy; 0x98uy; 0x90uy; 0x90uy
                    0x92uy; 0x92uy; 0x88uy; 0x88uy
                |]

        // Mode byte 0x0e from libfprint-tod-goodix-53xc FpMcuSwitchToFdtUp / SwitchToFdtUp
        // 1. Send 0x34 with reply = false
        let fdtUpNoReply = Array.concat [| [| 0x0euy; 0x01uy |]; dacBytes; upThresholds; [| 0x00uy |] |]
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtUp fdtUpNoReply, Protocol.CommandMcuSwitchToFdtUp, timeoutMs = 2000)

        // 2. Send 0x34 with reply = true and wait for finger lift event
        let fdtUpWait = Array.concat [| [| 0x0euy; 0x01uy |]; dacBytes; upThresholds; [| 0x01uy |] |]
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtUp fdtUpWait, Protocol.CommandMcuSwitchToFdtUp, timeoutMs = 2000)
        let! _ = this.ReadCommandResponse(Protocol.CommandMcuSwitchToFdtUp, timeoutMs = timeout)
        return ()
    }

    /// Robust finger-up detection: polls FDT manual mode (0x36) until FDT values return to
    /// baseline idle tolerance (requiring 2 consecutive clear samples).
    /// Pure 0x36 polling exactly mirrors fdt-monitor and avoids leftover 0x34 arming.
    /// Re-arms the MCU to sleep mode afterwards.
    member this.WaitForFingerUpRobust(?timeoutMs: int, ?onStillHolding: unit -> unit) : Task<Result<unit, DriverError>> = task {
        let totalTimeout = defaultArg timeoutMs 15000
        let sw = Stopwatch.StartNew()
        let isGoodixDebug =
            let v = Environment.GetEnvironmentVariable("GOODIX_DEBUG")
            v = "1" || String.Equals(v, "true", StringComparison.OrdinalIgnoreCase)

        // Drain any pending USB packets from previous commands
        transport.DrainBuffer(50)

        // Determine session baseline idle reference (never overwrite sessionIdle with touch data)
        let! idle = task {
            let existing = sessionIdle |> Option.orElse currentFdtIdle
            match existing with
            | Some id -> return id
            | None ->
                let! sRes = this.ReadFdtManual(timeoutMs = 1000)
                match sRes with
                | Ok s ->
                    sessionIdle <- Some s
                    currentFdtIdle <- Some s
                    return s
                | Error _ -> return Array.create 8 280us
        }

        let mutable consecutiveClear = 0
        let mutable lastHintTime = sw.ElapsedMilliseconds
        let mutable finished = false

        while not finished && sw.ElapsedMilliseconds < int64 totalTimeout do
            let! pollRes = this.ReadFdtManual(timeoutMs = 1000)
            match pollRes with
            | Ok sample ->
                let isClear, meanDelta = FdtCalculations.isFingerLifted sample idle
                if isClear then
                    consecutiveClear <- consecutiveClear + 1
                    if consecutiveClear >= 2 then
                        finished <- true
                else
                    consecutiveClear <- 0
                    if sw.ElapsedMilliseconds - lastHintTime >= 3000L then
                        lastHintTime <- sw.ElapsedMilliseconds
                        match onStillHolding with
                        | Some cb -> cb ()
                        | None -> ()

                if isGoodixDebug then
                    let fdtStr = sample |> Array.map (fun v -> (int v).ToString().PadLeft(4)) |> String.concat " "
                    let deltaStr =
                        Array.map2 (fun curr baseVal ->
                            let diff = int curr - int baseVal
                            let sign = if diff >= 0 then "+" else ""
                            (sign + diff.ToString()).PadLeft(5)
                        ) sample idle
                        |> String.concat " "
                    let status = if isClear then $"CLEAR (streak {consecutiveClear}/2)" else "TOUCHED"
                    eprintfn $"[DEBUG][FingerUp] FDT: [ {fdtStr} ] | delta: [ {deltaStr} ] (mean={meanDelta,6:F1}, {status})"

            | Error err ->
                if isGoodixDebug then
                    eprintfn $"[DEBUG][FingerUp] ReadFdtManual error: {err}"
                transport.DrainBuffer(50)
                consecutiveClear <- 0

            if not finished then
                do! Task.Delay 50

        if finished then
            let _ = this.SendAndExpectAck(Protocol.packSwitchToSleepMode(), Protocol.CommandMcuSwitchToSleepMode)
            transport.DrainBuffer(50)
            return Ok ()
        else
            return Error (Timeout $"Finger was not lifted within {totalTimeout} ms")
    }

    // ------------------------------------------------------------------------
    // Workflow 7: Sleep
    // ------------------------------------------------------------------------

    member this.Sleep() : Task<Result<unit, DriverError>> = taskResult {
        do! this.SendAndExpectAck(Protocol.packSwitchToSleepMode(), Protocol.CommandMcuSwitchToSleepMode)
        return ()
    }

    interface IDisposable with
        member this.Dispose() =
            transport.Dispose()
            tlsTunnel.Dispose()
