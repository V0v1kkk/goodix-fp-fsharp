namespace GoodixFp.Core

open System
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

// ============================================================================
// High-Level Goodix 53xd Driver
// ============================================================================

type Goodix53xdDevice(transport: IUsbTransport, tlsTunnel: ITlsPskTunnel) =

    let mutable currentOtp: SensorOtp option = None

    new(transport: IUsbTransport) =
        new Goodix53xdDevice(transport, new PureFSharpTlsPskTunnel())

    member this.Transport = transport
    member this.TlsTunnel = tlsTunnel
    member this.CurrentOtp = currentOtp

    // ------------------------------------------------------------------------
    // Low-Level Packet Exchange Helpers
    // ------------------------------------------------------------------------

    member this.SendAndExpectAck(packet: byte[], expectedCommand: byte, ?timeoutMs: int) : Result<unit, DriverError> =
        result {
            let timeout = defaultArg timeoutMs 2000
            do! transport.Write(packet)
            let! response = transport.Read(64, timeout)
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
            let! response = transport.Read(1024, timeout)
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
            let! firstResponse = transport.Read(1024, timeout)
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
        // 1. Send NOP wakeup
        do! this.SendNopWakeup()

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

        return otp
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

        // Switch to FDT down mode
        let fdtPayload = [|
            0x8cuy; 0x01uy
            0x28uy; 0x01uy; 0x22uy; 0x01uy; 0x28uy; 0x01uy; 0x24uy; 0x01uy
            otp.FdtDac.[0]; otp.FdtDac.[0]; otp.FdtDac.[1]; otp.FdtDac.[1]
            otp.FdtDac.[2]; otp.FdtDac.[2]; otp.FdtDac.[3]; otp.FdtDac.[3]
            0x98uy; 0x98uy; 0x90uy; 0x90uy; 0x92uy; 0x92uy; 0x88uy; 0x88uy
            0x01uy // reply = true, wait for finger down
        |]
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtDown fdtPayload, Protocol.CommandMcuSwitchToFdtDown)
        let! downResp = transport.Read(64, timeout)
        let! _ =
            match downResp with
            | Protocol.CommandResponse (Protocol.CommandMcuSwitchToFdtDown, _) -> Ok ()
            | _ -> Error (ProtocolError "Failed waiting for finger down")
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
    // Workflow 6: Wait for Finger Up Event
    // ------------------------------------------------------------------------

    member this.WaitForFingerUp(?timeoutMs: int) : Task<Result<unit, DriverError>> = taskResult {
        let timeout = defaultArg timeoutMs 5000
        let mode = [| 0x01uy; 0x00uy |]
        do! this.SendAndExpectAck(Protocol.packSwitchToFdtUp mode, Protocol.CommandMcuSwitchToFdtUp)
        let! upResp = transport.Read(64, timeout)
        let! _ =
            match upResp with
            | Protocol.CommandResponse (Protocol.CommandMcuSwitchToFdtUp, _) -> Ok ()
            | _ -> Error (ProtocolError "Failed waiting for finger up")
        return ()
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
