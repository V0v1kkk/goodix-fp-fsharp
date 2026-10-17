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

    member private this.SendAndExpectAck(packet: byte[], expectedCommand: byte, ?timeoutMs: int) : Result<unit, DriverError> =
        result {
            let timeout = defaultArg timeoutMs 2000
            do! transport.Write(packet)
            let! response = transport.Read(64, timeout)
            match response with
            | Protocol.AckResponse (cmd, success) when cmd = expectedCommand ->
                if success then return ()
                else return! Error (ProtocolError $"Device returned NAK for command 0x{cmd:x2}")
            | Protocol.AckResponse (cmd, _) ->
                return! Error (ProtocolError $"Expected ACK for command 0x{expectedCommand:x2}, got 0x{cmd:x2}")
            | Protocol.InvalidPacket reason ->
                return! Error (InvalidPacket reason)
            | Protocol.CommandResponse (cmd, _) ->
                return! Error (ProtocolError $"Unexpected command response 0x{cmd:x2} while expecting ACK for 0x{expectedCommand:x2}")
        }

    member private this.SendAndReceive(packet: byte[], expectedCommand: byte, ?timeoutMs: int) : Result<byte[], DriverError> =
        result {
            let timeout = defaultArg timeoutMs 3000
            do! this.SendAndExpectAck(packet, expectedCommand, timeout)
            let! response = transport.Read(1024, timeout)
            match response with
            | Protocol.CommandResponse (cmd, payload) when cmd = expectedCommand ->
                return payload
            | Protocol.CommandResponse (cmd, _) ->
                return! Error (ProtocolError $"Expected response for command 0x{expectedCommand:x2}, got 0x{cmd:x2}")
            | Protocol.AckResponse (cmd, _) ->
                return! Error (ProtocolError $"Unexpected ACK for command 0x{cmd:x2} while expecting response")
            | Protocol.InvalidPacket reason ->
                return! Error (InvalidPacket reason)
        }

    // ------------------------------------------------------------------------
    // Workflow 1: Probe Device Information
    // ------------------------------------------------------------------------

    member this.ProbeInfo() : Task<Result<DeviceInfo, DriverError>> = taskResult {
        // 1. Send NOP
        do! this.SendAndExpectAck(Protocol.packNop(), Protocol.CommandNop)

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
    // Workflow 2: Provision Zero PSK
    // ------------------------------------------------------------------------

    member this.ProvisionZeroPsk() : Task<Result<unit, DriverError>> = taskResult {
        // Read current PSK status (flags = 0xbb020001)
        let readPskPacket = Protocol.packPresetPskRead 0xbb020001u (Some 32) (Some 0)
        let! pskPayload = this.SendAndReceive(readPskPacket, Protocol.CommandPresetPskReadR)
        let pskValid =
            pskPayload.Length >= 41 &&
            pskPayload.[0] = 0x00uy &&
            ReadOnlySpan(pskPayload, 9, 32).SequenceEqual(ReadOnlySpan(Protocol.PmkHashZero))

        if not pskValid then
            // Write PSK White-Box with flag 0xbb010003u, chunk length 114, offset 0, and pre_flags
            let writePacket = Protocol.packPresetPskWrite 0xbb010003u Protocol.PskWhiteBox (Some 114) (Some 0) (Some Protocol.PreFlagsPresetPskWrite)
            let! writeResp = this.SendAndReceive(writePacket, Protocol.CommandPresetPskWriteR)
            if writeResp.Length > 0 && writeResp.[0] = 0x00uy then
                // Re-verify PSK status
                let! recheckPayload = this.SendAndReceive(readPskPacket, Protocol.CommandPresetPskReadR)
                let recheckValid =
                    recheckPayload.Length >= 41 &&
                    recheckPayload.[0] = 0x00uy &&
                    ReadOnlySpan(recheckPayload, 9, 32).SequenceEqual(ReadOnlySpan(Protocol.PmkHashZero))
                if recheckValid then
                    return ()
                else
                    return! Error (ProtocolError "PSK verification failed after writing PSK White-Box")
            else
                return! Error (ProtocolError "Failed to write PSK White-Box")
        else
            return ()
    }

    // ------------------------------------------------------------------------
    // Workflow 3: Activate Session (Init + TLS Handshake)
    // ------------------------------------------------------------------------

    member this.ActivateSession() : Task<Result<SensorOtp, DriverError>> = taskResult {
        // Enable chip before reset
        do! this.SendAndExpectAck(Protocol.packEnableChip true, Protocol.CommandEnableChip)

        // Reset device
        let resetPacket = Protocol.packReset true false 20uy
        do! this.SendAndExpectAck(resetPacket, Protocol.CommandReset)
        let! resetPayload = transport.Read(64, 2000)
        let! _ =
            match resetPayload with
            | Protocol.CommandResponse (Protocol.CommandReset, payload) when payload.Length >= 1 && payload.[0] = 0x01uy ->
                Ok ()
            | _ ->
                Error (ResetFailed "Reset response invalid or rejected")

        // Read Chip ID
        let! _ = this.SendAndReceive(Protocol.packReadSensorRegister 0x0000us 4uy, Protocol.CommandReadSensorRegister)

        // Read OTP
        let! otpPayload = this.SendAndReceive(Protocol.packReadOtp(), Protocol.CommandReadOtp)
        let! otp = SensorOtp.parse otpPayload
        currentOtp <- Some otp

        // MCU switch to idle mode
        do! this.SendAndExpectAck(Protocol.packSwitchToIdleMode 20uy, Protocol.CommandMcuSwitchToIdleMode)

        // Upload MCU config
        let! uploadResp = this.SendAndReceive(Protocol.packUploadConfig Protocol.Goodix53xdConfig, Protocol.CommandUploadConfigMcu)
        if uploadResp.Length = 0 || uploadResp.[0] <> 0x01uy then
            do! Error (ProtocolError "Failed to upload MCU config")

        // Initiate TLS handshake
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
