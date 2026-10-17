namespace GoodixFp.Core

open System

module Protocol =

    // ========================================================================
    // Message Pack Flags
    // ========================================================================

    [<Literal>]
    let FlagsMessageProtocol = 0xa0uy

    [<Literal>]
    let FlagsTransportLayerSecurity = 0xb0uy

    [<Literal>]
    let FlagsTransportLayerSecurityData = 0xb2uy

    // ========================================================================
    // Command Constants
    // ========================================================================

    [<Literal>]
    let CommandNop = 0x00uy

    [<Literal>]
    let CommandMcuGetImage = 0x20uy

    [<Literal>]
    let CommandMcuSwitchToFdtDown = 0x32uy

    [<Literal>]
    let CommandMcuSwitchToFdtUp = 0x34uy

    [<Literal>]
    let CommandMcuSwitchToFdtMode = 0x36uy

    [<Literal>]
    let CommandNav = 0x50uy

    [<Literal>]
    let CommandMcuSwitchToSleepMode = 0x60uy

    [<Literal>]
    let CommandMcuSwitchToIdleMode = 0x70uy

    [<Literal>]
    let CommandWriteSensorRegister = 0x80uy

    [<Literal>]
    let CommandReadSensorRegister = 0x82uy

    [<Literal>]
    let CommandUploadConfigMcu = 0x90uy

    [<Literal>]
    let CommandSwitchToSleepMode = 0x92uy

    [<Literal>]
    let CommandSetPowerdownScanFrequency = 0x94uy

    [<Literal>]
    let CommandEnableChip = 0x96uy

    [<Literal>]
    let CommandReset = 0xa2uy

    [<Literal>]
    let CommandMcuEraseApp = 0xa4uy

    [<Literal>]
    let CommandReadOtp = 0xa6uy

    [<Literal>]
    let CommandFirmwareVersion = 0xa8uy

    [<Literal>]
    let CommandSetPovConfig = 0xacuy

    [<Literal>]
    let CommandQueryMcuState = 0xaeuy

    [<Literal>]
    let CommandAck = 0xb0uy

    [<Literal>]
    let CommandSetDrvState = 0xc4uy

    [<Literal>]
    let CommandRequestTlsConnection = 0xd0uy

    [<Literal>]
    let CommandMcuGetPovImage = 0xd2uy

    [<Literal>]
    let CommandTlsSuccessfullyEstablished = 0xd4uy

    [<Literal>]
    let CommandPovImageCheck = 0xd6uy

    [<Literal>]
    let CommandPresetPskWriteR = 0xe0uy

    [<Literal>]
    let CommandPresetPskReadR = 0xe4uy

    [<Literal>]
    let CommandWriteFirmware = 0xf0uy

    [<Literal>]
    let CommandReadFirmware = 0xf2uy

    [<Literal>]
    let CommandCheckFirmware = 0xf4uy

    [<Literal>]
    let CommandGetIapVersion = 0xf6uy

    // ========================================================================
    // Preset Cryptographic & Hardware Constants
    // ========================================================================

    /// 256-byte sensor calibration config for Goodix 53xd / 538d
    let Goodix53xdConfig: byte[] =
        Convert.FromHexString(
            "701160712c9d2cc91ce518fd00fd00fd03ba000180ca0008008400bec38600b1" +
            "b68800baba8a00b3b38c00bcbc8e00b1b19000bbbb9200b1b194000000960000" +
            "00980000009a000000d2000000d4000000d6000000d800000050000105d00000" +
            "00700000007200785674003412200010402a0102042200012024003200800001" +
            "005c000101560024205800010232000402660000027c00005882007f082a0182" +
            "072200012024001400800001405c00e700560006145800040232000c02660000" +
            "027c000058820080082a0108005c000101540000016200080464001000660000" +
            "027c0000582a0108005c00dc005200080054000001660000027c00005820c51d"
        )

    /// 96-byte White-Box PSK for zero-key provisioning
    let PskWhiteBox: byte[] =
        Convert.FromHexString(
            "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b" +
            "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e" +
            "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5"
        )

    /// 32-byte PMK hash for zero PSK
    let PmkHashZero: byte[] =
        Convert.FromHexString("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925")

    /// 32-byte Zero PSK
    let ZeroPsk: byte[] = Array.zeroCreate 32

    // ========================================================================
    // Message Pack Encoding & Decoding
    // ========================================================================

    let encodeMessagePack (flags: byte) (payload: byte[]) : byte[] =
        let payloadLen = if isNull payload then 0 else payload.Length
        let lenLo = byte (payloadLen &&& 0xff)
        let lenHi = byte ((payloadLen >>> 8) &&& 0xff)
        let checksum = byte ((int flags + int lenLo + int lenHi) &&& 0xff)
        let result = Array.zeroCreate (4 + payloadLen)
        result.[0] <- flags
        result.[1] <- lenLo
        result.[2] <- lenHi
        result.[3] <- checksum
        if payloadLen > 0 then
            Array.Copy(payload, 0, result, 4, payloadLen)
        result

    let decodeMessagePack (data: byte[]) : Result<byte * byte[], DriverError> =
        if isNull data || data.Length < 4 then
            Error (InvalidPacket "Message pack shorter than 4-byte header")
        else
            let flags = data.[0]
            let len = int data.[1] ||| (int data.[2] <<< 8)
            let expectedChecksum = byte ((int flags + int data.[1] + int data.[2]) &&& 0xff)
            if data.[3] <> expectedChecksum then
                Error (InvalidPacket $"Message pack checksum mismatch: expected {expectedChecksum:x2}, got {data.[3]:x2}")
            elif data.Length < 4 + len then
                Error (InvalidPacket $"Message pack truncated: expected {4 + len} bytes, got {data.Length}")
            else
                let payload = Array.sub data 4 len
                Ok (flags, payload)

    // ========================================================================
    // Inner Message Protocol Encoding & Decoding
    // ========================================================================

    let encodeMessageProtocol (command: byte) (payload: byte[]) (checksum: bool) : byte[] =
        let payloadLen = if isNull payload then 0 else payload.Length
        let lengthField = payloadLen + 1
        let lenLo = byte (lengthField &&& 0xff)
        let lenHi = byte ((lengthField >>> 8) &&& 0xff)

        let headerAndPayload = Array.zeroCreate (3 + payloadLen)
        headerAndPayload.[0] <- command
        headerAndPayload.[1] <- lenLo
        headerAndPayload.[2] <- lenHi
        if payloadLen > 0 then
            Array.Copy(payload, 0, headerAndPayload, 3, payloadLen)

        let mutable sum = 0
        for b in headerAndPayload do
            sum <- sum + int b

        let checksumByte =
            if checksum then byte ((0xaa - sum) &&& 0xff)
            else 0x88uy

        let result = Array.zeroCreate (headerAndPayload.Length + 1)
        Array.Copy(headerAndPayload, result, headerAndPayload.Length)
        result.[result.Length - 1] <- checksumByte
        result

    let decodeMessageProtocol (data: byte[]) (checksum: bool) : Result<byte * byte[], DriverError> =
        if isNull data || data.Length < 4 then
            Error (InvalidPacket "Message protocol shorter than 4 bytes")
        else
            let command = data.[0]
            let lengthField = int data.[1] ||| (int data.[2] <<< 8)
            let totalLen = 3 + lengthField
            if data.Length < totalLen then
                Error (InvalidPacket $"Message protocol truncated: expected {totalLen} bytes, got {data.Length}")
            else
                let checksumByte = data.[totalLen - 1]
                if checksum then
                    let mutable sum = 0
                    for i in 0 .. totalLen - 2 do
                        sum <- sum + int data.[i]
                    let expectedChecksum = byte ((0xaa - sum) &&& 0xff)
                    if checksumByte <> expectedChecksum then
                        Error (InvalidPacket $"Message protocol checksum mismatch: expected {expectedChecksum:x2}, got {checksumByte:x2}")
                    else
                        let payloadLen = lengthField - 1
                        let payload = Array.sub data 3 payloadLen
                        Ok (command, payload)
                else
                    if checksumByte <> 0x88uy then
                        Error (InvalidPacket $"Message protocol non-checksum marker mismatch: expected 0x88, got {checksumByte:x2}")
                    else
                        let payloadLen = lengthField - 1
                        let payload = Array.sub data 3 payloadLen
                        Ok (command, payload)

    // ========================================================================
    // ACK Decoding
    // ========================================================================

    let decodeAck (data: byte[]) : Result<byte * bool, DriverError> =
        if isNull data || data.Length < 2 then
            Error (InvalidPacket "ACK packet must have at least 2 bytes")
        elif (data.[1] &&& 0x01uy) = 0uy then
            Error (InvalidPacket "Invalid ACK framing bit 0 not set")
        else
            let command = data.[0]
            let success = (data.[1] &&& 0x02uy) <> 0uy
            Ok (command, success)

    // ========================================================================
    // Active Patterns for Packet Classification
    // ========================================================================

    /// Matches and extracts MessagePack header and payload: (flags, payload)
    let (|MessagePack|_|) (data: byte[]) : (byte * byte[]) option =
        match decodeMessagePack data with
        | Ok (flags, payload) -> Some (flags, payload)
        | Error _ -> None

    /// Matches and extracts MessageProtocol command and payload: (command, payload)
    let (|MessageProtocol|_|) (data: byte[]) : (byte * byte[]) option =
        match decodeMessageProtocol data true with
        | Ok (cmd, payload) -> Some (cmd, payload)
        | Error _ ->
            // Fallback: check without checksum
            match decodeMessageProtocol data false with
            | Ok (cmd, payload) -> Some (cmd, payload)
            | Error _ -> None

    /// Classifies an incoming buffer as AckResponse, CommandResponse, or InvalidPacket
    let (|AckResponse|CommandResponse|InvalidPacket|) (data: byte[]) =
        match data with
        | MessagePack (flags, inner) ->
            if flags = FlagsTransportLayerSecurity || flags = FlagsTransportLayerSecurityData then
                CommandResponse (flags, inner)
            else
                match inner with
                | MessageProtocol (CommandAck, ackPayload) ->
                    match decodeAck ackPayload with
                    | Ok (ackedCmd, success) -> AckResponse (ackedCmd, success)
                    | Error (InvalidPacket reason) -> InvalidPacket reason
                    | Error err -> InvalidPacket (string err)
                | MessageProtocol (cmd, payload) ->
                    CommandResponse (cmd, payload)
                | _ ->
                    InvalidPacket "Failed to decode inner message protocol"
        | _ ->
            InvalidPacket "Failed to decode outer message pack"

    // ========================================================================
    // Command Construction Helpers
    // ========================================================================

    let packNop () : byte[] =
        let inner = encodeMessageProtocol CommandNop (Array.zeroCreate 4) false
        encodeMessagePack FlagsMessageProtocol inner

    let packReset (resetSensor: bool) (softResetMcu: bool) (sleepTime: byte) : byte[] =
        let b0 =
            (if resetSensor then 0x01uy else 0x00uy) |||
            (if softResetMcu then 0x02uy else 0x00uy) |||
            (if resetSensor then 0x04uy else 0x00uy)
        let payload = [| b0; sleepTime |]
        let inner = encodeMessageProtocol CommandReset payload true
        encodeMessagePack FlagsMessageProtocol inner

    let packEnableChip (enable: bool) : byte[] =
        let payload = [| (if enable then 0x01uy else 0x00uy); 0x00uy |]
        let inner = encodeMessageProtocol CommandEnableChip payload true
        encodeMessagePack FlagsMessageProtocol inner

    let packFirmwareVersion () : byte[] =
        let payload = [| 0x00uy; 0x00uy |]
        let inner = encodeMessageProtocol CommandFirmwareVersion payload true
        encodeMessagePack FlagsMessageProtocol inner

    let packReadOtp () : byte[] =
        let payload = [| 0x00uy; 0x00uy |]
        let inner = encodeMessageProtocol CommandReadOtp payload true
        encodeMessagePack FlagsMessageProtocol inner

    let packUploadConfig (config: byte[]) : byte[] =
        let inner = encodeMessageProtocol CommandUploadConfigMcu config true
        encodeMessagePack FlagsMessageProtocol inner

    let packSwitchToIdleMode (sleepTime: byte) : byte[] =
        let payload = [| sleepTime; 0x00uy |]
        let inner = encodeMessageProtocol CommandMcuSwitchToIdleMode payload true
        encodeMessagePack FlagsMessageProtocol inner

    let packSwitchToSleepMode () : byte[] =
        let payload = [| 0x01uy; 0x00uy |]
        let inner = encodeMessageProtocol CommandMcuSwitchToSleepMode payload true
        encodeMessagePack FlagsMessageProtocol inner

    let packSwitchToFdtDown (mode: byte[]) : byte[] =
        let inner = encodeMessageProtocol CommandMcuSwitchToFdtDown mode true
        encodeMessagePack FlagsMessageProtocol inner

    let packSwitchToFdtUp (mode: byte[]) : byte[] =
        let inner = encodeMessageProtocol CommandMcuSwitchToFdtUp mode true
        encodeMessagePack FlagsMessageProtocol inner

    let packSwitchToFdtMode (mode: byte[]) : byte[] =
        let inner = encodeMessageProtocol CommandMcuSwitchToFdtMode mode true
        encodeMessagePack FlagsMessageProtocol inner

    let packRequestTlsConnection () : byte[] =
        let payload = [| 0x00uy; 0x00uy |]
        let inner = encodeMessageProtocol CommandRequestTlsConnection payload true
        encodeMessagePack FlagsMessageProtocol inner

    let packTlsSuccessfullyEstablished () : byte[] =
        let payload = [| 0x00uy; 0x00uy |]
        let inner = encodeMessageProtocol CommandTlsSuccessfullyEstablished payload true
        encodeMessagePack FlagsMessageProtocol inner

    let packGetImage (payload: byte[]) (flags: byte) : byte[] =
        let inner = encodeMessageProtocol CommandMcuGetImage payload true
        encodeMessagePack FlagsMessageProtocol inner

    let packWriteSensorRegister (address: uint16) (value: byte[]) : byte[] =
        let addrLo = byte (address &&& 0xffus)
        let addrHi = byte ((address >>> 8) &&& 0xffus)
        let msg = Array.concat [ [| 0x00uy; addrLo; addrHi |]; value ]
        let inner = encodeMessageProtocol CommandWriteSensorRegister msg true
        encodeMessagePack FlagsMessageProtocol inner

    let packReadSensorRegister (address: uint16) (length: byte) : byte[] =
        let addrLo = byte (address &&& 0xffus)
        let addrHi = byte ((address >>> 8) &&& 0xffus)
        let msg = [| 0x00uy; addrLo; addrHi; length |]
        let inner = encodeMessageProtocol CommandReadSensorRegister msg true
        encodeMessagePack FlagsMessageProtocol inner

    let packPresetPskWrite (flags: uint32) (payload: byte[]) (length: int option) (offset: int option) : byte[] =
        let flagsBytes = BitConverter.GetBytes(flags)
        let payloadLenBytes = BitConverter.GetBytes(uint32 payload.Length)
        let rawData = Array.concat [ flagsBytes; payloadLenBytes; payload ]

        let finalData =
            match length, offset with
            | Some len, Some off ->
                let totalLenBytes = BitConverter.GetBytes(uint32 rawData.Length)
                let lenBytes = BitConverter.GetBytes(uint32 len)
                let offBytes = BitConverter.GetBytes(uint32 off)
                let slice = Array.sub rawData off len
                Array.concat [ totalLenBytes; lenBytes; offBytes; slice ]
            | _ -> rawData

        let inner = encodeMessageProtocol CommandPresetPskWriteR finalData true
        encodeMessagePack FlagsMessageProtocol inner

    let packPresetPskRead (flags: uint32) (length: int option) (offset: int option) : byte[] =
        let flagsBytes = BitConverter.GetBytes(flags)
        let zeroBytes = BitConverter.GetBytes(0u)
        let prefix =
            match length, offset with
            | Some len, Some off ->
                let lenBytes = BitConverter.GetBytes(uint32 len)
                let offBytes = BitConverter.GetBytes(uint32 off)
                Array.concat [ lenBytes; offBytes ]
            | _ -> [||]
        let finalData = Array.concat [ prefix; flagsBytes; zeroBytes ]
        let inner = encodeMessageProtocol CommandPresetPskReadR finalData true
        encodeMessagePack FlagsMessageProtocol inner
