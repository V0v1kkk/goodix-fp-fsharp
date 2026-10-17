namespace GoodixFp.Core

open System

module Crc32 =

    /// Precomputed IEEE 802.3 (ISO 3309) polynomial 0xEDB88320 table
    let private Table: uint32[] =
        let poly = 0xEDB88320u
        Array.init 256 (fun i ->
            let mutable c = uint32 i
            for _ in 0 .. 7 do
                if (c &&& 1u) <> 0u then
                    c <- (c >>> 1) ^^^ poly
                else
                    c <- c >>> 1
            c)

    /// Computes standard 32-bit CRC (IEEE 802.3) over a byte span.
    let compute (data: ReadOnlySpan<byte>) : uint32 =
        let mutable crc = 0xFFFFFFFFu
        for i in 0 .. data.Length - 1 do
            let b = data.[i]
            let tableIndex = int ((crc ^^^ uint32 b) &&& 0xFFu)
            crc <- (crc >>> 8) ^^^ Table.[tableIndex]
        crc ^^^ 0xFFFFFFFFu

    /// Computes standard 32-bit CRC (IEEE 802.3) over a byte array.
    let computeBytes (data: byte[]) : uint32 =
        if isNull data then 0u
        else compute (ReadOnlySpan data)

    /// Computes standard 32-bit CRC and returns as 4 big-endian bytes.
    let computeBigEndianBytes (data: ReadOnlySpan<byte>) : byte[] =
        let crc = compute data
        [|
            byte (crc >>> 24)
            byte (crc >>> 16)
            byte (crc >>> 8)
            byte crc
        |]

    /// Computes standard 32-bit CRC and returns as 4 little-endian bytes.
    let computeLittleEndianBytes (data: ReadOnlySpan<byte>) : byte[] =
        let crc = compute data
        [|
            byte crc
            byte (crc >>> 8)
            byte (crc >>> 16)
            byte (crc >>> 24)
        |]

module GoodixFrameCrc =

    [<Literal>]
    let FrameDataLength = 7680

    [<Literal>]
    let FrameTotalLength = 7684

    /// Verifies the 7,684-byte Goodix frame payload where the first 7,680 bytes
    /// are 12-bit packed sensor pixel data and the last 4 bytes are CRC32.
    let verify (frameBytes: ReadOnlySpan<byte>) : Result<unit, DriverError> =
        if frameBytes.Length < FrameTotalLength then
            Error (ValidationError ("GoodixFrameCrc", $"Frame length {frameBytes.Length} is less than required {FrameTotalLength}"))
        else
            let dataSlice = frameBytes.Slice(0, FrameDataLength)
            let computed = Crc32.compute dataSlice

            let b0 = uint32 frameBytes.[FrameDataLength]
            let b1 = uint32 frameBytes.[FrameDataLength + 1]
            let b2 = uint32 frameBytes.[FrameDataLength + 2]
            let b3 = uint32 frameBytes.[FrameDataLength + 3]

            let bigEndianReceived = (b0 <<< 24) ||| (b1 <<< 16) ||| (b2 <<< 8) ||| b3
            let littleEndianReceived = b0 ||| (b1 <<< 8) ||| (b2 <<< 16) ||| (b3 <<< 24)

            if computed = bigEndianReceived || computed = littleEndianReceived then
                Ok ()
            else
                Error (ChecksumMismatch (computed, bigEndianReceived))
