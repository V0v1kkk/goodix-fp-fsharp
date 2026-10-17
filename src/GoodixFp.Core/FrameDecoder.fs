namespace GoodixFp.Core

open System
open System.Text

module FrameDecoder =

    [<Literal>]
    let PackedFrameSize = 7680

    [<Literal>]
    let PixelCount = 5120

    [<Literal>]
    let Width80 = 80

    [<Literal>]
    let Height64 = 64

    /// Variant 1: Unpacks 7,680 packed bytes into 5,120 12-bit uint16 pixels
    /// in goodix53xd.c sequential row-wise order (64x80).
    let unpackSequential (packed: byte[]) : Result<uint16[], DriverError> =
        if isNull packed || packed.Length < PackedFrameSize then
            Error (ValidationError ("packed", $"Expected at least {PackedFrameSize} bytes, got {if isNull packed then 0 else packed.Length}"))
        else
            let pixels = Array.zeroCreate PixelCount
            let mutable pixIdx = 0
            for i in 0 .. 6 .. PackedFrameSize - 6 do
                let c0 = packed.[i]
                let c1 = packed.[i + 1]
                let c2 = packed.[i + 2]
                let c3 = packed.[i + 3]
                let c4 = packed.[i + 4]
                let c5 = packed.[i + 5]

                pixels.[pixIdx] <- ((uint16 (c0 &&& 0x0fuy)) <<< 8) ||| uint16 c1
                pixels.[pixIdx + 1] <- (uint16 c3 <<< 4) ||| uint16 (c0 >>> 4)
                pixels.[pixIdx + 2] <- ((uint16 (c5 &&& 0x0fuy)) <<< 8) ||| uint16 c2
                pixels.[pixIdx + 3] <- (uint16 c4 <<< 4) ||| uint16 (c5 >>> 4)
                pixIdx <- pixIdx + 4
            Ok pixels

    /// Variant 2: Unpacks 7,680 packed bytes and transposes to Goodix native
    /// ImageRestructInterface (0x12dbf0) column-to-row layout into 80x64.
    /// Formula: out[((i &&& 0x3f) * 80) + (i >>> 6)] = p_i
    let unpackAndTranspose80x64 (packed: byte[]) : Result<uint16[], DriverError> =
        match unpackSequential packed with
        | Error err -> Error err
        | Ok sequential ->
            let transposed = Array.zeroCreate PixelCount
            for i in 0 .. PixelCount - 1 do
                let targetIdx = ((i &&& 0x3f) * Width80) + (i >>> 6)
                transposed.[targetIdx] <- sequential.[i]
            Ok transposed

    /// Variant 3: Zero-allocation high-performance Span<byte> / Span<uint16>
    /// version of unpackAndTranspose80x64.
    let unpackAndTranspose80x64Span (packed: ReadOnlySpan<byte>) (destination: Span<uint16>) : Result<unit, DriverError> =
        if packed.Length < PackedFrameSize then
            Error (ValidationError ("packed", $"Packed span length {packed.Length} < {PackedFrameSize}"))
        elif destination.Length < PixelCount then
            Error (ValidationError ("destination", $"Destination span length {destination.Length} < {PixelCount}"))
        else
            for chunkIdx in 0 .. 1279 do
                let byteOff = chunkIdx * 6
                let c0 = packed.[byteOff]
                let c1 = packed.[byteOff + 1]
                let c2 = packed.[byteOff + 2]
                let c3 = packed.[byteOff + 3]
                let c4 = packed.[byteOff + 4]
                let c5 = packed.[byteOff + 5]

                let p0 = ((uint16 (c0 &&& 0x0fuy)) <<< 8) ||| uint16 c1
                let p1 = (uint16 c3 <<< 4) ||| uint16 (c0 >>> 4)
                let p2 = ((uint16 (c5 &&& 0x0fuy)) <<< 8) ||| uint16 c2
                let p3 = (uint16 c4 <<< 4) ||| uint16 (c5 >>> 4)

                let i0 = chunkIdx * 4
                let i1 = i0 + 1
                let i2 = i0 + 2
                let i3 = i0 + 3

                destination.[((i0 &&& 0x3f) * Width80) + (i0 >>> 6)] <- p0
                destination.[((i1 &&& 0x3f) * Width80) + (i1 >>> 6)] <- p1
                destination.[((i2 &&& 0x3f) * Width80) + (i2 >>> 6)] <- p2
                destination.[((i3 &&& 0x3f) * Width80) + (i3 >>> 6)] <- p3

            Ok ()

    // ========================================================================
    // Grayscale Bit-Depth Squashing (12-bit -> 8-bit)
    // ========================================================================

    /// Scales 12-bit (0..4095) pixels to 8-bit (0..255) by dividing by 16.
    let squash12To8Bit (pixels: uint16[]) : byte[] =
        Array.map (fun (p: uint16) -> byte (min 4095us p / 16us)) pixels

    /// Scales 12-bit pixels to 8-bit using linear min-max normalization.
    let squash12To8BitLinear (pixels: uint16[]) : byte[] =
        if isNull pixels || pixels.Length = 0 then [||]
        else
            let mutable minVal = 0xffffus
            let mutable maxVal = 0x0000us
            for p in pixels do
                if p < minVal then minVal <- p
                if p > maxVal then maxVal <- p

            if maxVal = minVal then
                Array.zeroCreate pixels.Length
            else
                let range = float (maxVal - minVal)
                Array.map (fun (p: uint16) ->
                    let norm = (float (p - minVal) / range) * 255.0
                    byte (Math.Clamp(Math.Round(norm), 0.0, 255.0))
                ) pixels

    // ========================================================================
    // Image Export Helpers (PGM / PPM)
    // ========================================================================

    /// Exports 12-bit raw frame as binary PGM (P5) with maxval 4095 (big-endian).
    let toPgm12Bit (pixels: uint16[]) (width: int) (height: int) : byte[] =
        let header = Encoding.ASCII.GetBytes($"P5\n{width} {height}\n4095\n")
        let dataLen = width * height * 2
        let result = Array.zeroCreate (header.Length + dataLen)
        Buffer.BlockCopy(header, 0, result, 0, header.Length)

        let mutable outIdx = header.Length
        for i in 0 .. (width * height) - 1 do
            let pix = if i < pixels.Length then min 4095us pixels.[i] else 0us
            result.[outIdx] <- byte (pix >>> 8)
            result.[outIdx + 1] <- byte (pix &&& 0xffus)
            outIdx <- outIdx + 2
        result

    /// Exports 8-bit grayscale frame as binary PGM (P5) with maxval 255.
    let toPgm8Bit (pixels: byte[]) (width: int) (height: int) : byte[] =
        let header = Encoding.ASCII.GetBytes($"P5\n{width} {height}\n255\n")
        let dataLen = width * height
        let result = Array.zeroCreate (header.Length + dataLen)
        Buffer.BlockCopy(header, 0, result, 0, header.Length)
        let copyLen = min dataLen pixels.Length
        Buffer.BlockCopy(pixels, 0, result, header.Length, copyLen)
        result

    /// Exports 8-bit grayscale frame as binary PPM (P6, RGB).
    let toPpm8Bit (pixels: byte[]) (width: int) (height: int) : byte[] =
        let header = Encoding.ASCII.GetBytes($"P6\n{width} {height}\n255\n")
        let count = width * height
        let result = Array.zeroCreate (header.Length + (count * 3))
        Buffer.BlockCopy(header, 0, result, 0, header.Length)
        let mutable outIdx = header.Length
        for i in 0 .. count - 1 do
            let b = if i < pixels.Length then pixels.[i] else 0uy
            result.[outIdx] <- b
            result.[outIdx + 1] <- b
            result.[outIdx + 2] <- b
            outIdx <- outIdx + 3
        result
