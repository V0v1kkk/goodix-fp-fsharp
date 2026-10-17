namespace GoodixFp.Core

open System

// ============================================================================
// Canonical [<Struct>] Single-Case DU Discipline (Vladimir's F# Style Guide)
// ============================================================================

[<Struct>]
type UsbVid = private UsbVid of uint16 with
    member this.Value = let (UsbVid v) = this in v

module UsbVid =
    let value (UsbVid v) = v
    let create (v: uint16) =
        if v = 0us then Error "UsbVid must be non-zero"
        else Ok (UsbVid v)
    let createUnsafe (v: uint16) = UsbVid v

[<Struct>]
type UsbPid = private UsbPid of uint16 with
    member this.Value = let (UsbPid v) = this in v

module UsbPid =
    let value (UsbPid v) = v
    let create (v: uint16) =
        if v = 0us then Error "UsbPid must be non-zero"
        else Ok (UsbPid v)
    let createUnsafe (v: uint16) = UsbPid v

[<Struct>]
type ChipId = private ChipId of uint16 with
    member this.Value = let (ChipId v) = this in v

module ChipId =
    let value (ChipId v) = v
    let create (v: uint16) =
        if v = 0us then Error "ChipId must be non-zero"
        else Ok (ChipId v)
    let createUnsafe (v: uint16) = ChipId v

[<Struct>]
type FirmwareVersion = private FirmwareVersion of string with
    member this.Value = let (FirmwareVersion v) = this in v

module FirmwareVersion =
    let value (FirmwareVersion v) = v
    let create (s: string) =
        if String.IsNullOrWhiteSpace s then Error "FirmwareVersion must not be empty"
        else Ok (FirmwareVersion (s.Trim()))
    let createUnsafe (s: string) = FirmwareVersion s

[<Struct>]
type RegisterAddress = private RegisterAddress of uint16 with
    member this.Value = let (RegisterAddress v) = this in v

module RegisterAddress =
    let value (RegisterAddress v) = v
    let create (v: uint16) = Ok (RegisterAddress v)
    let createUnsafe (v: uint16) = RegisterAddress v

[<Struct>]
type PskHash = private PskHash of byte[] with
    member this.Value = let (PskHash v) = this in v

module PskHash =
    let value (PskHash v) = v
    let create (bytes: byte[]) =
        if isNull bytes || bytes.Length <> 32 then
            Error "PskHash must be exactly 32 bytes"
        else
            Ok (PskHash (Array.copy bytes))
    let createUnsafe (bytes: byte[]) = PskHash bytes

[<Struct>]
type QualityScore = private QualityScore of int with
    member this.Value = let (QualityScore v) = this in v

module QualityScore =
    let value (QualityScore v) = v
    let create (v: int) =
        if v < 0 || v > 100 then Error "QualityScore must be between 0 and 100"
        else Ok (QualityScore v)
    let createUnsafe (v: int) = QualityScore v

[<Struct>]
type CoverageScore = private CoverageScore of int with
    member this.Value = let (CoverageScore v) = this in v

module CoverageScore =
    let value (CoverageScore v) = v
    let create (v: int) =
        if v < 0 || v > 100 then Error "CoverageScore must be between 0 and 100"
        else Ok (CoverageScore v)
    let createUnsafe (v: int) = CoverageScore v

[<Struct>]
type TemplateId = private TemplateId of int with
    member this.Value = let (TemplateId v) = this in v

module TemplateId =
    let value (TemplateId v) = v
    let create (v: int) =
        if v < 0 then Error "TemplateId must be non-negative"
        else Ok (TemplateId v)
    let createUnsafe (v: int) = TemplateId v

// ============================================================================
// Domain Errors
// ============================================================================

type DriverError =
    | UsbError of message: string * code: int
    | ProtocolError of message: string
    | ChecksumMismatch of expected: uint32 * actual: uint32
    | InvalidPacket of reason: string
    | TlsHandshakeFailed of reason: string
    | TlsDecryptionFailed of reason: string
    | DeviceNotReady of reason: string
    | FirmwareMismatch of expected: string * actual: string
    | ResetFailed of reason: string
    | Timeout of operation: string
    | ValidationError of field: string * reason: string
    | InternalError of exn: exn
with
    member this.Message =
        match this with
        | UsbError (msg, code) -> $"USB error (code {code}): {msg}"
        | ProtocolError msg -> $"Protocol error: {msg}"
        | ChecksumMismatch (expected, actual) -> $"Checksum mismatch: expected 0x{expected:X8}, actual 0x{actual:X8}"
        | InvalidPacket reason -> $"Invalid packet: {reason}"
        | TlsHandshakeFailed reason -> $"TLS handshake failed: {reason}"
        | TlsDecryptionFailed reason -> $"TLS decryption failed: {reason}"
        | DeviceNotReady reason -> $"Device not ready: {reason}"
        | FirmwareMismatch (expected, actual) -> $"Firmware mismatch: expected '{expected}', actual '{actual}'"
        | ResetFailed reason -> $"Reset failed: {reason}"
        | Timeout op -> $"Operation timed out: {op}"
        | ValidationError (field, reason) -> $"Validation error on {field}: {reason}"
        | InternalError ex -> $"Internal error: {ex.Message}"

    override this.ToString() = this.Message

// ============================================================================
// Sensor OTP (One-Time Programmable) Parameters
// ============================================================================

type SensorOtp = {
    Raw: byte[]
    DacH: byte
    DacL: byte
    FdtDac: byte[]
}

module SensorOtp =
    let parse (data: byte[]) : Result<SensorOtp, DriverError> =
        if isNull data || data.Length < 64 then
            Error (ValidationError ("SensorOtp", $"Expected at least 64 bytes of OTP, got {if isNull data then 0 else data.Length}"))
        else
            let rawCopy = Array.take 64 data
            let dacH = rawCopy.[26]
            let dacL = rawCopy.[45]
            let fdtDac = [| rawCopy.[33]; rawCopy.[41]; rawCopy.[42]; rawCopy.[43] |]
            Ok {
                Raw = rawCopy
                DacH = dacH
                DacL = dacL
                FdtDac = fdtDac
            }

// ============================================================================
// Frame and Image Data Types
// ============================================================================

type RawFrame12Bit = {
    Pixels: uint16[]
    Width: int
    Height: int
}

module RawFrame12Bit =
    let ExpectedPixelCount = 5120 // 80 * 64
    let DefaultWidth = 80
    let DefaultHeight = 64

    let create (pixels: uint16[]) : Result<RawFrame12Bit, DriverError> =
        if isNull pixels || pixels.Length <> ExpectedPixelCount then
            Error (ValidationError ("RawFrame12Bit", $"Expected {ExpectedPixelCount} pixels, got {if isNull pixels then 0 else pixels.Length}"))
        else
            Ok {
                Pixels = Array.copy pixels
                Width = DefaultWidth
                Height = DefaultHeight
            }

type PreprocessedFrame = {
    NormalizedPixels: byte[]
    BData: byte[]
    OutStruct: byte[]
    Quality: QualityScore
    Coverage: CoverageScore
}

module PreprocessedFrame =
    let PixelCount = 5120
    let BDataSize = 19600
    let OutStructSize = 28

    let createWithTrailer (pixels: byte[]) (bData: byte[]) (outStruct: byte[]) (quality: QualityScore) (coverage: CoverageScore) : Result<PreprocessedFrame, DriverError> =
        if isNull pixels || pixels.Length <> PixelCount then
            Error (ValidationError ("PreprocessedFrame.NormalizedPixels", $"Expected {PixelCount} bytes, got {if isNull pixels then 0 else pixels.Length}"))
        elif isNull bData || bData.Length <> BDataSize then
            Error (ValidationError ("PreprocessedFrame.BData", $"Expected {BDataSize} bytes, got {if isNull bData then 0 else bData.Length}"))
        else
            let trailer =
                if isNull outStruct || outStruct.Length < OutStructSize then
                    Array.zeroCreate<byte> OutStructSize
                else
                    Array.sub outStruct 0 OutStructSize
            Ok {
                NormalizedPixels = Array.copy pixels
                BData = Array.copy bData
                OutStruct = trailer
                Quality = quality
                Coverage = coverage
            }

    let create (pixels: byte[]) (bData: byte[]) (quality: QualityScore) (coverage: CoverageScore) : Result<PreprocessedFrame, DriverError> =
        createWithTrailer pixels bData (Array.zeroCreate<byte> OutStructSize) quality coverage

// ============================================================================
// Fingerprint Matcher Interface
// ============================================================================

type IFingerprintMatcher =
    abstract member ExtractTemplate: frame: PreprocessedFrame -> Result<byte[], DriverError>
    abstract member Match: enrolledTemplate: byte[] * candidate: PreprocessedFrame -> Result<float, DriverError>
    abstract member Verify: enrolledTemplate: byte[] * candidate: PreprocessedFrame * threshold: float -> Result<bool, DriverError>
