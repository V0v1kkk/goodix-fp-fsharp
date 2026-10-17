namespace GoodixFp.NativeMatcher

open System
open System.IO
open GoodixFp.Core

// ============================================================================
// Canonical [<Struct>] Single-Case DU Discipline (Vladimir's F# Style Guide)
// ============================================================================

[<Struct>]
type LibraryPath = private LibraryPath of string with
    member this.Value = let (LibraryPath v) = this in v

module LibraryPath =
    let value (LibraryPath v) = v
    let create (s: string) : Result<LibraryPath, DriverError> =
        if String.IsNullOrWhiteSpace s then
            Error (ValidationError ("LibraryPath", "LibraryPath must not be empty"))
        elif not (File.Exists s) then
            Error (ValidationError ("LibraryPath", $"Library file not found at '{s}'"))
        else
            Ok (LibraryPath s)
    let createUnsafe (s: string) = LibraryPath s

[<Struct>]
type FingerId = private FingerId of string with
    member this.Value = let (FingerId v) = this in v

module FingerId =
    let value (FingerId v) = v
    let create (s: string) : Result<FingerId, DriverError> =
        if String.IsNullOrWhiteSpace s then
            Error (ValidationError ("FingerId", "FingerId must not be empty"))
        else
            Ok (FingerId (s.Trim()))
    let ofInt (i: int) : Result<FingerId, DriverError> =
        create (string i)
    let createUnsafe (s: string) = FingerId s

[<Struct>]
type TemplateBlob = private TemplateBlob of byte[] with
    member this.Value = let (TemplateBlob v) = this in v
    member this.Length = (let (TemplateBlob v) = this in v).Length

module TemplateBlob =
    let ExpectedMagic = [| 0x54uy; 0x47uy; 0x4cuy; 0x41uy |] // "TGLA"
    let ExpectedSize = 65649

    let value (TemplateBlob v) = v

    let create (bytes: byte[]) : Result<TemplateBlob, DriverError> =
        if isNull bytes || bytes.Length < 4 then
            Error (ValidationError ("TemplateBlob", "Template blob must contain at least 4 bytes"))
        elif bytes.[0..3] <> ExpectedMagic then
            let actualHeader = System.Text.Encoding.ASCII.GetString(bytes, 0, Math.Min(4, bytes.Length))
            Error (ValidationError ("TemplateBlob", $"Magic header mismatch: expected 'TGLA', got '{actualHeader}'"))
        else
            Ok (TemplateBlob (Array.copy bytes))

    let createUnsafe (bytes: byte[]) = TemplateBlob bytes
