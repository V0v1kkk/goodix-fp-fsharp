namespace GoodixFp.Daemon

open System

// ============================================================================
// Single-Case Domain DUs
// ============================================================================

[<Struct>]
type Username = private Username of string with
    member this.Value = let (Username v) = this in v
    override this.ToString() = this.Value

module Username =
    let value (Username v) = v
    let create (s: string) : Result<Username, string> =
        if String.IsNullOrWhiteSpace s then
            Error "Username must not be empty"
        elif s.Contains('/') || s.Contains('\\') || s.Contains("..") || s.Contains(':') || s.Contains('\u0000') then
            Error $"Username '{s}' contains invalid characters"
        else
            Ok (Username (s.Trim()))
    let createUnsafe (s: string) = Username s

[<Struct>]
type FingerName = private FingerName of string with
    member this.Value = let (FingerName v) = this in v
    override this.ToString() = this.Value

module FingerName =
    let StandardNames = [
        "left-thumb"
        "left-index-finger"
        "left-middle-finger"
        "left-ring-finger"
        "left-little-finger"
        "right-thumb"
        "right-index-finger"
        "right-middle-finger"
        "right-ring-finger"
        "right-little-finger"
    ]

    let isValidStandardName (name: string) =
        List.contains name StandardNames

    let value (FingerName v) = v

    let normalize (s: string) : string =
        match s.Trim().ToLowerInvariant().Replace('_', '-') with
        | "right-index" | "right-index-finger" | "index-right" -> "right-index-finger"
        | "left-index" | "left-index-finger" | "index-left" -> "left-index-finger"
        | "right-thumb" | "thumb-right" -> "right-thumb"
        | "left-thumb" | "thumb-left" -> "left-thumb"
        | "right-middle" | "right-middle-finger" | "middle-right" -> "right-middle-finger"
        | "left-middle" | "left-middle-finger" | "middle-left" -> "left-middle-finger"
        | "right-ring" | "right-ring-finger" | "ring-right" -> "right-ring-finger"
        | "left-ring" | "left-ring-finger" | "ring-left" -> "left-ring-finger"
        | "right-little" | "right-little-finger" | "little-right" -> "right-little-finger"
        | "left-little" | "left-little-finger" | "little-left" -> "left-little-finger"
        | "any" -> "any"
        | other -> other

    let create (s: string) : Result<FingerName, string> =
        if String.IsNullOrWhiteSpace s then
            Error "Finger name must not be empty"
        else
            let normalized = normalize s
            if isValidStandardName normalized then
                Ok (FingerName normalized)
            else
                let validList = String.concat ", " StandardNames
                Error $"Invalid standard finger name '{s}'. Valid names are: {validList}"

    let createWithAny (s: string) : Result<FingerName, string> =
        if String.IsNullOrWhiteSpace s then
            Error "Finger name must not be empty"
        else
            let normalized = normalize s
            if normalized = "any" || isValidStandardName normalized then
                Ok (FingerName normalized)
            else
                let validList = String.concat ", " StandardNames
                Error $"Invalid finger name '{s}'. Valid names are 'any' or: {validList}"

    let createUnsafe (s: string) = FingerName s

    let toFileName (finger: FingerName) : string =
        let name = finger.Value
        let shortName =
            if name.EndsWith("-finger") then
                name.Substring(0, name.Length - "-finger".Length)
            else
                name
        $"{shortName}.tgla"

    let tryFromFileName (fileName: string) : FingerName option =
        let baseName =
            if fileName.EndsWith(".tgla", StringComparison.OrdinalIgnoreCase) then
                fileName.Substring(0, fileName.Length - 5)
            else
                fileName
        match create baseName with
        | Ok fn -> Some fn
        | Error _ -> None

[<Struct>]
type BusSender = private BusSender of string with
    member this.Value = let (BusSender v) = this in v
    override this.ToString() = this.Value

module BusSender =
    let value (BusSender v) = v
    let create (s: string) : Result<BusSender, string> =
        if String.IsNullOrWhiteSpace s then Error "BusSender must not be empty"
        else Ok (BusSender s)
    let createUnsafe (s: string) = BusSender s

[<Struct>]
type CallerUid = private CallerUid of uint32 with
    member this.Value = let (CallerUid v) = this in v
    member this.IsRoot = (let (CallerUid v) = this in v) = 0u
    override this.ToString() = string this.Value

module CallerUid =
    let value (CallerUid v) = v
    let create (uid: uint32) = Ok (CallerUid uid)
    let createUnsafe (uid: uint32) = CallerUid uid
    let root = CallerUid 0u

// ============================================================================
// D-Bus Protocol Constants
// ============================================================================

module FprintConstants =
    [<Literal>]
    let ServiceName = "net.reactivated.Fprint"

    [<Literal>]
    let ManagerPath = "/net/reactivated/Fprint/Manager"
    [<Literal>]
    let ManagerInterface = "net.reactivated.Fprint.Manager"

    [<Literal>]
    let DevicePath = "/net/reactivated/Fprint/Device/0"
    [<Literal>]
    let DeviceInterface = "net.reactivated.Fprint.Device"

    [<Literal>]
    let PropertiesInterface = "org.freedesktop.DBus.Properties"
    [<Literal>]
    let IntrospectableInterface = "org.freedesktop.DBus.Introspectable"

    module Errors =
        [<Literal>]
        let NoSuchDevice = "net.reactivated.Fprint.Error.NoSuchDevice"
        [<Literal>]
        let PermissionDenied = "net.reactivated.Fprint.Error.PermissionDenied"
        [<Literal>]
        let AlreadyInUse = "net.reactivated.Fprint.Error.AlreadyInUse"
        [<Literal>]
        let ClaimDevice = "net.reactivated.Fprint.Error.ClaimDevice"
        [<Literal>]
        let NoActionInProgress = "net.reactivated.Fprint.Error.NoActionInProgress"
        [<Literal>]
        let NoEnrolledPrints = "net.reactivated.Fprint.Error.NoEnrolledPrints"
        [<Literal>]
        let InvalidFingername = "net.reactivated.Fprint.Error.InvalidFingername"
        [<Literal>]
        let PrintsNotDeleted = "net.reactivated.Fprint.Error.PrintsNotDeleted"
        [<Literal>]
        let Internal = "net.reactivated.Fprint.Error.Internal"

    module Signals =
        [<Literal>]
        let VerifyFingerSelected = "VerifyFingerSelected"
        [<Literal>]
        let VerifyFingerMatched = "VerifyFingerMatched"
        [<Literal>]
        let VerifyStatus = "VerifyStatus"
        [<Literal>]
        let EnrollStatus = "EnrollStatus"

    module VerifyStatuses =
        [<Literal>]
        let Match = "verify-match"
        [<Literal>]
        let NoMatch = "verify-no-match"
        [<Literal>]
        let RetryScan = "verify-retry-scan"
        [<Literal>]
        let RemoveAndRetry = "verify-remove-and-retry"
        [<Literal>]
        let SwipeTooShort = "verify-swipe-too-short"
        [<Literal>]
        let FingerNotCentered = "verify-finger-not-centered"
        [<Literal>]
        let TooFast = "verify-too-fast"
        [<Literal>]
        let Disconnected = "verify-disconnected"
        [<Literal>]
        let UnknownError = "verify-unknown-error"

module IntrospectXml =
    let ManagerXml =
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n" +
        "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n" +
        "<node>\n" +
        "  <interface name=\"net.reactivated.Fprint.Manager\">\n" +
        "    <method name=\"GetDevices\">\n" +
        "      <arg name=\"devices\" type=\"ao\" direction=\"out\"/>\n" +
        "    </method>\n" +
        "    <method name=\"GetDefaultDevice\">\n" +
        "      <arg name=\"device\" type=\"o\" direction=\"out\"/>\n" +
        "    </method>\n" +
        "  </interface>\n" +
        "  <interface name=\"org.freedesktop.DBus.Introspectable\">\n" +
        "    <method name=\"Introspect\">\n" +
        "      <arg name=\"xml_data\" type=\"s\" direction=\"out\"/>\n" +
        "    </method>\n" +
        "  </interface>\n" +
        "</node>\n"

    let DeviceXml =
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n" +
        "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n" +
        "<node>\n" +
        "  <interface name=\"net.reactivated.Fprint.Device\">\n" +
        "    <method name=\"ListEnrolledFingers\">\n" +
        "      <arg name=\"username\" type=\"s\" direction=\"in\"/>\n" +
        "      <arg name=\"enrolled_fingers\" type=\"as\" direction=\"out\"/>\n" +
        "    </method>\n" +
        "    <method name=\"DeleteEnrolledFingers\">\n" +
        "      <arg name=\"username\" type=\"s\" direction=\"in\"/>\n" +
        "    </method>\n" +
        "    <method name=\"DeleteEnrolledFingers2\"/>\n" +
        "    <method name=\"DeleteEnrolledFinger\">\n" +
        "      <arg name=\"finger_name\" type=\"s\" direction=\"in\"/>\n" +
        "    </method>\n" +
        "    <method name=\"Claim\">\n" +
        "      <arg name=\"username\" type=\"s\" direction=\"in\"/>\n" +
        "    </method>\n" +
        "    <method name=\"Release\"/>\n" +
        "    <method name=\"VerifyStart\">\n" +
        "      <arg name=\"finger_name\" type=\"s\" direction=\"in\"/>\n" +
        "    </method>\n" +
        "    <method name=\"VerifyStop\"/>\n" +
        "    <method name=\"EnrollStart\">\n" +
        "      <arg name=\"finger_name\" type=\"s\" direction=\"in\"/>\n" +
        "    </method>\n" +
        "    <method name=\"EnrollStop\"/>\n" +
        "    <signal name=\"VerifyFingerSelected\">\n" +
        "      <arg name=\"finger_name\" type=\"s\"/>\n" +
        "    </signal>\n" +
        "    <signal name=\"VerifyFingerMatched\">\n" +
        "      <arg name=\"finger_name\" type=\"s\"/>\n" +
        "    </signal>\n" +
        "    <signal name=\"VerifyStatus\">\n" +
        "      <arg name=\"result\" type=\"s\"/>\n" +
        "      <arg name=\"done\" type=\"b\"/>\n" +
        "    </signal>\n" +
        "    <signal name=\"EnrollStatus\">\n" +
        "      <arg name=\"result\" type=\"s\"/>\n" +
        "      <arg name=\"done\" type=\"b\"/>\n" +
        "    </signal>\n" +
        "    <property name=\"name\" type=\"s\" access=\"read\"/>\n" +
        "    <property name=\"num-enroll-stages\" type=\"i\" access=\"read\"/>\n" +
        "    <property name=\"scan-type\" type=\"s\" access=\"read\"/>\n" +
        "    <property name=\"finger-present\" type=\"b\" access=\"read\"/>\n" +
        "    <property name=\"finger-needed\" type=\"b\" access=\"read\"/>\n" +
        "  </interface>\n" +
        "  <interface name=\"org.freedesktop.DBus.Properties\">\n" +
        "    <method name=\"Get\">\n" +
        "      <arg name=\"interface_name\" type=\"s\" direction=\"in\"/>\n" +
        "      <arg name=\"property_name\" type=\"s\" direction=\"in\"/>\n" +
        "      <arg name=\"value\" type=\"v\" direction=\"out\"/>\n" +
        "    </method>\n" +
        "    <method name=\"GetAll\">\n" +
        "      <arg name=\"interface_name\" type=\"s\" direction=\"in\"/>\n" +
        "      <arg name=\"properties\" type=\"a{sv}\" direction=\"out\"/>\n" +
        "    </method>\n" +
        "    <method name=\"Set\">\n" +
        "      <arg name=\"interface_name\" type=\"s\" direction=\"in\"/>\n" +
        "      <arg name=\"property_name\" type=\"s\" direction=\"in\"/>\n" +
        "      <arg name=\"value\" type=\"v\" direction=\"in\"/>\n" +
        "    </method>\n" +
        "    <signal name=\"PropertiesChanged\">\n" +
        "      <arg name=\"interface_name\" type=\"s\"/>\n" +
        "      <arg name=\"changed_properties\" type=\"a{sv}\"/>\n" +
        "      <arg name=\"invalidated_properties\" type=\"as\"/>\n" +
        "    </signal>\n" +
        "  </interface>\n" +
        "  <interface name=\"org.freedesktop.DBus.Introspectable\">\n" +
        "    <method name=\"Introspect\">\n" +
        "      <arg name=\"xml_data\" type=\"s\" direction=\"out\"/>\n" +
        "    </method>\n" +
        "  </interface>\n" +
        "</node>\n"
