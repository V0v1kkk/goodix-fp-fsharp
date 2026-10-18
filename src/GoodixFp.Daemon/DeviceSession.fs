namespace GoodixFp.Daemon

open System
open System.Threading
open System.Threading.Tasks
open GoodixFp.Core
open GoodixFp.NativeMatcher

// ============================================================================
// Device Runner Interface (Hardware vs Mock)
// ============================================================================

type IDeviceRunner =
    abstract member RunVerificationAsync:
        user: Username *
        finger: FingerName *
        templates: (FingerId * TemplateBlob) list *
        onSelected: (string -> unit) *
        onMatched: (string -> unit) *
        onStatus: (string * bool -> unit) *
        onFingerPresentChanged: (bool -> unit) *
        onFingerNeededChanged: (bool -> unit) *
        ct: CancellationToken -> Task<unit>

// ============================================================================
// Production Hardware Device Runner
// ============================================================================

type HardwareDeviceRunner(maxRetries: int) =

    let resolveMatcherLibPath () : Result<LibraryPath, string> =
        let envOverride =
            let e1 = Environment.GetEnvironmentVariable("GOODIX_TOD_LIB")
            if not (String.IsNullOrWhiteSpace e1) then e1
            else
                let e2 = Environment.GetEnvironmentVariable("GOODIX_BLOB_PATH")
                if not (String.IsNullOrWhiteSpace e2) then e2
                else Environment.GetEnvironmentVariable("GOODIX_LIB_PATH")

        let candidate =
            if not (String.IsNullOrWhiteSpace envOverride) then
                envOverride.Trim()
            else
                "/usr/lib/goodix-fp/libgoodix_tod_53xc.so"

        if not (IO.File.Exists candidate) then
            Error $"Goodix TOD matcher library not found at '{candidate}'. Never searching $HOME in daemon mode."
        else
            match LibraryPath.create candidate with
            | Ok lp -> Ok lp
            | Error err -> Error err.Message

    interface IDeviceRunner with
        member this.RunVerificationAsync
            (user: Username,
             finger: FingerName,
             templates: (FingerId * TemplateBlob) list,
             onSelected: string -> unit,
             onMatched: string -> unit,
             onStatus: string * bool -> unit,
             onFingerPresentChanged: bool -> unit,
             onFingerNeededChanged: bool -> unit,
             ct: CancellationToken) : Task<unit> = task {

            // Emit VerifyFingerSelected signal
            let selectedFinger =
                if finger.Value = "any" then
                    if templates.Length = 1 then
                        let (fid, _) = templates.[0]
                        fid.Value
                    else "any"
                else finger.Value
            onSelected selectedFinger

            let retries = max 1 maxRetries

            match resolveMatcherLibPath () with
            | Error err ->
                eprintfn $"[!] Matcher error: {err}"
                onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
            | Ok libPath ->
                let vid = UsbVid.createUnsafe 0x27c6us
                let pid = UsbPid.createUnsafe 0x538dus
                match LibUsbTransport.Open(vid, pid) with
                | Error err ->
                    eprintfn $"[!] Failed to open Goodix USB device: {err}"
                    onStatus (FprintConstants.VerifyStatuses.Disconnected, true)
                | Ok transport ->
                    use devDisp = transport
                    let tunnel : ITlsPskTunnel = new PureFSharpTlsPskTunnel() :> ITlsPskTunnel
                    use tunDisp = tunnel
                    let dev = new Goodix53xdDevice(transport, tunnel)

                    let! actRes = dev.ActivateSession()
                    match actRes with
                    | Error err ->
                        eprintfn $"[!] Session activation failed: {err}"
                        onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
                    | Ok _ ->
                        match GoodixTodMatcher.Create(customPath = libPath.Value, ?baseline = dev.BaselineFrame) with
                        | Error err ->
                            eprintfn $"[!] Matcher creation failed: {err}"
                            let! _ = dev.Sleep()
                            onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
                        | Ok matcher ->
                            use matchDisp = matcher
                            let mutable attempt = 1
                            let mutable finished = false

                            while not finished && not ct.IsCancellationRequested do
                                onFingerNeededChanged true
                                onFingerPresentChanged false

                                let! downRes = dev.WaitForFingerDown(timeoutMs = 15000, cancellationToken = ct)
                                if ct.IsCancellationRequested then
                                    finished <- true
                                else
                                    match downRes with
                                    | Error (Timeout "WaitForFingerDown cancelled") ->
                                        finished <- true
                                    | Error (Timeout _) ->
                                        eprintfn "[!] Verification timed out waiting for touch"
                                        let! _ = dev.Sleep()
                                        onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
                                        finished <- true
                                    | Error (UsbError (msg, _)) ->
                                        eprintfn $"[!] USB error waiting for finger: {msg}"
                                        let! _ = dev.Sleep()
                                        onStatus (FprintConstants.VerifyStatuses.Disconnected, true)
                                        finished <- true
                                    | Error err ->
                                        eprintfn $"[!] Driver error: {err}"
                                        let! _ = dev.Sleep()
                                        onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
                                        finished <- true
                                    | Ok () ->
                                        onFingerPresentChanged true
                                        onFingerNeededChanged false

                                        let! capRes = dev.CaptureFrame()
                                        match capRes with
                                        | Error err ->
                                            eprintfn $"[!] Frame capture failed: {err}"
                                            let! _ = dev.Sleep()
                                            onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
                                            finished <- true
                                        | Ok frame ->
                                            match matcher.IdentifyProbe(frame.Pixels, templates) with
                                            | Error err ->
                                                eprintfn $"[!] Identification failed: {err}"
                                                let! _ = dev.Sleep()
                                                onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
                                                finished <- true
                                            | Ok (Some matchedFid) ->
                                                onMatched matchedFid.Value
                                                onStatus (FprintConstants.VerifyStatuses.Match, true)
                                                let! _ = dev.Sleep()
                                                finished <- true
                                            | Ok None ->
                                                if attempt < retries && not ct.IsCancellationRequested then
                                                    onStatus (FprintConstants.VerifyStatuses.RetryScan, false)
                                                    let! _ = dev.WaitForFingerUpRobust(timeoutMs = 10000, cancellationToken = ct)
                                                    onFingerPresentChanged false
                                                    attempt <- attempt + 1
                                                else
                                                    onStatus (FprintConstants.VerifyStatuses.NoMatch, true)
                                                    let! _ = dev.Sleep()
                                                    finished <- true

                            onFingerPresentChanged false
                            onFingerNeededChanged false
        }

// ============================================================================
// Device Session & State Machine
// ============================================================================

type DeviceSession(runner: IDeviceRunner,
                   onSelectedSignal: string -> unit,
                   onMatchedSignal: string -> unit,
                   onStatusSignal: string * bool -> unit) =

    let syncLock = obj()
    let mutable claimedOwner: (BusSender * Username * DateTimeOffset) option = None
    let mutable activeVerify: (BusSender * CancellationTokenSource * Task) option = None

    let mutable fingerPresent = false
    let mutable fingerNeeded = false

    member this.IsClaimed =
        lock syncLock (fun () -> claimedOwner.IsSome)

    member this.ClaimedUser =
        lock syncLock (fun () -> claimedOwner |> Option.map (fun (_, u, _) -> u))

    member this.ClaimedSender =
        lock syncLock (fun () -> claimedOwner |> Option.map (fun (s, _, _) -> s))

    member this.FingerPresent =
        lock syncLock (fun () -> fingerPresent)

    member this.FingerNeeded =
        lock syncLock (fun () -> fingerNeeded)

    member this.Claim(sender: BusSender, user: Username) : Result<unit, string * string> =
        lock syncLock (fun () ->
            match claimedOwner with
            | Some (s, _, _) when s.Value = sender.Value ->
                Error (FprintConstants.Errors.AlreadyInUse, "Device is already claimed by this client")
            | Some _ ->
                Error (FprintConstants.Errors.AlreadyInUse, "Device is already claimed by another client")
            | None ->
                claimedOwner <- Some (sender, user, DateTimeOffset.UtcNow)
                Ok ()
        )

    member this.Release(sender: BusSender) : Task<Result<unit, string * string>> = task {
        let verifyToCancel =
            lock syncLock (fun () ->
                match claimedOwner with
                | None ->
                    Error (FprintConstants.Errors.ClaimDevice, "Device is not claimed")
                | Some (ownerSender, _, _) when ownerSender.Value <> sender.Value ->
                    Error (FprintConstants.Errors.ClaimDevice, "Device is claimed by another client")
                | Some _ ->
                    let cancelTarget = activeVerify
                    activeVerify <- None
                    claimedOwner <- None
                    fingerPresent <- false
                    fingerNeeded <- false
                    Ok cancelTarget
            )

        match verifyToCancel with
        | Error err -> return Error err
        | Ok None -> return Ok ()
        | Ok (Some (_, cts, t)) ->
            cts.Cancel()
            try
                do! t
            with _ -> ()
            cts.Dispose()
            return Ok ()
    }

    member this.VerifyStart(sender: BusSender, finger: FingerName) : Result<unit, string * string> =
        lock syncLock (fun () ->
            match claimedOwner with
            | None ->
                Error (FprintConstants.Errors.ClaimDevice, "Device is not claimed")
            | Some (ownerSender, _, _) when ownerSender.Value <> sender.Value ->
                Error (FprintConstants.Errors.ClaimDevice, "Device is claimed by another client")
            | Some (_, user, _) ->
                match activeVerify with
                | Some _ ->
                    Error (FprintConstants.Errors.AlreadyInUse, "Verification is already in progress")
                | None ->
                    let templates = TemplateStore.loadUserTemplates user
                    if List.isEmpty templates then
                        Error (FprintConstants.Errors.NoEnrolledPrints, $"No enrolled prints found for user '{user.Value}'")
                    else
                        let cts = new CancellationTokenSource()
                        let ct = cts.Token

                        let t = runner.RunVerificationAsync(
                            user,
                            finger,
                            templates,
                            onSelectedSignal,
                            onMatchedSignal,
                            onStatusSignal,
                            (fun fp -> lock syncLock (fun () -> fingerPresent <- fp)),
                            (fun fn -> lock syncLock (fun () -> fingerNeeded <- fn)),
                            ct
                        )

                        // Attach completion callback to clean up activeVerify
                        t.ContinueWith(fun (_: Task) ->
                            lock syncLock (fun () ->
                                match activeVerify with
                                | Some (s, c, _) when s.Value = sender.Value ->
                                    activeVerify <- None
                                    fingerPresent <- false
                                    fingerNeeded <- false
                                    c.Dispose()
                                | _ -> ()
                            )
                        ) |> ignore

                        activeVerify <- Some (sender, cts, t)
                        Ok ()
        )

    member this.VerifyStop(sender: BusSender) : Task<Result<unit, string * string>> = task {
        let verifyToCancel =
            lock syncLock (fun () ->
                match claimedOwner with
                | None ->
                    Error (FprintConstants.Errors.ClaimDevice, "Device is not claimed")
                | Some (ownerSender, _, _) when ownerSender.Value <> sender.Value ->
                    Error (FprintConstants.Errors.ClaimDevice, "Device is claimed by another client")
                | Some _ ->
                    match activeVerify with
                    | None ->
                        Error (FprintConstants.Errors.NoActionInProgress, "No verification is currently in progress")
                    | Some (verifySender, _, _) when verifySender.Value <> sender.Value ->
                        Error (FprintConstants.Errors.ClaimDevice, "Verification is owned by another client")
                    | Some (_, cts, t) ->
                        activeVerify <- None
                        fingerPresent <- false
                        fingerNeeded <- false
                        Ok (cts, t)
            )

        match verifyToCancel with
        | Error err -> return Error err
        | Ok (cts, t) ->
            cts.Cancel()
            try
                do! t
            with _ -> ()
            cts.Dispose()
            return Ok ()
    }

    member this.OnNameOwnerChanged(name: string, oldOwner: string, newOwner: string) : Task<unit> = task {
        let shouldRelease =
            lock syncLock (fun () ->
                match claimedOwner with
                | Some (s, _, _) when s.Value = oldOwner && String.IsNullOrEmpty newOwner ->
                    true
                | Some (s, _, _) when s.Value = name && String.IsNullOrEmpty newOwner ->
                    true
                | _ -> false
            )

        if shouldRelease then
            eprintfn $"[*] Claiming client {oldOwner} disconnected from bus. Releasing device."
            let! _ = this.Release(BusSender.createUnsafe oldOwner)
            ()
    }

    member this.GetProperty(propName: string) : Result<obj, string * string> =
        lock syncLock (fun () ->
            match propName with
            | "name" -> Ok (box "Goodix Fingerprint Reader (GoodixTod)")
            | "num-enroll-stages" ->
                let stages = if claimedOwner.IsSome then 12 else -1
                Ok (box stages)
            | "scan-type" -> Ok (box "press")
            | "finger-present" -> Ok (box fingerPresent)
            | "finger-needed" -> Ok (box fingerNeeded)
            | other ->
                Error ("org.freedesktop.DBus.Error.UnknownProperty", $"Unknown property '{other}'")
        )

    member this.GetAllProperties() : (string * obj) list =
        lock syncLock (fun () ->
            [
                ("name", box "Goodix Fingerprint Reader (GoodixTod)")
                ("num-enroll-stages", box (if claimedOwner.IsSome then 12 else -1))
                ("scan-type", box "press")
                ("finger-present", box fingerPresent)
                ("finger-needed", box fingerNeeded)
            ]
        )
