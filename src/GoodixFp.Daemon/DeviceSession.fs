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
            let e0 = Environment.GetEnvironmentVariable("GOODIX_FPRINTD_MATCHER")
            if not (String.IsNullOrWhiteSpace e0) then e0
            else
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
            let timeoutMs =
                let envVal = Environment.GetEnvironmentVariable("GOODIX_FPRINTD_VERIFY_TIMEOUT_MS")
                match Int32.TryParse envVal with
                | true, v when v > 0 -> v
                | _ -> 30000

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
                    use dev = new Goodix53xdDevice(transport, tunnel)

                    let mutable sensorSlept = false
                    let sleepSensor () = task {
                        if not sensorSlept then
                            sensorSlept <- true
                            try
                                let! _ = dev.Sleep()
                                ()
                            with _ -> ()
                    }

                    try
                        let! actRes = dev.ActivateSession()
                        match actRes with
                        | Error err ->
                            eprintfn $"[!] Session activation failed: {err}"
                            onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
                        | Ok _ ->
                            match GoodixTodMatcher.Create(customPath = libPath.Value, ?baseline = dev.BaselineFrame) with
                            | Error err ->
                                eprintfn $"[!] Matcher creation failed: {err}"
                                do! sleepSensor ()
                                onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
                            | Ok matcher ->
                                use matchDisp = matcher
                                let mutable attempt = 1
                                let mutable finished = false

                                while not finished && not ct.IsCancellationRequested do
                                    onFingerNeededChanged true
                                    onFingerPresentChanged false

                                    let! downRes = dev.WaitForFingerDown(timeoutMs = timeoutMs, cancellationToken = ct)
                                    if ct.IsCancellationRequested then
                                        finished <- true
                                    else
                                        match downRes with
                                        | Error (Timeout "WaitForFingerDown cancelled") ->
                                            finished <- true
                                        | Error (Timeout _) ->
                                            eprintfn "[!] Verification timed out waiting for touch"
                                            do! sleepSensor ()
                                            onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
                                            finished <- true
                                        | Error (UsbError (msg, _)) ->
                                            eprintfn $"[!] USB error waiting for finger: {msg}"
                                            do! sleepSensor ()
                                            onStatus (FprintConstants.VerifyStatuses.Disconnected, true)
                                            finished <- true
                                        | Error err ->
                                            eprintfn $"[!] Driver error: {err}"
                                            do! sleepSensor ()
                                            onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
                                            finished <- true
                                        | Ok () ->
                                            onFingerPresentChanged true
                                            onFingerNeededChanged false

                                            let! capRes = dev.CaptureFrame()
                                            match capRes with
                                            | Error err ->
                                                eprintfn $"[!] Frame capture failed: {err}"
                                                do! sleepSensor ()
                                                onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
                                                finished <- true
                                            | Ok frame ->
                                                match matcher.IdentifyProbe(frame.Pixels, templates) with
                                                | Error err ->
                                                    eprintfn $"[!] Identification failed: {err}"
                                                    do! sleepSensor ()
                                                    onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
                                                    finished <- true
                                                | Ok (Some matchedFid) ->
                                                    onMatched matchedFid.Value
                                                    onStatus (FprintConstants.VerifyStatuses.Match, true)
                                                    do! sleepSensor ()
                                                    finished <- true
                                                | Ok None ->
                                                    if attempt < retries && not ct.IsCancellationRequested then
                                                        onStatus (FprintConstants.VerifyStatuses.RetryScan, false)
                                                        let! _ = dev.WaitForFingerUpRobust(timeoutMs = 10000, cancellationToken = ct)
                                                        onFingerPresentChanged false
                                                        attempt <- attempt + 1
                                                    else
                                                        onStatus (FprintConstants.VerifyStatuses.NoMatch, true)
                                                        do! sleepSensor ()
                                                        finished <- true
                    finally
                        ()

                    // Ensure sensor is asleep on any exit (e.g. cancellation) before USB transport disposes
                    do! sleepSensor ()
                    onFingerPresentChanged false
                    onFingerNeededChanged false
        }

// ============================================================================
// Device Session & State Machine
// ============================================================================

type private VerifyState =
    | VerifyIdle
    | VerifyRunning of sender: BusSender * cts: CancellationTokenSource * task: Task
    | VerifyCompleted of sender: BusSender * task: Task

type DeviceSession(runner: IDeviceRunner,
                   onSelectedSignal: string -> unit,
                   onMatchedSignal: string -> unit,
                   onStatusSignal: string * bool -> unit) =

    let syncLock = obj()
    let mutable claimedOwner: (BusSender * Username * DateTimeOffset) option = None
    let mutable verifyState: VerifyState = VerifyIdle

    let mutable fingerPresent = false
    let mutable fingerNeeded = false

    let launchVerificationWithinLock (sender: BusSender) (user: Username) (finger: FingerName) : Result<unit, string * string> =
        let templates = TemplateStore.loadUserTemplates user
        if List.isEmpty templates then
            Error (FprintConstants.Errors.NoEnrolledPrints, $"No enrolled prints found for user '{user.Value}'")
        else
            let cts = new CancellationTokenSource()
            let ct = cts.Token

            let t : Task = Task.Run(Func<Task>(fun () ->
                runner.RunVerificationAsync(
                    user,
                    finger,
                    templates,
                    onSelectedSignal,
                    onMatchedSignal,
                    onStatusSignal,
                    (fun fp -> lock syncLock (fun () -> fingerPresent <- fp)),
                    (fun fn -> lock syncLock (fun () -> fingerNeeded <- fn)),
                    ct
                ) :> Task
            ))

            // When background task completes, transition to VerifyCompleted to allow
            // clean VerifyStop without returning NoActionInProgress.
            t.ContinueWith(fun (completedT: Task) ->
                lock syncLock (fun () ->
                    match verifyState with
                    | VerifyRunning (s, c, runningT) when s.Value = sender.Value && obj.ReferenceEquals(runningT, completedT) ->
                        verifyState <- VerifyCompleted (s, completedT)
                        fingerPresent <- false
                        fingerNeeded <- false
                        c.Dispose()
                    | _ -> ()
                )
            ) |> ignore

            verifyState <- VerifyRunning (sender, cts, t)
            Ok ()

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
                verifyState <- VerifyIdle
                Ok ()
        )

    member this.Release(sender: BusSender) : Task<Result<unit, string * string>> = task {
        let actionToWait =
            lock syncLock (fun () ->
                match claimedOwner with
                | None ->
                    Error (FprintConstants.Errors.ClaimDevice, "Device is not claimed")
                | Some (ownerSender, _, _) when ownerSender.Value <> sender.Value ->
                    Error (FprintConstants.Errors.ClaimDevice, "Device is claimed by another client")
                | Some _ ->
                    let currentState = verifyState
                    verifyState <- VerifyIdle
                    claimedOwner <- None
                    fingerPresent <- false
                    fingerNeeded <- false
                    Ok currentState
            )

        match actionToWait with
        | Error err -> return Error err
        | Ok VerifyIdle -> return Ok ()
        | Ok (VerifyCompleted (_, t)) ->
            try do! t with _ -> ()
            return Ok ()
        | Ok (VerifyRunning (_, cts, t)) ->
            cts.Cancel()
            try do! t with _ -> ()
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
                match verifyState with
                | VerifyRunning _ ->
                    Error (FprintConstants.Errors.AlreadyInUse, "Verification is already in progress")
                | VerifyCompleted (_, prevTask) ->
                    // Previous verification completed (done=true was emitted).
                    // Await any pending background cleanup synchronously (non-blocking if already done)
                    try prevTask.GetAwaiter().GetResult() with _ -> ()
                    launchVerificationWithinLock sender user finger
                | VerifyIdle ->
                    launchVerificationWithinLock sender user finger
        )

    member this.VerifyStop(sender: BusSender) : Task<Result<unit, string * string>> = task {
        let actionToStop =
            lock syncLock (fun () ->
                match claimedOwner with
                | None ->
                    Error (FprintConstants.Errors.ClaimDevice, "Device is not claimed")
                | Some (ownerSender, _, _) when ownerSender.Value <> sender.Value ->
                    Error (FprintConstants.Errors.ClaimDevice, "Device is claimed by another client")
                | Some _ ->
                    match verifyState with
                    | VerifyIdle ->
                        Error (FprintConstants.Errors.NoActionInProgress, "No verification is currently in progress")
                    | VerifyCompleted (s, completedTask) ->
                        if s.Value <> sender.Value then
                            Error (FprintConstants.Errors.ClaimDevice, "Verification is owned by another client")
                        else
                            verifyState <- VerifyIdle
                            fingerPresent <- false
                            fingerNeeded <- false
                            Ok (None, completedTask)
                    | VerifyRunning (s, cts, runningTask) ->
                        if s.Value <> sender.Value then
                            Error (FprintConstants.Errors.ClaimDevice, "Verification is owned by another client")
                        else
                            verifyState <- VerifyIdle
                            fingerPresent <- false
                            fingerNeeded <- false
                            Ok (Some cts, runningTask)
            )

        match actionToStop with
        | Error err -> return Error err
        | Ok (None, t) ->
            try do! t with _ -> ()
            return Ok ()
        | Ok (Some cts, t) ->
            cts.Cancel()
            try do! t with _ -> ()
            cts.Dispose()
            return Ok ()
    }

    member this.OnNameOwnerChanged(name: string, oldOwner: string, newOwner: string) : Task<unit> = task {
        let shouldRelease =
            lock syncLock (fun () ->
                match claimedOwner with
                | Some (s, _, _) when (s.Value = oldOwner || s.Value = name) && String.IsNullOrEmpty newOwner ->
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
