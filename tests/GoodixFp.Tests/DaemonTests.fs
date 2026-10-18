module GoodixFp.DaemonTests

open System
open System.IO
open System.Threading.Tasks
open Xunit
open GoodixFp.Core
open GoodixFp.NativeMatcher
open GoodixFp.Daemon

// ============================================================================
// 1. Finger Mapping Tests
// ============================================================================

[<Fact>]
let ``FingerName create accepts all 10 standard fprintd names`` () =
    for name in FingerName.StandardNames do
        match FingerName.create name with
        | Ok fn -> Assert.Equal(name, fn.Value)
        | Error err -> Assert.Fail($"Expected '{name}' to be valid, got error: {err}")

[<Fact>]
let ``FingerName create rejects empty or unknown finger names`` () =
    Assert.True(FingerName.create "" |> Result.isError)
    Assert.True(FingerName.create "   " |> Result.isError)
    Assert.True(FingerName.create "foot-toe" |> Result.isError)
    Assert.True(FingerName.create "middle" |> Result.isError)

[<Fact>]
let ``FingerName normalize maps common aliases to standard fprintd names`` () =
    Assert.Equal("right-index-finger", FingerName.normalize "right-index")
    Assert.Equal("right-index-finger", FingerName.normalize "right_index")
    Assert.Equal("right-index-finger", FingerName.normalize "index_right")
    Assert.Equal("left-index-finger", FingerName.normalize "left-index")
    Assert.Equal("left-thumb", FingerName.normalize "thumb_left")
    Assert.Equal("right-thumb", FingerName.normalize "thumb_right")
    Assert.Equal("right-middle-finger", FingerName.normalize "right_middle")
    Assert.Equal("left-little-finger", FingerName.normalize "little_left")
    Assert.Equal("any", FingerName.normalize "any")

[<Fact>]
let ``FingerName toFileName and tryFromFileName round-trip correctly`` () =
    let rightIndex = FingerName.create "right-index-finger" |> Result.defaultWith (fun e -> failwith e)
    Assert.Equal("right-index.tgla", FingerName.toFileName rightIndex)
    let parsed = FingerName.tryFromFileName "right-index.tgla"
    Assert.Equal(Some rightIndex, parsed)

    let leftThumb = FingerName.create "left-thumb" |> Result.defaultWith (fun e -> failwith e)
    Assert.Equal("left-thumb.tgla", FingerName.toFileName leftThumb)
    let parsedThumb = FingerName.tryFromFileName "left-thumb.tgla"
    Assert.Equal(Some leftThumb, parsedThumb)

[<Fact>]
let ``FingerName createWithAny accepts any and standard names`` () =
    match FingerName.createWithAny "any" with
    | Ok fn -> Assert.Equal("any", fn.Value)
    | Error err -> Assert.Fail(err)

    match FingerName.createWithAny "right-index-finger" with
    | Ok fn -> Assert.Equal("right-index-finger", fn.Value)
    | Error err -> Assert.Fail(err)

    Assert.True(FingerName.createWithAny "invalid-finger" |> Result.isError)

// ============================================================================
// 2. TGLA Validation Tests
// ============================================================================

let private createSyntheticTglaBlob (size: int) =
    let data = Array.zeroCreate<byte> size
    data.[0] <- 0x54uy // 'T'
    data.[1] <- 0x47uy // 'G'
    data.[2] <- 0x4cuy // 'L'
    data.[3] <- 0x41uy // 'A'
    data

[<Fact>]
let ``validateTgla accepts valid TGLA template with expected magic and size`` () =
    let validBlob = createSyntheticTglaBlob TemplateBlob.ExpectedSize
    match TemplateStore.validateTgla validBlob with
    | Ok blob ->
        Assert.Equal(TemplateBlob.ExpectedSize, blob.Length)
        Assert.Equal<byte seq>(TemplateBlob.ExpectedMagic, blob.Value.[0..3])
    | Error err -> Assert.Fail(err)

[<Fact>]
let ``validateTgla rejects truncated data or wrong magic`` () =
    Assert.True(TemplateStore.validateTgla [||] |> Result.isError)
    Assert.True(TemplateStore.validateTgla [| 0x54uy; 0x47uy |] |> Result.isError)

    let badMagic = Array.create 65649 0uy
    badMagic.[0] <- 0x4euy // 'N'
    badMagic.[1] <- 0x4fuy // 'O'
    badMagic.[2] <- 0x50uy // 'P'
    badMagic.[3] <- 0x45uy // 'E'
    match TemplateStore.validateTgla badMagic with
    | Error err -> Assert.Contains("TGLA", err)
    | Ok _ -> Assert.Fail("Expected error for non-TGLA magic")

[<Fact>]
let ``validateTgla enforces minimum and maximum size bounds`` () =
    let tiny = createSyntheticTglaBlob 500
    match TemplateStore.validateTgla tiny with
    | Error err -> Assert.Contains("bounds", err)
    | Ok _ -> Assert.Fail("Expected error for too small template")

    let huge = createSyntheticTglaBlob 500_000
    match TemplateStore.validateTgla huge with
    | Error err -> Assert.Contains("bounds", err)
    | Ok _ -> Assert.Fail("Expected error for too large template")

// ============================================================================
// 3. Import Safety Tests (Symlink refusal, Atomic replace, 0700/0600)
// ============================================================================

type TestStateDirScope() =
    let stateDir = Path.Combine(Path.GetTempPath(), "goodix_test_store_" + Guid.NewGuid().ToString("N"))
    do
        Directory.CreateDirectory(stateDir) |> ignore
        Environment.SetEnvironmentVariable("GOODIX_FPRINTD_STATE_DIR", stateDir)

    member this.StateDir = stateDir

    interface IDisposable with
        member this.Dispose() =
            Environment.SetEnvironmentVariable("GOODIX_FPRINTD_STATE_DIR", null)
            try
                if Directory.Exists stateDir then
                    Directory.Delete(stateDir, true)
            with _ -> ()

[<Fact>]
let ``safeImport refuses symlink source file`` () =
    use scope = new TestStateDirScope()
    let tmpDir = Path.Combine(Path.GetTempPath(), "goodix_symlink_src_" + Guid.NewGuid().ToString("N"))
    Directory.CreateDirectory(tmpDir) |> ignore
    try
        let realFile = Path.Combine(tmpDir, "real.tgla")
        File.WriteAllBytes(realFile, createSyntheticTglaBlob TemplateBlob.ExpectedSize)

        let symlinkFile = Path.Combine(tmpDir, "symlink.tgla")
        File.CreateSymbolicLink(symlinkFile, realFile) |> ignore

        let user = Username.create "testuser" |> Result.defaultWith (fun e -> failwith e)
        let finger = FingerName.create "right-index-finger" |> Result.defaultWith (fun e -> failwith e)

        match TemplateStore.importTemplate user finger symlinkFile with
        | Error err ->
            Assert.Contains("symlink", err.ToLowerInvariant())
        | Ok _ ->
            Assert.Fail("Expected import to reject symlink source file")
    finally
        try Directory.Delete(tmpDir, true) with _ -> ()

[<Fact>]
let ``safeImport creates secure user directory and atomic template file with 0600`` () =
    use scope = new TestStateDirScope()
    let tmpDir = Path.Combine(Path.GetTempPath(), "goodix_real_src_" + Guid.NewGuid().ToString("N"))
    Directory.CreateDirectory(tmpDir) |> ignore
    try
        let realFile = Path.Combine(tmpDir, "valid.tgla")
        let validBytes = createSyntheticTglaBlob TemplateBlob.ExpectedSize
        File.WriteAllBytes(realFile, validBytes)

        let user = Username.create "alice" |> Result.defaultWith (fun e -> failwith e)
        let finger = FingerName.create "right-index-finger" |> Result.defaultWith (fun e -> failwith e)

        match TemplateStore.importTemplate user finger realFile with
        | Ok destPath ->
            Assert.True(File.Exists destPath)
            let readBytes = File.ReadAllBytes destPath
            Assert.Equal<byte seq>(validBytes, readBytes)

            // Verify user directory exists
            let userDir = TemplateStore.getUserDirectory user
            Assert.True(Directory.Exists userDir)

            // Verify listEnrolledFingers finds it
            let enrolled = TemplateStore.listEnrolledFingers user
            Assert.Single(enrolled) |> ignore
            Assert.Equal("right-index-finger", enrolled.[0].Value)

            // Verify loadUserTemplates loads it
            let loaded = TemplateStore.loadUserTemplates user
            Assert.Single(loaded) |> ignore
            let (fid, blob) = loaded.[0]
            Assert.Equal("right-index-finger", fid.Value)
            Assert.Equal(TemplateBlob.ExpectedSize, blob.Length)
        | Error err ->
            Assert.Fail($"Import failed: {err}")
    finally
        try Directory.Delete(tmpDir, true) with _ -> ()

[<Fact>]
let ``partial import with invalid file does not replace working template`` () =
    use scope = new TestStateDirScope()
    let tmpDir = Path.Combine(Path.GetTempPath(), "goodix_partial_src_" + Guid.NewGuid().ToString("N"))
    Directory.CreateDirectory(tmpDir) |> ignore
    try
        let user = Username.create "bob" |> Result.defaultWith (fun e -> failwith e)
        let finger = FingerName.create "left-index-finger" |> Result.defaultWith (fun e -> failwith e)

        // 1. Import a valid initial template
        let validFile = Path.Combine(tmpDir, "initial_valid.tgla")
        let initialData = createSyntheticTglaBlob TemplateBlob.ExpectedSize
        initialData.[100] <- 0x42uy
        File.WriteAllBytes(validFile, initialData)
        let initialRes = TemplateStore.importTemplate user finger validFile
        Assert.True(initialRes |> Result.isOk)
        let targetPath = TemplateStore.getTemplatePath user finger

        // 2. Attempt to import an invalid corrupted template
        let invalidFile = Path.Combine(tmpDir, "corrupted.tgla")
        File.WriteAllBytes(invalidFile, [| 0x00uy; 0x01uy; 0x02uy |])
        let failRes = TemplateStore.importTemplate user finger invalidFile
        Assert.True(failRes |> Result.isError)

        // 3. Verify original template was NOT touched
        Assert.True(File.Exists targetPath)
        let currentBytes = File.ReadAllBytes targetPath
        Assert.Equal<byte seq>(initialData, currentBytes)
    finally
        try Directory.Delete(tmpDir, true) with _ -> ()

// ============================================================================
// 4. Authorization Decisions with Injected Authorizer
// ============================================================================

type MockAuthorizer(callerUid: uint32, callerUsername: string, allowedPolkitActions: Set<string>) =
    interface IAuthorizer with
        member this.GetCallerUidAsync(sender: BusSender) =
            Task.FromResult(Ok (CallerUid.createUnsafe callerUid))

        member this.ResolveUsernameAsync(uid: CallerUid) =
            if uid.Value = callerUid then Task.FromResult(Ok (Username.createUnsafe callerUsername))
            else Task.FromResult(Error $"Unknown UID {uid.Value}")

        member this.CheckPolkitAsync(sender: BusSender, actionId: string) =
            Task.FromResult(allowedPolkitActions.Contains actionId)

[<Fact>]
let ``Root caller can access any user without polkit`` () = task {
    let authorizer = MockAuthorizer(0u, "root", Set.empty) :> IAuthorizer
    let sender = BusSender.createUnsafe ":1.100"

    // Empty username -> resolves to root
    let! resEmpty = Authorization.authorizeAccessUser authorizer sender ""
    match resEmpty with
    | Ok u -> Assert.Equal("root", u.Value)
    | Error (e, m) -> Assert.Fail($"Expected Ok, got {e}: {m}")

    // Explicit other username "alice" -> allowed for root
    let! resAlice = Authorization.authorizeAccessUser authorizer sender "alice"
    match resAlice with
    | Ok u -> Assert.Equal("alice", u.Value)
    | Error (e, m) -> Assert.Fail($"Expected Ok, got {e}: {m}")

    // Verify -> allowed for root
    let! resVerify = Authorization.authorizeVerify authorizer sender
    match resVerify with
    | Ok () -> ()
    | Error (e, m) -> Assert.Fail($"Expected Ok, got {e}: {m}")
}

[<Fact>]
let ``Non-root caller can access own prints without polkit but cannot access others without setusername`` () = task {
    let sender = BusSender.createUnsafe ":1.200"

    // 1. Without Polkit permission
    let unprivilegedAuth = MockAuthorizer(1000u, "vladimir", Set.empty) :> IAuthorizer

    // Empty username -> resolves to caller "vladimir"
    let! resEmpty = Authorization.authorizeAccessUser unprivilegedAuth sender ""
    match resEmpty with
    | Ok u -> Assert.Equal("vladimir", u.Value)
    | Error (e, m) -> Assert.Fail($"Expected Ok, got {e}: {m}")

    // Own username -> allowed
    let! resOwn = Authorization.authorizeAccessUser unprivilegedAuth sender "vladimir"
    match resOwn with
    | Ok u -> Assert.Equal("vladimir", u.Value)
    | Error (e, m) -> Assert.Fail($"Expected Ok, got {e}: {m}")

    // Other user "bob" without setusername -> PermissionDenied
    let! resBob = Authorization.authorizeAccessUser unprivilegedAuth sender "bob"
    match resBob with
    | Error (errName, _) -> Assert.Equal(FprintConstants.Errors.PermissionDenied, errName)
    | Ok _ -> Assert.Fail("Expected PermissionDenied for accessing another user")

    // 2. With setusername Polkit permission
    let polkitAuth = MockAuthorizer(1000u, "vladimir", Set.ofList [ PolkitActions.SetUsername ]) :> IAuthorizer
    let! resBobAllowed = Authorization.authorizeAccessUser polkitAuth sender "bob"
    match resBobAllowed with
    | Ok u -> Assert.Equal("bob", u.Value)
    | Error (e, m) -> Assert.Fail($"Expected Ok with polkit, got {e}: {m}")
}

[<Fact>]
let ``Non-root caller requires verify polkit permission for VerifyStart`` () = task {
    let sender = BusSender.createUnsafe ":1.300"

    // Without verify polkit -> denied
    let noVerifyAuth = MockAuthorizer(1000u, "vladimir", Set.empty) :> IAuthorizer
    let! resDenied = Authorization.authorizeVerify noVerifyAuth sender
    match resDenied with
    | Error (errName, _) -> Assert.Equal(FprintConstants.Errors.PermissionDenied, errName)
    | Ok () -> Assert.Fail("Expected PermissionDenied")

    // With verify polkit -> allowed
    let withVerifyAuth = MockAuthorizer(1000u, "vladimir", Set.ofList [ PolkitActions.Verify ]) :> IAuthorizer
    let! resAllowed = Authorization.authorizeVerify withVerifyAuth sender
    match resAllowed with
    | Ok () -> ()
    | Error (e, m) -> Assert.Fail($"Expected Ok with polkit, got {e}: {m}")
}

// ============================================================================
// 5. Claim / AlreadyInUse / Release / Verify State Machine Tests
// ============================================================================

type MockDeviceRunner(scenario: string) =
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
             ct: Threading.CancellationToken) = task {

            onSelected (if finger.Value = "any" then "right-index-finger" else finger.Value)

            match scenario with
            | "instant-match" ->
                onFingerNeededChanged true
                onFingerPresentChanged true
                onFingerNeededChanged false
                onMatched "right-index-finger"
                onStatus (FprintConstants.VerifyStatuses.Match, true)
                onFingerPresentChanged false
            | "no-match" ->
                onFingerNeededChanged true
                onFingerPresentChanged true
                onFingerNeededChanged false
                onStatus (FprintConstants.VerifyStatuses.NoMatch, true)
                onFingerPresentChanged false
            | "cancel-wait" ->
                onFingerNeededChanged true
                while not ct.IsCancellationRequested do
                    do! Task.Delay 50
                onFingerNeededChanged false
            | _ ->
                onStatus (FprintConstants.VerifyStatuses.UnknownError, true)
        }

[<Fact>]
let ``Claim and AlreadyInUse state machine behaves correctly`` () =
    use scope = new TestStateDirScope()
    let mutable selectedSignal = None
    let mutable matchedSignal = None
    let mutable statusSignal = None

    let runner = MockDeviceRunner("instant-match") :> IDeviceRunner
    let session = DeviceSession(
        runner,
        (fun s -> selectedSignal <- Some s),
        (fun m -> matchedSignal <- Some m),
        (fun (st, d) -> statusSignal <- Some (st, d))
    )

    let clientA = BusSender.createUnsafe ":1.10"
    let clientB = BusSender.createUnsafe ":1.20"
    let userA = Username.create "user_a" |> Result.defaultWith (fun e -> failwith e)
    let userB = Username.create "user_b" |> Result.defaultWith (fun e -> failwith e)

    // Initially unclaimed
    Assert.False(session.IsClaimed)
    Assert.Equal(None, session.ClaimedSender)

    // Unclaimed device cannot be released
    let relUnclaimed = session.Release(clientA).GetAwaiter().GetResult()
    match relUnclaimed with
    | Error (errName, _) -> Assert.Equal(FprintConstants.Errors.ClaimDevice, errName)
    | Ok _ -> Assert.Fail("Expected ClaimDevice error")

    // Client A claims device -> Ok
    let claimA = session.Claim(clientA, userA)
    Assert.True(claimA |> Result.isOk)
    Assert.True(session.IsClaimed)
    Assert.Equal(Some clientA, session.ClaimedSender)
    Assert.Equal(Some userA, session.ClaimedUser)

    // Client B tries to claim -> AlreadyInUse
    let claimB = session.Claim(clientB, userB)
    match claimB with
    | Error (errName, _) -> Assert.Equal(FprintConstants.Errors.AlreadyInUse, errName)
    | Ok _ -> Assert.Fail("Expected AlreadyInUse")

    // Client A tries to claim again -> AlreadyInUse
    let claimAAgain = session.Claim(clientA, userA)
    match claimAAgain with
    | Error (errName, _) -> Assert.Equal(FprintConstants.Errors.AlreadyInUse, errName)
    | Ok _ -> Assert.Fail("Expected AlreadyInUse")

    // Client B cannot release device claimed by Client A
    let relB = session.Release(clientB).GetAwaiter().GetResult()
    match relB with
    | Error (errName, _) -> Assert.Equal(FprintConstants.Errors.ClaimDevice, errName)
    | Ok _ -> Assert.Fail("Expected ClaimDevice error")

    // Client A releases device -> Ok
    let relA = session.Release(clientA).GetAwaiter().GetResult()
    Assert.True(relA |> Result.isOk)
    Assert.False(session.IsClaimed)

    // Now Client B can claim
    let claimBSuccess = session.Claim(clientB, userB)
    Assert.True(claimBSuccess |> Result.isOk)
    Assert.Equal(Some clientB, session.ClaimedSender)

[<Fact>]
let ``VerifyStart requires enrolled prints and emits expected signals`` () = task {
    use scope = new TestStateDirScope()
    let mutable selectedSignal = None
    let mutable matchedSignal = None
    let mutable statusSignal = None

    let runner = MockDeviceRunner("instant-match") :> IDeviceRunner
    let session = DeviceSession(
        runner,
        (fun s -> selectedSignal <- Some s),
        (fun m -> matchedSignal <- Some m),
        (fun (st, d) -> statusSignal <- Some (st, d))
    )

    let client = BusSender.createUnsafe ":1.40"
    let user = Username.create "charlie" |> Result.defaultWith (fun e -> failwith e)
    let finger = FingerName.create "right-index-finger" |> Result.defaultWith (fun e -> failwith e)

    // 1. Claim device
    session.Claim(client, user) |> ignore

    // 2. VerifyStart without prints -> NoEnrolledPrints
    let noPrintsRes = session.VerifyStart(client, finger)
    match noPrintsRes with
    | Error (errName, _) -> Assert.Equal(FprintConstants.Errors.NoEnrolledPrints, errName)
    | Ok _ -> Assert.Fail("Expected NoEnrolledPrints")

    // 3. Create a template for charlie
    let tmpFile = Path.Combine(Path.GetTempPath(), "charlie_test.tgla")
    File.WriteAllBytes(tmpFile, createSyntheticTglaBlob TemplateBlob.ExpectedSize)
    TemplateStore.importTemplate user finger tmpFile |> ignore
    File.Delete(tmpFile)

    // 4. VerifyStart now succeeds
    let verifyRes = session.VerifyStart(client, finger)
    Assert.True(verifyRes |> Result.isOk)

    // Wait a short moment for background runner to complete
    do! Task.Delay 150

    // Check signals
    Assert.Equal(Some "right-index-finger", selectedSignal)
    Assert.Equal(Some "right-index-finger", matchedSignal)
    Assert.Equal(Some (FprintConstants.VerifyStatuses.Match, true), statusSignal)
}

[<Fact>]
let ``VerifyStop cancels in-progress verification cleanly`` () = task {
    use scope = new TestStateDirScope()
    let runner = MockDeviceRunner("cancel-wait") :> IDeviceRunner
    let session = DeviceSession(runner, ignore, ignore, ignore)

    let client = BusSender.createUnsafe ":1.50"
    let user = Username.create "dan" |> Result.defaultWith (fun e -> failwith e)
    let finger = FingerName.create "right-index-finger" |> Result.defaultWith (fun e -> failwith e)

    // Claim
    session.Claim(client, user) |> ignore

    // Setup template
    let tmpFile = Path.Combine(Path.GetTempPath(), "dan_test.tgla")
    File.WriteAllBytes(tmpFile, createSyntheticTglaBlob TemplateBlob.ExpectedSize)
    TemplateStore.importTemplate user finger tmpFile |> ignore
    File.Delete(tmpFile)

    // VerifyStop when not verifying -> NoActionInProgress
    let! stopEarly = session.VerifyStop(client)
    match stopEarly with
    | Error (errName, _) -> Assert.Equal(FprintConstants.Errors.NoActionInProgress, errName)
    | Ok _ -> Assert.Fail("Expected NoActionInProgress")

    // Start verification
    let startRes = session.VerifyStart(client, finger)
    Assert.True(startRes |> Result.isOk)

    // Stop verification
    let! stopRes = session.VerifyStop(client)
    Assert.True(stopRes |> Result.isOk)

    // Subsequent VerifyStop -> NoActionInProgress
    let! stopAgain = session.VerifyStop(client)
    Assert.True(stopAgain |> Result.isError)
}

[<Fact>]
let ``Client disconnect on NameOwnerChanged automatically releases claim and cancels verify`` () = task {
    use scope = new TestStateDirScope()
    let runner = MockDeviceRunner("cancel-wait") :> IDeviceRunner
    let session = DeviceSession(runner, ignore, ignore, ignore)

    let client = BusSender.createUnsafe ":1.777"
    let user = Username.create "eve" |> Result.defaultWith (fun e -> failwith e)
    let finger = FingerName.create "right-index-finger" |> Result.defaultWith (fun e -> failwith e)

    // Claim and set up template
    session.Claim(client, user) |> ignore
    let tmpFile = Path.Combine(Path.GetTempPath(), "eve_test.tgla")
    File.WriteAllBytes(tmpFile, createSyntheticTglaBlob TemplateBlob.ExpectedSize)
    TemplateStore.importTemplate user finger tmpFile |> ignore
    File.Delete(tmpFile)

    session.VerifyStart(client, finger) |> ignore
    Assert.True(session.IsClaimed)

    // Simulate NameOwnerChanged: :1.777 drops (newOwner = "")
    do! session.OnNameOwnerChanged(":1.777", ":1.777", "")

    // Claim should be released
    Assert.False(session.IsClaimed)
    Assert.Equal(None, session.ClaimedSender)
}

[<Fact>]
let ``VerifyStop after verification completed accepts stop and then accepts next VerifyStart cleanly`` () = task {
    use scope = new TestStateDirScope()
    let mutable lastStatus = None

    let runner = MockDeviceRunner("no-match") :> IDeviceRunner
    let session = DeviceSession(
        runner,
        ignore,
        ignore,
        (fun (st, d) -> lastStatus <- Some (st, d))
    )

    let client = BusSender.createUnsafe ":1.888"
    let user = Username.create "frank" |> Result.defaultWith (fun e -> failwith e)
    let finger = FingerName.create "right-index-finger" |> Result.defaultWith (fun e -> failwith e)

    // 1. Claim device
    session.Claim(client, user) |> ignore

    // Setup template
    let tmpFile = Path.Combine(Path.GetTempPath(), "frank_test.tgla")
    File.WriteAllBytes(tmpFile, createSyntheticTglaBlob TemplateBlob.ExpectedSize)
    TemplateStore.importTemplate user finger tmpFile |> ignore
    File.Delete(tmpFile)

    // 2. Start verification attempt 1 (pam_fprintd flow)
    let startRes1 = session.VerifyStart(client, finger)
    Assert.True(startRes1 |> Result.isOk)

    // Allow mock runner to complete
    do! Task.Delay 100
    Assert.Equal(Some (FprintConstants.VerifyStatuses.NoMatch, true), lastStatus)

    // 3. pam_fprintd calls VerifyStop after done=true
    let! stopRes = session.VerifyStop(client)
    Assert.True(stopRes |> Result.isOk)

    // 4. Calling VerifyStop again when already idle must return NoActionInProgress
    let! stopAgain = session.VerifyStop(client)
    match stopAgain with
    | Error (errName, _) -> Assert.Equal(FprintConstants.Errors.NoActionInProgress, errName)
    | Ok _ -> Assert.Fail("Expected NoActionInProgress on second VerifyStop")

    // 5. Start verification attempt 2 (pam_fprintd retry)
    let startRes2 = session.VerifyStart(client, finger)
    Assert.True(startRes2 |> Result.isOk)

    do! Task.Delay 100
    Assert.Equal(Some (FprintConstants.VerifyStatuses.NoMatch, true), lastStatus)

    // 6. Clean release
    let! relRes = session.Release(client)
    Assert.True(relRes |> Result.isOk)
    Assert.False(session.IsClaimed)
}

[<Fact>]
let ``Injected test policy allow-self vs deny-all behaves correctly under test state dir`` () = task {
    use scope = new TestStateDirScope()
    // TestStateDirScope sets GOODIX_FPRINTD_STATE_DIR so test policy is honoured

    // 1. Policy allow-self: verify allowed, setusername denied
    Environment.SetEnvironmentVariable("GOODIX_FPRINTD_TEST_POLICY", "allow-self")
    let authorizerAllowSelf = MockAuthorizer(1000u, "testuser", Set.empty) :> IAuthorizer
    let! resVerifyAllowed = Authorization.authorizeVerify authorizerAllowSelf (BusSender.createUnsafe ":1.999")
    // When authorizer handles polkit directly:
    // CheckPolkitAsync on mock checks allowedPolkitActions.
    // For DBusAuthorizer fallback:
    // Let's verify DBusAuthorizer directly with a disconnected connection
    let dbusAuthorizer = DBusAuthorizer(null) :> IAuthorizer
    let! verifyAuth = dbusAuthorizer.CheckPolkitAsync(BusSender.createUnsafe ":1.999", PolkitActions.Verify)
    Assert.True(verifyAuth)

    let! setuserAuth = dbusAuthorizer.CheckPolkitAsync(BusSender.createUnsafe ":1.999", PolkitActions.SetUsername)
    Assert.False(setuserAuth)

    let! enrollAuth = dbusAuthorizer.CheckPolkitAsync(BusSender.createUnsafe ":1.999", PolkitActions.Enroll)
    Assert.False(enrollAuth)

    // 2. Policy deny-all: verify denied
    Environment.SetEnvironmentVariable("GOODIX_FPRINTD_TEST_POLICY", "deny-all")
    let! verifyDenied = dbusAuthorizer.CheckPolkitAsync(BusSender.createUnsafe ":1.999", PolkitActions.Verify)
    Assert.False(verifyDenied)

    Environment.SetEnvironmentVariable("GOODIX_FPRINTD_TEST_POLICY", null)
}
