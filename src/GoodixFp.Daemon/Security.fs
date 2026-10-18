namespace GoodixFp.Daemon

open System
open System.IO
open System.Runtime.InteropServices
open System.Threading.Tasks
open Tmds.DBus.Protocol

// ============================================================================
// Native Libc User Resolution
// ============================================================================

module NativeLibc =
    [<Struct; StructLayout(LayoutKind.Sequential)>]
    type private Passwd =
        val pw_name: nativeint
        val pw_passwd: nativeint
        val pw_uid: uint32
        val pw_gid: uint32
        val pw_gecos: nativeint
        val pw_dir: nativeint
        val pw_shell: nativeint

    [<DllImport("libc", EntryPoint = "getpwuid", SetLastError = true)>]
    extern nativeint getpwuid(uint32 uid)

    [<DllImport("libc", EntryPoint = "geteuid")>]
    extern uint32 geteuid()

    let getUsernameFromPasswdFile (uid: uint32) : string option =
        try
            if File.Exists "/etc/passwd" then
                File.ReadLines "/etc/passwd"
                |> Seq.tryPick (fun line ->
                    let parts = line.Split([| ':' |])
                    if parts.Length >= 3 && parts.[2] = string uid then
                        let name = parts.[0].Trim()
                        if not (String.IsNullOrWhiteSpace name) then Some name else None
                    else None)
            else None
        with _ -> None

    let getUsername (uid: uint32) : string option =
        try
            let ptr = getpwuid uid
            if ptr <> 0n then
                let pw = Marshal.PtrToStructure<Passwd>(ptr)
                if pw.pw_name <> 0n then
                    let name = Marshal.PtrToStringAnsi pw.pw_name
                    if not (String.IsNullOrWhiteSpace name) then Some name
                    else getUsernameFromPasswdFile uid
                else getUsernameFromPasswdFile uid
            else
                getUsernameFromPasswdFile uid
        with _ ->
            getUsernameFromPasswdFile uid

// ============================================================================
// Polkit Actions & Authorizer Interface
// ============================================================================

module PolkitActions =
    [<Literal>]
    let Verify = "net.reactivated.fprint.device.verify"
    [<Literal>]
    let Enroll = "net.reactivated.fprint.device.enroll"
    [<Literal>]
    let SetUsername = "net.reactivated.fprint.device.setusername"

type IAuthorizer =
    abstract member GetCallerUidAsync: sender: BusSender -> Task<Result<CallerUid, string>>
    abstract member ResolveUsernameAsync: uid: CallerUid -> Task<Result<Username, string>>
    abstract member CheckPolkitAsync: sender: BusSender * actionId: string -> Task<bool>

// ============================================================================
// Production D-Bus Authorizer
// ============================================================================

type DBusAuthorizer(connection: DBusConnection) =
    let getTestPolicy () =
        let isTestOverride =
            not (String.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("GOODIX_FPRINTD_STATE_DIR")))
        if isTestOverride then
            let p = Environment.GetEnvironmentVariable("GOODIX_FPRINTD_TEST_POLICY")
            if String.IsNullOrWhiteSpace p then None
            else Some (p.Trim().ToLowerInvariant())
        else
            None

    let checkNameHasOwner (name: string) : Task<bool> = task {
        if obj.ReferenceEquals(connection, null) then return false
        else
            try
                let mutable writer = connection.GetMessageWriter()
                writer.WriteMethodCallHeader(
                    destination = "org.freedesktop.DBus",
                    path = "/org/freedesktop/DBus",
                    ``interface`` = "org.freedesktop.DBus",
                    ``member`` = "NameHasOwner",
                    signature = "s"
                )
                writer.WriteString(name)
                let msg = writer.CreateMessage()
                let! hasOwner = connection.CallMethodAsync(msg, (fun reply _ ->
                    let mutable reader = reply.GetBodyReader()
                    reader.ReadBool()
                ), null)
                return hasOwner
            with _ ->
                return false
    }

    interface IAuthorizer with
        member this.GetCallerUidAsync(sender: BusSender) : Task<Result<CallerUid, string>> = task {
            try
                let mutable writer = connection.GetMessageWriter()
                writer.WriteMethodCallHeader(
                    destination = "org.freedesktop.DBus",
                    path = "/org/freedesktop/DBus",
                    ``interface`` = "org.freedesktop.DBus",
                    ``member`` = "GetConnectionUnixUser",
                    signature = "s"
                )
                writer.WriteString(sender.Value)
                let msg = writer.CreateMessage()

                let! uid = connection.CallMethodAsync(msg, (fun reply _ ->
                    let mutable reader = reply.GetBodyReader()
                    reader.ReadUInt32()
                ), null)
                return Ok (CallerUid.createUnsafe uid)
            with ex ->
                return Error ex.Message
        }

        member this.ResolveUsernameAsync(uid: CallerUid) : Task<Result<Username, string>> = task {
            match NativeLibc.getUsername uid.Value with
            | Some name ->
                match Username.create name with
                | Ok user -> return Ok user
                | Error err -> return Error err
            | None ->
                return Error $"Could not find username for UID {uid.Value}"
        }

        member this.CheckPolkitAsync(sender: BusSender, actionId: string) : Task<bool> = task {
            let! hasPolkit = checkNameHasOwner "org.freedesktop.PolicyKit1"
            if not hasPolkit then
                // Polkit is unreachable (e.g. private test system bus without polkitd).
                // Test policy injection is HONOURED ONLY if GOODIX_FPRINTD_STATE_DIR is also set.
                // In production (systemd unit with strict hardening and stock state dir), testPolicy is always None.
                match getTestPolicy () with
                | Some "allow-self" ->
                    // Allows verifying own prints (matching stock allow_active=yes),
                    // but administrative operations (setusername, enroll) remain denied.
                    return actionId = PolkitActions.Verify
                | Some "deny-all" ->
                    return false
                | _ ->
                    // Fail closed in production or when test policy is unspecified
                    return false
            else
                try
                    let mutable writer = connection.GetMessageWriter()
                    writer.WriteMethodCallHeader(
                        destination = "org.freedesktop.PolicyKit1",
                        path = "/org/freedesktop/PolicyKit1/Authority",
                        ``interface`` = "org.freedesktop.PolicyKit1.Authority",
                        ``member`` = "CheckAuthorization",
                        signature = "(sa{sv})sa{ss}us"
                    )

                    // 1. Subject struct (sa{sv})
                    writer.WriteStructureStart()
                    writer.WriteString("system-bus-name")
                    let dictStart = writer.WriteDictionaryStart()
                    writer.WriteDictionaryEntryStart()
                    writer.WriteString("name")
                    writer.WriteVariantString(sender.Value)
                    writer.WriteDictionaryEnd(dictStart)

                    // 2. Action ID
                    writer.WriteString(actionId)

                    // 3. Details dictionary a{ss} (empty)
                    let detailsStart = writer.WriteDictionaryStart()
                    writer.WriteDictionaryEnd(detailsStart)

                    // 4. Flags (0 = no interaction)
                    writer.WriteUInt32(0u)

                    // 5. Cancellation ID string (empty)
                    writer.WriteString("")

                    let msg = writer.CreateMessage()

                    let! (isAuthorized, _) = connection.CallMethodAsync(msg, (fun reply _ ->
                        let mutable reader = reply.GetBodyReader()
                        reader.AlignStruct()
                        let auth = reader.ReadBool()
                        let challenge = reader.ReadBool()
                        (auth, challenge)
                    ), null)
                    return isAuthorized
                with _ ->
                    return false
        }

// ============================================================================
// Authorization Decisions
// ============================================================================

module Authorization =

    let authorizeAccessUser (authorizer: IAuthorizer) (sender: BusSender) (requestedUser: string) : Task<Result<Username, string * string>> = task {
        if String.IsNullOrWhiteSpace requestedUser then
            let! uidRes = authorizer.GetCallerUidAsync sender
            match uidRes with
            | Error err ->
                return Error (FprintConstants.Errors.PermissionDenied, $"Failed to determine caller UID: {err}")
            | Ok uid ->
                let! nameRes = authorizer.ResolveUsernameAsync uid
                match nameRes with
                | Error err ->
                    return Error (FprintConstants.Errors.PermissionDenied, $"Failed to resolve caller username: {err}")
                | Ok callerUser ->
                    return Ok callerUser
        else
            match Username.create requestedUser with
            | Error err ->
                return Error (FprintConstants.Errors.PermissionDenied, err)
            | Ok targetUser ->
                let! uidRes = authorizer.GetCallerUidAsync sender
                match uidRes with
                | Error err ->
                    return Error (FprintConstants.Errors.PermissionDenied, $"Failed to determine caller UID: {err}")
                | Ok uid when uid.IsRoot ->
                    return Ok targetUser
                | Ok uid ->
                    let! callerNameRes = authorizer.ResolveUsernameAsync uid
                    match callerNameRes with
                    | Ok callerUser when String.Equals(callerUser.Value, targetUser.Value, StringComparison.Ordinal) ->
                        return Ok targetUser
                    | _ ->
                        let! isAuthorized = authorizer.CheckPolkitAsync(sender, PolkitActions.SetUsername)
                        if isAuthorized then
                            return Ok targetUser
                        else
                            return Error (FprintConstants.Errors.PermissionDenied, $"Not authorized to access fingerprints for user '{targetUser.Value}'")
    }

    let authorizeVerify (authorizer: IAuthorizer) (sender: BusSender) : Task<Result<unit, string * string>> = task {
        let! uidRes = authorizer.GetCallerUidAsync sender
        match uidRes with
        | Error err ->
            return Error (FprintConstants.Errors.PermissionDenied, $"Failed to determine caller UID: {err}")
        | Ok uid when uid.IsRoot ->
            return Ok ()
        | Ok _ ->
            let! isAuthorized = authorizer.CheckPolkitAsync(sender, PolkitActions.Verify)
            if isAuthorized then
                return Ok ()
            else
                return Error (FprintConstants.Errors.PermissionDenied, "Not authorized to verify fingerprints")
    }
