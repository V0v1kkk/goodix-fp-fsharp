namespace GoodixFp.Core

open System
open System.IO
open System.Runtime.InteropServices

/// <summary>
/// Storage and path resolution for Goodix biometric templates and firmware.
/// Handles privilege separation, resolving user directories when invoked via PAM / sudo.
/// </summary>
module Storage =

    [<DllImport("libc", EntryPoint = "geteuid")>]
    extern uint32 private geteuid()

    let private isRootDefault () : bool =
        try
            geteuid() = 0u
        with _ ->
            Environment.UserName = "root"

    /// <summary>
    /// Parses /etc/passwd or a custom passwd-formatted file to find a user's home directory.
    /// </summary>
    let tryGetHomeFromPasswdFile (passwdPath: string) (username: string) : string option =
        try
            if File.Exists passwdPath then
                File.ReadLines passwdPath
                |> Seq.tryPick (fun line ->
                    let parts = line.Split(':')
                    if parts.Length >= 6 && parts.[0] = username then
                        let dir = parts.[5].Trim()
                        if not (String.IsNullOrWhiteSpace dir) then Some dir else None
                    else
                        None
                )
            else
                None
        with _ ->
            None

    /// <summary>
    /// Resolves a user's home directory using passwd lookup with fallback to /home/{username}.
    /// </summary>
    let resolveUserHomeWith
        (getPasswdHome: string -> string option)
        (dirExists: string -> bool)
        (username: string) : string option =
        match getPasswdHome username with
        | Some h when dirExists h -> Some h
        | Some h -> Some h
        | None ->
            let standardHome = Path.Combine("/home", username)
            if dirExists standardHome then Some standardHome
            else None

    /// <summary>
    /// Resolves the home directory of a user on the current system.
    /// </summary>
    let resolveUserHome (username: string) : string option =
        resolveUserHomeWith
            (tryGetHomeFromPasswdFile "/etc/passwd")
            Directory.Exists
            username

    /// <summary>
    /// Identifies the target / invoking user from explicit parameter, PAM_USER, SUDO_USER, USER, or LOGNAME.
    /// </summary>
    let resolveInvokingUserWith
        (getEnv: string -> string option)
        (explicitUser: string option) : string option =
        match explicitUser with
        | Some u when not (String.IsNullOrWhiteSpace u) && u <> "root" -> Some u
        | _ ->
            match getEnv "PAM_USER" with
            | Some pam when not (String.IsNullOrWhiteSpace pam) && pam <> "root" -> Some pam
            | _ ->
                match getEnv "SUDO_USER" with
                | Some sudo when not (String.IsNullOrWhiteSpace sudo) && sudo <> "root" -> Some sudo
                | _ -> None

    /// <summary>
    /// Identifies the invoking regular user from PAM or sudo environment.
    /// </summary>
    let resolveInvokingUser (explicitUser: string option) : string option =
        resolveInvokingUserWith
            (fun key ->
                let v = Environment.GetEnvironmentVariable key
                if String.IsNullOrWhiteSpace v then None else Some v)
            explicitUser

    /// <summary>
    /// Pure resolver for template directories based on execution context (root vs regular user).
    /// </summary>
    let resolveTemplateDirectoryWith
        (isRoot: unit -> bool)
        (getEnv: string -> string option)
        (getUserHome: string -> string option)
        (dirExists: string -> bool)
        (customDir: string option)
        (targetUser: string option) : string =

        match customDir with
        | Some dir when not (String.IsNullOrWhiteSpace dir) -> dir
        | _ ->
            let invokingUser = resolveInvokingUserWith getEnv targetUser

            if isRoot () then
                match invokingUser with
                | Some user ->
                    match getUserHome user with
                    | Some home ->
                        let xdg = getEnv "XDG_DATA_HOME"
                        let userTmplDir =
                            match xdg with
                            | Some x when not (String.IsNullOrWhiteSpace x) && (x.StartsWith home || not (x.StartsWith "/root")) ->
                                Path.Combine(x, "goodix-fp", "templates")
                            | _ ->
                                Path.Combine(home, ".local", "share", "goodix-fp", "templates")

                        if dirExists userTmplDir then
                            userTmplDir
                        elif dirExists "/var/lib/goodix-fp/templates" then
                            "/var/lib/goodix-fp/templates"
                        elif dirExists "/etc/goodix-fp/templates" then
                            "/etc/goodix-fp/templates"
                        else
                            userTmplDir
                    | None ->
                        if dirExists "/var/lib/goodix-fp/templates" then
                            "/var/lib/goodix-fp/templates"
                        elif dirExists "/etc/goodix-fp/templates" then
                            "/etc/goodix-fp/templates"
                        else
                            "/var/lib/goodix-fp/templates"
                | None ->
                    if dirExists "/var/lib/goodix-fp/templates" then
                        "/var/lib/goodix-fp/templates"
                    elif dirExists "/etc/goodix-fp/templates" then
                        "/etc/goodix-fp/templates"
                    else
                        "/var/lib/goodix-fp/templates"
            else
                match invokingUser with
                | Some otherUser when targetUser.IsSome ->
                    match getUserHome otherUser with
                    | Some home -> Path.Combine(home, ".local", "share", "goodix-fp", "templates")
                    | None ->
                        let xdg = getEnv "XDG_DATA_HOME"
                        match xdg with
                        | Some x when not (String.IsNullOrWhiteSpace x) -> Path.Combine(x, "goodix-fp", "templates")
                        | _ ->
                            let userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
                            let home =
                                match getEnv "HOME" with
                                | Some h when not (String.IsNullOrWhiteSpace h) -> h
                                | _ -> userProfile
                            Path.Combine(home, ".local", "share", "goodix-fp", "templates")
                | _ ->
                    let xdg = getEnv "XDG_DATA_HOME"
                    match xdg with
                    | Some x when not (String.IsNullOrWhiteSpace x) -> Path.Combine(x, "goodix-fp", "templates")
                    | _ ->
                        let userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
                        let home =
                            match getEnv "HOME" with
                            | Some h when not (String.IsNullOrWhiteSpace h) -> h
                            | _ -> userProfile
                        Path.Combine(home, ".local", "share", "goodix-fp", "templates")

    /// <summary>
    /// Safely creates directory if it does not exist.
    /// </summary>
    let ensureDirectoryExists (path: string) : unit =
        try
            if not (Directory.Exists path) then
                Directory.CreateDirectory(path) |> ignore
        with _ -> ()

    /// <summary>
    /// Gets the primary template directory for the current user or invoking PAM/sudo user.
    /// </summary>
    let getTemplateDirectory (customDir: string option) (targetUser: string option) : string =
        let tmplDir =
            resolveTemplateDirectoryWith
                isRootDefault
                (fun k ->
                    let v = Environment.GetEnvironmentVariable k
                    if String.IsNullOrWhiteSpace v then None else Some v)
                resolveUserHome
                Directory.Exists
                customDir
                targetUser
        if not (isRootDefault ()) then
            ensureDirectoryExists tmplDir
        tmplDir

    /// <summary>
    /// Returns ordered candidate directories to search for templates (user directory followed by system fallbacks).
    /// </summary>
    let getTemplateDirectories (customDir: string option) (targetUser: string option) : string list =
        let primary = getTemplateDirectory customDir targetUser
        let candidates = [
            primary
            "/var/lib/goodix-fp/templates"
            "/etc/goodix-fp/templates"
        ]
        candidates |> List.distinct

    /// <summary>
    /// Resolves the Goodix firmware blob path across user and system directories.
    /// </summary>
    let getFirmwarePath (targetUser: string option) : string =
        let primaryPath =
            let baseDir =
                let xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME")
                if not (String.IsNullOrWhiteSpace xdg) then xdg
                else
                    let home =
                        match resolveInvokingUser targetUser with
                        | Some u -> resolveUserHome u |> Option.defaultValue (Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))
                        | None -> Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
                    Path.Combine(home, ".local", "share")
            Path.Combine(baseDir, "goodix-fp", "GF5298_GM168SEC_APP_13016.bin")
        let candidates = [
            primaryPath
            "/home/vladimir/.local/share/goodix-fp/GF5298_GM168SEC_APP_13016.bin"
            "/lib/firmware/goodix/GF5298_GM168SEC_APP_13016.bin"
            "/var/lib/goodix-fp/GF5298_GM168SEC_APP_13016.bin"
            "/usr/share/goodix-fp/GF5298_GM168SEC_APP_13016.bin"
        ]
        candidates |> List.tryFind File.Exists |> Option.defaultValue primaryPath

    /// <summary>
    /// Loads all enrolled .tgla fingerprint raw template bytes across user and fallback directories.
    /// Returns list of (fingerName, rawBlobBytes).
    /// </summary>
    let loadAllRawTemplates (customDir: string option) (targetUser: string option) : (string * byte[]) list =
        let dirs = getTemplateDirectories customDir targetUser
        let seenFingers = System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase)
        let mutable result = []
        for dir in dirs do
            if Directory.Exists dir then
                for file in Directory.GetFiles(dir, "*.tgla") do
                    let fingerName = Path.GetFileNameWithoutExtension(file)
                    if seenFingers.Add(fingerName) then
                        try
                            let bytes = File.ReadAllBytes(file)
                            result <- (fingerName, bytes) :: result
                        with _ -> ()
        List.rev result
