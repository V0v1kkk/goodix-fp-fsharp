namespace GoodixFp.Daemon

open System
open System.IO
open System.Runtime.InteropServices
open Microsoft.Win32.SafeHandles
open GoodixFp.Core
open GoodixFp.NativeMatcher

// ============================================================================
// Low-Level Safe POSIX File Operations
// ============================================================================

module private PosixFs =
    [<Literal>]
    let O_RDONLY = 0x0000
    [<Literal>]
    let O_WRONLY = 0x0001
    [<Literal>]
    let O_CREAT = 0x0040
    [<Literal>]
    let O_EXCL = 0x0080
    [<Literal>]
    let O_NOFOLLOW = 0x20000
    [<Literal>]
    let O_CLOEXEC = 0x80000

    [<Literal>]
    let Mode_0700 = 0x1c0 // 0700 octal = 448 decimal
    [<Literal>]
    let Mode_0600 = 0x180 // 0600 octal = 384 decimal

    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int ``open``(string pathname, int flags, int mode)

    [<DllImport("libc", EntryPoint = "close", SetLastError = true)>]
    extern int close(int fd)

    [<DllImport("libc", EntryPoint = "fsync", SetLastError = true)>]
    extern int fsync(int fd)

    [<DllImport("libc", EntryPoint = "chmod", SetLastError = true)>]
    extern int chmod(string pathname, int mode)

    [<DllImport("libc", EntryPoint = "unlink", SetLastError = true)>]
    extern int unlink(string pathname)

    [<DllImport("libc", EntryPoint = "geteuid")>]
    extern uint32 geteuid()

    let isSymlink (path: string) : bool =
        try
            let fi = FileInfo(path)
            fi.LinkTarget <> null || fi.Attributes.HasFlag(FileAttributes.ReparsePoint)
        with _ -> false

    let safeReadBytes (path: string) : Result<byte[], string> =
        if isSymlink path then
            Error (sprintf "Refusing to read symlink '%s'" path)
        else
            let flags = O_RDONLY ||| O_NOFOLLOW ||| O_CLOEXEC
            let fd = ``open``(path, flags, 0)
            if fd < 0 then
                let err = Marshal.GetLastPInvokeError()
                if err = 40 then // ELOOP
                    Error (sprintf "Refusing to read symlink '%s' (ELOOP)" path)
                else
                    Error (sprintf "Failed to open file '%s' (errno %d)" path err)
            else
                try
                    use handle = new SafeFileHandle(nativeint fd, true)
                    use stream = new FileStream(handle, FileAccess.Read)
                    let len = stream.Length
                    if len > 1024L * 1024L then
                        Error (sprintf "File '%s' exceeds maximum allowable template size" path)
                    else
                        let buf = Array.zeroCreate<byte> (int len)
                        stream.ReadExactly(buf)
                        Ok buf
                with ex ->
                    Error (sprintf "Error reading '%s': %s" path ex.Message)

    let safeWriteAtomic (destPath: string) (data: byte[]) : Result<unit, string> =
        try
            let dir = Path.GetDirectoryName(destPath)
            if not (Directory.Exists dir) then
                Directory.CreateDirectory(dir) |> ignore
                chmod(dir, Mode_0700) |> ignore

            let baseFileName = Path.GetFileName(destPath)
            let guidStr = Guid.NewGuid().ToString("N")
            let tempFile = Path.Combine(dir, sprintf ".%s.tmp.%s" baseFileName guidStr)
            let flags = O_WRONLY ||| O_CREAT ||| O_EXCL ||| O_NOFOLLOW ||| O_CLOEXEC
            let fd = ``open``(tempFile, flags, Mode_0600)
            if fd < 0 then
                let err = Marshal.GetLastPInvokeError()
                Error (sprintf "Failed to create secure temp file '%s' (errno %d)" tempFile err)
            else
                let writeResult =
                    try
                        chmod(tempFile, Mode_0600) |> ignore
                        use handle = new SafeFileHandle(nativeint fd, true)
                        use stream = new FileStream(handle, FileAccess.Write)
                        stream.Write(data, 0, data.Length)
                        stream.Flush(true)
                        if fsync(fd) <> 0 then
                            let err = Marshal.GetLastPInvokeError()
                            Error (sprintf "fsync failed on '%s' (errno %d)" tempFile err)
                        else
                            Ok ()
                    with ex ->
                        Error (sprintf "Failed to write to temp file '%s': %s" tempFile ex.Message)

                match writeResult with
                | Error err ->
                    unlink(tempFile) |> ignore
                    Error err
                | Ok () ->
                    try
                        File.Move(tempFile, destPath, overwrite = true)
                        chmod(destPath, Mode_0600) |> ignore
                        Ok ()
                    with ex ->
                        unlink(tempFile) |> ignore
                        Error (sprintf "Atomic rename from '%s' to '%s' failed: %s" tempFile destPath ex.Message)
        with ex ->
            Error (sprintf "Safe atomic write failed: %s" ex.Message)

// ============================================================================
// Template Store
// ============================================================================

module TemplateStore =

    [<Literal>]
    let DefaultStateDir = "/var/lib/goodix-fp/templates"

    let getRootDirectory () : string =
        let envOverride = Environment.GetEnvironmentVariable("GOODIX_FPRINTD_STATE_DIR")
        if not (String.IsNullOrWhiteSpace envOverride) then
            envOverride.Trim()
        else
            DefaultStateDir

    let getUserDirectory (user: Username) : string =
        Path.Combine(getRootDirectory (), user.Value)

    let getTemplatePath (user: Username) (finger: FingerName) : string =
        let fileName = FingerName.toFileName finger
        Path.Combine(getUserDirectory user, fileName)

    /// Validates raw template bytes: checks 'TGLA' magic header and size bounds.
    let validateTgla (bytes: byte[]) : Result<TemplateBlob, string> =
        if isNull bytes || bytes.Length < 4 then
            Error "Template data is too short to contain a TGLA header"
        elif bytes.[0] <> 0x54uy || bytes.[1] <> 0x47uy || bytes.[2] <> 0x4cuy || bytes.[3] <> 0x41uy then
            let magic = System.Text.Encoding.ASCII.GetString(bytes, 0, Math.Min(4, bytes.Length))
            Error (sprintf "Template header mismatch: expected 'TGLA', got '%s'" magic)
        elif bytes.Length < 1024 || bytes.Length > 262144 then
            Error (sprintf "Template size %d bytes is out of valid bounds (1024 - 262144 bytes)" bytes.Length)
        else
            match TemplateBlob.create bytes with
            | Ok blob -> Ok blob
            | Error err -> Error err.Message

    /// Ensures the store root and user directory exist with mode 0700.
    let ensureUserDirectorySecure (user: Username) : Result<string, string> =
        try
            let root = getRootDirectory ()
            if not (Directory.Exists root) then
                Directory.CreateDirectory(root) |> ignore
                PosixFs.chmod(root, PosixFs.Mode_0700) |> ignore

            let userDir = getUserDirectory user
            if not (Directory.Exists userDir) then
                Directory.CreateDirectory(userDir) |> ignore
                PosixFs.chmod(userDir, PosixFs.Mode_0700) |> ignore

            Ok userDir
        with ex ->
            Error (sprintf "Failed to create secure template directory: %s" ex.Message)

    /// Safe import of an existing .tgla template file into the protected system store.
    /// Rejects symlinks, verifies TGLA structure, ensures 0700 dirs and 0600 file,
    /// performs atomic rename, and requires euid == 0 (root) unless in test mode.
    let importTemplate (user: Username) (finger: FingerName) (sourcePath: string) : Result<string, string> =
        let isTestOverride = not (String.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("GOODIX_FPRINTD_STATE_DIR")))
        if not isTestOverride && PosixFs.geteuid() <> 0u then
            Error "Importing templates into the system store requires root privileges (EUID 0)"
        elif not (File.Exists sourcePath) then
            Error (sprintf "Source template file not found at '%s'" sourcePath)
        else
            match PosixFs.safeReadBytes sourcePath with
            | Error err -> Error err
            | Ok data ->
                match validateTgla data with
                | Error err -> Error (sprintf "Invalid template file: %s" err)
                | Ok blob ->
                    match ensureUserDirectorySecure user with
                    | Error err -> Error err
                    | Ok _ ->
                        let destPath = getTemplatePath user finger
                        match PosixFs.safeWriteAtomic destPath blob.Value with
                        | Error err -> Error err
                        | Ok () -> Ok destPath

    /// Lists all enrolled standard finger names for a given user in the secure store.
    let listEnrolledFingers (user: Username) : FingerName list =
        let userDir = getUserDirectory user
        if not (Directory.Exists userDir) then
            []
        else
            try
                Directory.GetFiles(userDir, "*.tgla")
                |> Array.choose (fun filePath ->
                    if PosixFs.isSymlink filePath then None
                    else
                        let fileName = Path.GetFileName(filePath)
                        FingerName.tryFromFileName fileName
                )
                |> Array.distinct
                |> Array.toList
            with _ ->
                []

    /// Loads all valid enrolled templates for a user for matching.
    let loadUserTemplates (user: Username) : (FingerId * TemplateBlob) list =
        let userDir = getUserDirectory user
        if not (Directory.Exists userDir) then
            []
        else
            try
                Directory.GetFiles(userDir, "*.tgla")
                |> Array.choose (fun filePath ->
                    match PosixFs.safeReadBytes filePath with
                    | Error _ -> None
                    | Ok bytes ->
                        match validateTgla bytes with
                        | Error _ -> None
                        | Ok blob ->
                            let fileName = Path.GetFileName(filePath)
                            match FingerName.tryFromFileName fileName with
                            | Some fn ->
                                match FingerId.create fn.Value with
                                | Ok fid -> Some (fid, blob)
                                | Error _ -> None
                            | None -> None
                )
                |> Array.toList
            with _ ->
                []

    let hasEnrolledFingers (user: Username) : bool =
        not (List.isEmpty (listEnrolledFingers user))
