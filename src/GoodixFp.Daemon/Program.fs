namespace GoodixFp.Daemon

open System
open System.Threading
open System.Threading.Tasks
open Tmds.DBus.Protocol

type DaemonCliOptions =
    | RunDaemon
    | ImportTemplate of user: string * finger: string * file: string
    | ListTemplates of user: string
    | ShowHelp

module Program =

    let printHelp () =
        printfn "goodix-fprintd — Goodix Fingerprint Reader fprintd D-Bus Bridge Daemon"
        printfn ""
        printfn "Usage:"
        printfn "  goodix-fprintd [daemon]                 Run the fprintd D-Bus service (default)"
        printfn "  goodix-fprintd import [options]         Import a .tgla template into the secure store"
        printfn "  goodix-fprintd list --user <name>       List enrolled fingerprints for a user"
        printfn "  goodix-fprintd help | --help | -h       Show this help message"
        printfn ""
        printfn "Import Options:"
        printfn "  --user <name>            Target system username"
        printfn "  --finger <fprintd-name>  Standard finger name (e.g. right-index-finger, left-thumb)"
        printfn "  --file <path>            Path to existing .tgla template file (e.g. ~/.local/share/goodix-fp/templates/right-index.tgla)"
        printfn ""
        printfn "Standard Finger Names:"
        for f in FingerName.StandardNames do
            printfn $"  - {f}"
        printfn ""

    let parseArgs (args: string list) : Result<DaemonCliOptions, string> =
        match args with
        | [] | [ "daemon" ] ->
            Ok RunDaemon
        | "help" :: _ | "--help" :: _ | "-h" :: _ ->
            Ok ShowHelp
        | "list" :: rest ->
            let rec parseList r userOpt =
                match r with
                | [] ->
                    match userOpt with
                    | Some u -> Ok (ListTemplates u)
                    | None -> Error "Missing required '--user <name>' option for 'list'"
                | "--user" :: u :: tail -> parseList tail (Some u)
                | unknown :: _ -> Error $"Unrecognized option '{unknown}' for 'list'"
            parseList rest None
        | "import" :: rest ->
            let rec parseImport r userOpt fingerOpt fileOpt =
                match r with
                | [] ->
                    match userOpt, fingerOpt, fileOpt with
                    | Some u, Some fn, Some f -> Ok (ImportTemplate (u, fn, f))
                    | None, _, _ -> Error "Missing required '--user <name>' option for 'import'"
                    | _, None, _ -> Error "Missing required '--finger <name>' option for 'import'"
                    | _, _, None -> Error "Missing required '--file <path>' option for 'import'"
                | "--user" :: u :: tail -> parseImport tail (Some u) fingerOpt fileOpt
                | "--finger" :: fn :: tail -> parseImport tail userOpt (Some fn) fileOpt
                | "--file" :: f :: tail -> parseImport tail userOpt fingerOpt (Some f)
                | unknown :: _ -> Error $"Unrecognized option '{unknown}' for 'import'"
            parseImport rest None None None
        | unknown :: _ ->
            Error $"Unknown command '{unknown}'. Run 'goodix-fprintd help' for usage."

    let runImport (userStr: string) (fingerStr: string) (fileStr: string) : int =
        match Username.create userStr with
        | Error err ->
            eprintfn $"[!] Invalid username: {err}"
            1
        | Ok user ->
            match FingerName.create fingerStr with
            | Error err ->
                eprintfn $"[!] Invalid finger name: {err}"
                1
            | Ok finger ->
                match TemplateStore.importTemplate user finger fileStr with
                | Ok destPath ->
                    printfn $"[+] Successfully imported template for user '{user.Value}', finger '{finger.Value}'"
                    printfn $"    Destination: {destPath}"
                    0
                | Error err ->
                    eprintfn $"[!] Import failed: {err}"
                    1

    let runList (userStr: string) : int =
        match Username.create userStr with
        | Error err ->
            eprintfn $"[!] Invalid username: {err}"
            1
        | Ok user ->
            let fingers = TemplateStore.listEnrolledFingers user
            if List.isEmpty fingers then
                printfn $"No fingerprints enrolled for user '{user.Value}' in {TemplateStore.getUserDirectory user}"
            else
                printfn $"Enrolled fingerprints for user '{user.Value}':"
                for f in fingers do
                    let path = TemplateStore.getTemplatePath user f
                    printfn $" - {f.Value} ({path})"
            0

    let runDaemonService () : Task<int> = task {
        try
            eprintfn "[*] Starting Goodix fprintd D-Bus bridge daemon..."
            let connection = new DBusConnection(DBusAddress.System)
            do! connection.ConnectAsync()

            let authorizer = new DBusAuthorizer(connection) :> IAuthorizer
            let runner = new HardwareDeviceRunner(maxRetries = 3) :> IDeviceRunner

            let onSelected (finger: string) =
                DBusSignalEmitter.emitVerifyFingerSelected connection finger

            let onMatched (finger: string) =
                DBusSignalEmitter.emitVerifyFingerMatched connection finger

            let onStatus (status: string, doneFlag: bool) =
                DBusSignalEmitter.emitVerifyStatus connection (status, doneFlag)

            let deviceSession = new DeviceSession(runner, onSelected, onMatched, onStatus)

            let managerHandler = new ManagerMethodHandler() :> IPathMethodHandler
            let deviceHandler = new DeviceMethodHandler(deviceSession, authorizer) :> IPathMethodHandler

            connection.AddMethodHandler managerHandler
            connection.AddMethodHandler deviceHandler

            // Subscribe to NameOwnerChanged to detect client drops
            let rule = new MatchRule()
            rule.Type <- Nullable MessageType.Signal
            rule.Sender <- "org.freedesktop.DBus"
            rule.Path <- "/org/freedesktop/DBus"
            rule.Interface <- "org.freedesktop.DBus"
            rule.Member <- "NameOwnerChanged"

            let nameOwnerReader = MessageValueReader(fun (msg: Message) _ ->
                let mutable r = msg.GetBodyReader()
                let name = r.ReadString()
                let oldOwner = r.ReadString()
                let newOwner = r.ReadString()
                (name, oldOwner, newOwner)
            )

            let! _ = connection.AddMatchAsync(rule, nameOwnerReader, (fun (notif: Notification<string * string * string>) ->
                if notif.HasValue then
                    try
                        let (name, oldOwner, newOwner) = notif.Value
                        deviceSession.OnNameOwnerChanged(name, oldOwner, newOwner).GetAwaiter().GetResult()
                    with ex ->
                        eprintfn $"[!] Error handling NameOwnerChanged: {ex.Message}"
            ))

            do! connection.RequestNameAsync(
                FprintConstants.ServiceName,
                RequestNameOptions.ReplaceExisting
            )

            eprintfn $"[*] Successfully acquired bus name '{FprintConstants.ServiceName}' on system bus."
            eprintfn $"[*] Managing templates at: {TemplateStore.getRootDirectory ()}"
            eprintfn "[*] Ready to serve fprintd clients."

            let tcs = new TaskCompletionSource<int>()
            use cts = new CancellationTokenSource()

            let shutdownHandler = fun () ->
                if not tcs.Task.IsCompleted then
                    eprintfn "\n[*] Shutdown signal received. Exiting daemon..."
                    tcs.TrySetResult(0) |> ignore

            Console.CancelKeyPress.Add(fun args ->
                args.Cancel <- true
                shutdownHandler ()
            )

            AppDomain.CurrentDomain.ProcessExit.Add(fun _ ->
                shutdownHandler ()
            )

            let! exitCode = tcs.Task
            connection.Dispose()
            return exitCode
        with ex ->
            eprintfn $"[!] Daemon startup error: {ex.Message}"
            return 1
    }

    [<EntryPoint>]
    let main (argv: string[]) : int =
        let args = argv |> Array.toList
        match parseArgs args with
        | Error err ->
            eprintfn $"Error: {err}\n"
            printHelp ()
            1
        | Ok ShowHelp ->
            printHelp ()
            0
        | Ok (ImportTemplate (u, fn, f)) ->
            runImport u fn f
        | Ok (ListTemplates u) ->
            runList u
        | Ok RunDaemon ->
            (runDaemonService ()).GetAwaiter().GetResult()
