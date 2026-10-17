namespace GoodixFp.Cli

open System
open System.IO
open System.Threading.Tasks
open FsToolkit.ErrorHandling
open GoodixFp.Core
open GoodixFp.NativeMatcher

module Storage =

    let getTemplateDirectory () : string =
        let xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME")
        let baseDir =
            if not (String.IsNullOrWhiteSpace xdg) then xdg
            else Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share")
        let tmplDir = Path.Combine(baseDir, "goodix-fp", "templates")
        if not (Directory.Exists tmplDir) then
            Directory.CreateDirectory(tmplDir) |> ignore
        tmplDir

    let loadAllTemplates () : (FingerId * TemplateBlob) list =
        let dir = getTemplateDirectory ()
        if not (Directory.Exists dir) then []
        else
            Directory.GetFiles(dir, "*.tgla")
            |> Array.choose (fun file ->
                try
                    let fingerName = Path.GetFileNameWithoutExtension(file)
                    let bytes = File.ReadAllBytes(file)
                    match FingerId.create fingerName, TemplateBlob.create bytes with
                    | Ok fid, Ok blob -> Some (fid, blob)
                    | _ -> None
                with _ -> None
            )
            |> Array.toList

type CliOptions = {
    Command: string
    FingerName: string option
    Prefix: string option
    UseBouncyCastle: bool
    Vid: uint16
    Pid: uint16
}

module CommandLine =

    let defaultOptions = {
        Command = "help"
        FingerName = None
        Prefix = None
        UseBouncyCastle = false
        Vid = 0x27c6us
        Pid = 0x538dus
    }

    let rec parseArgs (args: string list) (opts: CliOptions) : Result<CliOptions, string> =
        match args with
        | [] -> Ok opts
        | "help" :: _ | "--help" :: _ | "-h" :: _ ->
            Ok { opts with Command = "help" }
        | "probe" :: rest ->
            parseOptions rest { opts with Command = "probe" }
        | "provision-psk" :: rest ->
            parseOptions rest { opts with Command = "provision-psk" }
        | "capture" :: rest ->
            let (prefix, remaining) =
                match rest with
                | p :: r when not (p.StartsWith("-")) -> (Some p, r)
                | _ -> (None, rest)
            parseOptions remaining { opts with Command = "capture"; Prefix = prefix }
        | "enroll" :: name :: rest when not (name.StartsWith("-")) ->
            parseOptions rest { opts with Command = "enroll"; FingerName = Some name }
        | "enroll" :: _ ->
            Error "The 'enroll' command requires a finger name, e.g. 'goodix-fp enroll index_right'"
        | "verify" :: rest ->
            parseOptions rest { opts with Command = "verify" }
        | unknown :: _ ->
            Error $"Unknown command or argument '{unknown}'. Run 'goodix-fp help' for usage."

    and private parseOptions (args: string list) (opts: CliOptions) : Result<CliOptions, string> =
        match args with
        | [] -> Ok opts
        | "--tls" :: "bc" :: rest ->
            parseOptions rest { opts with UseBouncyCastle = true }
        | "--tls" :: "pure" :: rest ->
            parseOptions rest { opts with UseBouncyCastle = false }
        | "--tls" :: other :: _ ->
            Error $"Invalid TLS engine '{other}'. Expected 'pure' or 'bc'."
        | "--vid" :: hexStr :: rest ->
            try
                let v = Convert.ToUInt16(hexStr, 16)
                parseOptions rest { opts with Vid = v }
            with _ -> Error $"Invalid hex VID '{hexStr}'"
        | "--pid" :: hexStr :: rest ->
            try
                let p = Convert.ToUInt16(hexStr, 16)
                parseOptions rest { opts with Pid = p }
            with _ -> Error $"Invalid hex PID '{hexStr}'"
        | unknown :: _ ->
            Error $"Unknown flag or argument '{unknown}'"

module DeviceRunner =

    let openDevice (opts: CliOptions) : Result<Goodix53xdDevice, DriverError> =
        result {
            let! vid = UsbVid.create opts.Vid |> Result.mapError (fun e -> ValidationError ("VID", e))
            let! pid = UsbPid.create opts.Pid |> Result.mapError (fun e -> ValidationError ("PID", e))
            let! transport = LibUsbTransport.Open(vid, pid)
            let tunnel : ITlsPskTunnel =
                if opts.UseBouncyCastle then
                    new BouncyCastleTlsPskTunnel() :> ITlsPskTunnel
                else
                    new PureFSharpTlsPskTunnel() :> ITlsPskTunnel
            return new Goodix53xdDevice(transport, tunnel)
        }

    let withDevice (opts: CliOptions) (action: Goodix53xdDevice -> Task<int>) : Task<int> = task {
        match openDevice opts with
        | Error err ->
            eprintfn $"[!] Failed to open device: {err}"
            return 1
        | Ok dev ->
            let devDisp = dev :> IDisposable
            try
                return! action dev
            finally
                devDisp.Dispose()
    }

    let withMatcher (action: GoodixTodMatcher -> Task<int>) : Task<int> = task {
        match GoodixTodMatcher.Create() with
        | Error err ->
            eprintfn $"[!] Failed to initialize Goodix TOD matcher: {err}"
            return 1
        | Ok matcher ->
            let matchDisp = matcher :> IDisposable
            try
                return! action matcher
            finally
                matchDisp.Dispose()
    }

    let runProbe (opts: CliOptions) : Task<int> =
        printfn $"[*] Probing Goodix 53xd device (VID: 0x{opts.Vid:X4}, PID: 0x{opts.Pid:X4})..."
        withDevice opts (fun dev -> task {
            let! probeRes = dev.ProbeInfo()
            match probeRes with
            | Error err ->
                eprintfn $"[!] Probe failed: {err}"
                return 1
            | Ok info ->
                printfn "\n=== Goodix 53xd Device Report ==="
                printfn $"  Firmware Version : {info.Firmware.Value}"
                printfn $"  Sensor Chip ID   : 0x{info.Chip.Value:X4}"
                printfn $"  OTP DAC High     : 0x{info.Otp.DacH:X2} ({info.Otp.DacH})"
                printfn $"  OTP DAC Low      : 0x{info.Otp.DacL:X2} ({info.Otp.DacL})"
                printfn $"  OTP FDT DAC      : [| 0x{info.Otp.FdtDac.[0]:X2}; 0x{info.Otp.FdtDac.[1]:X2}; 0x{info.Otp.FdtDac.[2]:X2}; 0x{info.Otp.FdtDac.[3]:X2} |]"
                printfn "=================================\n"
                return 0
        })

    let runProvisionPsk (opts: CliOptions) : Task<int> =
        printfn $"[*] Provisioning PSK White-Box on device (VID: 0x{opts.Vid:X4}, PID: 0x{opts.Pid:X4})..."
        withDevice opts (fun dev -> task {
            let! pskRes = dev.ProvisionZeroPsk()
            match pskRes with
            | Error err ->
                eprintfn $"[!] PSK provisioning failed: {err}"
                return 1
            | Ok () ->
                printfn "[+] PSK White-Box successfully provisioned and verified."
                return 0
        })

    let runCapture (opts: CliOptions) : Task<int> =
        let prefix = defaultArg opts.Prefix "capture"
        let tlsEngine = if opts.UseBouncyCastle then "BouncyCastle" else "Pure F#"
        printfn $"[*] Initializing capture session (TLS: {tlsEngine})..."
        withDevice opts (fun dev -> task {
            printfn "[*] Activating session and performing TLS handshake..."
            let! actRes = dev.ActivateSession()
            match actRes with
            | Error err ->
                eprintfn $"[!] Session activation failed: {err}"
                return 1
            | Ok _ ->
                printfn "[*] Waiting for finger on sensor..."
                let! downRes = dev.WaitForFingerDown(timeoutMs = 15000)
                match downRes with
                | Error err ->
                    eprintfn $"[!] Finger detection timed out or failed: {err}"
                    return 1
                | Ok () ->
                    printfn "[+] Finger detected! Capturing frame..."
                    let! capRes = dev.CaptureFrame()
                    match capRes with
                    | Error err ->
                        eprintfn $"[!] Frame capture failed: {err}"
                        return 1
                    | Ok rawFrame ->
                        let! _ = dev.WaitForFingerUp(timeoutMs = 3000)
                        let! _ = dev.Sleep()

                        // Export raw 12-bit PGM
                        let rawPgm = FrameDecoder.toPgm12Bit rawFrame.Pixels 80 64
                        let rawPath = $"{prefix}_raw16.pgm"
                        File.WriteAllBytes(rawPath, rawPgm)
                        printfn $"[+] Saved raw 12-bit PGM image: {rawPath}"

                        // Preprocess and export enhanced 8-bit PGM
                        let (qual, cov) = GoodixTodMatcher.ComputeQualityAndCoverage rawFrame.Pixels
                        let enhPixels = FrameDecoder.squash12To8BitLinear rawFrame.Pixels
                        let enhPgm = FrameDecoder.toPgm8Bit enhPixels 80 64
                        let enhPath = $"{prefix}_enh8.pgm"
                        File.WriteAllBytes(enhPath, enhPgm)
                        printfn $"[+] Saved enhanced 8-bit PGM image: {enhPath}"
                        printfn $"[+] Quality Score  : {qual.Value} / 100"
                        printfn $"[+] Coverage Score : {cov.Value} / 100"
                        return 0
        })

    let runEnroll (opts: CliOptions) (fingerName: string) : Task<int> =
        printfn $"[*] Starting enrollment for '{fingerName}' (12 touches required)..."
        withDevice opts (fun dev -> task {
            printfn "[*] Activating session and performing TLS handshake..."
            let! actRes = dev.ActivateSession()
            match actRes with
            | Error err ->
                eprintfn $"[!] Session activation failed: {err}"
                return 1
            | Ok _ ->
                return! withMatcher (fun matcher -> task {
                    match matcher.StartEnroll() with
                    | Error err ->
                        eprintfn $"[!] Start enrollment failed: {err}"
                        return 1
                    | Ok () ->
                        let mutable enrolledCount = 0
                        let mutable failure = false

                        while enrolledCount < 12 && not failure do
                            printf $"--> [{enrolledCount + 1}/12] Place finger on sensor: "
                            let! downRes = dev.WaitForFingerDown(timeoutMs = 20000)
                            match downRes with
                            | Error err ->
                                eprintfn $"\n[!] Timed out waiting for touch: {err}"
                                failure <- true
                            | Ok () ->
                                printf "Capturing... "
                                let! capRes = dev.CaptureFrame()
                                match capRes with
                                | Error err ->
                                    eprintfn $"\n[!] Capture failed: {err}"
                                    failure <- true
                                | Ok frame ->
                                    let! _ = dev.WaitForFingerUp(timeoutMs = 5000)
                                    match matcher.MergeSample(frame.Pixels) with
                                    | Error err ->
                                        eprintfn $"\n[!] Merge sample rejected: {err}"
                                        failure <- true
                                    | Ok count ->
                                        enrolledCount <- count
                                        printfn "Sample accepted! (Lift finger)"

                        let! _ = dev.Sleep()

                        if failure || enrolledCount < 12 then
                            eprintfn "[!] Enrollment was aborted or incomplete."
                            return 1
                        else
                            printfn "[*] Generating enrolled template..."
                            let fid = FingerId.create fingerName |> Result.defaultWith (fun _ -> FingerId.createUnsafe fingerName)
                            match matcher.CommitTemplate(fid) with
                            | Error err ->
                                eprintfn $"[!] Failed to commit template: {err}"
                                return 1
                            | Ok templateBlob ->
                                let tmplDir = Storage.getTemplateDirectory ()
                                let tmplPath = Path.Combine(tmplDir, $"{fingerName}.tgla")
                                File.WriteAllBytes(tmplPath, templateBlob.Value)
                                printfn $"[+] Template committed ({templateBlob.Length} bytes) with 'TGLA' header."
                                printfn $"[+] Successfully enrolled finger '{fingerName}' to: {tmplPath}"
                                return 0
                })
        })

    let runVerify (opts: CliOptions) : Task<int> =
        let templates = Storage.loadAllTemplates ()
        if List.isEmpty templates then
            eprintfn $"[!] No enrolled templates found in: {Storage.getTemplateDirectory ()}"
            eprintfn "    Please enroll a finger first using: goodix-fp enroll <finger-name>"
            Task.FromResult 1
        else
            printfn $"[*] Loaded {templates.Length} enrolled template(s). Connecting to device..."
            withDevice opts (fun dev -> task {
                let! actRes = dev.ActivateSession()
                match actRes with
                | Error err ->
                    eprintfn $"[!] Session activation failed: {err}"
                    return 1
                | Ok _ ->
                    printfn "[*] Touch sensor to verify..."
                    let! downRes = dev.WaitForFingerDown(timeoutMs = 15000)
                    match downRes with
                    | Error _ ->
                        eprintfn "[!] Verification timed out waiting for touch."
                        return 1
                    | Ok () ->
                        printfn "[*] Finger detected. Capturing probe..."
                        let! capRes = dev.CaptureFrame()
                        match capRes with
                        | Error err ->
                            eprintfn $"[!] Frame capture failed: {err}"
                            return 1
                        | Ok frame ->
                            let! _ = dev.WaitForFingerUp(timeoutMs = 3000)
                            let! _ = dev.Sleep()

                            return! withMatcher (fun matcher -> task {
                                match matcher.IdentifyProbe(frame.Pixels, templates) with
                                | Error err ->
                                    eprintfn $"[!] Identification failed: {err}"
                                    return 1
                                | Ok (Some matchedFid) ->
                                    printfn $"[+] MATCH VERIFIED: {matchedFid.Value}"
                                    return 0 // Exit code 0 for PAM success
                                | Ok None ->
                                    printfn "[-] NO MATCH (Access Denied)"
                                    return 1 // Exit code 1 for PAM failure
                            })
            })

module Program =

    let printHelp () =
        printfn "================================================================="
        printfn "  Goodix FP Linux Driver & Matcher CLI (F# / .NET 10 Native AOT)"
        printfn "================================================================="
        printfn "Usage: goodix-fp <command> [options]\n"
        printfn "Commands:"
        printfn "  probe                     Query firmware version, chip ID, and OTP"
        printfn "  provision-psk             Write zero PSK whitebox and verify PMK_HASH"
        printfn "  capture [prefix]          Capture baseline & frame, export PGM images"
        printfn "  enroll <finger-name>      12-touch interactive enrollment loop"
        printfn "  verify                    Verify finger against enrolled templates (PAM)"
        printfn "  help                      Show this help message\n"
        printfn "Options:"
        printfn "  --tls <pure|bc>           TLS PSK engine (default: pure)"
        printfn "  --vid <hex>               USB Vendor ID (default: 27c6)"
        printfn "  --pid <hex>               USB Product ID (default: 538d)\n"
        printfn "Templates directory:"
        printfn "  ${XDG_DATA_HOME:-$HOME/.local/share}/goodix-fp/templates/\n"

    [<EntryPoint>]
    let main (argv: string[]) : int =
        let args = argv |> Array.toList
        match CommandLine.parseArgs args CommandLine.defaultOptions with
        | Error err ->
            eprintfn $"Error: {err}\n"
            printHelp ()
            1
        | Ok opts ->
            match opts.Command with
            | "help" ->
                printHelp ()
                0
            | "probe" ->
                (DeviceRunner.runProbe opts).GetAwaiter().GetResult()
            | "provision-psk" ->
                (DeviceRunner.runProvisionPsk opts).GetAwaiter().GetResult()
            | "capture" ->
                (DeviceRunner.runCapture opts).GetAwaiter().GetResult()
            | "enroll" ->
                let name = opts.FingerName |> Option.defaultValue "default_finger"
                (DeviceRunner.runEnroll opts name).GetAwaiter().GetResult()
            | "verify" ->
                (DeviceRunner.runVerify opts).GetAwaiter().GetResult()
            | other ->
                eprintfn $"Unrecognized command '{other}'"
                1
