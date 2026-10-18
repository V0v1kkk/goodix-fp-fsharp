namespace GoodixFp.Cli

open System
open System.IO
open System.Diagnostics
open System.Threading.Tasks
open Org.BouncyCastle.Tls
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

    let getFirmwarePath () : string =
        let xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME")
        let primaryPath =
            let baseDir =
                if not (String.IsNullOrWhiteSpace xdg) then xdg
                else Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share")
            Path.Combine(baseDir, "goodix-fp", "GF5298_GM168SEC_APP_13016.bin")
        if File.Exists primaryPath then primaryPath
        elif File.Exists "/home/vladimir/.local/share/goodix-fp/GF5298_GM168SEC_APP_13016.bin" then
            "/home/vladimir/.local/share/goodix-fp/GF5298_GM168SEC_APP_13016.bin"
        else primaryPath

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
        | "benchmark" :: rest | "bench" :: rest ->
            parseOptions rest { opts with Command = "benchmark" }
        | "probe" :: rest ->
            parseOptions rest { opts with Command = "probe" }
        | "diagnose" :: rest ->
            parseOptions rest { opts with Command = "diagnose" }
        | "provision-psk" :: rest ->
            parseOptions rest { opts with Command = "provision-psk" }
        | "calibrate" :: rest ->
            let (prefix, remaining) =
                match rest with
                | p :: r when not (p.StartsWith("-")) -> (Some p, r)
                | _ -> (None, rest)
            parseOptions remaining { opts with Command = "calibrate"; Prefix = prefix }
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
        | "test-merge" :: raw :: rest ->
            let (calib, remaining) =
                match rest with
                | c :: r when not (c.StartsWith("-")) -> (Some c, r)
                | _ -> (None, rest)
            parseOptions remaining { opts with Command = "test-merge"; Prefix = Some raw; FingerName = calib }
        | "test-merge" :: rest ->
            parseOptions rest { opts with Command = "test-merge" }
        | unknown :: _ ->
            Error $"Unknown command or argument '{unknown}'. Run 'goodix-fp help' for usage."

    and private parseOptions (args: string list) (opts: CliOptions) : Result<CliOptions, string> =
        match args with
        | [] -> Ok opts
        | "--calibrate-only" :: rest ->
            parseOptions rest { opts with Command = "calibrate" }
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

    let withMatcher (baseline: RawFrame12Bit option) (action: GoodixTodMatcher -> Task<int>) : Task<int> = task {
        match GoodixTodMatcher.Create(?baseline = baseline) with
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

    let runDiagnose (opts: CliOptions) : Task<int> =
        printfn $"[*] Running diagnostic raw probe on device (VID: 0x{opts.Vid:X4}, PID: 0x{opts.Pid:X4})..."
        withDevice opts (fun dev -> task {
            let testCommand (name: string) (packet: byte[]) =
                printfn $"\n--- Testing {name} ---"
                printfn $"Tx ({packet.Length} bytes): {Convert.ToHexString(packet)}"
                match dev.Transport.Write(packet) with
                | Error e -> printfn $"Tx Error: {e}"
                | Ok () ->
                    match dev.Transport.Read(1024, 2000) with
                    | Ok rx ->
                        printfn $"Rx ({rx.Length} bytes): {Convert.ToHexString(rx)}"
                        if rx.Length >= 6 && rx.[4] = 0xb0uy then
                            match dev.Transport.Read(1024, 2000) with
                            | Ok rx2 -> printfn $"Rx2 ({rx2.Length} bytes): {Convert.ToHexString(rx2)}"
                            | Error e -> printfn $"Rx2 Error: {e}"
                    | Error e -> printfn $"Rx Error: {e}"

            testCommand "NOP" (Protocol.packNop())

            let mcuStatePack = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol 0x2cuy [| 0x01uy; 0x00uy |] true)
            testCommand "Query MCU State (0x2c)" mcuStatePack

            testCommand "Firmware Version (0xa8)" (Protocol.packFirmwareVersion())

            let iapVerPack = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol (Protocol.encodeMessageProtocol 0xf6uy [| 50uy; 0x00uy |] true)
            testCommand "Get IAP Version (0xf6)" iapVerPack

            testCommand "Read PSK 0xbb020001 (len 32)" (Protocol.packPresetPskRead 0xbb020001u 32 0)

            testCommand "Read PSK 0xbb010002 (len 256)" (Protocol.packPresetPskRead 0xbb010002u 256 0)

            testCommand "Read PSK 0xbb010003 (len 96)" (Protocol.packPresetPskRead 0xbb010003u 96 0)

            testCommand "Read PSK 0xbb010003 (len 114)" (Protocol.packPresetPskRead 0xbb010003u 114 0)

            testCommand "Read PSK 0xbb010003 (len 128)" (Protocol.packPresetPskRead 0xbb010003u 128 0)

            let! r03_96 = dev.ReadPresetPsk(0xbb010003u, 96, 0)
            match r03_96 with
            | Ok p -> printfn $"\ndev.ReadPresetPsk(0xbb010003, 96, 0) -> OK ({p.Length} bytes): {Convert.ToHexString(p)}"
            | Error e -> printfn $"\ndev.ReadPresetPsk(0xbb010003, 96, 0) -> Error: {e}"

            let! r03_114 = dev.ReadPresetPsk(0xbb010003u, 114, 0)
            match r03_114 with
            | Ok p -> printfn $"dev.ReadPresetPsk(0xbb010003, 114, 0) -> OK ({p.Length} bytes): {Convert.ToHexString(p)}"
            | Error e -> printfn $"dev.ReadPresetPsk(0xbb010003, 114, 0) -> Error: {e}"

            let! r03_128 = dev.ReadPresetPsk(0xbb010003u, 128, 0)
            match r03_128 with
            | Ok p -> printfn $"dev.ReadPresetPsk(0xbb010003, 128, 0) -> OK ({p.Length} bytes): {Convert.ToHexString(p)}"
            | Error e -> printfn $"dev.ReadPresetPsk(0xbb010003, 128, 0) -> Error: {e}"

            return 0
        })


    let runProvisionPsk (opts: CliOptions) : Task<int> =
        let fwPath = Storage.getFirmwarePath ()
        printfn $"[*] Loading firmware image from: {fwPath}"
        if not (File.Exists fwPath) then
            eprintfn $"[!] Firmware file not found: {fwPath}"
            eprintfn "    Please run 'scripts/fetch-goodix-blob.sh' to extract the firmware first."
            Task.FromResult 1
        else
            let firmwareBytes = File.ReadAllBytes fwPath
            match Protocol.verifyFirmwareImage firmwareBytes with
            | Error err ->
                eprintfn $"[!] Firmware verification failed: {err}"
                Task.FromResult 1
            | Ok () ->
                printfn $"[+] Firmware verified: {firmwareBytes.Length} bytes, header and ARM code CRCs valid."
                printfn $"[*] Provisioning PSK White-Box on device (VID: 0x{opts.Vid:X4}, PID: 0x{opts.Pid:X4})..."
                withDevice opts (fun dev -> task {
                    let! pskRes = dev.ProvisionZeroPsk(firmwareBytes)
                    match pskRes with
                    | Error err ->
                        eprintfn $"[!] PSK provisioning failed: {err}"
                        return 1
                    | Ok () ->
                        printfn "[+] PSK White-Box successfully provisioned and verified (in APP mode)."
                        return 0
                })

    let runCalibrate (opts: CliOptions) : Task<int> =
        let prefix = defaultArg opts.Prefix "calib"
        let tlsEngine = if opts.UseBouncyCastle then "BouncyCastle" else "Pure F#"
        printfn $"[*] Initializing calibration session (TLS: {tlsEngine})..."
        withDevice opts (fun dev -> task {
            printfn "[*] Activating session and performing TLS handshake..."
            let! actRes = dev.ActivateSession()
            match actRes with
            | Error err ->
                eprintfn $"[!] Session activation failed: {err}"
                return 1
            | Ok _ ->
                printfn "[*] Baseline calibration frame captured during ActivateSession (no touch)..."
                let! rawFrame = task {
                    match dev.BaselineFrame with
                    | Some b -> return b
                    | None ->
                        let! capRes = dev.CaptureFrame()
                        match capRes with
                        | Ok f -> return f
                        | Error err -> return failwith $"Failed to capture frame: {err}"
                }
                let! _ = dev.Sleep()
                let rawPgm = FrameDecoder.toPgm12Bit rawFrame.Pixels 80 64
                let outPath = $"{prefix}-baseline16.pgm"
                let dir = Path.GetDirectoryName(outPath)
                if not (String.IsNullOrWhiteSpace dir) && not (Directory.Exists dir) then
                    Directory.CreateDirectory(dir) |> ignore
                File.WriteAllBytes(outPath, rawPgm)
                printfn $"[+] Verified GoodixFrameCrc on {rawPgm.Length} bytes frame payload."
                printfn $"[+] Saved baseline 16-bit PGM image: {outPath}"
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
                return! withMatcher dev.BaselineFrame (fun matcher -> task {
                    match matcher.StartEnroll() with
                    | Error err ->
                        eprintfn $"[!] Start enrollment failed: {err}"
                        return 1
                    | Ok () ->
                        let mutable enrolledCount = 0
                        let mutable failure = false

                        while enrolledCount < 12 && not failure do
                            printf $"--> [{enrolledCount + 1}/12] Place finger on sensor: "
                            Console.Out.Flush()
                            let! downRes = dev.WaitForFingerDown(timeoutMs = 20000)
                            match downRes with
                            | Error err ->
                                eprintfn $"\n[!] Timed out waiting for touch: {err}"
                                failure <- true
                            | Ok () ->
                                printf "Capturing... "
                                Console.Out.Flush()
                                let! capRes = dev.CaptureFrame()
                                match capRes with
                                | Error err ->
                                    eprintfn $"\n[!] Capture failed: {err}"
                                    failure <- true
                                | Ok frame ->
                                    let hasTouch =
                                        match dev.BaselineFrame with
                                        | None -> true
                                        | Some b ->
                                            let mutable sigCount = 0
                                            for i in 0 .. frame.Pixels.Length - 1 do
                                                if abs (int frame.Pixels.[i] - int b.Pixels.[i]) > 30 then
                                                    sigCount <- sigCount + 1
                                            sigCount > 50

                                    if not hasTouch then
                                        printfn "(transient noise, retrying...)"
                                    else
                                        printf "Lift finger... "
                                        Console.Out.Flush()
                                        let mutable fingerLifted = false
                                        while not fingerLifted && not failure do
                                            let! upRes = dev.WaitForFingerUp(timeoutMs = 5000)
                                            match upRes with
                                            | Ok () ->
                                                fingerLifted <- true
                                            | Error (UsbError (_, -7)) ->
                                                printf "(still holding, please lift)... "
                                                Console.Out.Flush()
                                            | Error err ->
                                                eprintfn $"\n[!] Finger up detection failed: {err}"
                                                failure <- true

                                        if fingerLifted then
                                            printfn "OK"
                                            if enrolledCount = 0 then
                                                try
                                                    let dir = "/tmp/goodix-fp"
                                                    if not (Directory.Exists dir) then Directory.CreateDirectory dir |> ignore
                                                    let sampleRawPgm = FrameDecoder.toPgm12Bit frame.Pixels 80 64
                                                    File.WriteAllBytes(Path.Combine(dir, "enroll-sample1-raw16.pgm"), sampleRawPgm)
                                                    match matcher.Preprocess(frame) with
                                                    | Ok p ->
                                                        let enhPgm = FrameDecoder.toPgm8Bit p.NormalizedPixels 80 64
                                                        File.WriteAllBytes(Path.Combine(dir, "enroll-sample1-enhanced8.pgm"), enhPgm)
                                                    | _ -> ()
                                                with _ -> ()

                                            match matcher.MergeSample(frame.Pixels) with
                                            | Error err ->
                                                eprintfn $"[!] Touch rejected ({err}), please try step [{enrolledCount + 1}/12] again..."
                                            | Ok count ->
                                                enrolledCount <- count
                                                printfn $"[+] Sample [{enrolledCount}/12] accepted!"
                                                Console.Out.Flush()

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
                    Console.Out.Flush()
                    let! downRes = dev.WaitForFingerDown(timeoutMs = 15000)
                    match downRes with
                    | Error _ ->
                        eprintfn "[!] Verification timed out waiting for touch."
                        return 1
                    | Ok () ->
                        printfn "[*] Finger detected. Capturing probe..."
                        Console.Out.Flush()
                        let! capRes = dev.CaptureFrame()
                        match capRes with
                        | Error err ->
                            eprintfn $"[!] Frame capture failed: {err}"
                            return 1
                        | Ok frame ->
                            let! _ = dev.WaitForFingerUp(timeoutMs = 3000)
                            let! _ = dev.Sleep()

                            return! withMatcher dev.BaselineFrame (fun matcher -> task {
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

    let runBenchmarkSync () : int =
        printfn "================================================================="
        printfn "  Goodix FP Benchmark Suite (.NET 10 Native AOT / Linux-x64)"
        printfn "=================================================================\n"

        // --------------------------------------------------------------------
        // [1/5] TLS 1.2 PSK Handshake: Pure F# vs BouncyCastle (200 iterations)
        // --------------------------------------------------------------------
        printfn "[1/5] TLS 1.2 PSK Handshake (200 iterations):"
        let psk = Array.zeroCreate<byte> 32

        // Warmup Pure F#
        for _ in 1 .. 5 do
            let client = new TlsClientProtocol()
            client.Connect(TestPskTlsClient(psk))
            use server = new PureFSharpTlsPskTunnel(psk)
            let chLen = client.GetAvailableOutputBytes()
            let chBuf = Array.zeroCreate<byte> chLen
            client.ReadOutput(chBuf, 0, chLen) |> ignore
            let shBytes = ((server :> ITlsPskTunnel).HandleHandshake(chBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
            client.OfferInput(shBytes)
            let cFlightLen = client.GetAvailableOutputBytes()
            let cFlightBuf = Array.zeroCreate<byte> cFlightLen
            client.ReadOutput(cFlightBuf, 0, cFlightLen) |> ignore
            let sfBytes = ((server :> ITlsPskTunnel).HandleHandshake(cFlightBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
            client.OfferInput(sfBytes)

        let swPureHs = Stopwatch.StartNew()
        for _ in 1 .. 200 do
            let client = new TlsClientProtocol()
            client.Connect(TestPskTlsClient(psk))
            use server = new PureFSharpTlsPskTunnel(psk)
            let chLen = client.GetAvailableOutputBytes()
            let chBuf = Array.zeroCreate<byte> chLen
            client.ReadOutput(chBuf, 0, chLen) |> ignore
            let shBytes = ((server :> ITlsPskTunnel).HandleHandshake(chBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
            client.OfferInput(shBytes)
            let cFlightLen = client.GetAvailableOutputBytes()
            let cFlightBuf = Array.zeroCreate<byte> cFlightLen
            client.ReadOutput(cFlightBuf, 0, cFlightLen) |> ignore
            let sfBytes = ((server :> ITlsPskTunnel).HandleHandshake(cFlightBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
            client.OfferInput(sfBytes)
        swPureHs.Stop()

        let usPureHs = float swPureHs.ElapsedTicks * 1_000_000.0 / float Stopwatch.Frequency / 200.0
        let opsPureHs = 200.0 / swPureHs.Elapsed.TotalSeconds
        printfn $"  Pure F# RFC 4279/5246 : {usPureHs,7:F1} us/op | {opsPureHs,7:F1} handshakes/sec"

        // Warmup BouncyCastle
        for _ in 1 .. 5 do
            let client = new TlsClientProtocol()
            client.Connect(TestPskTlsClient(psk))
            use server = new BouncyCastleTlsPskTunnel(psk)
            let pump () =
                let cAvail = client.GetAvailableOutputBytes()
                if cAvail > 0 then
                    let cBuf = Array.zeroCreate<byte> cAvail
                    client.ReadOutput(cBuf, 0, cAvail) |> ignore
                    match (server :> ITlsPskTunnel).HandleHandshake(cBuf) with
                    | Ok (Some sResp) -> client.OfferInput(sResp)
                    | _ -> ()
            let mutable iters = 0
            while (not client.IsConnected || not (server :> ITlsPskTunnel).IsHandshakeComplete) && iters < 10 do
                pump ()
                iters <- iters + 1

        let swBcHs = Stopwatch.StartNew()
        for _ in 1 .. 200 do
            let client = new TlsClientProtocol()
            client.Connect(TestPskTlsClient(psk))
            use server = new BouncyCastleTlsPskTunnel(psk)
            let pump () =
                let cAvail = client.GetAvailableOutputBytes()
                if cAvail > 0 then
                    let cBuf = Array.zeroCreate<byte> cAvail
                    client.ReadOutput(cBuf, 0, cAvail) |> ignore
                    match (server :> ITlsPskTunnel).HandleHandshake(cBuf) with
                    | Ok (Some sResp) -> client.OfferInput(sResp)
                    | _ -> ()
            let mutable iters = 0
            while (not client.IsConnected || not (server :> ITlsPskTunnel).IsHandshakeComplete) && iters < 10 do
                pump ()
                iters <- iters + 1
        swBcHs.Stop()

        let usBcHs = float swBcHs.ElapsedTicks * 1_000_000.0 / float Stopwatch.Frequency / 200.0
        let opsBcHs = 200.0 / swBcHs.Elapsed.TotalSeconds
        let speedupHs = usBcHs / usPureHs
        printfn $"  BouncyCastle (Native) : {usBcHs,7:F1} us/op | {opsBcHs,7:F1} handshakes/sec"
        printfn $"  Speedup (Pure vs BC)  : {speedupHs:F2}x faster\n"

        // --------------------------------------------------------------------
        // [2/5] TLS 7,684-byte Frame Decryption (5,000 iterations)
        // --------------------------------------------------------------------
        printfn "[2/5] TLS 7,684-byte Frame Decryption (5,000 iterations):"
        let frame7684 = Array.init 7684 (fun i -> byte (i &&& 0xff))

        let pureDecClient = new TlsClientProtocol()
        pureDecClient.Connect(TestPskTlsClient(psk))
        use pureDecServer = new PureFSharpTlsPskTunnel(psk)

        let chDecLen = pureDecClient.GetAvailableOutputBytes()
        let chDecBuf = Array.zeroCreate<byte> chDecLen
        pureDecClient.ReadOutput(chDecBuf, 0, chDecLen) |> ignore
        let shDecBytes = ((pureDecServer :> ITlsPskTunnel).HandleHandshake(chDecBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
        pureDecClient.OfferInput(shDecBytes)

        let cfDecLen = pureDecClient.GetAvailableOutputBytes()
        let cfDecBuf = Array.zeroCreate<byte> cfDecLen
        pureDecClient.ReadOutput(cfDecBuf, 0, cfDecLen) |> ignore
        let sfDecBytes = ((pureDecServer :> ITlsPskTunnel).HandleHandshake(cfDecBuf) |> Result.defaultWith (fun e -> failwith (string e))).Value
        pureDecClient.OfferInput(sfDecBytes)

        pureDecClient.WriteApplicationData(frame7684, 0, frame7684.Length)
        let appDecLen = pureDecClient.GetAvailableOutputBytes()
        let appDecBuf = Array.zeroCreate<byte> appDecLen
        pureDecClient.ReadOutput(appDecBuf, 0, appDecLen) |> ignore

        let encryptedPayloadForPure = Array.concat [
            [| 0xb2uy; 0x00uy; 0x20uy; 0xd2uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |]
            appDecBuf
        ]

        // Warmup
        for _ in 1 .. 50 do
            pureDecServer.ResetClientSeqNum()
            (pureDecServer :> ITlsPskTunnel).DecryptApplicationData(encryptedPayloadForPure) |> ignore

        let swDec = Stopwatch.StartNew()
        for _ in 1 .. 5000 do
            pureDecServer.ResetClientSeqNum()
            match (pureDecServer :> ITlsPskTunnel).DecryptApplicationData(encryptedPayloadForPure) with
            | Ok plain -> ()
            | Error err -> failwith $"Decryption failed: {err}"
        swDec.Stop()

        let usDec = float swDec.ElapsedTicks * 1_000_000.0 / float Stopwatch.Frequency / 5000.0
        let fpsDec = 5000.0 / swDec.Elapsed.TotalSeconds
        let mbsDec = (float (5000L * 7684L) / (1024.0 * 1024.0)) / swDec.Elapsed.TotalSeconds
        printfn $"  Pure F# Decrypt       : {usDec,7:F1} us/frame | {mbsDec,7:F1} MB/s | {fpsDec,7:F1} frames/sec\n"

        // --------------------------------------------------------------------
        // [3/5] FrameDecoder 80x64 Unpack & Transpose (20,000 iterations)
        // --------------------------------------------------------------------
        printfn "[3/5] FrameDecoder 80x64 Unpack & Transpose (20,000 iterations):"
        let packed = Array.zeroCreate<byte> FrameDecoder.PackedFrameSize
        let rnd = Random(12345)
        rnd.NextBytes(packed)
        let spanDest = Array.zeroCreate<uint16> FrameDecoder.PixelCount

        // Warmup
        for _ in 1 .. 100 do
            FrameDecoder.unpackSequential packed |> ignore
            FrameDecoder.unpackAndTranspose80x64 packed |> ignore
            FrameDecoder.unpackAndTranspose80x64Span (ReadOnlySpan packed) (Span spanDest) |> ignore

        let swSeq = Stopwatch.StartNew()
        for _ in 1 .. 20000 do
            FrameDecoder.unpackSequential packed |> ignore
        swSeq.Stop()
        let usSeq = float swSeq.ElapsedTicks * 1_000_000.0 / float Stopwatch.Frequency / 20000.0
        let fpsSeq = 20000.0 / swSeq.Elapsed.TotalSeconds
        printfn $"  Sequential Array      : {usSeq,7:F1} us/frame | {fpsSeq,7:F1} FPS"

        let swTransArr = Stopwatch.StartNew()
        for _ in 1 .. 20000 do
            FrameDecoder.unpackAndTranspose80x64 packed |> ignore
        swTransArr.Stop()
        let usTransArr = float swTransArr.ElapsedTicks * 1_000_000.0 / float Stopwatch.Frequency / 20000.0
        let fpsTransArr = 20000.0 / swTransArr.Elapsed.TotalSeconds
        printfn $"  Transpose Array       : {usTransArr,7:F1} us/frame | {fpsTransArr,7:F1} FPS"

        let pSpan = ReadOnlySpan packed
        let dSpan = Span spanDest
        let swTransSpan = Stopwatch.StartNew()
        for _ in 1 .. 20000 do
            FrameDecoder.unpackAndTranspose80x64Span pSpan dSpan |> ignore
        swTransSpan.Stop()
        let usTransSpan = float swTransSpan.ElapsedTicks * 1_000_000.0 / float Stopwatch.Frequency / 20000.0
        let fpsTransSpan = 20000.0 / swTransSpan.Elapsed.TotalSeconds
        printfn $"  Transpose Span (Zero) : {usTransSpan,7:F1} us/frame | {fpsTransSpan,7:F1} FPS\n"

        // --------------------------------------------------------------------
        // [4/5] Packet Framing & CRC32 (50,000 iterations)
        // --------------------------------------------------------------------
        printfn "[4/5] Packet Framing & CRC32 (50,000 iterations):"
        let rawConfig = Protocol.Goodix53xdConfig
        let inner = Protocol.encodeMessageProtocol Protocol.CommandUploadConfigMcu rawConfig true
        let encodedPack = Protocol.encodeMessagePack Protocol.FlagsMessageProtocol inner

        // Warmup
        for _ in 1 .. 100 do
            match encodedPack with
            | Protocol.AckResponse _ -> ()
            | Protocol.CommandResponse _ -> ()
            | Protocol.InvalidPacket _ -> ()
            Crc32.compute (ReadOnlySpan rawConfig) |> ignore

        let swAp = Stopwatch.StartNew()
        for _ in 1 .. 50000 do
            match encodedPack with
            | Protocol.AckResponse _ -> ()
            | Protocol.CommandResponse _ -> ()
            | Protocol.InvalidPacket _ -> ()
        swAp.Stop()
        let usAp = float swAp.ElapsedTicks * 1_000_000.0 / float Stopwatch.Frequency / 50000.0
        let opsAp = 50000.0 / swAp.Elapsed.TotalSeconds
        printfn $"  ActivePattern Classify: {usAp,7:F2} us/op    | {opsAp,9:F1} ops/sec"

        let configSpan = ReadOnlySpan rawConfig
        let swCrc = Stopwatch.StartNew()
        for _ in 1 .. 50000 do
            Crc32.compute configSpan |> ignore
        swCrc.Stop()
        let usCrc = float swCrc.ElapsedTicks * 1_000_000.0 / float Stopwatch.Frequency / 50000.0
        let mbsCrc = (float (50000L * int64 rawConfig.Length) / (1024.0 * 1024.0)) / swCrc.Elapsed.TotalSeconds
        printfn $"  CRC32 (7,680 bytes)   : {usCrc,7:F2} us/op    | {mbsCrc,7:F1} MB/s\n"

        // --------------------------------------------------------------------
        // [5/5] Goodix TOD Native Matcher: Preprocess & Identify (500 iterations)
        // --------------------------------------------------------------------
        printfn "[5/5] Goodix TOD Native Matcher (500 iterations):"
        let generateSyntheticRidgeFrame (shiftX: float) (shiftY: float) (noise: float) : uint16[] =
            let width = 80
            let height = 64
            let cx = 40.0 + shiftX
            let cy = 32.0 + shiftY
            let pixels = Array.zeroCreate<uint16> (width * height)
            for y in 0 .. height - 1 do
                for x in 0 .. width - 1 do
                    let dx = float x - cx
                    let dy = float y - cy
                    let r = Math.Sqrt(dx * dx + dy * dy)
                    let theta = Math.Atan2(dy, dx)
                    let ridge = Math.Cos(r * 0.8 + 2.0 * theta)
                    let rawVal = 1500.0 + 350.0 * ridge + noise * (float ((x * 17 + y * 31) % 10) - 5.0)
                    let clamped = Math.Clamp(rawVal, 0.0, 4095.0)
                    pixels.[y * width + x] <- uint16 clamped
            pixels

        match GoodixTodMatcher.Create() with
        | Error err ->
            eprintfn $"  [!] Goodix TOD native matcher not available: {err}"
        | Ok matcher ->
            use _m = matcher
            matcher.StartEnroll() |> ignore
            for i in 0 .. 11 do
                let sx = float (i % 3 - 1) * 1.5
                let sy = float (i / 3 - 2) * 1.5
                let sample = generateSyntheticRidgeFrame sx sy 1.0
                matcher.MergeSample(sample) |> ignore

            let fid = FingerId.createUnsafe "bench_finger"
            let blob = matcher.CommitTemplate(fid) |> Result.defaultWith (fun e -> failwith (string e))
            let templates = [ (fid, blob) ]
            let testFrame = generateSyntheticRidgeFrame 0.5 0.5 1.0

            // Warmup
            for _ in 1 .. 10 do
                matcher.Preprocess(testFrame) |> ignore
                matcher.IdentifyProbe(testFrame, templates) |> ignore

            let swPrep = Stopwatch.StartNew()
            for _ in 1 .. 500 do
                matcher.Preprocess(testFrame) |> ignore
            swPrep.Stop()
            let usPrep = float swPrep.ElapsedTicks * 1_000_000.0 / float Stopwatch.Frequency / 500.0
            let fpsPrep = 500.0 / swPrep.Elapsed.TotalSeconds
            printfn $"  PreProcessorUnify     : {usPrep,7:F1} us/frame | {fpsPrep,7:F1} FPS"

            let swId = Stopwatch.StartNew()
            for _ in 1 .. 500 do
                matcher.IdentifyProbe(testFrame, templates) |> ignore
            swId.Stop()
            let usId = float swId.ElapsedTicks * 1_000_000.0 / float Stopwatch.Frequency / 500.0
            let idSec = 500.0 / swId.Elapsed.TotalSeconds
            printfn $"  1:1 Probe Identify    : {usId,7:F1} us/match | {idSec,7:F1} matches/sec"

        0

    let runBenchmark () : Task<int> =
        Task.FromResult(runBenchmarkSync ())

    let runTestMerge (rawPath: string) (calibPath: string option) : Task<int> =
        task {
            let calibDesc = defaultArg calibPath "none"
            printfn $"[*] Testing offline merge of '{rawPath}' (calib: {calibDesc})..."
            if not (File.Exists rawPath) then
                eprintfn $"[!] Raw PGM file not found: {rawPath}"
                return 1
            else
                let rawBytes = File.ReadAllBytes rawPath
                let rawPixels = FrameDecoder.fromPgm12Bit rawBytes
                printfn $"[+] Loaded raw pixels: {rawPixels.Length} pixels"
                let calibPixels =
                    match calibPath with
                    | Some cp when File.Exists cp ->
                        let calibBytes = File.ReadAllBytes cp
                        let p = FrameDecoder.fromPgm12Bit calibBytes
                        printfn $"[+] Loaded calib pixels: {p.Length} pixels"
                        Some p
                    | _ -> None

                let baselineFrame =
                    match calibPixels with
                    | Some p -> RawFrame12Bit.create p |> Result.toOption
                    | None -> None

                return! withMatcher baselineFrame (fun matcher -> task {
                    printfn "[*] Calling StartEnroll()..."
                    match matcher.StartEnroll() with
                    | Error e ->
                        eprintfn $"[!] StartEnroll failed: {e}"
                        return 1
                    | Ok () ->
                        printfn "[*] Preprocessing raw frame..."
                        match matcher.Preprocess(rawPixels) with
                        | Error e ->
                            eprintfn $"[!] Preprocess failed: {e}"
                            return 1
                        | Ok prep ->
                            let nonZeroBData = prep.BData |> Array.filter ((<>) 0uy) |> Array.length
                            printfn $"[+] Preprocess succeeded: Quality={prep.Quality.Value}, Coverage={prep.Coverage.Value}, BData={prep.BData.Length} bytes ({nonZeroBData} non-zero bytes)"
                            printfn "[*] Calling MergeSample()..."
                            match matcher.MergeSample(rawPixels, prep.NormalizedPixels, prep.Quality, prep.Coverage, prep.BData) with
                            | Error e ->
                                eprintfn $"[!] MergeSample failed: {e}"
                                return 1
                            | Ok count ->
                                printfn $"[+] MergeSample succeeded! Enrolled sample count = {count}"
                                return 0
                })
        }

module Program =

    let printHelp () =
        printfn "================================================================="
        printfn "  Goodix FP Linux Driver & Matcher CLI (F# / .NET 10 Native AOT)"
        printfn "================================================================="
        printfn "Usage: goodix-fp <command> [options]\n"
        printfn "Commands:"
        printfn "  probe                     Query firmware version, chip ID, and OTP"
        printfn "  provision-psk             Write zero PSK whitebox and restore APP firmware"
        printfn "  calibrate [prefix]        Capture baseline calibration frame (no touch)"
        printfn "  capture [prefix]          Capture baseline & frame, export PGM images"
        printfn "  enroll <finger-name>      12-touch interactive enrollment loop"
        printfn "  verify                    Verify finger against enrolled templates (PAM)"
        printfn "  benchmark                 Run Native AOT performance benchmark suite"
        printfn "  test-merge <raw> [calib]  Test offline preprocessing & sample merging"
        printfn "  help                      Show this help message\n"
        printfn "Options:"
        printfn "  --calibrate-only          Run calibration capture only"
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
            | "diagnose" ->
                (DeviceRunner.runDiagnose opts).GetAwaiter().GetResult()
            | "provision-psk" ->
                (DeviceRunner.runProvisionPsk opts).GetAwaiter().GetResult()
            | "calibrate" ->
                (DeviceRunner.runCalibrate opts).GetAwaiter().GetResult()
            | "capture" ->
                (DeviceRunner.runCapture opts).GetAwaiter().GetResult()
            | "enroll" ->
                let name = opts.FingerName |> Option.defaultValue "default_finger"
                (DeviceRunner.runEnroll opts name).GetAwaiter().GetResult()
            | "verify" ->
                (DeviceRunner.runVerify opts).GetAwaiter().GetResult()
            | "benchmark" ->
                (DeviceRunner.runBenchmark ()).GetAwaiter().GetResult()
            | "test-merge" ->
                let raw = opts.Prefix |> Option.defaultValue "/tmp/goodix-fp/enroll-sample1-raw16.pgm"
                let calib = opts.FingerName
                (DeviceRunner.runTestMerge raw calib).GetAwaiter().GetResult()
            | other ->
                eprintfn $"Unrecognized command '{other}'"
                1
