namespace GoodixFp.NativeMatcher

open System
open System.IO
open System.Runtime.InteropServices
open FsToolkit.ErrorHandling
open GoodixFp.Core

// ============================================================================
// High-Level Goodix TOD Native Matcher
// ============================================================================

type GoodixTodMatcher(nativeFunctions: NativeFunctions, baselineFrame: RawFrame12Bit option) =

    let syncLock = obj()
    let mutable isDisposed = false
    let mutable enrolledSamples = 0

    // Initialize calibration and context on construction
    do
        lock syncLock (fun () ->
            let rcPpp = nativeFunctions.PppParamInit.Invoke(0x0c)
            if rcPpp <> 0 then
                failwith $"PppParamInit failed with return code {rcPpp}"

            let rcCal = nativeFunctions.PreprocessInitCalidata.Invoke()
            if rcCal <> 0 then
                failwith $"PreprocessInitCalidata failed with return code {rcCal}"

            // Setup calibration baseline frame if provided, otherwise standard dark frame
            let baseline =
                match baselineFrame with
                | Some b -> b.Pixels
                | None -> Array.create RawFrame12Bit.ExpectedPixelCount 500us

            let calibParam = Array.zeroCreate<byte> 0x30
            let bImgHandle = GCHandle.Alloc(baseline, GCHandleType.Pinned)
            try
                let bImgPtr = bImgHandle.AddrOfPinnedObject()
                BitConverter.GetBytes(int64 bImgPtr).CopyTo(calibParam, 0x18)
                BitConverter.GetBytes(64).CopyTo(calibParam, 0x24)
                BitConverter.GetBytes(80).CopyTo(calibParam, 0x28)
                let calibHandle = GCHandle.Alloc(calibParam, GCHandleType.Pinned)
                try
                    let rcPrep = nativeFunctions.PreprocessorInit.Invoke(calibHandle.AddrOfPinnedObject())
                    if rcPrep <> 0 then
                        failwith $"PreprocessorInit failed with return code {rcPrep}"
                finally
                    calibHandle.Free()
            finally
                bImgHandle.Free()

            // Setup algorithm configuration block (series=2, sensor_type=12, w=80, h=64)
            let param = Array.zeroCreate<byte> 24
            BitConverter.GetBytes(2).CopyTo(param, 0)
            param.[4] <- 0x0cuy
            BitConverter.GetBytes(80us).CopyTo(param, 8)
            BitConverter.GetBytes(64us).CopyTo(param, 10)
            let paramHandle = GCHandle.Alloc(param, GCHandleType.Pinned)
            try
                let rcCfg = nativeFunctions.CreateAlgConfig.Invoke(paramHandle.AddrOfPinnedObject())
                if rcCfg <> 1 then
                    failwith $"CreateAlgConfig failed with return code {rcCfg}"
            finally
                paramHandle.Free()

            // Relax overlay ratio constraints in global config block
            let algConfigAddr = nativeint (int64 nativeFunctions.LibraryBase + 0x2490b0L)
            Marshal.WriteInt32(algConfigAddr, 0x60, 100)
            Marshal.WriteInt32(algConfigAddr, 0x64, 100)

            let rcCtx = nativeFunctions.AlgCreateContextInterface.Invoke(algConfigAddr, 0x68, 0UL)
            if rcCtx <> 0u then
                failwith $"AlgCreateContextInterface failed with return code {rcCtx}"
        )

    member this.NativeFunctions = nativeFunctions

    // ------------------------------------------------------------------------
    // Packet Formatting (0x1af28 bytes expected by AlgFormatImageInterface)
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // Packet Formatting (0x1af28 bytes expected by AlgFormatImageInterface)
    // ------------------------------------------------------------------------

    static member FormatImagePacket(rawPixels: uint16[], enhancedPixels: byte[], quality: byte, coverage: byte, ?bData: byte[]) : byte[] =
        let pkt = Array.zeroCreate<byte> 0x1af28
        pkt.[0] <- 0x4auy
        BitConverter.GetBytes(80us).CopyTo(pkt, 2)
        BitConverter.GetBytes(64us).CopyTo(pkt, 4)
        BitConverter.GetBytes(0x01080000u).CopyTo(pkt, 6)
        BitConverter.GetBytes(5120u).CopyTo(pkt, 0x10)
        BitConverter.GetBytes(10240u).CopyTo(pkt, 0x14)
        BitConverter.GetBytes(1us).CopyTo(pkt, 0x18)
        pkt.[0x20] <- quality
        pkt.[0x21] <- coverage
        BitConverter.GetBytes(0x696d6773u).CopyTo(pkt, 0x24) // 'imgs' magic

        Buffer.BlockCopy(rawPixels, 0, pkt, 0x28, 10240)
        Buffer.BlockCopy(enhancedPixels, 0, pkt, 0xec18, 5120)
        match bData with
        | Some b when b.Length = PreprocessedFrame.BDataSize ->
            Buffer.BlockCopy(b, 0, pkt, 0x16210, PreprocessedFrame.BDataSize)
        | _ -> ()
        pkt

    // ------------------------------------------------------------------------
    // Preprocessing: Image Enhancement and Quality Assessment
    // ------------------------------------------------------------------------

    static member ComputeQualityAndCoverage(pixels: uint16[]) : QualityScore * CoverageScore =
        if isNull pixels || pixels.Length = 0 then
            (QualityScore.createUnsafe 0, CoverageScore.createUnsafe 0)
        else
            let mutable minVal = 0xffffus
            let mutable maxVal = 0x0000us
            let mutable sum = 0L
            for p in pixels do
                if p < minVal then minVal <- p
                if p > maxVal then maxVal <- p
                sum <- sum + int64 p

            let mean = double sum / double pixels.Length
            let mutable varSum = 0.0
            let mutable activeCount = 0
            for p in pixels do
                let diff = double p - mean
                varSum <- varSum + diff * diff
                if Math.Abs(diff) > 40.0 then activeCount <- activeCount + 1

            let stdDev = Math.Sqrt(varSum / double pixels.Length)
            let quality = Math.Clamp(int (stdDev * 100.0 / 250.0), 10, 100)
            let coverage = Math.Clamp(int (double activeCount * 100.0 / double pixels.Length), 10, 100)
            (QualityScore.createUnsafe quality, CoverageScore.createUnsafe coverage)

    member this.PreprocessNative(raw: RawFrame12Bit) : Result<PreprocessedFrame, DriverError> =
        lock syncLock (fun () ->
            try
                let rawPixels =
                    match baselineFrame with
                    | Some b when b.Pixels.Length = raw.Pixels.Length ->
                        Array.init raw.Pixels.Length (fun i -> uint16 (max 0 (int raw.Pixels.[i] - int b.Pixels.[i])))
                    | _ -> raw.Pixels
                let bData = Array.zeroCreate<byte> PreprocessedFrame.BDataSize
                let inStruct = Array.zeroCreate<byte> 0x40
                let outStruct = Array.zeroCreate<byte> 0x40
                let qualCov = Array.zeroCreate<int32> 2
                let temp1 = Array.zeroCreate<byte> 65536
                let temp2 = Array.zeroCreate<byte> 65536

                let rawHandle = GCHandle.Alloc(rawPixels, GCHandleType.Pinned)
                let bDataHandle = GCHandle.Alloc(bData, GCHandleType.Pinned)
                let inHandle = GCHandle.Alloc(inStruct, GCHandleType.Pinned)
                let outHandle = GCHandle.Alloc(outStruct, GCHandleType.Pinned)
                let qcHandle = GCHandle.Alloc(qualCov, GCHandleType.Pinned)
                let t1Handle = GCHandle.Alloc(temp1, GCHandleType.Pinned)
                let t2Handle = GCHandle.Alloc(temp2, GCHandleType.Pinned)

                try
                    let rawPtr = rawHandle.AddrOfPinnedObject()
                    let bDataPtr = bDataHandle.AddrOfPinnedObject()

                    BitConverter.GetBytes(int64 rawPtr).CopyTo(inStruct, 0)
                    BitConverter.GetBytes(80).CopyTo(inStruct, 0x10)
                    BitConverter.GetBytes(5120 * 2).CopyTo(inStruct, 0x14)
                    BitConverter.GetBytes(64us).CopyTo(inStruct, 0x18)

                    BitConverter.GetBytes(int64 bDataPtr).CopyTo(outStruct, 0)
                    BitConverter.GetBytes(PreprocessedFrame.BDataSize).CopyTo(outStruct, 0x14)

                    let rc =
                        nativeFunctions.PreProcessorUnify.Invoke(
                            inHandle.AddrOfPinnedObject(),
                            t1Handle.AddrOfPinnedObject(),
                            t2Handle.AddrOfPinnedObject(),
                            outHandle.AddrOfPinnedObject(),
                            qcHandle.AddrOfPinnedObject(),
                            0u,
                            qcHandle.AddrOfPinnedObject(),
                            0uy,
                            0uy
                        )

                    let (qCalc, cCalc) = GoodixTodMatcher.ComputeQualityAndCoverage rawPixels
                    let q =
                        if rc = 0 && qualCov.[0] > 0 then QualityScore.createUnsafe (Math.Clamp(qualCov.[0], 25, 100))
                        else QualityScore.createUnsafe (Math.Clamp(qCalc.Value, 25, 100))
                    let c =
                        if rc = 0 && qualCov.[1] > 0 then CoverageScore.createUnsafe (Math.Clamp(qualCov.[1], 25, 100))
                        else CoverageScore.createUnsafe (Math.Clamp(cCalc.Value, 25, 100))
                    let finalPixels = FrameDecoder.squash12To8BitLinear rawPixels
                    PreprocessedFrame.create finalPixels bData q c
                finally
                    rawHandle.Free()
                    bDataHandle.Free()
                    inHandle.Free()
                    outHandle.Free()
                    qcHandle.Free()
                    t1Handle.Free()
                    t2Handle.Free()
            with ex ->
                Error (InternalError ex)
        )

    member this.Preprocess(raw: RawFrame12Bit) : Result<PreprocessedFrame, DriverError> =
        match this.PreprocessNative(raw) with
        | Ok prep when prep.Quality.Value > 0 && prep.Coverage.Value > 0 -> Ok prep
        | _ ->
            lock syncLock (fun () ->
                try
                    let rawPixels =
                        match baselineFrame with
                        | Some b when b.Pixels.Length = raw.Pixels.Length ->
                            Array.init raw.Pixels.Length (fun i -> uint16 (max 0 (int raw.Pixels.[i] - int b.Pixels.[i])))
                        | _ -> raw.Pixels
                    let (qual, cov) = GoodixTodMatcher.ComputeQualityAndCoverage rawPixels
                    let q = QualityScore.createUnsafe (Math.Clamp(qual.Value, 25, 100))
                    let c = CoverageScore.createUnsafe (Math.Clamp(cov.Value, 25, 100))
                    let finalPixels = FrameDecoder.squash12To8BitLinear rawPixels
                    let bData = Array.zeroCreate<byte> PreprocessedFrame.BDataSize
                    PreprocessedFrame.create finalPixels bData q c
                with ex ->
                    Error (InternalError ex)
            )

    member this.Preprocess(pixels: uint16[]) : Result<PreprocessedFrame, DriverError> =
        result {
            let! raw = RawFrame12Bit.create pixels
            return! this.Preprocess(raw)
        }

    // ------------------------------------------------------------------------
    // Multi-Sample Enrollment Session
    // ------------------------------------------------------------------------

    member this.StartEnroll() : Result<unit, DriverError> =
        lock syncLock (fun () ->
            try
                enrolledSamples <- 0
                let rc = nativeFunctions.AlgEnrollstartInterface.Invoke()
                if rc = 0 then Ok ()
                else Error (ProtocolError $"AlgEnrollstartInterface failed with code {rc}")
            with ex ->
                Error (InternalError ex)
        )

    member this.MergeSample(rawPixels: uint16[], enhancedPixels: byte[], quality: QualityScore, coverage: CoverageScore, ?bData: byte[]) : Result<int, DriverError> =
        lock syncLock (fun () ->
            try
                let q = byte (Math.Clamp(quality.Value, 25, 100))
                let c = byte (Math.Clamp(coverage.Value, 25, 100))
                let pkt = GoodixTodMatcher.FormatImagePacket(rawPixels, enhancedPixels, q, c, ?bData = bData)

                let pktHandle = GCHandle.Alloc(pkt, GCHandleType.Pinned)
                try
                    let rcFmt = nativeFunctions.AlgFormatImageInterface.Invoke(pktHandle.AddrOfPinnedObject())
                    if rcFmt <> 0 then
                        Error (ProtocolError $"AlgFormatImageInterface failed with code {rcFmt}")
                    else
                        let sampleCount = Array.zeroCreate<byte> 1
                        let maxSamples = Array.zeroCreate<byte> 1
                        let scHandle = GCHandle.Alloc(sampleCount, GCHandleType.Pinned)
                        let msHandle = GCHandle.Alloc(maxSamples, GCHandleType.Pinned)
                        try
                            let rcMerge = nativeFunctions.AlgMergeFeatureInterface.Invoke(scHandle.AddrOfPinnedObject(), msHandle.AddrOfPinnedObject())
                            if rcMerge <> 0 then
                                Error (ProtocolError $"AlgMergeFeatureInterface failed with code {rcMerge}")
                            else
                                let rcStatus = nativeFunctions.AlgUpdateEnrollstatusInterface.Invoke()
                                if rcStatus = 0 then
                                    enrolledSamples <- 12
                                    Ok 12
                                elif rcStatus = 0x800001 then
                                    enrolledSamples <- enrolledSamples + 1
                                    Ok enrolledSamples
                                else
                                    Error (ProtocolError $"Unexpected status from AlgUpdateEnrollstatusInterface: 0x{rcStatus:x8}")
                        finally
                            scHandle.Free()
                            msHandle.Free()
                finally
                    pktHandle.Free()
            with ex ->
                Error (InternalError ex)
        )

    member this.MergeSample(rawPixels: uint16[]) : Result<int, DriverError> =
        result {
            let! prep = this.Preprocess(rawPixels)
            return! this.MergeSample(rawPixels, prep.NormalizedPixels, prep.Quality, prep.Coverage, prep.BData)
        }

    member this.CommitTemplate(?fingerId: FingerId) : Result<TemplateBlob, DriverError> =
        let fid = defaultArg fingerId (FingerId.createUnsafe "finger1")
        lock syncLock (fun () ->
            try
                let tmplSize = nativeFunctions.AlgGetTemplateSizeInterface.Invoke(0xf0uy, IntPtr.Zero)
                if tmplSize <= 0 then
                    Error (ProtocolError $"Invalid template size from AlgGetTemplateSizeInterface: {tmplSize}")
                else
                    let tmplBuf = Array.zeroCreate<byte> tmplSize
                    let fidBytes = System.Text.Encoding.ASCII.GetBytes(fid.Value)
                    let fidBuf = Array.zeroCreate<byte> 32
                    Buffer.BlockCopy(fidBytes, 0, fidBuf, 0, Math.Min(32, fidBytes.Length))

                    let tmplHandle = GCHandle.Alloc(tmplBuf, GCHandleType.Pinned)
                    let fidHandle = GCHandle.Alloc(fidBuf, GCHandleType.Pinned)
                    try
                        let rcCommit =
                            nativeFunctions.AlgCommitTemplateInterface.Invoke(
                                tmplHandle.AddrOfPinnedObject(),
                                uint32 tmplSize,
                                0xf0uy,
                                fidHandle.AddrOfPinnedObject(),
                                32u
                            )
                        if rcCommit <> 0 then
                            Error (ProtocolError $"AlgCommitTemplateInterface failed with code {rcCommit}")
                        else
                            let _ = nativeFunctions.AlgEnrollFinishInterface.Invoke()
                            let _ = nativeFunctions.AlgClearContextInterface.Invoke()
                            TemplateBlob.create tmplBuf
                    finally
                        tmplHandle.Free()
                        fidHandle.Free()
            with ex ->
                Error (InternalError ex)
        )

    // ------------------------------------------------------------------------
    // Feature Identification / Match Probe
    // ------------------------------------------------------------------------

    member this.IdentifyProbe(rawPixels: uint16[], enhancedPixels: byte[], templateBlob: byte[], quality: byte, coverage: byte, ?bData: byte[]) : Result<bool * int, DriverError> =
        lock syncLock (fun () ->
            try
                let pkt = GoodixTodMatcher.FormatImagePacket(rawPixels, enhancedPixels, quality, coverage, ?bData = bData)
                let pktHandle = GCHandle.Alloc(pkt, GCHandleType.Pinned)
                try
                    let rcFmt = nativeFunctions.AlgFormatImageInterface.Invoke(pktHandle.AddrOfPinnedObject())
                    if rcFmt <> 0 then
                        Error (ProtocolError $"AlgFormatImageInterface probe failed with code {rcFmt}")
                    else
                        let matchResult = Array.zeroCreate<int32> 1
                        let matchedIdx = Array.zeroCreate<int32> 1
                        let mrHandle = GCHandle.Alloc(matchResult, GCHandleType.Pinned)
                        let miHandle = GCHandle.Alloc(matchedIdx, GCHandleType.Pinned)
                        let tmplHandle = GCHandle.Alloc(templateBlob, GCHandleType.Pinned)
                        try
                            let rcId =
                                nativeFunctions.AlgIdentifyFeatureSetInterface.Invoke(
                                    tmplHandle.AddrOfPinnedObject(),
                                    uint32 templateBlob.Length,
                                    mrHandle.AddrOfPinnedObject(),
                                    0u,
                                    1u,
                                    miHandle.AddrOfPinnedObject()
                                )
                            let _ = nativeFunctions.AlgClearContextInterface.Invoke()
                            let isMatch = (matchResult.[0] = 1 && rcId = 0)
                            Ok (isMatch, matchedIdx.[0])
                        finally
                            mrHandle.Free()
                            miHandle.Free()
                            tmplHandle.Free()
                finally
                    pktHandle.Free()
            with ex ->
                Error (InternalError ex)
        )

    member this.IdentifyProbe(rawPixels: uint16[], templates: (FingerId * TemplateBlob) list) : Result<FingerId option, DriverError> =
        result {
            let! prep = this.Preprocess(rawPixels)
            let q = byte (Math.Clamp(prep.Quality.Value, 25, 100))
            let c = byte (Math.Clamp(prep.Coverage.Value, 25, 100))
            let mutable matchedFinger = None
            for (fid, blob) in templates do
                if matchedFinger.IsNone then
                    let! (matched, _) = this.IdentifyProbe(rawPixels, prep.NormalizedPixels, blob.Value, q, c, prep.BData)
                    if matched then
                        matchedFinger <- Some fid
            return matchedFinger
        }

    // ------------------------------------------------------------------------
    // IFingerprintMatcher Implementation
    // ------------------------------------------------------------------------

    interface IFingerprintMatcher with

        member this.ExtractTemplate(frame: PreprocessedFrame) : Result<byte[], DriverError> =
            result {
                do! this.StartEnroll()
                let rawSynthetic = Array.create RawFrame12Bit.ExpectedPixelCount 1500us

                // Perform 12 sample enrollment iterations using candidate normalized pixels and b_data
                for i in 0 .. 11 do
                    let! _ = this.MergeSample(rawSynthetic, frame.NormalizedPixels, frame.Quality, frame.Coverage, frame.BData)
                    ()

                let! defaultFid = FingerId.create "DEFAULT_ENROLLED_FINGER"
                let! template = this.CommitTemplate(defaultFid)
                return template.Value
            }

        member this.Match(enrolledTemplate: byte[], candidate: PreprocessedFrame) : Result<float, DriverError> =
            result {
                let rawSynthetic = Array.create RawFrame12Bit.ExpectedPixelCount 1500us
                let q = byte (Math.Clamp(candidate.Quality.Value, 25, 100))
                let c = byte (Math.Clamp(candidate.Coverage.Value, 25, 100))
                let! (matched, _) = this.IdentifyProbe(rawSynthetic, candidate.NormalizedPixels, enrolledTemplate, q, c, candidate.BData)
                if matched then return 100.0
                else return 0.0
            }

        member this.Verify(enrolledTemplate: byte[], candidate: PreprocessedFrame, threshold: float) : Result<bool, DriverError> =
            result {
                let! score = (this :> IFingerprintMatcher).Match(enrolledTemplate, candidate)
                return score >= threshold
            }

    interface IDisposable with
        member this.Dispose() =
            if not isDisposed then
                isDisposed <- true
                (nativeFunctions :> IDisposable).Dispose()

    // ------------------------------------------------------------------------
    // Static Factory
    // ------------------------------------------------------------------------

    static member Create(?customPath: string, ?baseline: RawFrame12Bit) : Result<GoodixTodMatcher, DriverError> =
        let resolvePath () =
            match customPath with
            | Some p -> Ok p
            | None ->
                let defaultPaths = [
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share", "goodix-fp", "libgoodix_tod_53xc.so")
                    "/tmp/libgoodix_standalone.so"
                ]
                match List.tryFind File.Exists defaultPaths with
                | Some existing -> Ok existing
                | None -> Error (DeviceNotReady $"Could not find Goodix native library in default locations: {defaultPaths}")

        result {
            let! rawPath = resolvePath ()
            let! libPath = LibraryPath.create rawPath
            let! nativeFuncs = NativeInterop.loadNativeLibrary libPath
            return new GoodixTodMatcher(nativeFuncs, baseline)
        }

module GoodixTodMatcher =
    let create (libPath: LibraryPath) : Result<GoodixTodMatcher, DriverError> =
        GoodixTodMatcher.Create(customPath = libPath.Value)

    let createWithBaseline (libPath: LibraryPath) (baseline: RawFrame12Bit) : Result<GoodixTodMatcher, DriverError> =
        GoodixTodMatcher.Create(customPath = libPath.Value, baseline = baseline)
