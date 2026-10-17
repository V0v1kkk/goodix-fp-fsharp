namespace GoodixFp.NativeMatcher

open System
open System.IO
open System.Runtime.InteropServices
open GoodixFp.Core

// ============================================================================
// Verified Function Delegate Signatures (from test_alg_e2e.py)
// ============================================================================

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type PppParamInitDelegate = delegate of int -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type PreprocessInitCalidataDelegate = delegate of unit -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type PreprocessorInitDelegate = delegate of nativeint -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type PreProcessorUnifyDelegate = delegate of nativeint * nativeint * nativeint * nativeint * nativeint * uint32 * nativeint * byte * byte -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type CreateAlgConfigDelegate = delegate of nativeint -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type AlgCreateContextInterfaceDelegate = delegate of nativeint * int * uint64 -> uint32

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type AlgEnrollstartInterfaceDelegate = delegate of unit -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type AlgFormatImageInterfaceDelegate = delegate of nativeint -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type AlgMergeFeatureInterfaceDelegate = delegate of nativeint * nativeint -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type AlgUpdateEnrollstatusInterfaceDelegate = delegate of unit -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type AlgGetTemplateSizeInterfaceDelegate = delegate of byte * nativeint -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type AlgCommitTemplateInterfaceDelegate = delegate of nativeint * uint32 * byte * nativeint * uint32 -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type AlgEnrollFinishInterfaceDelegate = delegate of unit -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type AlgClearContextInterfaceDelegate = delegate of unit -> int

[<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
type AlgIdentifyFeatureSetInterfaceDelegate = delegate of nativeint * uint32 * nativeint * uint32 * uint32 * nativeint -> int

// ============================================================================
// Native Function Table Record
// ============================================================================

type NativeFunctions = {
    LibraryHandle: nativeint
    LibraryBase: nativeint
    PppParamInit: PppParamInitDelegate
    PreprocessInitCalidata: PreprocessInitCalidataDelegate
    PreprocessorInit: PreprocessorInitDelegate
    PreProcessorUnify: PreProcessorUnifyDelegate
    CreateAlgConfig: CreateAlgConfigDelegate
    AlgCreateContextInterface: AlgCreateContextInterfaceDelegate
    AlgEnrollstartInterface: AlgEnrollstartInterfaceDelegate
    AlgFormatImageInterface: AlgFormatImageInterfaceDelegate
    AlgMergeFeatureInterface: AlgMergeFeatureInterfaceDelegate
    AlgUpdateEnrollstatusInterface: AlgUpdateEnrollstatusInterfaceDelegate
    AlgGetTemplateSizeInterface: AlgGetTemplateSizeInterfaceDelegate
    AlgCommitTemplateInterface: AlgCommitTemplateInterfaceDelegate
    AlgEnrollFinishInterface: AlgEnrollFinishInterfaceDelegate
    AlgClearContextInterface: AlgClearContextInterfaceDelegate
    AlgIdentifyFeatureSetInterface: AlgIdentifyFeatureSetInterfaceDelegate
} with
    interface IDisposable with
        member this.Dispose() =
            if this.LibraryHandle <> IntPtr.Zero then
                NativeLibrary.Free(this.LibraryHandle)

module NativeInterop =

    let private findLibraryBase (libFileName: string) : Result<int64, DriverError> =
        try
            let lines = File.ReadAllLines("/proc/self/maps")
            let matchOpt =
                lines
                |> Array.tryFind (fun l -> l.Contains(libFileName) && l.Contains("00000000"))
            match matchOpt with
            | Some line ->
                let startHex = line.Split('-').[0].Trim()
                let mapStart = Convert.ToInt64(startHex, 16)
                Ok (mapStart - 0x100000L)
            | None ->
                Error (DeviceNotReady $"Could not resolve mapped base address for '{libFileName}' in /proc/self/maps")
        with ex ->
            Error (InternalError ex)

    let private bindDelegate (baseOffset: int64) (offset: int64) (delegateType: Type) : obj =
        let funcPtr = nativeint (baseOffset + offset)
        Marshal.GetDelegateForFunctionPointer(funcPtr, delegateType)

    let loadNativeLibrary (path: LibraryPath) : Result<NativeFunctions, DriverError> =
        try
            let fullPath = path.Value
            let handle = NativeLibrary.Load(fullPath)
            if handle = IntPtr.Zero then
                Error (DeviceNotReady $"Failed to load native library '{fullPath}'")
            else
                let fileName = Path.GetFileName(fullPath)
                match findLibraryBase fileName with
                | Error err ->
                    NativeLibrary.Free(handle)
                    Error err
                | Ok baseOffset ->
                    let functions = {
                        LibraryHandle = handle
                        LibraryBase = nativeint baseOffset
                        PppParamInit = bindDelegate baseOffset 0x111430L typeof<PppParamInitDelegate> :?> PppParamInitDelegate
                        PreprocessInitCalidata = bindDelegate baseOffset 0x111770L typeof<PreprocessInitCalidataDelegate> :?> PreprocessInitCalidataDelegate
                        PreprocessorInit = bindDelegate baseOffset 0x111570L typeof<PreprocessorInitDelegate> :?> PreprocessorInitDelegate
                        PreProcessorUnify = bindDelegate baseOffset 0x1119a0L typeof<PreProcessorUnifyDelegate> :?> PreProcessorUnifyDelegate
                        CreateAlgConfig = bindDelegate baseOffset 0x1434d0L typeof<CreateAlgConfigDelegate> :?> CreateAlgConfigDelegate
                        AlgCreateContextInterface = bindDelegate baseOffset 0x111cf0L typeof<AlgCreateContextInterfaceDelegate> :?> AlgCreateContextInterfaceDelegate
                        AlgEnrollstartInterface = bindDelegate baseOffset 0x111e20L typeof<AlgEnrollstartInterfaceDelegate> :?> AlgEnrollstartInterfaceDelegate
                        AlgFormatImageInterface = bindDelegate baseOffset 0x111eb0L typeof<AlgFormatImageInterfaceDelegate> :?> AlgFormatImageInterfaceDelegate
                        AlgMergeFeatureInterface = bindDelegate baseOffset 0x111f40L typeof<AlgMergeFeatureInterfaceDelegate> :?> AlgMergeFeatureInterfaceDelegate
                        AlgUpdateEnrollstatusInterface = bindDelegate baseOffset 0x111fd0L typeof<AlgUpdateEnrollstatusInterfaceDelegate> :?> AlgUpdateEnrollstatusInterfaceDelegate
                        AlgGetTemplateSizeInterface = bindDelegate baseOffset 0x112420L typeof<AlgGetTemplateSizeInterfaceDelegate> :?> AlgGetTemplateSizeInterfaceDelegate
                        AlgCommitTemplateInterface = bindDelegate baseOffset 0x112220L typeof<AlgCommitTemplateInterfaceDelegate> :?> AlgCommitTemplateInterfaceDelegate
                        AlgEnrollFinishInterface = bindDelegate baseOffset 0x112060L typeof<AlgEnrollFinishInterfaceDelegate> :?> AlgEnrollFinishInterfaceDelegate
                        AlgClearContextInterface = bindDelegate baseOffset 0x112390L typeof<AlgClearContextInterfaceDelegate> :?> AlgClearContextInterfaceDelegate
                        AlgIdentifyFeatureSetInterface = bindDelegate baseOffset 0x1122d0L typeof<AlgIdentifyFeatureSetInterfaceDelegate> :?> AlgIdentifyFeatureSetInterfaceDelegate
                    }
                    Ok functions
        with ex ->
            Error (InternalError ex)
