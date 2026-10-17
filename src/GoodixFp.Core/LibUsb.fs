namespace GoodixFp.Core

open System
open System.Runtime.InteropServices

// ============================================================================
// USB Transport Interface
// ============================================================================

type IUsbTransport =
    inherit IDisposable
    abstract member Write: data: byte[] -> Result<unit, DriverError>
    abstract member Read: length: int * timeoutMs: int -> Result<byte[], DriverError>
    abstract member DrainBuffer: ?timeoutMs: int -> unit
    abstract member ResetConnection: unit -> Result<unit, DriverError>

// ============================================================================
// Native LibUsb-1.0 P/Invoke Bindings
// ============================================================================

module private NativeLibUsb =

    [<Literal>]
    let LibUsbName = "libusb-1.0.so.0"

    [<DllImport(LibUsbName, CallingConvention = CallingConvention.Cdecl)>]
    extern int libusb_init(nativeint& ctx)

    [<DllImport(LibUsbName, CallingConvention = CallingConvention.Cdecl)>]
    extern void libusb_exit(nativeint ctx)

    [<DllImport(LibUsbName, CallingConvention = CallingConvention.Cdecl)>]
    extern nativeint libusb_open_device_with_vid_pid(nativeint ctx, uint16 vendor_id, uint16 product_id)

    [<DllImport(LibUsbName, CallingConvention = CallingConvention.Cdecl)>]
    extern void libusb_close(nativeint dev_handle)

    [<DllImport(LibUsbName, CallingConvention = CallingConvention.Cdecl)>]
    extern int libusb_kernel_driver_active(nativeint dev_handle, int interface_number)

    [<DllImport(LibUsbName, CallingConvention = CallingConvention.Cdecl)>]
    extern int libusb_detach_kernel_driver(nativeint dev_handle, int interface_number)

    [<DllImport(LibUsbName, CallingConvention = CallingConvention.Cdecl)>]
    extern int libusb_claim_interface(nativeint dev_handle, int interface_number)

    [<DllImport(LibUsbName, CallingConvention = CallingConvention.Cdecl)>]
    extern int libusb_release_interface(nativeint dev_handle, int interface_number)

    [<DllImport(LibUsbName, CallingConvention = CallingConvention.Cdecl)>]
    extern int libusb_bulk_transfer(
        nativeint dev_handle,
        byte endpoint,
        byte[] data,
        int length,
        int& transferred,
        uint32 timeout
    )

    [<DllImport(LibUsbName, CallingConvention = CallingConvention.Cdecl)>]
    extern int libusb_clear_halt(nativeint dev_handle, byte endpoint)

    [<DllImport(LibUsbName, CallingConvention = CallingConvention.Cdecl)>]
    extern nativeint libusb_strerror(int errcode)

module private LibUsbConstants =
    [<Literal>]
    let EndpointOut = 0x01uy

    [<Literal>]
    let EndpointIn = 0x83uy

    [<Literal>]
    let ChunkSize = 64 // 0x40 bytes chunking

open LibUsbConstants

// ============================================================================
// LibUsb Implementation for Goodix 53xd Devices
// ============================================================================

type LibUsbTransport private (vid: UsbVid, pid: UsbPid, iface: int, initialCtx: nativeint, initialHandle: nativeint) =
    let mutable ctx = initialCtx
    let mutable handle = initialHandle
    let mutable isDisposed = false

    static let tryOpenDevice (vid: UsbVid) (pid: UsbPid) (iface: int) =
        let mutable newCtx = 0n
        let initRes = NativeLibUsb.libusb_init(&newCtx)
        if initRes <> 0 then
            Error (UsbError ("Failed to initialize libusb", initRes))
        else
            let devHandle = NativeLibUsb.libusb_open_device_with_vid_pid(newCtx, vid.Value, pid.Value)
            if devHandle = 0n then
                NativeLibUsb.libusb_exit(newCtx)
                Error (DeviceNotReady $"Device with VID 0x{vid.Value:x4} PID 0x{pid.Value:x4} not found or permission denied")
            else
                let detachAndClaim () =
                    if NativeLibUsb.libusb_kernel_driver_active(devHandle, iface) = 1 then
                        let detachRes = NativeLibUsb.libusb_detach_kernel_driver(devHandle, iface)
                        if detachRes <> 0 then Error (UsbError ("Failed to detach kernel driver", detachRes))
                        else Ok ()
                    else Ok ()

                match detachAndClaim () with
                | Error err ->
                    NativeLibUsb.libusb_close(devHandle)
                    NativeLibUsb.libusb_exit(newCtx)
                    Error err
                | Ok () ->
                    let claimRes = NativeLibUsb.libusb_claim_interface(devHandle, iface)
                    if claimRes <> 0 then
                        NativeLibUsb.libusb_close(devHandle)
                        NativeLibUsb.libusb_exit(newCtx)
                        Error (UsbError ("Failed to claim interface", claimRes))
                    else
                        NativeLibUsb.libusb_clear_halt(devHandle, EndpointOut) |> ignore
                        NativeLibUsb.libusb_clear_halt(devHandle, EndpointIn) |> ignore
                        let drainBuf = Array.zeroCreate<byte> 1024
                        let mutable transferred = 0
                        while NativeLibUsb.libusb_bulk_transfer(devHandle, EndpointIn, drainBuf, drainBuf.Length, &transferred, 50u) = 0 && transferred > 0 do
                            ()
                        Ok (newCtx, devHandle)

    static member Open(vid: UsbVid, pid: UsbPid, ?interfaceNumber: int) : Result<LibUsbTransport, DriverError> =
        let iface = defaultArg interfaceNumber 0
        match tryOpenDevice vid pid iface with
        | Ok (c, h) -> Ok (new LibUsbTransport(vid, pid, iface, c, h))
        | Error err -> Error err


    interface IUsbTransport with
        /// Writes data with 64-byte padding & chunking on Bulk OUT (0x01).
        member this.Write(data: byte[]) : Result<unit, DriverError> =
            if isDisposed then
                Error (UsbError ("Transport has been disposed", -1))
            elif isNull data || data.Length = 0 then
                Ok ()
            else
                // Pad data to multiple of 64 bytes (0x40)
                let rem = data.Length % ChunkSize
                let paddedData =
                    if rem = 0 then data
                    else
                        let padNeeded = ChunkSize - rem
                        Array.concat [ data; Array.zeroCreate padNeeded ]

                let mutable err: DriverError option = None
                let mutable offset = 0
                while offset < paddedData.Length && err.IsNone do
                    let chunk = Array.sub paddedData offset ChunkSize
                    let mutable transferred = 0
                    let ret = NativeLibUsb.libusb_bulk_transfer(handle, EndpointOut, chunk, ChunkSize, &transferred, 5000u)
                    if ret <> 0 then
                        err <- Some (UsbError ($"Bulk transfer out failed at offset {offset}", ret))
                    offset <- offset + ChunkSize

                match err with
                | Some e -> Error e
                | None -> Ok ()

        /// Reads data from Bulk IN (0x83) with multi-packet framing support.
        member this.Read(length: int, timeoutMs: int) : Result<byte[], DriverError> =
            if isDisposed then
                Error (UsbError ("Transport has been disposed", -1))
            else
                let buffer = Array.zeroCreate<byte> (max length 64)
                let mutable transferred = 0
                let ret = NativeLibUsb.libusb_bulk_transfer(handle, EndpointIn, buffer, buffer.Length, &transferred, uint32 timeoutMs)
                if ret <> 0 then
                    Error (UsbError ($"Bulk transfer in failed", ret))
                elif transferred = 0 then
                    Error (Timeout "Bulk transfer in timed out with 0 bytes")
                else
                    let received = Array.sub buffer 0 transferred
                    // Check if received is a MessagePack that expects more data
                    if received.Length >= 4 then
                        let expectedLen = int received.[1] ||| (int received.[2] <<< 8)
                        let totalPackLen = 4 + expectedLen
                        if received.Length < totalPackLen then
                            // Multi-packet framing read
                            let accumulated = ResizeArray<byte>(received)
                            let mutable readMoreErr: DriverError option = None
                            while accumulated.Count < totalPackLen && readMoreErr.IsNone do
                                let needed = totalPackLen - accumulated.Count
                                let chunkBuf = Array.zeroCreate<byte> (max needed 64)
                                let mutable chunkTransferred = 0
                                let chunkRet = NativeLibUsb.libusb_bulk_transfer(handle, EndpointIn, chunkBuf, chunkBuf.Length, &chunkTransferred, uint32 timeoutMs)
                                if chunkRet <> 0 then
                                    readMoreErr <- Some (UsbError ("Failed while reading remaining message pack chunks", chunkRet))
                                elif chunkTransferred = 0 then
                                    readMoreErr <- Some (Timeout "Timed out waiting for remaining message pack bytes")
                                else
                                    accumulated.AddRange(Array.sub chunkBuf 0 chunkTransferred)

                            match readMoreErr with
                            | Some e -> Error e
                            | None -> Ok (accumulated.ToArray())
                        else
                            Ok received
                    else
                        Ok received

        member this.DrainBuffer(?timeoutMs: int) =
            let timeout = defaultArg timeoutMs 50
            if not isDisposed && handle <> 0n then
                let drainBuf = Array.zeroCreate<byte> 1024
                let mutable transferred = 0
                while NativeLibUsb.libusb_bulk_transfer(handle, EndpointIn, drainBuf, drainBuf.Length, &transferred, uint32 timeout) = 0 && transferred > 0 do
                    ()

        member this.ResetConnection() : Result<unit, DriverError> =
            if not isDisposed then
                try
                    if handle <> 0n then
                        NativeLibUsb.libusb_release_interface(handle, iface) |> ignore
                        NativeLibUsb.libusb_close(handle)
                        handle <- 0n
                    if ctx <> 0n then
                        NativeLibUsb.libusb_exit(ctx)
                        ctx <- 0n
                with _ -> ()

            let mutable result = Error (DeviceNotReady "Device did not re-enumerate after reset")
            let mutable attempts = 0
            while attempts < 20 && result.IsError do
                System.Threading.Thread.Sleep(300)
                attempts <- attempts + 1
                match tryOpenDevice vid pid iface with
                | Ok (newCtx, newHandle) ->
                    ctx <- newCtx
                    handle <- newHandle
                    isDisposed <- false
                    result <- Ok ()
                | Error _ -> ()
            result

        member this.Dispose() =
            if not isDisposed then
                isDisposed <- true
                try
                    if handle <> 0n then
                        NativeLibUsb.libusb_release_interface(handle, iface) |> ignore
                        NativeLibUsb.libusb_close(handle)
                        handle <- 0n
                    if ctx <> 0n then
                        NativeLibUsb.libusb_exit(ctx)
                        ctx <- 0n
                with _ -> ()
