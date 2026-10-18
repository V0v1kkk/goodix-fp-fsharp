namespace GoodixFp.Daemon

open System
open System.Threading.Tasks
open Tmds.DBus.Protocol

// ============================================================================
// D-Bus Signal Emitter Helper
// ============================================================================

module DBusSignalEmitter =

    let emitVerifyFingerSelected (connection: DBusConnection) (fingerName: string) =
        try
            let mutable writer = connection.GetMessageWriter()
            writer.WriteSignalHeader(
                destination = null,
                path = FprintConstants.DevicePath,
                ``interface`` = FprintConstants.DeviceInterface,
                ``member`` = FprintConstants.Signals.VerifyFingerSelected,
                signature = "s"
            )
            writer.WriteString(fingerName)
            let msg = writer.CreateMessage()
            connection.TrySendMessage(msg) |> ignore
        with ex ->
            eprintfn $"[!] Failed to emit VerifyFingerSelected signal: {ex.Message}"

    let emitVerifyFingerMatched (connection: DBusConnection) (fingerName: string) =
        try
            let mutable writer = connection.GetMessageWriter()
            writer.WriteSignalHeader(
                destination = null,
                path = FprintConstants.DevicePath,
                ``interface`` = FprintConstants.DeviceInterface,
                ``member`` = FprintConstants.Signals.VerifyFingerMatched,
                signature = "s"
            )
            writer.WriteString(fingerName)
            let msg = writer.CreateMessage()
            connection.TrySendMessage(msg) |> ignore
        with ex ->
            eprintfn $"[!] Failed to emit VerifyFingerMatched signal: {ex.Message}"

    let emitVerifyStatus (connection: DBusConnection) (result: string, doneFlag: bool) =
        try
            let mutable writer = connection.GetMessageWriter()
            writer.WriteSignalHeader(
                destination = null,
                path = FprintConstants.DevicePath,
                ``interface`` = FprintConstants.DeviceInterface,
                ``member`` = FprintConstants.Signals.VerifyStatus,
                signature = "sb"
            )
            writer.WriteString(result)
            writer.WriteBool(doneFlag)
            let msg = writer.CreateMessage()
            connection.TrySendMessage(msg) |> ignore
        with ex ->
            eprintfn $"[!] Failed to emit VerifyStatus signal: {ex.Message}"

// ============================================================================
// Manager Method Handler (/net/reactivated/Fprint/Manager)
// ============================================================================

type ManagerMethodHandler() =
    interface IPathMethodHandler with
        member this.Path = FprintConstants.ManagerPath
        member this.HandlesChildPaths = false

        member this.HandleMethodAsync(context: MethodContext) : ValueTask =
            let iface = context.Request.InterfaceAsString
            let memberName = context.Request.MemberAsString

            match iface with
            | FprintConstants.IntrospectableInterface ->
                if memberName = "Introspect" then
                    let mutable writer = context.CreateReplyWriter("s")
                    writer.WriteString(IntrospectXml.ManagerXml)
                    context.Reply(writer.CreateMessage())
                else
                    context.ReplyUnknownMethodError()
                ValueTask.CompletedTask

            | FprintConstants.ManagerInterface ->
                match memberName with
                | "GetDevices" ->
                    let mutable writer = context.CreateReplyWriter("ao")
                    let arr = [| ObjectPath FprintConstants.DevicePath |]
                    writer.WriteArray(arr)
                    context.Reply(writer.CreateMessage())
                | "GetDefaultDevice" ->
                    let mutable writer = context.CreateReplyWriter("o")
                    writer.WriteObjectPath(FprintConstants.DevicePath)
                    context.Reply(writer.CreateMessage())
                | _ ->
                    context.ReplyUnknownMethodError()
                ValueTask.CompletedTask

            | _ ->
                context.ReplyUnknownMethodError()
                ValueTask.CompletedTask

// ============================================================================
// Device Method Handler (/net/reactivated/Fprint/Device/0)
// ============================================================================

type DeviceMethodHandler(deviceSession: DeviceSession, authorizer: IAuthorizer) =
    interface IPathMethodHandler with
        member this.Path = FprintConstants.DevicePath
        member this.HandlesChildPaths = false

        member this.HandleMethodAsync(context: MethodContext) : ValueTask =
            let iface = context.Request.InterfaceAsString
            let memberName = context.Request.MemberAsString
            let sender = BusSender.createUnsafe (context.Request.SenderAsString |> Option.ofObj |> Option.defaultValue "")

            match iface with
            | FprintConstants.IntrospectableInterface ->
                if memberName = "Introspect" then
                    let mutable writer = context.CreateReplyWriter("s")
                    writer.WriteString(IntrospectXml.DeviceXml)
                    context.Reply(writer.CreateMessage())
                else
                    context.ReplyUnknownMethodError()
                ValueTask.CompletedTask

            | FprintConstants.PropertiesInterface ->
                match memberName with
                | "Get" ->
                    let mutable reader = context.Request.GetBodyReader()
                    let targetIface = reader.ReadString()
                    let propName = reader.ReadString()
                    if targetIface = FprintConstants.DeviceInterface then
                        match deviceSession.GetProperty(propName) with
                        | Ok v ->
                            let mutable writer = context.CreateReplyWriter("v")
                            match v with
                            | :? string as s -> writer.WriteVariantString(s)
                            | :? int32 as i -> writer.WriteVariantInt32(i)
                            | :? bool as b -> writer.WriteVariantBool(b)
                            | other -> writer.WriteVariantString(string other)
                            context.Reply(writer.CreateMessage())
                        | Error (errName, errMsg) ->
                            context.ReplyError(errName, errMsg)
                    else
                        context.ReplyError("org.freedesktop.DBus.Error.UnknownInterface", $"Unknown interface '{targetIface}'")
                    ValueTask.CompletedTask

                | "GetAll" ->
                    let mutable reader = context.Request.GetBodyReader()
                    let targetIface = reader.ReadString()
                    if targetIface = FprintConstants.DeviceInterface || String.IsNullOrEmpty targetIface then
                        let props = deviceSession.GetAllProperties()
                        let mutable writer = context.CreateReplyWriter("a{sv}")
                        let dictStart = writer.WriteDictionaryStart()
                        for (k, v) in props do
                            writer.WriteDictionaryEntryStart()
                            writer.WriteString(k)
                            match v with
                            | :? string as s -> writer.WriteVariantString(s)
                            | :? int32 as i -> writer.WriteVariantInt32(i)
                            | :? bool as b -> writer.WriteVariantBool(b)
                            | other -> writer.WriteVariantString(string other)
                        writer.WriteDictionaryEnd(dictStart)
                        context.Reply(writer.CreateMessage())
                    else
                        let mutable writer = context.CreateReplyWriter("a{sv}")
                        let dictStart = writer.WriteDictionaryStart()
                        writer.WriteDictionaryEnd(dictStart)
                        context.Reply(writer.CreateMessage())
                    ValueTask.CompletedTask

                | "Set" ->
                    context.ReplyError("org.freedesktop.DBus.Error.PropertyReadOnly", "All device properties are read-only")
                    ValueTask.CompletedTask

                | _ ->
                    context.ReplyUnknownMethodError()
                    ValueTask.CompletedTask

            | FprintConstants.DeviceInterface ->
                task {
                    match memberName with
                    | "ListEnrolledFingers" ->
                        let mutable reader = context.Request.GetBodyReader()
                        let requestedUser = reader.ReadString()
                        let! authRes = Authorization.authorizeAccessUser authorizer sender requestedUser
                        match authRes with
                        | Error (errName, errMsg) ->
                            context.ReplyError(errName, errMsg)
                        | Ok targetUser ->
                            let fingers = TemplateStore.listEnrolledFingers targetUser
                            if List.isEmpty fingers then
                                context.ReplyError(FprintConstants.Errors.NoEnrolledPrints, $"No enrolled prints found for user '{targetUser.Value}'")
                            else
                                let mutable writer = context.CreateReplyWriter("as")
                                let arr = fingers |> List.map (fun f -> f.Value) |> List.toArray
                                writer.WriteArray(arr)
                                context.Reply(writer.CreateMessage())

                    | "Claim" ->
                        let mutable reader = context.Request.GetBodyReader()
                        let requestedUser = reader.ReadString()
                        let! authRes = Authorization.authorizeAccessUser authorizer sender requestedUser
                        match authRes with
                        | Error (errName, errMsg) ->
                            context.ReplyError(errName, errMsg)
                        | Ok targetUser ->
                            match deviceSession.Claim(sender, targetUser) with
                            | Ok () ->
                                let mutable writer = context.CreateReplyWriter("")
                                context.Reply(writer.CreateMessage())
                            | Error (errName, errMsg) ->
                                context.ReplyError(errName, errMsg)

                    | "Release" ->
                        let! relRes = deviceSession.Release(sender)
                        match relRes with
                        | Ok () ->
                            let mutable writer = context.CreateReplyWriter("")
                            context.Reply(writer.CreateMessage())
                        | Error (errName, errMsg) ->
                            context.ReplyError(errName, errMsg)

                    | "VerifyStart" ->
                        let mutable reader = context.Request.GetBodyReader()
                        let fingerNameStr = reader.ReadString()
                        let! authRes = Authorization.authorizeVerify authorizer sender
                        match authRes with
                        | Error (errName, errMsg) ->
                            context.ReplyError(errName, errMsg)
                        | Ok () ->
                            match FingerName.createWithAny fingerNameStr with
                            | Error err ->
                                context.ReplyError(FprintConstants.Errors.InvalidFingername, err)
                            | Ok fn ->
                                match deviceSession.VerifyStart(sender, fn) with
                                | Ok () ->
                                    let mutable writer = context.CreateReplyWriter("")
                                    context.Reply(writer.CreateMessage())
                                | Error (errName, errMsg) ->
                                    context.ReplyError(errName, errMsg)

                    | "VerifyStop" ->
                        let! stopRes = deviceSession.VerifyStop(sender)
                        match stopRes with
                        | Ok () ->
                            let mutable writer = context.CreateReplyWriter("")
                            context.Reply(writer.CreateMessage())
                        | Error (errName, errMsg) ->
                            context.ReplyError(errName, errMsg)

                    | "EnrollStart" ->
                        match deviceSession.ClaimedSender with
                        | None ->
                            context.ReplyError(FprintConstants.Errors.ClaimDevice, "Device is not claimed")
                        | Some s when s.Value <> sender.Value ->
                            context.ReplyError(FprintConstants.Errors.ClaimDevice, "Device is claimed by another client")
                        | Some _ ->
                            let! uidRes = authorizer.GetCallerUidAsync sender
                            let isRoot = match uidRes with Ok uid -> uid.IsRoot | _ -> false
                            let! isAuth = authorizer.CheckPolkitAsync(sender, PolkitActions.Enroll)
                            if not isRoot && not isAuth then
                                context.ReplyError(FprintConstants.Errors.PermissionDenied, "Not authorized to enroll fingerprints")
                            else
                                context.ReplyError(
                                    FprintConstants.Errors.Internal,
                                    "Enrollment is not supported via fprintd bridge. Use 'goodix-fp enroll <finger>' and import."
                                )

                    | "EnrollStop" ->
                        match deviceSession.ClaimedSender with
                        | None ->
                            context.ReplyError(FprintConstants.Errors.ClaimDevice, "Device is not claimed")
                        | Some s when s.Value <> sender.Value ->
                            context.ReplyError(FprintConstants.Errors.ClaimDevice, "Device is claimed by another client")
                        | Some _ ->
                            context.ReplyError(FprintConstants.Errors.NoActionInProgress, "No enrollment is in progress")

                    | "DeleteEnrolledFingers" ->
                        let mutable reader = context.Request.GetBodyReader()
                        let requestedUser = reader.ReadString()
                        let! authRes = Authorization.authorizeAccessUser authorizer sender requestedUser
                        match authRes with
                        | Error (errName, errMsg) ->
                            context.ReplyError(errName, errMsg)
                        | Ok _ ->
                            context.ReplyError(
                                FprintConstants.Errors.PrintsNotDeleted,
                                "Fingerprint deletion is not supported via D-Bus; manage template files under /var/lib/goodix-fp/templates/ via root."
                            )

                    | "DeleteEnrolledFingers2" | "DeleteEnrolledFinger" ->
                        match deviceSession.ClaimedSender with
                        | None ->
                            context.ReplyError(FprintConstants.Errors.ClaimDevice, "Device is not claimed")
                        | Some s when s.Value <> sender.Value ->
                            context.ReplyError(FprintConstants.Errors.ClaimDevice, "Device is claimed by another client")
                        | Some _ ->
                            let! uidRes = authorizer.GetCallerUidAsync sender
                            let isRoot = match uidRes with Ok uid -> uid.IsRoot | _ -> false
                            let! isAuth = authorizer.CheckPolkitAsync(sender, PolkitActions.Enroll)
                            if not isRoot && not isAuth then
                                context.ReplyError(FprintConstants.Errors.PermissionDenied, "Not authorized to delete fingerprints")
                            else
                                context.ReplyError(
                                    FprintConstants.Errors.PrintsNotDeleted,
                                    "Fingerprint deletion is not supported via D-Bus; manage template files under /var/lib/goodix-fp/templates/ via root."
                                )

                    | _ ->
                        context.ReplyUnknownMethodError()
                } |> ValueTask

            | _ ->
                context.ReplyUnknownMethodError()
                ValueTask.CompletedTask
