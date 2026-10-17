# goodix-fp-fsharp

Production-grade, pure F# reverse-engineered driver and protocol toolkit for **Goodix 53xc / 53xd** fingerprint sensors (e.g., `0x27c6:0x538d`, `0x27c6:0x530c`, `0x27c6:0x532d` found on Dell XPS and Inspiron laptops).

## Features

- **Strict Functional Architecture**: Idiomatic F# 10 following Vladimir's F# Style Guide:
  - Canonical `[<Struct>]` single-case DUs with private constructors and validation modules (`UsbVid`, `UsbPid`, `ChipId`, `FirmwareVersion`, `RegisterAddress`, `PskHash`, `QualityScore`, `CoverageScore`, `TemplateId`).
  - Total functions returning `Result<'T, DriverError>` using `FsToolkit.ErrorHandling` (`result { }` and `taskResult { }`).
  - Pure transforms and data structures ordered first, effectful I/O next, composition root last.
- **Protocol Classification via Active Patterns**:
  - `(|MessagePack|_|)` and `(|MessageProtocol|_|)` for outer and inner framing.
  - `(|AckResponse|CommandResponse|InvalidPacket|)` for deterministic, compiler-checked packet routing.
  - Full Goodix command support: `0x00` NOP, `0x20` GetImage, `0x32` FdtDown, `0x34` FdtUp, `0x36` FdtMode, `0x60` Sleep, `0x70` Idle, `0x80` WriteReg, `0x82` ReadReg, `0x90` UploadConfig, `0x96` EnableChip, `0xa2` Reset, `0xa6` ReadOtp, `0xa8` FirmwareVersion, `0xb0` Ack, `0xd0` RequestTls, `0xd4` TlsEstablished, `0xe0` PresetPskWrite, `0xe4` PresetPskRead.
- **Dual TLS 1.2 PSK Server Implementations**:
  - `PureFSharpTlsPskTunnel`: 100% pure F# RFC 4279 / RFC 5246 TLS 1.2 PSK server for `TLS_PSK_WITH_AES_128_CBC_SHA256` (`0x00AE`) built directly on `System.Security.Cryptography.Aes` and `HMACSHA256` (`P_SHA256` PRF, pre-master secret `0x0020` + 32 zero bytes + `0x0020` + 32 zero bytes, `master_secret`, `key_block`, `ClientHello` parsing, `ServerHello` + `ServerHelloDone` with RFC 5746 renegotiation info, `ClientKeyExchange` + `ChangeCipherSpec` + `Finished` verification, `ChangeCipherSpec` + `Finished` generation, and AES-128-CBC decryption stripping the 9-byte `0xb2` header).
  - `BouncyCastleTlsPskTunnel`: In-memory TLS 1.2 PSK server built on `Org.BouncyCastle.Tls` (`PskTlsServer` / `BasicTlsPskIdentity` / `TlsServerProtocol`).
- **High-Performance Frame Decoder**:
  - `unpackSequential`: Sequential row-wise unpacking (64x80).
  - `unpackAndTranspose80x64`: Column-to-row native Goodix `ImageRestructInterface` transpose (`out[((i &&& 0x3f) * 80) + (i >>> 6)]`) into 80 columns x 64 rows.
  - `unpackAndTranspose80x64Span`: Zero-allocation `Span<byte>` / `Span<uint16>` SIMD/JIT-friendly unpacker.
  - PGM (P5, 12-bit and 8-bit) and PPM (P6) binary image export.
- **Pure F# IEEE 802.3 CRC-32 & Frame Verification**:
  - Validates 7,680 data bytes against 4-byte CRC32 trailer (both big-endian and little-endian).
- **Native LibUsb-1.0 Transport**:
  - 64-byte (`0x40`) chunking and padding on Bulk OUT (`0x01`).
  - Multi-packet framing reads on Bulk IN (`0x83`).
- **Automated Dell Somerville Blob Fetch & Patching Script**:
  - `scripts/fetch-goodix-blob.sh`: Downloads `libfprint-2-tod1-goodix_0.0.6-0ubuntu1~somerville1_amd64.deb`, verifies SHA-256 (`bfa30696fbed9b86cfb5339293d458b9175d05b8895a8644d6b72615ffc9756b`), applies the 3-step ELF binary patch in Python, and outputs a standalone `.so`.

## Repository Structure

```
goodix-fp-fsharp/
├── LICENSE
├── README.md
├── .gitignore
├── GoodixFp.sln
├── GoodixFp.slnx
├── scripts/
│   └── fetch-goodix-blob.sh
├── src/
│   └── GoodixFp.Core/
│       ├── Types.fs          # Canonical single-case [<Struct>] DUs & domain models
│       ├── Crc32.fs          # Pure F# IEEE 802.3 CRC32 & frame verification
│       ├── Protocol.fs       # Message Pack & Protocol framing + Active Patterns
│       ├── FrameDecoder.fs   # 12-bit unpacking, 80x64 transpose & PGM/PPM export
│       ├── TlsPsk.fs         # Pure F# & BouncyCastle TLS 1.2 PSK tunnels
│       ├── LibUsb.fs         # libusb-1.0 P/Invoke with 64-byte chunking & framing
│       └── Device53xd.fs     # Goodix53xdDevice high-level taskResult driver workflows
├── tests/
│   └── GoodixFp.Tests/
│       └── Tests.fs          # Comprehensive unit & handshake verification tests
└── benchmarks/
    └── GoodixFp.Benchmarks/
        └── Program.fs        # BenchmarkDotNet comparing Pure F# vs BC & Array vs Span
```

## Building & Testing

Prerequisites:
- [.NET 10 SDK](https://dotnet.microsoft.com/)
- `libusb-1.0` (for live hardware access)

```bash
# Build the complete solution
dotnet build GoodixFp.sln

# Run all 20 unit tests (including TLS 1.2 PSK handshakes)
dotnet test GoodixFp.sln

# Run quick benchmark smoke test
dotnet run --project benchmarks/GoodixFp.Benchmarks/GoodixFp.Benchmarks.fsproj

# Run full BenchmarkDotNet profiling sweep
dotnet run -c Release --project benchmarks/GoodixFp.Benchmarks/GoodixFp.Benchmarks.fsproj -- --filter *
```

## Vendor Blob Extraction & Patching

To extract and patch the canonical Dell libfprint TOD blob:

```bash
./scripts/fetch-goodix-blob.sh
```

This verifies the exact SHA-256 hash `bfa30696fbed9b86cfb5339293d458b9175d05b8895a8644d6b72615ffc9756b`, replaces version 2 with 0 in `.gnu.version` (`0x21ac..0x232f`), zeroes `vn_next` at `0x23ac`, repoints `DT_NEEDED[0]` to `libc.so.6`, sets `DT_VERNEEDNUM = 4` in `.dynamic` at `0x144dd0`, and writes the patched shared library to `${XDG_DATA_HOME:-$HOME/.local/share}/goodix-fp/libgoodix_tod_53xc.so`.

## License

MIT License. See [LICENSE](LICENSE) for details.
