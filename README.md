# Senbei

A static unpacker for Crackproof-protected 64-bit and 32-bit PE files. Point it
at a file or a folder and it writes decrypted copies — no launch of the
protected program, no kernel driver, no code runs out of the protected binary.

> _"Crackproof"? It's senbei (煎餅 — rice cracker). Cracks itself._

Senbei reads a protected `.exe` or `.dll`, replays the unpacking algorithm
entirely in memory, and writes the recovered image to a new file. The core is a
pure, panic-free library with no file I/O; the CLI wraps it with scanning, a
progress bar, and a run log. A browser version (WebAssembly, fully client-side)
lives in [`web/`](web/).

## Legal notice and intended use

**Read this before using Senbei.**

- Senbei is a research and interoperability tool. It exists to enable lawful
  reverse engineering, security research, preservation, and interoperability
  with software you already legitimately possess.
- **Only process binaries you own or are explicitly authorized to analyze.**
  Depending on your jurisdiction and license agreements, circumventing
  technological protection measures may be restricted (for example under
  DMCA §1201 in the United States, which contains exemptions for security
  research and interoperability). It is your responsibility to ensure your use
  is lawful.
- Senbei does not bypass any access control for you: it performs a purely
  static transformation of a file already on your disk. It derives everything
  it needs from the input file itself, contains no vendor code or secrets, and
  distributes no keys, cracks, or copyrighted content.
- Senbei does not enable online play, license fraud, or cheating, and must not
  be used to redistribute decrypted binaries. Do not upload outputs anywhere.
- The authors provide this software "as is", without warranty of any kind, and
  accept no liability for misuse. See [LICENSE](LICENSE) (AGPL-3.0).
- "Crackproof" is a trademark of its respective owner; this project is not
  affiliated with or endorsed by the protection vendor or any software
  publisher. Names are used for identification only.

## What it handles

| Kind | Description |
| --- | --- |
| `Exe` | Crackproof-protected executable (PE32+ and PE32). |
| `NativeDll` | Protected native (unmanaged) DLL. |
| `ManagedDll` | Protected .NET assembly (has a CLR data directory). |
| `._` companion | Stub + external encrypted payload layout, spliced automatically. |
| `global-metadata.dat` | il2cpp metadata with obfuscated method tokens, de-obfuscated in place. |

Detection is content-based (header key-table at offset 4096, magic `KONN`),
not extension-based. Anything unrecognized is left untouched.

## Quick start

```cmd
cargo build --release

senbei protected.exe
:: -> unpack\protected.unpack.exe

senbei "C:\Games\MyGame"
:: -> C:\Games\MyGame\unpack\...  (recursive, skips non-targets)
```

Every output is sanity-checked statically; structurally broken results are
flagged as suspect rather than silently trusted.

## Documentation

- [Usage reference](docs/usage.md) — CLI flags, exit codes, integrity check
- [Design](docs/design.md) — architecture, routing, and error model
- [Development](docs/development.md) — building, testing, environment variables
- [Web version](web/README.md) — run Senbei in a browser

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).
