# Senbei

A static unpacker for CrackProof-protected Windows PE files and Android AArch64 shared libraries.

> _"Crackproof"? It's senbei (煎餅 — rice cracker). Cracks itself._

## Usage

```cmd
cargo build --release
senbei protected.exe
senbei game.apk
senbei "C:\Games\MyGame"
```

Outputs are written below an `unpack` directory unless `--out` is supplied.

Full documentation: <https://xn--ri8h.gitbook.io/crackproof-research/senbei>

## Legal notice and intended use

**Read this before using Senbei.**

- Senbei is a research and interoperability tool. It exists to enable lawful reverse engineering, security research, preservation, and interoperability with software you already legitimately possess.
- **Only process binaries you own or are explicitly authorized to analyze.** Depending on your jurisdiction and license agreements, circumventing technological protection measures may be restricted (for example under DMCA §1201 in the United States, which contains exemptions for security research and interoperability). It is your responsibility to ensure your use is lawful.
- Senbei does not bypass any access control for you: it performs a purely static transformation of a file already on your disk. It derives everything it needs from the input file itself, contains no vendor code, and distributes no cracks or copyrighted content. (One Android packaging variant's embedded metadata layer is unwrapped with an XOR keystream recovered from a ciphertext/plaintext pair during analysis of a single build; that keystream is research output shipped with the unpacker, not a vendor-distributed key, and builds it doesn't match are left alone.)
- Senbei does not enable online play, license fraud, or cheating, and must not be used to redistribute decrypted binaries. Do not upload outputs anywhere.
- The authors provide this software "as is", without warranty of any kind, and accept no liability for misuse. See [LICENSE](LICENSE) (AGPL-3.0).
- "Crackproof" is a trademark of its respective owner; this project is not affiliated with or endorsed by the protection vendor or any software publisher. Names are used for identification only.

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).
