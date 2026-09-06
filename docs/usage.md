# Usage

```text
senbei <file|folder> [--out DIR] [-v|--verbose] [-q|--quiet]... [--scan-all] [--no-log] [--no-pause] [-V|--version] [-h|--help]
```

## Single File

The output is written below `<parent>/unpack/` with `.unpack` inserted before the extension. `--out DIR` changes both the output and log directory.

```cmd
senbei app.exe
senbei app.exe --out C:\out
```

For `global-metadata.dat`, Senbei writes `global-metadata.unpack.dat` only when method tokens change. Unsupported metadata versions remain untouched and are reported as skipped.

## Android Targets

Protected `.so` files are restored from their encrypted payload sections and written as `libil2cpp.unpack.so` or the corresponding input name. APK, APKS, and XAPK files are treated as containers: their manifests are read first, nested APKs are followed when necessary, and only `.so` and exact `global-metadata.dat` entries are extracted.

If a restored library contains embedded metadata, the unwrapped blob is written beside it as `global-metadata.unpack.dat`. Identical loose and package entries are restored once, preferring the loose file.

## Folder Mode

Folder mode walks recursively, skips directories named `unpack`, and mirrors recognized outputs below `<root>/unpack/` or `--out DIR`. Windows candidates are `.exe`, `.dll`, and `global-metadata.dat`; Android candidates are `.so` and `global-metadata.dat`. A matching `.exe._` or `.dll._` payload is consumed by its stub and is excluded from the skipped count.

The summary has the form `12 unpacked · 3 skipped · 0 errors · 1 suspect · 2 metadata`; the package count is appended when packages were opened. Each file is isolated so one failed target does not stop the folder run.

## Integrity Check

PE outputs are checked for valid headers, section ranges, entry-point mapping, readable import names, relocation requirements, and managed metadata signatures. Android outputs are validated during ELF restoration, including decoded container sizes, fixup bounds, and rebuilt dynamic tables.

A clean report is not a proof of correctness, but a non-clean report is a reliable broken-output signal. Suspect PE files are still written and counted separately.

## Flags

| Flag | Behavior |
| --- | --- |
| `--out DIR` | Write outputs and logs below `DIR`. |
| `-v`, `--verbose` | Print per-stage progress. |
| `-q`, `--quiet` | Hide progress and per-file lines; repeat to suppress all standard output. |
| `--no-log` | Do not write a run log. |
| `--scan-all` | Probe every selected target-name candidate, including files below the size floor. |
| `--no-pause` | Disable the Explorer-friendly Windows exit prompt. |
| `-V`, `--version` | Print the version and exit. |
| `-h`, `--help` | Show usage. |

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | The requested restore completed without errors. |
| `1` | A target failed, a scan probe was unreadable, or a single-file restore errored. |
| `2` | The command line was invalid. |
