# Usage

```
senbei <file|folder> [--out DIR] [-v|--verbose] [-q|--quiet]... [--scan-all]
                     [--no-log] [--no-pause] [-V|--version] [-h|--help]
```

Real runs print `Senbei <version>` once at start. Use `-V` / `--version` to
print the version and exit.

## Single file

The decrypted image is written under `<parent>/unpack/` with `.unpack` inserted
before the extension. A `senbei-<timestamp>.log` is written in the same
directory. With `--out DIR`, both the output and the log go into `DIR` instead:

```cmd
senbei app.exe
:: -> unpack\app.unpack.exe
:: -> unpack\senbei-YYYYMMDD-HHMMSS.log

senbei app.exe --out C:\out
:: -> C:\out\app.unpack.exe
:: -> C:\out\senbei-YYYYMMDD-HHMMSS.log
```

Pointing senbei directly at an il2cpp `global-metadata.dat` rewrites its
obfuscated method tokens back to the contiguous per-module range il2cpp
expects; the output is `global-metadata.unpack.dat`, written only when tokens
actually changed. Only metadata format version 31 is rewritten; other versions
are reported and left untouched.

## Folder mode

Senbei walks the directory recursively, skips any subdirectory literally named
`unpack`, and unpacks every file it recognises as Crackproof-protected (by
content, not extension — renamed files and `.bak` backups are still found).
Results land under `<root>/unpack/` (or `--out DIR`), mirroring the input
tree's relative paths. The run log is written **in that same out directory**:

```cmd
senbei "C:\Games\MyGame"
:: -> C:\Games\MyGame\unpack\...
:: -> C:\Games\MyGame\unpack\senbei-YYYYMMDD-HHMMSS.log
```

Folder mode also picks up `global-metadata.dat` files and external-companion
`._` payloads: a module whose `<name>._` sibling matches its header region is
spliced with the companion automatically (no flag needed) and unpacked as one
image, with the output named for the stub.

Each file is processed in isolation: an error or panic on one file is caught,
counted, and logged, and the run continues. Folder mode finishes with a summary
line, then duration:

```
12 unpacked · 3 skipped · 0 errors · 1 suspect · 2 metadata
done in 1234 ms
```

## Integrity check

A successful unpack is not always a runnable one: a layout heuristic can pick
the wrong offset and leave the entry-point stub or import strings encrypted, so
the pipeline reports success but the OS loader faults at runtime (typically
`0xC0000005`, STATUS_ACCESS_VIOLATION). To catch this, senbei runs a static
sanity check over every output it produces — inspecting the bytes alone, with
no reference image and no execution.

It flags only defects that cannot occur in a correctly unpacked image:

- malformed DOS/PE headers, bad optional-header magic, implausible section
  count, zero `SizeOfImage`, or section raw-data ranges that run past EOF;
- an entry point that doesn't map into a section, isn't in an executable
  section, or whose stub is all zeros or all `0xCC` int3 padding (the classic
  left-encrypted symptom);
- a native (unmanaged) DLL with no base-relocation directory — it cannot
  survive being mapped at a non-preferred base;
- **any** import descriptor whose DLL name doesn't resolve or isn't readable
  ASCII (imports left encrypted) — the whole table is walked, not just the
  first entry;
- for a managed assembly, a COR20 header whose `cb` isn't `0x48` or a
  MetaData stream missing its `BSJB` signature (the CLR would reject the
  image outright).

The entry-point and import checks are skipped for managed assemblies, whose
native EP and import stub are legitimately not what the native loader expects.

The check is deliberately conservative: a clean report is **not** a proof of
correctness, but a non-clean report is a reliable "this is broken" signal. A
suspect file is still written (the bytes are the best available) and flagged —
single-file mode prints a warning to stderr, folder mode prints a yellow `!`
line, adds a `SUSPECT` entry to the run log, and counts it in the summary's
`suspect` total (which is additive to `unpacked`).

## Flags

| Flag | Behavior |
| --- | --- |
| `--out DIR` | Write outputs (and the log, unless `--no-log`) under `DIR`. |
| `-v`, `--verbose` | Print detailed `[N/9]` per-stage unpack progress (and the destination path) for each file. In folder mode this replaces the progress bar. |
| `-q`, `--quiet` | Once: hide progress bar and per-file lines; keep banner, summary, and duration. Twice (`-q -q`): suppress all stdio (exit code only). |
| `--no-log` | Do not write `senbei-*.log`. Console output is unchanged by this flag alone. |
| `--scan-all` | Probe every file in a folder, including ones the scan pre-filter skips (under 4128 bytes, or a bulk-asset extension like `.ab`/`.xml`/`.acb`). Much slower on large game trees; finds the same targets in practice. |
| `--no-pause` | Skip the "Press Enter to exit" prompt (for scripted runs). |
| `-V`, `--version` | Print `Senbei <version>` and exit. |
| `-h`, `--help` | Show usage. |

On Windows, when launched from Explorer (the process owns its console) senbei
pauses for Enter before exiting so the window doesn't vanish. `--no-pause`
disables this; it has no effect when stdout is piped or run from another
process.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success (single file unpacked, or folder run with no errors). |
| `1` | At least one file failed, a scan probe was unreadable, or a single-file unpack errored. |
| `2` | Usage error: no path given, unknown option, missing `--out` value, or multiple input paths (help printed). |

A folder run also fails with `1` when parts of the tree could not be scanned
(unreadable directory entries or files that failed the content probe) — those
are potential missed targets, not clean skips. An il2cpp metadata blob whose
format version senbei does not handle is *not* an error: it is reported, left
untouched, and counted as skipped.
