//! Corpus test over the user-managed `senbei/samples` folder.
//!
//! Drop real Crackproof `*.exe` / `*.dll` inputs in there (and/or il2cpp
//! `*.dat` metadata blobs), optionally alongside a byte-exact golden named
//! `<base>.golden.<ext>`. Each input is processed and classified:
//!
//! - golden present, bytes identical  -> pass (silent)
//! - golden present, bytes differ     -> FAIL (the test fails)
//! - no golden                        -> WARNING (printed; needs a manual check)
//!
//! Inputs go through [`senbei::job::unpack_bytes`], the same routing the CLI
//! uses, **not** `unpack_auto` directly. That matters: `unpack_auto` alone
//! cannot reach the external-companion layout, whose stub is meaningless
//! without its `<name>._` payload — a corpus wired to `unpack_auto` silently
//! covers none of the splice / export-overlay / TLS-restore code, nor the
//! marker-less "new layout" those builds use. A `<input>._` sibling in the
//! samples folder is picked up automatically, exactly as it is on disk.
//!
//! An input whose bytes carry the il2cpp metadata magic is routed through
//! [`senbei::metadata::deobfuscate`] instead, giving the method-token remap
//! real-world coverage (its unit tests only build synthetic layouts).
//!
//! The folder is git-ignored (see `senbei/samples/README.md`), so the set of
//! samples is whatever happens to be on the machine. An empty/absent folder is
//! a no-op pass.

mod common;
use common::samples_dir;
use std::path::Path;
use walkdir::WalkDir;

/// An input is a `.exe`/`.dll`/`.dat` whose name doesn't carry the `.golden.`
/// marker — those are goldens, not inputs. External companions (`<name>._`)
/// have extension `_` and are therefore never inputs in their own right; they
/// are consumed by their base module.
fn is_input(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let ext = ext.to_ascii_lowercase();
    if ext != "exe" && ext != "dll" && ext != "dat" {
        return false;
    }
    // Reject goldens like `foo.golden.exe`.
    !path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_ascii_lowercase().contains(".golden."))
        .unwrap_or(false)
}

/// Golden path for an input: `<base>.golden.<ext>` next to it.
fn golden_for(input: &Path) -> std::path::PathBuf {
    let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    input.with_file_name(format!("{stem}.golden.{ext}"))
}

/// External-companion path for an input: `<full file name>._` next to it,
/// matching what the CLI looks for on disk.
fn companion_for(input: &Path) -> Option<std::path::PathBuf> {
    let name = input.file_name()?;
    let mut n = name.to_os_string();
    n.push("._");
    let p = input.with_file_name(n);
    p.is_file().then_some(p)
}

#[test]
fn samples_unpack_against_goldens() {
    let dir = samples_dir();
    // An absent/empty corpus fails only when explicitly required — a green
    // run that unpacked nothing hides every unpack regression, but on public
    // CI there is no corpus at all (binaries are never committed), so the
    // gate is opt-in via SENBEI_REQUIRE_SAMPLES rather than implied by CI.
    // Locally the corpus is the user-managed samples/ folder (see
    // samples/README.md).
    let require = std::env::var_os("SENBEI_REQUIRE_SAMPLES").is_some();
    if !dir.is_dir() {
        assert!(
            !require,
            "samples: {} does not exist — corpus required (CI)",
            dir.display()
        );
        eprintln!("samples: {} does not exist, nothing to test", dir.display());
        return;
    }

    let mut inputs: Vec<_> = WalkDir::new(&dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0
                || !entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("unpack"))
        })
        .map(|entry| entry.unwrap_or_else(|e| panic!("walk {}: {e}", dir.display())))
        .filter(|entry| entry.file_type().is_file() && is_input(entry.path()))
        .map(|entry| entry.into_path())
        .collect();
    inputs.sort();

    if inputs.is_empty() {
        assert!(
            !require,
            "samples: no .exe/.dll inputs in {} — corpus required (CI)",
            dir.display()
        );
        eprintln!("samples: no .exe/.dll inputs in {}", dir.display());
        return;
    }

    let mut passed = 0usize;
    let mut warnings: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for input in &inputs {
        let name = input
            .strip_prefix(&dir)
            .unwrap_or(input)
            .to_string_lossy()
            .to_string();
        let bytes = match std::fs::read(input) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{name}: read error: {e}"));
                continue;
            }
        };

        let got = if senbei::metadata::is_metadata(&bytes) {
            // il2cpp metadata: method-token de-obfuscation, no PE pipeline and
            // no integrity check (the output is not a PE image).
            match senbei::metadata::deobfuscate(&bytes) {
                Ok((out, _report)) => out,
                Err(e) => {
                    failures.push(format!("{name}: de-obfuscation failed: {e}"));
                    continue;
                }
            }
        } else {
            // Splice in the external companion when one sits next to the input,
            // then run the CLI's routing (which also overlays the stub's export
            // table and TLS directory for spliced inputs).
            let companion = match companion_for(input) {
                Some(p) => match std::fs::read(&p) {
                    Ok(b) => Some(b),
                    Err(e) => {
                        failures.push(format!("{name}: companion read error: {e}"));
                        continue;
                    }
                },
                None => None,
            };
            let image = match senbei::job::unpack_bytes(&bytes, companion.as_deref()) {
                Ok(img) => img,
                Err(e) => {
                    failures.push(format!("{name}: unpack failed: {e:?}"));
                    continue;
                }
            };
            // The static integrity check is a second, golden-independent gate:
            // it catches an output that is structurally plausible but would
            // crash at runtime (0xC0000005) even when a stale golden still
            // byte-matches. (Goldens are byte comparisons only — "matches
            // golden" ≠ runs.)
            if !image.integrity.ok() {
                failures.push(format!(
                    "{name}: integrity check failed: {}",
                    image.integrity.issues.join("; ")
                ));
                continue;
            }
            image.bytes
        };

        let golden = golden_for(input);
        if !golden.exists() {
            warnings.push(format!(
                "{name}: unpacked OK ({} bytes) but no golden ({}) — MANUAL CHECK",
                got.len(),
                golden.file_name().unwrap().to_string_lossy()
            ));
            continue;
        }

        let want = match std::fs::read(&golden) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{name}: golden read error: {e}"));
                continue;
            }
        };

        if got.len() != want.len() {
            failures.push(format!(
                "{name}: length differs: got {} want {}",
                got.len(),
                want.len()
            ));
            continue;
        }
        if let Some((i, (a, b))) = got.iter().zip(&want).enumerate().find(|(_, (a, b))| a != b) {
            failures.push(format!(
                "{name}: first diff at 0x{i:X}: got {a:02X} want {b:02X}"
            ));
            continue;
        }
        passed += 1;
    }

    eprintln!(
        "samples: {} input(s) — {} pass, {} warning(s), {} failure(s)",
        inputs.len(),
        passed,
        warnings.len(),
        failures.len()
    );
    for w in &warnings {
        eprintln!("  WARN  {w}");
    }
    for f in &failures {
        eprintln!("  FAIL  {f}");
    }

    assert!(failures.is_empty(), "{} sample(s) failed", failures.len());
}
