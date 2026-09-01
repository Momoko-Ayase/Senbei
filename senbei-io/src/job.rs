use senbei_pe as unpacker;
use std::path::{Path, PathBuf};

/// Crackproof header key table lives at this fixed file offset. For the
/// external-companion layout, the companion payload aligns to the stub here.
const HEADER_OFF: usize = 4096;

/// Build the unpacker input for `input`, transparently handling the
/// **external-companion** layout used by some il2cpp games.
///
/// In that layout a protected module is split into a thin on-disk loader stub
/// (`Foo.dll`, whose code sections are stripped to one page) plus an encrypted
/// `Foo.dll._` companion holding the real payload. The companion is byte-for-byte
/// the stub's payload region starting at the Crackproof header (offset 4096), so
/// `stub[..4096] ++ companion` reconstructs the ordinary embedded-payload file
/// the existing pipelines already unpack. The runtime loader does exactly this:
/// it maps `Foo.dll._` and feeds it through the standard Crackproof unpack.
///
/// The splice fires only when a sibling `<input>._` exists *and* its first 32
/// bytes equal the stub's header at offset 4096 — a precise signal that the
/// companion is this stub's payload. Otherwise the file is returned untouched,
/// so normal (embedded-payload) inputs are unaffected.
fn read_unpacker_input(input: &Path) -> std::io::Result<UnpackerInput> {
    let stub = std::fs::read(input)?;

    // Companion path: append "._" to the full file name (Foo.dll -> Foo.dll._).
    let companion = match input.file_name() {
        Some(name) => {
            let mut n = name.to_os_string();
            n.push("._");
            input.with_file_name(n)
        }
        None => {
            return Ok(UnpackerInput {
                bytes: stub,
                stub: None,
            });
        }
    };
    if !companion.is_file() {
        return Ok(UnpackerInput {
            bytes: stub,
            stub: None,
        });
    }
    let comp = std::fs::read(&companion)?;
    match splice_companion(&stub, &comp) {
        // A splice fired: keep the stub so its plaintext export table can be
        // overlaid onto the unpacked image (the companion does not carry it).
        Some(spliced) => Ok(UnpackerInput {
            bytes: spliced,
            stub: Some(stub),
        }),
        None => Ok(UnpackerInput {
            bytes: stub,
            stub: None,
        }),
    }
}

/// The bytes fed to the unpacker, plus the original loader stub when the input
/// was reconstructed from an external companion. The stub is retained because
/// the crackproof loader rebuilds the PE export table at runtime from data kept
/// in the stub — that table is *not* present in the encrypted companion, so the
/// unpacked image needs it overlaid from the stub afterwards
/// (see [`overlay_exports_from_stub`]).
struct UnpackerInput {
    bytes: Vec<u8>,
    stub: Option<Vec<u8>>,
}

/// Overlay the PE export table from the loader `stub` onto the unpacked image
/// `out`, for the external-companion layout.
///
/// In that layout the encrypted companion carries the real `.text`/`il2cpp`
/// payload but **not** a usable export directory: the crackproof loader rebuilds
/// exports at runtime from the plaintext copy retained in the stub's `.rdata`.
/// Statically, the spliced input therefore decrypts to a garbage export
/// directory (`NumberOfFunctions` etc. are ciphertext), which makes downstream
/// tools (IL2CppDumper, IDA) choke when they parse it. The fix does what the
/// loader does: copy the export-directory region byte-for-byte from the stub to
/// the same RVA in the unpacked image.
///
/// No-op (leaves `out` untouched) if there is no export directory, or if the
/// region cannot be mapped in either image — so a malformed stub can never
/// corrupt an otherwise-good unpack.
fn overlay_exports_from_stub(out: &mut [u8], stub: &[u8]) {
    let (export_rva, export_size) = match pe_export_dir(out) {
        Some(v) if v.1 != 0 => v,
        _ => return,
    };
    let dst = match rva_to_file_off(out, export_rva) {
        Some(o) => o,
        None => return,
    };
    let src = match rva_to_file_off(stub, export_rva) {
        Some(o) => o,
        None => return,
    };
    let n = export_size as usize;
    if dst + n <= out.len() && src + n <= stub.len() {
        out[dst..dst + n].copy_from_slice(&stub[src..src + n]);
    }
}

/// Restore the TLS directory from the loader `stub` onto the unpacked image
/// `out`, for the external-companion layout.
///
/// Crackproof strips the whole `IMAGE_TLS_DIRECTORY` from the encrypted payload
/// — the data-directory entry, the directory struct, the raw-data template, and
/// the base relocations for the struct's four 64-bit pointer fields — and
/// re-installs TLS itself from data kept in the stub when it loads the module.
/// A statically-unpacked DLL is loaded by the ordinary Windows loader instead,
/// which needs a valid TLS directory or it never allocates a TLS slot for the
/// module nor writes `_tls_index`. The module's C++ `thread_local` accesses then
/// read a garbage TLS slot — observed as a `0xC0000005` deep in IL2CPP type
/// resolution (a TypeDef token used as a raw `s_TypeInfoTable` index).
///
/// The stub retains the full plaintext `.rdata` (only `.text`/`il2cpp` are
/// stripped to one page), so the directory struct and its raw-data template are
/// copied back byte-for-byte at their RVAs, the data-directory entry is taken
/// from the stub header (the unpacked image's was overwritten with the zeroed
/// saved-header blob), and four DIR64 relocations are appended to `.reloc`.
///
/// No-op if the stub declares no TLS directory or if any required region cannot
/// be mapped/relocated — so it can never corrupt an otherwise-good unpack.
fn restore_tls_from_stub(out: &mut [u8], stub: &[u8]) {
    let pe = match read_u32(out, 0x3C) {
        Some(v) => v as usize,
        None => return,
    };
    if out.get(pe..pe + 4) != Some(&b"PE\0\0"[..]) {
        return;
    }
    // This restore is PE32+-only: it copies a 40-byte IMAGE_TLS_DIRECTORY64,
    // converts fields with a 64-bit image base, and appends DIR64 relocs. A
    // PE32 module needs the 24-byte struct / DIR32 handling (the unpacker core
    // does that itself — see `restore_pe32_tls_from_stub`), so bail rather than
    // read the data directories at the wrong (PE32+) offset and write garbage.
    if read_u16(out, pe + 24) != Some(0x20B) {
        return;
    }
    // TLS is data-directory index 9 (PE32+ directories at optional header +112).
    let tls_dd = match pe.checked_add(24 + 112 + 9 * 8) {
        Some(v) => v,
        None => return,
    };
    // The genuine entry survives in the stub header; the unpacked image's copy
    // was clobbered by the (zeroed-TLS) saved-header blob.
    let (tls_rva, tls_size) = match (read_u32(stub, tls_dd), read_u32(stub, tls_dd + 4)) {
        (Some(r), Some(s)) if r != 0 && s != 0 => (r, s),
        _ => return, // module has no TLS — nothing to restore
    };
    // Image base (PE32+, optional header +24) converts the struct's absolute VAs
    // back to RVAs for the raw-data template overlay.
    let image_base = match read_u64(out, pe + 24 + 24) {
        Some(v) => v,
        None => return,
    };

    // 1) Overlay the IMAGE_TLS_DIRECTORY struct from the stub at its RVA.
    let dst = match rva_to_file_off(out, tls_rva) {
        Some(o) => o,
        None => return,
    };
    let src = match rva_to_file_off(stub, tls_rva) {
        Some(o) => o,
        None => return,
    };
    let n = tls_size as usize;
    if dst.checked_add(n).is_none_or(|e| e > out.len())
        || src.checked_add(n).is_none_or(|e| e > stub.len())
    {
        return;
    }
    out[dst..dst + n].copy_from_slice(&stub[src..src + n]);

    // 2) Restore the data-directory entry so the loader processes TLS at all.
    write_u32_at(out, tls_dd, tls_rva);
    write_u32_at(out, tls_dd + 4, tls_size);

    // 3) Overlay the raw-data template [StartAddressOfRawData, EndAddressOfRawData).
    if let (Some(start_va), Some(end_va)) = (read_u64(out, dst), read_u64(out, dst + 8))
        && end_va > start_va
        && start_va >= image_base
    {
        let tpl_rva = (start_va - image_base) as u32;
        let tpl_len = (end_va - start_va) as usize;
        if let (Some(td), Some(ts)) = (
            rva_to_file_off(out, tpl_rva),
            rva_to_file_off(stub, tpl_rva),
        ) && td.checked_add(tpl_len).is_some_and(|e| e <= out.len())
            && ts.checked_add(tpl_len).is_some_and(|e| e <= stub.len())
        {
            out[td..td + tpl_len].copy_from_slice(&stub[ts..ts + tpl_len]);
        }
    }

    // 4) Append DIR64 relocations for the struct's four 64-bit pointer fields
    //    (Start/End/Index/CallBacks at +0/+8/+0x10/+0x18). Without them the
    //    loader would leave preferred-base VAs in a rebased image.
    add_tls_relocs(out, pe, tls_rva);
}

/// Append a single base-relocation block covering the four 64-bit pointer fields
/// of the TLS directory struct at `tls_rva`. The block is written immediately
/// after the existing relocation table (which must be free space and in bounds)
/// and the BaseReloc directory size is grown to include it. No-op if the table
/// is absent, the fields straddle a relocation page, or the slot is not free.
fn add_tls_relocs(out: &mut [u8], pe: usize, tls_rva: u32) {
    let reloc_dd = pe + 24 + 112 + 5 * 8; // BaseReloc = directory index 5
    let (reloc_rva, reloc_size) = match (read_u32(out, reloc_dd), read_u32(out, reloc_dd + 4)) {
        (Some(r), Some(s)) if r != 0 => (r, s),
        _ => return,
    };
    // All four fields (last at +0x18) must share one 0x1000 relocation page.
    let page = tls_rva & !0xFFF;
    if (tls_rva.wrapping_add(0x18)) & !0xFFF != page {
        return;
    }
    const BLOCK: usize = 8 + 4 * 2; // header + four DIR64 entries
    let at = match rva_to_file_off(out, reloc_rva.wrapping_add(reloc_size)) {
        Some(o) => o,
        None => return,
    };
    if at.checked_add(BLOCK).is_none_or(|e| e > out.len()) {
        return;
    }
    if out[at..at + BLOCK].iter().any(|&b| b != 0) {
        return; // refuse to clobber existing data
    }
    write_u32_at(out, at, page);
    write_u32_at(out, at + 4, BLOCK as u32);
    for (i, off) in [0u32, 8, 0x10, 0x18].iter().enumerate() {
        let entry = (10u16 << 12) | (((tls_rva.wrapping_add(*off)) & 0xFFF) as u16);
        let p = at + 8 + i * 2;
        out[p..p + 2].copy_from_slice(&entry.to_le_bytes());
    }
    write_u32_at(out, reloc_dd + 4, reloc_size.wrapping_add(BLOCK as u32));
}

/// Read the Export data-directory (RVA, size) from a PE image, or `None` if the
/// headers are too short/invalid to parse.
fn pe_export_dir(buf: &[u8]) -> Option<(u32, u32)> {
    let pe = read_u32(buf, 0x3C)? as usize;
    if buf.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    // Optional header at pe+24; data directories start at +96 on PE32 (0x10B)
    // and +112 on PE32+ (0x20B); Export is index 0.
    let dd_base = match read_u16(buf, pe + 24)? {
        0x20B => 112,
        0x10B => 96,
        _ => return None,
    };
    let dd = pe.checked_add(24 + dd_base)?;
    Some((read_u32(buf, dd)?, read_u32(buf, dd + 4)?))
}

/// Map an RVA to a file offset using the PE section table. Returns `None` if no
/// section contains the RVA or the headers cannot be parsed.
fn rva_to_file_off(buf: &[u8], rva: u32) -> Option<usize> {
    let pe = read_u32(buf, 0x3C)? as usize;
    if buf.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let nsec = read_u16(buf, pe + 6)? as usize;
    let opt_size = read_u16(buf, pe + 20)? as usize;
    let sh = pe.checked_add(24)?.checked_add(opt_size)?;
    for i in 0..nsec {
        let o = sh.checked_add(i.checked_mul(40)?)?;
        let vsz = read_u32(buf, o + 8)?;
        let va = read_u32(buf, o + 12)?;
        let raw = read_u32(buf, o + 20)?;
        if rva >= va && rva < va.wrapping_add(vsz.max(1)) {
            return Some((rva - va).wrapping_add(raw) as usize);
        }
    }
    None
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let b = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    let b = buf.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Write a little-endian `u32` at `off`, silently doing nothing if out of bounds.
fn write_u32_at(buf: &mut [u8], off: usize, val: u32) {
    if let Some(slot) = buf.get_mut(off..off + 4) {
        slot.copy_from_slice(&val.to_le_bytes());
    }
}

/// Splice a stub and its external-companion payload into the embedded-payload
/// form the pipelines expect, or `None` if `comp` is not this stub's payload.
///
/// The companion is byte-for-byte the stub's payload region from the Crackproof
/// header (offset 4096) onward, so the result is `stub[..4096] ++ comp`. The
/// splice fires only when the first 32 bytes of `comp` equal the stub's header
/// at offset 4096 — a 32-byte match on the key-table/magic region that confirms
/// the pairing and leaves ordinary (non-companion) inputs untouched.
fn splice_companion(stub: &[u8], comp: &[u8]) -> Option<Vec<u8>> {
    let hdr_end = HEADER_OFF + 32;
    if stub.len() >= hdr_end && comp.len() >= 32 && stub[HEADER_OFF..hdr_end] == comp[..32] {
        let mut spliced = Vec::with_capacity(HEADER_OFF + comp.len());
        spliced.extend_from_slice(&stub[..HEADER_OFF]);
        spliced.extend_from_slice(comp);
        return Some(spliced);
    }
    None
}

/// Summary of a folder-mode run.
#[derive(Default)]
pub struct Summary {
    pub unpacked: usize,
    pub skipped: usize,
    pub errors: usize,
    /// Files that unpacked without error but failed the static integrity check
    /// — likely to crash at runtime (e.g. 0xC0000005). Counted in addition to
    /// `unpacked` (a suspect file is still written).
    pub suspect: usize,
    /// il2cpp `global-metadata.dat` files de-obfuscated (method tokens remapped),
    /// including blobs unwrapped from restored Android libraries.
    pub metadata: usize,
    /// Android app packages (`.apk`/`.apks`/`.xapk`) opened and searched.
    pub packages: usize,
    /// Wall-clock duration of the folder run in milliseconds.
    pub duration_ms: u128,
}

impl Summary {
    /// The summary line shared by CLI output and the log file.
    pub fn line(&self) -> String {
        let mut line = format!(
            "{} unpacked · {} skipped · {} errors · {} suspect · {} metadata",
            self.unpacked, self.skipped, self.errors, self.suspect, self.metadata
        );
        if self.packages > 0 {
            line.push_str(&format!(" · {} packages", self.packages));
        }
        line
    }
}

/// Default output root for a folder unpack: `<root>/unpack`.
pub fn default_out_root_for_folder(root: &Path) -> PathBuf {
    root.join("unpack")
}

/// Default output root for a single-file unpack: `<parent>/unpack` (or `./unpack`
/// when the input has no parent directory).
pub fn default_out_root_for_file(input: &Path) -> PathBuf {
    let parent = input
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    parent.join("unpack")
}

/// Unpack all Crackproof-protected files under `root`, writing results into
/// a mirrored subtree under `out_dir` (or `root/unpack` if None).
///
/// Each file is processed independently: a panic or error in one file is
/// isolated and counted as an error; the loop continues.
pub fn run_folder(root: &Path, out_dir: Option<&Path>, quiet: bool) -> anyhow::Result<Summary> {
    run_folder_v(root, out_dir, if quiet { 1 } else { 0 }, false, false)
}

/// Like [`run_folder`], but prints detailed `[N/9]` step progress (and a final
/// `Write to <dest>` line) for each EXE when `verbose` is true.
///
/// `quiet` is a level: `>= 1` suppresses per-file UI lines and the progress bar.
/// When `no_log` is true, no `senbei-*.log` is created under the out root.
pub fn run_folder_v(
    root: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
) -> anyhow::Result<Summary> {
    run_folder_opts(
        root,
        out_dir,
        quiet,
        verbose,
        no_log,
        crate::scan::scan_all_env(),
    )
}

/// Like [`run_folder_v`], but with the scan pre-filter explicitly controlled.
///
/// When `scan_all` is true every regular file under `root` is opened and
/// content-probed, instead of skipping ones the free directory metadata already
/// rules out (extensionless, too small to hold a Crackproof key table, or a
/// bulk-asset extension). See [`crate::scan::find_targets_opts`] — exhaustive
/// scanning is dramatically slower on asset-heavy trees.
pub fn run_folder_opts(
    root: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
    scan_all: bool,
) -> anyhow::Result<Summary> {
    let t0 = std::time::Instant::now();
    let out_root = out_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_out_root_for_folder(root));
    std::fs::create_dir_all(&out_root)?;
    let log = if no_log {
        None
    } else {
        let log = crate::logfile::Log::create(&out_root)?;
        log.step(&format!("Senbei {}", env!("CARGO_PKG_VERSION")));
        log.step(&format!(
            "started {}",
            crate::logfile::local_stamp_display()
        ));
        log.step(&format!("input {}", root.display()));
        log.step(&format!("out {}", out_root.display()));
        Some(log)
    };
    // Single merged directory walk: returns Crackproof unpack candidates, il2cpp
    // metadata blobs, and Android targets from one traversal (see
    // [`crate::scan::find_targets_opts`]). Files the free directory metadata
    // already rules out are never opened — on asset-heavy trees the per-file
    // open+read latency, not the traversal, is the whole cost.
    let scan = crate::scan::find_targets_opts(root, scan_all);
    let candidates = scan.crackproof.as_slice();
    let metas = scan.metadata.as_slice();
    let scan_stats = &scan.stats;
    // Files the scan could not classify are potential missed targets, not
    // clean skips: an unreadable directory or a locked il2cpp game assembly must
    // fail the run (exit 1) rather than report "0 errors" over a partial scan.
    let scan_failed = scan_stats.walk_errors + scan_stats.probe_errors;
    if scan_failed > 0 && quiet == 0 {
        eprintln!(
            "warning: {} file(s) could not be read during the scan and may be missed targets",
            scan_failed
        );
    }
    if let Some(log) = &log {
        if scan_stats.walk_errors > 0 {
            log.step(&format!(
                "scan: {} directory entry(s) unreadable",
                scan_stats.walk_errors
            ));
        }
        if scan_stats.probe_errors > 0 {
            log.step(&format!(
                "scan: {} file(s) failed content probe (unreadable or detector panic)",
                scan_stats.probe_errors
            ));
        }
    }
    let suppress_file_lines = quiet >= 1;
    // Quiet wins over verbose: step progress only when quiet == 0 (spec: verbose
    // lines only when quiet == 0; quiet ≥ 2 must stay fully silent even with -v).
    let verbose_steps = verbose && quiet == 0;
    // Verbose mode prints multi-line `[N/9]` step output per file straight to
    // stdout; an active progress bar would be clobbered by it, so hide the bar
    // (its per-file ok/err lines still print) when verbose is on.
    let android_targets = scan.android_so.len() + scan.android_packages.len();
    let bar = crate::ui::progress(
        (candidates.len() + android_targets) as u64,
        quiet >= 1 || verbose,
    );
    let mut s = Summary {
        skipped: scan_stats.skipped,
        errors: scan_failed,
        ..Summary::default()
    };

    // Silence the default panic hook's stderr spew during per-file processing.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {})); // suppress "thread panicked" messages

    for input in candidates {
        let rel = rel_in_tree(root, input);
        let dest = out_root.join(out_name(&rel));

        // Wrap in catch_unwind so a single bad file never aborts the folder run.
        let input_owned = input.clone();
        let dest_owned = dest.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            unpack_one_v(&input_owned, &dest_owned, verbose_steps)
        }));

        match result {
            Ok(Ok((kind, report))) => {
                s.unpacked += 1;
                crate::ui::ok(&bar, suppress_file_lines, &rel, kind, &dest);
                if let Some(log) = &log {
                    log.step(&format!("OK {rel:?} -> {dest:?} ({kind:?})"));
                }
                if !report.ok() {
                    s.suspect += 1;
                    crate::ui::suspect(&bar, suppress_file_lines, &rel, &report);
                    if let Some(log) = &log {
                        log.step(&format!("SUSPECT {rel:?}: {}", report.issues.join("; ")));
                    }
                }
            }
            Ok(Err(e)) => {
                s.errors += 1;
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!("ERR {rel:?}: {e:#}"));
                }
            }
            Err(panic) => {
                s.errors += 1;
                let e = anyhow::anyhow!("unexpected panic: {}", panic_payload(&panic));
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!(
                        "ERR {rel:?}: panic during unpack: {}",
                        panic_payload(&panic)
                    ));
                }
            }
        }
        bar.inc(1);
    }

    // Android pass: protected AArch64 libraries and app packages. Loose `.so`
    // files restore first so the cross-source dedup keeps them over a copy
    // inside a package (loose beats `.apk` beats `.apks`/`.xapk` bundle).
    let mut android_seen = std::collections::HashSet::new();
    // Hashing a protected library costs a full read, so only pay it when a
    // duplicate source can actually exist in this run.
    let android_dedup = scan.android_so.len() > 1 || !scan.android_packages.is_empty();
    for input in &scan.android_so {
        let rel = rel_in_tree(root, input);
        let dest = out_root.join(out_name(&rel));
        // Unreadable here is fine: the restore reports the same error.
        if android_dedup
            && let Ok(bytes) = std::fs::read(input)
            && !android_seen.insert(crate::android::content_identity(&bytes))
        {
            s.skipped += 1;
            if let Some(log) = &log {
                log.step(&format!("SKIP {rel:?}: duplicate of an earlier target"));
            }
            bar.inc(1);
            continue;
        }
        let input_owned = input.clone();
        let dest_owned = dest.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::android::restore_so_file(&input_owned, &dest_owned, verbose_steps)
        }));
        match result {
            Ok(Ok(embedded)) => {
                s.unpacked += 1;
                crate::ui::ok_label(
                    &bar,
                    suppress_file_lines,
                    &rel.display().to_string(),
                    "So",
                    &dest,
                );
                if let Some(log) = &log {
                    log.step(&format!("OK {rel:?} -> {dest:?} (Android SO)"));
                }
                match write_embedded_metadata(embedded, &dest) {
                    Ok(Some(meta_dest)) => {
                        s.metadata += 1;
                        crate::ui::ok_label(
                            &bar,
                            suppress_file_lines,
                            &format!("{} (embedded metadata)", rel.display()),
                            "metadata",
                            &meta_dest,
                        );
                        if let Some(log) = &log {
                            log.step(&format!("META {rel:?} (embedded) -> {meta_dest:?}"));
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        s.errors += 1;
                        crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                        if let Some(log) = &log {
                            log.step(&format!("ERR {rel:?}: embedded metadata: {e:#}"));
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                s.errors += 1;
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!("ERR {rel:?}: {e:#}"));
                }
            }
            Err(panic) => {
                s.errors += 1;
                let e = anyhow::anyhow!("unexpected panic: {}", panic_payload(&panic));
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!(
                        "ERR {rel:?}: panic during restore: {}",
                        panic_payload(&panic)
                    ));
                }
            }
        }
        bar.inc(1);
    }
    for package in &scan.android_packages {
        let rel = rel_in_tree(root, package);
        s.packages += 1;
        let package_owned = package.clone();
        let rel_owned = rel.clone().into_owned();
        let out_root_owned = out_root.clone();
        let mut seen_taken = std::mem::take(&mut android_seen);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let outcomes = crate::android::restore_package(
                &package_owned,
                &rel_owned,
                &out_root_owned,
                &mut seen_taken,
                verbose_steps,
            );
            (outcomes, seen_taken)
        }));
        match result {
            Ok((Ok(outcomes), seen_back)) => {
                android_seen = seen_back;
                apply_package_outcomes(outcomes, &mut s, &bar, suppress_file_lines, &log);
            }
            Ok((Err(e), seen_back)) => {
                android_seen = seen_back;
                s.errors += 1;
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!("ERR {rel:?}: {e:#}"));
                }
            }
            Err(panic) => {
                // The dedup set may be in an unknown state after a panic; a
                // re-scan costs a duplicate restore at worst, never corruption.
                let e = anyhow::anyhow!("unexpected panic: {}", panic_payload(&panic));
                s.errors += 1;
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!(
                        "ERR {rel:?}: panic during package restore: {}",
                        panic_payload(&panic)
                    ));
                }
            }
        }
        bar.inc(1);
    }

    // il2cpp metadata pass. Crackproof's `-GMD` option obfuscates the method
    // tokens in `global-metadata.dat`; de-obfuscate any we find so the unpacked
    // il2cpp game assembly resolves methods instead of indexing its per-module
    // tables out of bounds (see [`senbei_metadata`]). This is additive to the
    // Crackproof module unpack above — the metadata blob is not itself a
    // Crackproof file.
    for meta in metas.iter() {
        let rel = rel_in_tree(root, meta);
        let dest = out_root.join(out_name(&rel));
        let meta_owned = meta.clone();
        let dest_owned = dest.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            deobfuscate_metadata_to(&meta_owned, &dest_owned, verbose_steps)
        }));
        match result {
            Ok(Ok(report)) if report.remapped > 0 => {
                s.metadata += 1;
                crate::ui::metadata(&bar, suppress_file_lines, &rel, report.remapped, &dest);
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {rel:?} -> {dest:?}: v{} remapped {} method tokens",
                        report.version, report.remapped
                    ));
                }
            }
            // Recognised metadata that needed no change (not -GMD-obfuscated):
            // leave it untouched and don't write a redundant copy.
            Ok(Ok(report)) => {
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {rel:?}: v{} already de-obfuscated",
                        report.version
                    ));
                }
            }
            Ok(Err(e)) => {
                // A metadata version we don't handle is NOT a run failure: the
                // game is simply not -GMD-obfuscated in a layout we know, the
                // file is left untouched, and the PE unpacks around it may be
                // fully successful. Count it as skipped (with a visible note),
                // matching the "anything that doesn't match is left untouched"
                // contract. Genuine corruption (Malformed) stays an error —
                // silently exiting 0 would let a failed de-obfuscation pass CI
                // while the il2cpp game assembly still crashes.
                if let Some(v) = unsupported_version(&e) {
                    s.skipped += 1;
                    if !suppress_file_lines {
                        eprintln!(
                            "- {}  unsupported metadata version {v}, left untouched",
                            rel.display()
                        );
                    }
                    if let Some(log) = &log {
                        log.step(&format!(
                            "META SKIP {rel:?}: unsupported metadata version {v}"
                        ));
                    }
                } else {
                    s.errors += 1;
                    crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                    if let Some(log) = &log {
                        log.step(&format!("META ERR {rel:?}: {e:#}"));
                    }
                }
            }
            Err(panic) => {
                s.errors += 1;
                let e = anyhow::anyhow!(
                    "unexpected panic during de-obfuscation: {}",
                    panic_payload(&panic)
                );
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!(
                        "META ERR {rel:?}: panic during de-obfuscation: {}",
                        panic_payload(&panic)
                    ));
                }
            }
        }
    }

    // Restore the original panic hook.
    std::panic::set_hook(default_hook);

    bar.finish_and_clear();
    s.duration_ms = t0.elapsed().as_millis();
    if let Some(log) = &log {
        log.step(&format!("done in {} ms", s.duration_ms));
        log.step(&format!("summary: {}", s.line()));
    }
    Ok(s)
}

/// Single-file (PE or metadata) with the same log/header/footer/timing as folder mode.
///
/// Always returns `Ok(Summary)` for per-file unpack outcomes (including failures,
/// which set `errors: 1`) so callers always receive `duration_ms`. Fatal `Err`
/// only when the out dir / log cannot be created.
pub fn run_file_v(
    input: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
) -> anyhow::Result<Summary> {
    let t0 = std::time::Instant::now();
    let out_root = out_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_out_root_for_file(input));
    std::fs::create_dir_all(&out_root)?;

    let log = if no_log {
        None
    } else {
        let log = crate::logfile::Log::create(&out_root)?;
        log.step(&format!("Senbei {}", env!("CARGO_PKG_VERSION")));
        log.step(&format!(
            "started {}",
            crate::logfile::local_stamp_display()
        ));
        log.step(&format!("input {}", input.display()));
        log.step(&format!("out {}", out_root.display()));
        Some(log)
    };

    let name = out_name(Path::new(input.file_name().unwrap_or_default()));
    let dest = out_root.join(name);
    let mut s = Summary::default();

    let prefix = {
        use std::io::Read;
        let mut buf = vec![0u8; 8 * 1024];
        match std::fs::File::open(input).and_then(|mut f| f.read(&mut buf).map(|n| (buf, n))) {
            Ok((buf, n)) => {
                let mut b = buf;
                b.truncate(n);
                b
            }
            Err(_) => Vec::new(),
        }
    };
    let is_meta = senbei_metadata::is_metadata(&prefix);
    // Android single-file targets are routed by content: a protected AArch64
    // library probe needs the whole file (its payload section is found through
    // the section-header table at the end), while a package is a container
    // handled entry-by-entry. Anything else falls through to the PE pipeline.
    let is_android_so = crate::android::is_elf64_aarch64(&prefix)
        && std::fs::read(input)
            .map(|bytes| senbei_android_engine::is_protected_libil2cpp(&bytes))
            .unwrap_or(false);
    let is_android_package = !is_android_so && crate::android::is_app_package(input, &prefix);

    if is_meta {
        match deobfuscate_metadata_to(input, &dest, verbose && quiet == 0) {
            Ok(report) if report.remapped > 0 => {
                s.metadata = 1;
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {:?} -> {:?}: v{} remapped {} method tokens",
                        input, dest, report.version, report.remapped
                    ));
                }
                if quiet == 0 {
                    println!(
                        "✓ metadata v{} -> {:?} ({} method tokens remapped)",
                        report.version, dest, report.remapped
                    );
                }
            }
            Ok(report) => {
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {:?}: v{} already de-obfuscated",
                        input, report.version
                    ));
                }
                if quiet == 0 {
                    println!(
                        "metadata v{}: already de-obfuscated, nothing to do",
                        report.version
                    );
                }
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("META ERR {:?}: {e:#}", input));
                }
                // Level 1 quiet: banner/summary/duration only (match folder mode).
                if quiet == 0 {
                    eprintln!("error: {e:#}");
                }
            }
        }
    } else if is_android_so {
        match crate::android::restore_so_file(input, &dest, verbose && quiet == 0) {
            Ok(embedded) => {
                s.unpacked = 1;
                if let Some(log) = &log {
                    log.step(&format!("OK {:?} -> {:?} (Android SO)", input, dest));
                }
                if quiet == 0 {
                    println!("✓ So  {}  ->  {}", input.display(), dest.display());
                }
                match write_embedded_metadata(embedded, &dest) {
                    Ok(Some(meta_dest)) => {
                        s.metadata += 1;
                        if let Some(log) = &log {
                            log.step(&format!("META {:?} (embedded) -> {:?}", input, meta_dest));
                        }
                        if quiet == 0 {
                            println!(
                                "✓ metadata  {} (embedded)  ->  {}",
                                input.display(),
                                meta_dest.display()
                            );
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        s.errors += 1;
                        if let Some(log) = &log {
                            log.step(&format!("ERR {:?}: embedded metadata: {e:#}", input));
                        }
                        if quiet == 0 {
                            eprintln!("error: embedded metadata: {e:#}");
                        }
                    }
                }
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("ERR {:?}: {e:#}", input));
                }
                if quiet == 0 {
                    eprintln!("error: {e:#}");
                }
            }
        }
    } else if is_android_package {
        s.packages = 1;
        let rel = PathBuf::from(input.file_name().unwrap_or_default());
        let mut seen = std::collections::HashSet::new();
        match crate::android::restore_package(
            input,
            &rel,
            &out_root,
            &mut seen,
            verbose && quiet == 0,
        ) {
            Ok(outcomes) => {
                let bar = crate::ui::progress(0, true);
                apply_package_outcomes(outcomes, &mut s, &bar, quiet >= 1, &log);
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("ERR {:?}: {e:#}", input));
                }
                if quiet == 0 {
                    eprintln!("error: {e:#}");
                }
            }
        }
    } else {
        match unpack_one_v(input, &dest, verbose && quiet == 0) {
            Ok((kind, report)) => {
                s.unpacked = 1;
                if let Some(log) = &log {
                    log.step(&format!("OK {:?} -> {:?} ({kind:?})", input, dest));
                }
                if quiet == 0 {
                    println!("✓ {:?} -> {:?}", kind, dest);
                }
                if !report.ok() {
                    s.suspect = 1;
                    if let Some(log) = &log {
                        log.step(&format!(
                            "SUSPECT {:?}: {}",
                            input,
                            report.issues.join("; ")
                        ));
                    }
                    if quiet == 0 {
                        eprintln!(
                            "! integrity check failed (likely to crash at runtime): {}",
                            report.issues.join("; ")
                        );
                    }
                }
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("ERR {:?}: {e:#}", input));
                }
                if quiet == 0 {
                    eprintln!("error: {e:#}");
                }
            }
        }
    }

    s.duration_ms = t0.elapsed().as_millis();
    if let Some(log) = &log {
        log.step(&format!("done in {} ms", s.duration_ms));
        log.step(&format!("summary: {}", s.line()));
    }
    Ok(s)
}

/// Path of `p` relative to `root`, for mirroring into the output tree.
///
/// Falls back to just the file name when `p` is not under `root` (e.g. a
/// `\\?\`-prefixed root against plain candidate paths): `Path::join` with an
/// *absolute* path replaces the output root outright, which would write the
/// output back over the source tree instead of under `--out`.
fn rel_in_tree<'a>(root: &Path, p: &'a Path) -> std::borrow::Cow<'a, Path> {
    match p.strip_prefix(root) {
        Ok(rel) => std::borrow::Cow::Borrowed(rel),
        Err(_) => std::borrow::Cow::Owned(PathBuf::from(p.file_name().unwrap_or_default())),
    }
}

/// Insert `.unpack` before the last dot in the **file name**, preserving any
/// parent directories. If the file name has no dot, append `.unpack`.
///
/// The dot search is scoped to the file-name component only: a relative path
/// like `v1.2/launcher` (dotted directory, extension-less file) must become
/// `v1.2/launcher.unpack`, not `v1.unpack.2/launcher`.
pub fn out_name(input: &Path) -> PathBuf {
    let file = input
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let renamed = match file.rfind('.') {
        Some(i) => format!("{}.unpack{}", &file[..i], &file[i..]),
        None => format!("{file}.unpack"),
    };
    match input.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(renamed),
        _ => PathBuf::from(renamed),
    }
}

/// Extract a printable message from a caught panic payload.
fn panic_payload(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string payload>".to_string()
    }
}

/// If `e`'s chain contains [`senbei_metadata::Error::UnsupportedVersion`],
/// return the version. Used to apply the folder-mode "leave untouched, don't
/// fail the run" policy to metadata versions this build can't de-obfuscate.
fn unsupported_version(e: &anyhow::Error) -> Option<u32> {
    for cause in e.chain() {
        if let Some(senbei_metadata::Error::UnsupportedVersion(v)) =
            cause.downcast_ref::<senbei_metadata::Error>()
        {
            return Some(*v);
        }
    }
    None
}

/// Write `bytes` to `dest` atomically: a sibling temp file, then a rename.
/// A direct `std::fs::write` truncates the destination first, so a mid-write
/// failure (disk full, AV lock, quota) destroys a previously good unpack at
/// the same path; the temp+rename keeps the old file until the new one is
/// complete. Best-effort temp cleanup on failure.
pub(crate) fn write_atomic(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp_name = dest.as_os_str().to_os_string();
    tmp_name.push(".senbei-tmp");
    let tmp = PathBuf::from(tmp_name);
    let r = std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, dest));
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// Detect `bytes` and run the right pipeline. Spliced external companions use
/// the EXE pipeline directly because that layout is definitionally EXE-style.
///
/// Routing spliced inputs straight to the EXE pipeline is safe: the
/// companion layout is definitionally the EXE-style shell (the runtime
/// loader maps the companion and runs the standard shell unpack), so the DLL
/// pipeline probe can never be right for it. Output bytes are identical to the
/// DLL-first + EXE-fallback route for every input that route handles.
fn unpack_spliced_or_auto(
    bytes: &[u8],
    spliced: bool,
    force_exe: bool,
    verbose: bool,
) -> Result<(unpacker::Kind, Vec<u8>), unpacker::UnpackError> {
    if spliced || force_exe {
        let detected = unpacker::detect(bytes).ok_or(unpacker::UnpackError::NotCrackproof)?;
        let out = unpacker::unpack_exe_v(bytes, verbose)?;
        return Ok((detected.kind, out));
    }
    unpacker::unpack_auto_v(bytes, verbose)
}

/// Unpack a single file to `dest`. Returns the Kind and integrity report on success.
pub fn unpack_one(
    input: &Path,
    dest: &Path,
) -> anyhow::Result<(unpacker::Kind, unpacker::IntegrityReport)> {
    unpack_one_v(input, dest, false)
}

/// Outcome of a byte-level unpack ([`unpack_bytes`]): the image, its detected
/// kind, and its integrity report. No file I/O is involved.
pub struct UnpackedImage {
    pub kind: unpacker::Kind,
    pub bytes: Vec<u8>,
    pub integrity: unpacker::IntegrityReport,
    /// True when the input was reconstructed from an external companion (the
    /// `._` layout), i.e. the export/TLS overlays ran.
    pub companion: bool,
}

/// Unpack in-memory `input` bytes, optionally paired with an external
/// companion payload `companion` (the `<input>._` file's contents).
///
/// This is the in-memory counterpart of [`unpack_one_v`]: splice a matching
/// companion, unpack, overlay the export table and TLS directory from the stub,
/// then run the static integrity check.
pub fn unpack_bytes(
    input: &[u8],
    companion: Option<&[u8]>,
) -> Result<UnpackedImage, unpacker::UnpackError> {
    unpack_bytes_impl(input, companion, false)
}

/// Like [`unpack_bytes`], but forces the EXE pipeline (no DLL-pipeline
/// probe). This is the web app's recovery path: the DLL-first probe relies
/// on `catch_unwind` to reject EXE-shell-layout DLLs, and panics cannot be
/// caught on wasm — the probe traps the whole call. The web app runs each
/// unpack in a disposable Web Worker and retries trapped DLLs with this
/// entry point, reproducing the CLI's dll-first/exe-fallback routing.
pub fn unpack_bytes_force_exe(
    input: &[u8],
    companion: Option<&[u8]>,
) -> Result<UnpackedImage, unpacker::UnpackError> {
    unpack_bytes_impl(input, companion, true)
}

fn unpack_bytes_impl(
    input: &[u8],
    companion: Option<&[u8]>,
    force_exe: bool,
) -> Result<UnpackedImage, unpacker::UnpackError> {
    let spliced = companion.and_then(|c| splice_companion(input, c));
    let bytes: &[u8] = spliced.as_deref().unwrap_or(input);
    let (kind, mut out) = unpack_spliced_or_auto(bytes, spliced.is_some(), force_exe, false)?;
    if spliced.is_some() {
        overlay_exports_from_stub(&mut out, input);
        restore_tls_from_stub(&mut out, input);
    }
    let integrity = unpacker::check_integrity(&out);
    Ok(UnpackedImage {
        kind,
        bytes: out,
        integrity,
        companion: spliced.is_some(),
    })
}

/// Like [`unpack_one`], but prints detailed `[N/9]` step progress (and a final
/// `Write to <dest>` line) to stdout when `verbose` is true.
pub fn unpack_one_v(
    input: &Path,
    dest: &Path,
    verbose: bool,
) -> anyhow::Result<(unpacker::Kind, unpacker::IntegrityReport)> {
    let UnpackerInput { bytes, stub } = read_unpacker_input(input)?;
    let (kind, mut out) = unpack_spliced_or_auto(&bytes, stub.is_some(), false, verbose)?;
    // External-companion layout: restore the export table from the stub, which
    // the encrypted companion does not carry (the loader rebuilds it at runtime).
    if let Some(stub) = stub {
        overlay_exports_from_stub(&mut out, &stub);
        // ...and the TLS directory, which Crackproof strips from the payload and
        // re-installs at runtime; the ordinary loader needs it or thread_local
        // access crashes (see [`restore_tls_from_stub`]).
        restore_tls_from_stub(&mut out, &stub);
    }
    let report = unpacker::check_integrity(&out);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_atomic(dest, &out)?;
    if verbose {
        println!("Write to {}", dest.display());
    }
    Ok((kind, report))
}

/// De-obfuscate an il2cpp `global-metadata.dat` to `dest`.
///
/// Crackproof's `-GMD` option scrambles each `Il2CppMethodDefinition`'s token
/// into a sparse, original-metadata-style value; il2cpp expects the contiguous
/// per-module index it indexes its codegen tables with, so a statically-unpacked
/// il2cpp game assembly reads garbage and crashes during init. This rewrites
/// the tokens back to their canonical form (see [`senbei_metadata::deobfuscate`]).
///
/// The output is written only when something actually changed
/// (`report.remapped > 0`); an already-clean metadata is left untouched and no
/// redundant copy is produced. Returns the [`metadata::Report`] either way so
/// the caller can report what happened.
pub fn deobfuscate_metadata_to(
    input: &Path,
    dest: &Path,
    verbose: bool,
) -> anyhow::Result<senbei_metadata::Report> {
    let data = std::fs::read(input)?;
    // The Android seeded-permutation variant is tried first (it validates
    // every restored RID); the structural remap is the fallback and the
    // Windows path. The [`senbei_metadata::Error`] is preserved in the chain
    // (rather than stringified) so the folder driver can apply its
    // unsupported-version policy.
    let (out, report) = crate::android::restore_metadata_bytes(&data)
        .map_err(|e| e.context(format!("{input:?}")))?;
    if report.remapped > 0 {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_atomic(dest, &out)?;
        if verbose {
            println!("Write to {}", dest.display());
        }
    }
    Ok(report)
}

/// Write an embedded metadata blob (unwrapped from a restored Android
/// library) next to the restored library. Returns the destination when a
/// blob was written.
fn write_embedded_metadata(
    embedded: Option<Vec<u8>>,
    so_dest: &Path,
) -> anyhow::Result<Option<PathBuf>> {
    let Some(blob) = embedded else {
        return Ok(None);
    };
    let dest = crate::android::embedded_metadata_dest(so_dest);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_atomic(&dest, &blob)?;
    Ok(Some(dest))
}

/// Fold one package's per-entry outcomes into the run summary, UI, and log.
fn apply_package_outcomes(
    outcomes: Vec<crate::android::EntryOutcome>,
    s: &mut Summary,
    bar: &indicatif::ProgressBar,
    quiet: bool,
    log: &Option<crate::logfile::Log>,
) {
    use crate::android::{EntryKind, EntryStatus};
    for outcome in outcomes {
        match outcome.status {
            EntryStatus::Restored => {
                match outcome.kind {
                    EntryKind::So => {
                        s.unpacked += 1;
                        crate::ui::ok_label(bar, quiet, &outcome.label, "So", &outcome.dest);
                    }
                    EntryKind::Metadata { remapped } => {
                        s.metadata += 1;
                        crate::ui::metadata(
                            bar,
                            quiet,
                            Path::new(&outcome.label),
                            remapped,
                            &outcome.dest,
                        );
                    }
                    EntryKind::EmbeddedMetadata => {
                        s.metadata += 1;
                        crate::ui::ok_label(bar, quiet, &outcome.label, "metadata", &outcome.dest);
                    }
                }
                if let Some(log) = log {
                    log.step(&format!("OK {} -> {:?}", outcome.label, outcome.dest));
                }
            }
            EntryStatus::Duplicate | EntryStatus::NotTarget | EntryStatus::Unchanged => {
                s.skipped += 1;
                if let Some(log) = log {
                    log.step(&format!("SKIP {} ({:?})", outcome.label, outcome.kind));
                }
            }
            EntryStatus::Failed(e) => {
                s.errors += 1;
                crate::ui::err(bar, quiet, Path::new(&outcome.label), &e);
                if let Some(log) = log {
                    log.step(&format!("ERR {}: {e:#}", outcome.label));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review regression: when the candidate path is not under `root` (e.g. a
    /// `\\?\`-prefixed root against plain walk paths), the output name must
    /// fall back to the bare file name — joining the absolute path would
    /// replace the output root and write back over the source tree.
    #[test]
    fn rel_in_tree_falls_back_to_file_name_outside_root() {
        let root = Path::new(r"D:\out-of-tree-root");
        let abs = Path::new(r"C:\game\bin\app.exe");
        let rel = rel_in_tree(root, abs);
        assert_eq!(rel.as_ref(), Path::new("app.exe"));

        // And the normal case still preserves the tree structure.
        let under = Path::new(r"D:\out-of-tree-root\bin\app.exe");
        let rel = rel_in_tree(root, under);
        assert_eq!(rel.as_ref(), Path::new(r"bin\app.exe"));
    }

    fn stub_with_header(header: &[u8; 32], extra: usize) -> Vec<u8> {
        let mut s = vec![0u8; HEADER_OFF];
        s.extend_from_slice(header);
        s.extend_from_slice(&vec![0xAAu8; extra]);
        s
    }

    #[test]
    fn splices_when_header_matches() {
        let header = [7u8; 32];
        let stub = stub_with_header(&header, 16);
        // Companion: same 32-byte header, then the real (longer) payload.
        let mut comp = header.to_vec();
        comp.extend_from_slice(&[0x42u8; 1000]);

        let out = splice_companion(&stub, &comp).expect("should splice");
        assert_eq!(out.len(), HEADER_OFF + comp.len());
        assert_eq!(&out[..HEADER_OFF], &stub[..HEADER_OFF]);
        assert_eq!(&out[HEADER_OFF..], &comp[..]);
    }

    #[test]
    fn no_splice_when_header_differs() {
        let stub = stub_with_header(&[7u8; 32], 16);
        let mut comp = vec![9u8; 32]; // different header
        comp.extend_from_slice(&[0x42u8; 1000]);
        assert!(splice_companion(&stub, &comp).is_none());
    }

    #[test]
    fn no_splice_when_too_short() {
        let short_stub = vec![0u8; HEADER_OFF + 8]; // < HEADER_OFF + 32
        let comp = vec![0u8; 64];
        assert!(splice_companion(&short_stub, &comp).is_none());

        let stub = stub_with_header(&[1u8; 32], 0);
        let short_comp = vec![1u8; 16]; // < 32
        assert!(splice_companion(&stub, &short_comp).is_none());
    }
}
