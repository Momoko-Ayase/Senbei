//! WebAssembly bindings for the senbei unpacker core.
//!
//! Everything here is I/O-free: the browser hands in file bytes and gets
//! recovered bytes back. No network, no filesystem, no uploads.
//!
//! One job runs per module instance. The page starts a disposable worker for
//! each job, because a Rust panic is a trap in WebAssembly and a trapped
//! instance cannot be used again.

use std::cell::RefCell;
use std::rc::Rc;

use senbei_engine::android::ResourceLimits;
use senbei_engine::progress::{self, Event};
use senbei_engine::{IntegrityReport, IntegritySeverity, ProtectionProfile};
use senbei_i18n::{Lang, Localize, Message, Msg, Step};
use senbei_io::android::{LibraryOutcome, MetadataOutcome, ModuleBinding};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;

/// Lines kept from one job's verbose progress. A library with many encoded
/// segments reports one line each; past this the log says it was cut.
const LOG_LINE_LIMIT: usize = 4000;

/// Ceilings for one Android job in a 32-bit address space.
///
/// One decoded entry or output image may reach 1 GiB. The task total counts
/// decoded bytes that are written and released as the restore proceeds, so it
/// sits above what the instance can hold at once; the instance's own memory is
/// the bound that matters there.
const BROWSER_LIMITS: ResourceLimits = ResourceLimits {
    max_entry_bytes: 1 << 30,
    max_total_bytes: 4 << 30,
    max_entries: 100_000,
    max_depth: 32,
};

/// Install a panic hook that forwards Rust panic messages to the browser
/// console (and to the JS error), instead of a bare `unreachable` trap.
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// One input file, filled in place.
///
/// The page appends a file to this in slices, so the file is held once, in
/// this instance's memory, and never as a second whole copy on the JS side.
#[wasm_bindgen]
pub struct InputBuffer {
    bytes: Vec<u8>,
}

#[wasm_bindgen]
impl InputBuffer {
    /// Reserve room for `capacity` bytes. Throws when the instance cannot.
    #[wasm_bindgen(constructor)]
    pub fn new(capacity: usize) -> Result<InputBuffer, JsError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| JsError::new("not enough memory for this input"))?;
        Ok(Self { bytes })
    }

    /// Append the next slice. Throws when it would pass the reserved size.
    pub fn append(&mut self, chunk: &[u8]) -> Result<(), JsError> {
        if chunk.len() > self.bytes.capacity() - self.bytes.len() {
            return Err(JsError::new("input is larger than its declared size"));
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    /// Bytes appended so far.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.bytes.len()
    }

    /// SHA-256 of the bytes appended so far, as lowercase hex.
    pub fn sha256(&self) -> String {
        senbei_io::android::content_identity(&self.bytes)
    }
}

/// What one job produced.
///
/// `info` is a JSON document with everything except the bytes. The recovered
/// bytes are handed out as views of this instance's memory, so the page can
/// copy them straight into a `Blob` without a second copy on the JS heap. A
/// view is valid only until the next call into this module.
#[wasm_bindgen]
pub struct Outcome {
    info: String,
    image: Vec<u8>,
    embedded_metadata: Option<Vec<u8>>,
    module: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl Outcome {
    /// The job's report as JSON: `status`, `kind`, `error`, `note`, `profile`,
    /// `routes`, `findings`, `warnings`, `errors`, `metadata`, `elf`, and
    /// `log`.
    ///
    /// `status` is `recovered`, `unchanged`, `unsupported`, `not_protected`,
    /// or `failed`. `profile` is the recovery profile in the format the CLI's
    /// JSON report uses; its messages are English. `routes`, `warnings`,
    /// `errors`, `error`, and `note` repeat the profile's messages as
    /// `{ text, local }`, where `local` is the wording in the page language
    /// when the message has one.
    #[wasm_bindgen(getter)]
    pub fn info(&self) -> String {
        self.info.clone()
    }

    /// A view of the recovered image or metadata blob. Empty unless `status`
    /// is `recovered`.
    pub fn image(&self) -> js_sys::Uint8Array {
        // SAFETY: the view borrows `self.image`, which this object owns and
        // never reallocates. The caller reads it before calling back into the
        // module, as the type documents.
        unsafe { js_sys::Uint8Array::view(&self.image) }
    }

    /// SHA-256 of the recovered image, as lowercase hex.
    pub fn image_sha256(&self) -> String {
        senbei_io::android::content_identity(&self.image)
    }

    /// A view of the metadata blob a restored Android library carried inside
    /// it, when it carried one.
    pub fn embedded_metadata(&self) -> Option<js_sys::Uint8Array> {
        // SAFETY: as for `image`.
        self.embedded_metadata
            .as_deref()
            .map(|bytes| unsafe { js_sys::Uint8Array::view(bytes) })
    }

    /// SHA-256 of the embedded metadata blob, when there is one.
    pub fn embedded_metadata_sha256(&self) -> Option<String> {
        self.embedded_metadata
            .as_deref()
            .map(senbei_io::android::content_identity)
    }

    /// Decoded module `0x0C` of a restored Android library. A v24 metadata
    /// blob of the same application needs it.
    pub fn take_module(&mut self) -> Option<Vec<u8>> {
        self.module.take()
    }
}

fn lang_of(tag: &str) -> Lang {
    Lang::from_tag(tag).unwrap_or(Lang::En)
}

/// A message as the page shows it: the recorded English, and the wording in
/// `lang` when the message has a catalog entry there.
fn message_value(message: &Message, lang: Lang) -> Value {
    let local =
        (lang != Lang::En && message.msg().is_some()).then(|| message.localized(lang).into_owned());
    json!({ "text": message.text(), "local": local })
}

fn messages_value(messages: &[Message], lang: Lang) -> Value {
    messages
        .iter()
        .map(|message| message_value(message, lang))
        .collect()
}

fn kind_str(kind: senbei_engine::Kind) -> &'static str {
    match kind {
        senbei_engine::Kind::NativeExe => "native-exe",
        senbei_engine::Kind::ManagedExe => "managed-exe",
        senbei_engine::Kind::NativeDll => "native-dll",
        senbei_engine::Kind::ManagedDll => "managed-dll",
    }
}

/// The integrity findings, in the checker's order.
fn findings_value(report: &IntegrityReport) -> Value {
    report
        .findings
        .iter()
        .zip(&report.issues)
        .map(|(finding, issue)| {
            json!({
                "severity": match finding.severity {
                    IntegritySeverity::Fatal => "fatal",
                    IntegritySeverity::Warning => "warning",
                },
                "message": issue.to_string(),
            })
        })
        .collect()
}

/// The name the workbench's catalogs give a step, where they have one.
///
/// The desktop window titles these steps in its own words and the page shows
/// the same titles, so it looks them up by this name. Steps that share a title
/// share a name.
fn step_key(step: &Step) -> Option<&'static str> {
    Some(match step {
        Step::DecryptHeader => "decrypt_header",
        Step::DecryptPayload => "decrypt_payload",
        Step::LocateConfig | Step::Pe32LocateConfig => "locate_config",
        Step::DecryptStage2 => "decrypt_stage2",
        Step::DecryptStages3To5 => "decrypt_stages_3_5",
        Step::DecryptSections | Step::DecryptSectionsNewLayout => "decrypt_sections",
        Step::LoadSections => "load_sections",
        Step::DecryptImports | Step::Pe32Imports => "decrypt_imports",
        Step::RebuildHeaders => "rebuild_headers",
        Step::Pe32Stages => "pe32_stages",
        Step::Pe32EighthStage => "pe32_eighth",
        Step::Pe32Load => "pe32_load",
        Step::Pe32Text { .. } => "pe32_text",
        Step::Pe32TextSkip => "pe32_text_skip",
        Step::Pe32Rebuild => "pe32_rebuild",
        Step::InitKeys => "init_keys",
        Step::DecryptKeyTable => "decrypt_key_table",
        Step::DecryptPrimary => "decrypt_primary",
        Step::RelocsParams => "relocs_params",
        Step::DecryptBlock1 => "decrypt_block1",
        Step::DecryptBlocks2To3 => "decrypt_block23",
        Step::DecryptBlock4 => "decrypt_block4",
        Step::DllSections => "dll_sections",
        Step::FixHeaders => "fix_headers",
        Step::AndroidPrimary => "android_primary",
        Step::AndroidAuxiliary => "android_aux",
        Step::AndroidTables => "android_tables",
        _ => return None,
    })
}

/// Run `job` with its verbose progress collected.
///
/// A step is logged as `{"ms", "step": title, "key": name, "i": n, "of":
/// total}` with its title in `lang` and its catalog name from [`step_key`];
/// `i` and `of` are null for the unnumbered Android stages. A detail line is
/// `{"ms", "detail": text}`; those are technical and stay English. `ms` is the
/// time since the job started.
/// `on_step`, when given, is called with `(title, i, of, name)` as each step
/// starts, so the page can show where a long job is.
fn with_log<R>(
    lang: Lang,
    on_step: Option<js_sys::Function>,
    job: impl FnOnce() -> R,
) -> (R, Vec<Value>) {
    let log = Rc::new(RefCell::new(Vec::new()));
    let sink_log = Rc::clone(&log);
    let started = js_sys::Date::now();
    let result = progress::with_sink(
        move |event| {
            let ms = (js_sys::Date::now() - started).max(0.0).round();
            let line = match event {
                Event::Step { step, position } => {
                    let title = step.localize(lang);
                    let key = step_key(step);
                    let (i, of) = position.unzip();
                    if let Some(on_step) = &on_step {
                        let arguments = js_sys::Array::of4(
                            &JsValue::from_str(&title),
                            &i.map_or(JsValue::NULL, JsValue::from),
                            &of.map_or(JsValue::NULL, JsValue::from),
                            &key.map_or(JsValue::NULL, JsValue::from_str),
                        );
                        // A failed callback must not stop the recovery.
                        let _ = on_step.apply(&JsValue::NULL, &arguments);
                    }
                    json!({ "ms": ms, "step": title, "key": key, "i": i, "of": of })
                }
                Event::Detail(line) => json!({ "ms": ms, "detail": line.trim() }),
            };
            let mut log = sink_log.borrow_mut();
            match log.len() {
                len if len < LOG_LINE_LIMIT => log.push(line),
                LOG_LINE_LIMIT => log.push(json!({ "truncated": true })),
                _ => {}
            }
        },
        job,
    );
    let log = log.take();
    (result, log)
}

struct Info<'a> {
    status: &'static str,
    kind: Option<&'a str>,
    profile: &'a ProtectionProfile,
    error: Option<&'a Message>,
    lang: Lang,
    log: Vec<Value>,
}

impl Info<'_> {
    /// The fields every job reports. Job-specific ones are added by the caller.
    fn value(self) -> Value {
        // Why an input that did not fail has no output.
        let note = match self.status {
            "unchanged" => Some(Message::new(Msg::TransformNoop)),
            "not_protected" => Some(Message::new(Msg::NotProtected)),
            _ => None,
        };
        let routes: Vec<Value> = self
            .profile
            .candidates
            .iter()
            .map(|attempt| {
                json!({
                    "layout": attempt.layout,
                    "outcome": attempt.outcome,
                    "warnings": messages_value(&attempt.warnings, self.lang),
                    "errors": messages_value(&attempt.errors, self.lang),
                })
            })
            .collect();
        json!({
            "status": self.status,
            "kind": self.kind,
            "error": self.error.map(|error| message_value(error, self.lang)),
            "note": note.map(|note| message_value(&note, self.lang)),
            "profile": self.profile,
            "routes": routes,
            "warnings": messages_value(&self.profile.warnings, self.lang),
            "errors": messages_value(&self.profile.errors, self.lang),
            "findings": [],
            "suspect": false,
            "companion": false,
            "metadata": null,
            "elf": null,
            "log": self.log,
        })
    }
}

impl Outcome {
    fn new(info: Value) -> Self {
        Self {
            info: info.to_string(),
            image: Vec::new(),
            embedded_metadata: None,
            module: None,
        }
    }
}

/// Classify a file from its first bytes without unpacking.
///
/// Returns `"native-exe"`, `"managed-exe"`, `"native-dll"`, `"managed-dll"`,
/// `"metadata"` (an il2cpp `global-metadata.dat`), or `undefined` for
/// anything unrecognized.
#[wasm_bindgen]
pub fn detect(input: &[u8]) -> Option<String> {
    if senbei_metadata::is_metadata(input) {
        return Some("metadata".to_string());
    }
    senbei_engine::detect(input).map(|d| kind_str(d.kind).to_string())
}

/// Return the pre-recovery profile for an input as JSON.
///
/// This never runs a recovery, so every candidate stays `not_attempted` and
/// `selected` is `null`. Two things are deliberately kept separate in the
/// returned document:
///
/// * a PE input reports `recognition: "recognized"` only when the header key
///   table carries the supported magic;
/// * an il2cpp metadata input reports the observed format version with
///   `recognition: "not_attempted"`, because a metadata magic/version match
///   identifies a format, not a protection.
///
/// Always returns a JSON object (never `null`); an unrecognized input gets a
/// profile with `recognition: "not_recognized"`.
#[wasm_bindgen]
pub fn inspect_profile_json(input: &[u8]) -> String {
    let profile = match senbei_metadata::identify(input) {
        Some(identity) => {
            let mut profile = ProtectionProfile::new(senbei_engine::ObservedTarget::metadata(
                Some(identity.version.raw()),
            ));
            profile.push_warning(
                "the il2cpp metadata magic and version identify a file format; \
                 they do not establish that the file is protected",
            );
            profile
        }
        None => senbei_engine::inspect_profile(input),
    };
    serde_json::to_string(&profile).unwrap_or_else(|_| "null".to_string())
}

/// Unpack a protected Windows module.
///
/// `companion` is the `<input>._` external payload when there is one.
/// `force_exe` selects the EXE-only route: the page's retry for a DLL whose
/// DLL-first probe trapped. `lang` is the page language for step titles and
/// message wording, and `on_step` receives each step title as it starts.
#[wasm_bindgen]
pub fn unpack_pe(
    input: &InputBuffer,
    companion: Option<InputBuffer>,
    force_exe: bool,
    lang: &str,
    on_step: Option<js_sys::Function>,
) -> Outcome {
    let lang = lang_of(lang);
    let companion = companion.as_ref().map(|buffer| buffer.bytes.as_slice());
    let ((profile, result), log) = with_log(lang, on_step, || {
        if force_exe {
            senbei_io::job::unpack_bytes_force_exe_profiled_v(&input.bytes, companion, true)
        } else {
            senbei_io::job::unpack_bytes_profiled_v(&input.bytes, companion, true)
        }
    });
    let observed_kind = profile.observed.kind.map(kind_str);
    match result {
        Ok(image) => {
            let mut info = Info {
                status: "recovered",
                kind: Some(kind_str(image.kind)),
                profile: &profile,
                error: None,
                lang,
                log,
            }
            .value();
            info["findings"] = findings_value(&image.integrity);
            info["suspect"] = json!(!image.integrity.ok());
            info["companion"] = json!(image.companion);
            Outcome {
                image: image.bytes,
                ..Outcome::new(info)
            }
        }
        Err(error) => {
            let error = error.message();
            let mut info = Info {
                status: "failed",
                kind: observed_kind,
                profile: &profile,
                error: Some(&error),
                lang,
                log,
            }
            .value();
            info["companion"] = json!(profile.observed.external_companion);
            Outcome::new(info)
        }
    }
}

/// Probe an AArch64 library for the protection, without restoring it.
///
/// Returns the probe's profile as JSON. `recognition` is `recognized` for a
/// protected library, `not_recognized` for an ordinary one, and `blocked` when
/// a ceiling stopped the probe before it could tell. The probe needs the whole
/// file: the payload is found through the section table at its end.
#[wasm_bindgen]
pub fn probe_library(input: &InputBuffer) -> String {
    let (profile, _) =
        senbei_engine::android::probe_libil2cpp_profiled_with_limits(&input.bytes, &BROWSER_LIMITS);
    serde_json::to_string(&profile).unwrap_or_else(|_| "null".to_string())
}

/// Probe and restore a protected Android AArch64 library.
///
/// A library the probe does not match is reported as `not_protected` and
/// nothing else runs. A restored library may also carry an embedded metadata
/// blob and module `0x0C`; see [`Outcome`].
#[wasm_bindgen]
pub fn restore_library(
    input: &InputBuffer,
    lang: &str,
    on_step: Option<js_sys::Function>,
) -> Outcome {
    let lang = lang_of(lang);
    let ((profile, outcome), log) = with_log(lang, on_step, || {
        senbei_io::android::restore_library_bytes(&input.bytes, true, &BROWSER_LIMITS)
    });
    let info = |status, error| {
        Info {
            status,
            kind: Some("android-library"),
            profile: &profile,
            error,
            lang,
            log,
        }
        .value()
    };
    match outcome {
        LibraryOutcome::Restored(restored) => {
            let mut info = info("recovered", None);
            info["elf"] = json!(restored.elf);
            Outcome {
                image: restored.image,
                embedded_metadata: restored.embedded_metadata,
                module: restored.method_index_module,
                ..Outcome::new(info)
            }
        }
        LibraryOutcome::NotProtected => Outcome::new(info("not_protected", None)),
        LibraryOutcome::Failed(error) => Outcome::new(info("failed", Some(&error))),
    }
}

/// Restore the method tokens or method indices of an il2cpp
/// `global-metadata.dat`.
///
/// `module` is module `0x0C` of the same application, when the page has
/// exactly one. `conflicting` is the number of different modules that
/// application's libraries yielded, when it is more than one. Only a v24 blob
/// needs a module, so only a v24 blob fails without one. `unchanged` means the
/// blob was already canonical and no bytes are returned.
#[wasm_bindgen]
pub fn restore_metadata(
    input: &InputBuffer,
    module: Option<Vec<u8>>,
    conflicting: usize,
    lang: &str,
) -> Outcome {
    let lang = lang_of(lang);
    let binding = match &module {
        Some(module) => ModuleBinding::One(module),
        None if conflicting > 1 => ModuleBinding::Conflicting {
            profiles: conflicting,
        },
        None => ModuleBinding::None,
    };
    let (profile, outcome) =
        senbei_io::android::restore_metadata_bytes_profiled(&input.bytes, binding);
    let info = |status,
                error,
                report: Option<&senbei_metadata::Report>,
                layout: Option<senbei_engine::LayoutKind>| {
        let mut info = Info {
            status,
            kind: Some("metadata"),
            profile: &profile,
            error,
            lang,
            log: Vec::new(),
        }
        .value();
        info["metadata"] = match report {
            Some(report) => json!({
                "version": report.version,
                "methods": report.methods,
                "remapped": report.remapped,
                "modules": report.modules,
                // The transform that ran, also for a blob it left as it was.
                "layout": layout,
            }),
            None => json!({ "version": profile.observed.metadata_version }),
        };
        // What this format version allows, as the native report records it.
        info["metadata"]["identity"] = json!(senbei_metadata::identify(&input.bytes));
        info
    };
    match outcome {
        MetadataOutcome::Restored {
            bytes,
            report,
            layout,
        } => Outcome {
            image: bytes,
            ..Outcome::new(info("recovered", None, Some(&report), Some(layout)))
        },
        MetadataOutcome::Unchanged { report, layout } => {
            Outcome::new(info("unchanged", None, Some(&report), Some(layout)))
        }
        MetadataOutcome::Unsupported { .. } => {
            Outcome::new(info("unsupported", None, None, None))
        }
        MetadataOutcome::Failed(error) => Outcome::new(info("failed", Some(&error), None, None)),
    }
}

/// Application identity from a package's root `AndroidManifest.xml`.
///
/// Returns `[package, version]`, or `undefined` when the manifest names no
/// application. `truncated` says the page's bounded read stopped before the
/// end of the entry; a truncated manifest names nothing.
#[wasm_bindgen]
pub fn manifest_identity(manifest: &[u8], truncated: bool) -> Option<Vec<String>> {
    senbei_io::android::manifest_identity(manifest, truncated)
        .map(|(package, version)| vec![package, version])
}

/// Why a package with an entry name that would leave it is refused.
///
/// The page lists packages itself, so it is the page that finds such an entry;
/// this gives it the engine's own message for that, as `{"text", "local"}`
/// JSON with `local` in `lang`.
#[wasm_bindgen]
pub fn unsafe_package_entry(package: &str, lang: &str) -> String {
    let message = Message::new(Msg::UnsafePackageEntry {
        package: package.to_owned(),
    });
    message_value(&message, lang_of(lang)).to_string()
}
