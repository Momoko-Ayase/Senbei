//! WebAssembly bindings for the senbei unpacker core.
//!
//! Everything here is I/O-free: the browser hands in file bytes and gets
//! unpacked file bytes back. No network, no filesystem, no uploads.

use wasm_bindgen::prelude::*;

/// Install a panic hook that forwards Rust panic messages to the browser
/// console (and to the JS error), instead of a bare `unreachable` trap.
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Result of unpacking one protected module.
#[wasm_bindgen]
pub struct UnpackResult {
    kind: String,
    bytes: Vec<u8>,
    suspect: bool,
    issues: Vec<String>,
    companion: bool,
}

#[wasm_bindgen]
impl UnpackResult {
    /// Detected module kind: `"native-exe"`, `"managed-exe"`, `"native-dll"`,
    /// or `"managed-dll"`.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    /// The unpacked image bytes.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// True when the static integrity check flagged the output as likely
    /// broken at runtime. The bytes are still the best available.
    #[wasm_bindgen(getter)]
    pub fn suspect(&self) -> bool {
        self.suspect
    }

    /// Human-readable integrity defects (empty when the check is clean).
    #[wasm_bindgen(getter)]
    pub fn issues(&self) -> Vec<String> {
        self.issues.clone()
    }

    /// True when the input was spliced from an external-companion (`._`)
    /// payload.
    #[wasm_bindgen(getter)]
    pub fn companion(&self) -> bool {
        self.companion
    }
}

/// Result of de-obfuscating an il2cpp `global-metadata.dat`.
#[wasm_bindgen]
pub struct MetadataResult {
    bytes: Vec<u8>,
    version: u32,
    methods: usize,
    remapped: usize,
    modules: usize,
}

#[wasm_bindgen]
impl MetadataResult {
    /// The (possibly rewritten) metadata bytes.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Total method-definition entries in the metadata.
    #[wasm_bindgen(getter)]
    pub fn methods(&self) -> usize {
        self.methods
    }

    /// Method tokens actually rewritten (0 means the input was already
    /// de-obfuscated and the bytes are unchanged).
    #[wasm_bindgen(getter)]
    pub fn remapped(&self) -> usize {
        self.remapped
    }

    /// Modules (images) owning at least one method.
    #[wasm_bindgen(getter)]
    pub fn modules(&self) -> usize {
        self.modules
    }
}

fn kind_str(kind: senbei_pe::Kind) -> &'static str {
    match kind {
        senbei_pe::Kind::NativeExe => "native-exe",
        senbei_pe::Kind::ManagedExe => "managed-exe",
        senbei_pe::Kind::NativeDll => "native-dll",
        senbei_pe::Kind::ManagedDll => "managed-dll",
    }
}

/// Classify a file's bytes without unpacking.
///
/// Returns `"native-exe"`, `"managed-exe"`, `"native-dll"`, `"managed-dll"`,
/// `"metadata"` (an il2cpp `global-metadata.dat`), or `undefined` for
/// anything unrecognized.
#[wasm_bindgen]
pub fn detect(input: &[u8]) -> Option<String> {
    if senbei_metadata::is_metadata(input) {
        return Some("metadata".to_string());
    }
    senbei_pe::detect(input).map(|d| kind_str(d.kind).to_string())
}

/// Unpack a protected module.
///
/// `input` is the protected `.exe`/`.dll`; `companion` is the optional
/// `<input>._` external-companion payload (pass `null`/`undefined` when there
/// is none). Throws a string error when the input is not a supported
/// Crackproof file or is corrupt.
#[wasm_bindgen]
pub fn unpack_file(
    input: &[u8],
    companion: Option<Vec<u8>>,
) -> Result<UnpackResult, JsError> {
    let r = senbei_io::job::unpack_bytes(input, companion.as_deref())
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(UnpackResult {
        kind: kind_str(r.kind).to_string(),
        bytes: r.bytes,
        suspect: !r.integrity.ok(),
        issues: r.integrity.issues,
        companion: r.companion,
    })
}

/// De-obfuscate the method tokens of an il2cpp `global-metadata.dat`.
///
/// The transform is idempotent: an already-clean metadata comes back
/// byte-identical with `remapped == 0`. Throws a string error for non-metadata
/// input, an unsupported format version, or a malformed layout.
#[wasm_bindgen]
pub fn deobfuscate_metadata(data: &[u8]) -> Result<MetadataResult, JsError> {
    let (bytes, report) =
        senbei_metadata::deobfuscate(data).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(MetadataResult {
        bytes,
        version: report.version,
        methods: report.methods,
        remapped: report.remapped,
        modules: report.modules,
    })
}

/// Unpack a protected module, forcing the EXE pipeline (no DLL-pipeline
/// probe). See [`senbei_io::job::unpack_bytes_force_exe`] for why the web app
/// needs this recovery path.
#[wasm_bindgen]
pub fn unpack_file_force_exe(
    input: &[u8],
    companion: Option<Vec<u8>>,
) -> Result<UnpackResult, JsError> {
    let r = senbei_io::job::unpack_bytes_force_exe(input, companion.as_deref())
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(UnpackResult {
        kind: kind_str(r.kind).to_string(),
        bytes: r.bytes,
        suspect: !r.integrity.ok(),
        issues: r.integrity.issues,
        companion: r.companion,
    })
}
