//! The seam between the window and the machine it runs on.
//!
//! The window sends [`Request`]s and drains [`Event`]s; it never touches the
//! filesystem itself, so the same window can sit on another backend (a browser
//! one has no folders and cannot write outputs, and says so in its
//! [`Capabilities`]).

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use senbei_engine::ProtectionProfile;
use senbei_engine::android::ResourceLimits;
use senbei_i18n::Step;
use senbei_io::report::{CompanionState, ContainerReport, InputReport, Mode, Report, ScanReport};

pub type ItemId = u64;
pub type GroupId = u64;
pub type JobId = u64;

/// What a backend can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Add folders and run them with folder semantics.
    pub folders: bool,
    /// Write unpacked outputs.
    pub unpack: bool,
    /// Show a file in the system file manager.
    pub reveal: bool,
}

/// What one input is, from a light look before anything runs.
#[derive(Debug, Clone)]
pub enum Identity {
    /// The system could not read it; its own words, in its own language.
    Unreadable(String),
    /// It exists but is neither a file nor a folder (a device or a pipe).
    NotAFile,
    NotTarget {
        size: u64,
    },
    Windows {
        size: u64,
        profile: Box<ProtectionProfile>,
        companion: CompanionState,
        companion_path: Option<String>,
    },
    Metadata {
        size: u64,
        identity: Option<senbei_metadata::MetadataIdentity>,
    },
    AndroidLibrary {
        size: u64,
    },
    Package {
        size: u64,
        container: Result<Box<ContainerReport>, String>,
    },
}

impl Identity {
    pub fn size(&self) -> Option<u64> {
        match self {
            Identity::Unreadable(_) | Identity::NotAFile => None,
            Identity::NotTarget { size }
            | Identity::Windows { size, .. }
            | Identity::Metadata { size, .. }
            | Identity::AndroidLibrary { size }
            | Identity::Package { size, .. } => Some(*size),
        }
    }

    /// True when a run has nothing to recover.
    pub fn not_protected(&self) -> bool {
        match self {
            Identity::NotTarget { .. } => true,
            Identity::Windows { profile, .. } => {
                profile.recognition != senbei_engine::RecognitionStatus::Recognized
            }
            _ => false,
        }
    }
}

/// Where an unpack writes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Output {
    /// `unpack\` beside each added file, or inside each added folder.
    Beside,
    /// One chosen folder.
    Folder(PathBuf),
}

/// Settings a run takes from the window.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub write_log: bool,
    pub threads: Option<NonZeroUsize>,
    pub scan_all: bool,
    pub limits: ResourceLimits,
    /// Keep the restored image of an inspection or dry run in memory.
    pub keep_bytes: bool,
    /// Largest restored image kept, in bytes.
    pub keep_cap: u64,
}

/// One piece of work in a job.
#[derive(Debug, Clone)]
pub enum Unit {
    /// One file. An unpack writes its output into `out_dir`.
    File { path: PathBuf, out_dir: PathBuf },
    /// Every target below `root`, with folder semantics: companions, loose
    /// library and metadata pairing, package groups. An unpack mirrors the
    /// tree into `out_dir`.
    Folder { root: PathBuf, out_dir: PathBuf },
}

impl Unit {
    pub fn path(&self) -> &PathBuf {
        match self {
            Unit::File { path, .. } => path,
            Unit::Folder { root, .. } => root,
        }
    }
}

/// A run of one mode over some units, one after another.
#[derive(Debug, Clone)]
pub struct Job {
    pub id: JobId,
    pub mode: Mode,
    pub units: Vec<Unit>,
    pub options: RunOptions,
}

/// Bytes a run produced for one output.
#[derive(Debug, Clone)]
pub enum Produced {
    /// Held in memory for this session.
    Kept(Arc<[u8]>),
    /// Written by an unpack; read from disk when shown.
    OnDisk(PathBuf),
    /// Larger than the memory cap; summarized without bytes.
    TooLarge(u64),
    /// Keeping bytes is turned off.
    NotKept,
}

/// Bytes to show in the hex view.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Source {
    /// A file on disk, as it is.
    File(PathBuf),
    /// The loader's header page followed by its `._` payload.
    Spliced { stub: PathBuf, companion: PathBuf },
    /// One entry of an app package, by its report label.
    Entry { package: PathBuf, label: String },
}

/// A dialog the window asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    Files,
    Folder,
    Output,
}

/// What the window asks of the backend.
#[derive(Debug, Clone)]
pub enum Request {
    Identify {
        items: Vec<(ItemId, PathBuf)>,
        limits: ResourceLimits,
    },
    Scan {
        group: GroupId,
        root: PathBuf,
        scan_all: bool,
        limits: ResourceLimits,
    },
    Run(Box<Job>),
    /// Stop the running job before its next input.
    Cancel,
    Load {
        source: Source,
        limits: ResourceLimits,
    },
    Pick(Pick),
    Reveal(PathBuf),
    Save {
        name: String,
        contents: Vec<u8>,
    },
}

/// What the backend reports back.
#[derive(Debug, Clone)]
pub enum Event {
    Identified(ItemId, Box<Identity>),
    ScanProgress {
        group: GroupId,
        found: usize,
    },
    Scanned {
        group: GroupId,
        targets: Vec<(PathBuf, Box<Identity>)>,
        scan: ScanReport,
    },
    UnitStarted {
        job: JobId,
        unit: usize,
        at: String,
    },
    /// A folder unit's scan finished with this many inputs to process.
    UnitScanned {
        job: JobId,
        unit: usize,
        inputs: usize,
        at: String,
    },
    InputStarted {
        job: JobId,
        unit: usize,
        path: PathBuf,
        at: String,
    },
    Step {
        job: JobId,
        step: Step,
        position: Option<(u8, u8)>,
        at: String,
    },
    Detail {
        job: JobId,
        text: String,
        at: String,
    },
    Produced {
        job: JobId,
        path: PathBuf,
        restored: Option<Produced>,
        entries: Vec<(String, Produced)>,
    },
    InputFinished {
        job: JobId,
        unit: usize,
        report: Box<InputReport>,
        at: String,
    },
    /// One unit ended. `report` carries the run-level part (mode, scan,
    /// run errors, timing); its inputs arrived one by one already.
    UnitFinished {
        job: JobId,
        unit: usize,
        report: Box<Report>,
        at: String,
    },
    JobFinished {
        job: JobId,
        cancelled: bool,
    },
    Loaded {
        source: Source,
        result: Result<Arc<[u8]>, LoadError>,
    },
    Picked(Pick, Vec<PathBuf>),
    Saved(Result<PathBuf, String>),
    /// Something the window could not do, in English from the system.
    Failed(String),
}

/// Why a view has no bytes to show.
#[derive(Debug, Clone)]
pub enum LoadError {
    /// A system or engine message.
    Message(senbei_i18n::Message),
    /// The file is larger than a view reads.
    TooLarge { size: u64, limit: u64 },
}

/// A machine the window can run on.
pub trait Backend {
    fn capabilities(&self) -> Capabilities;
    fn send(&self, request: Request);
    /// The next event, if one is waiting.
    fn poll(&self) -> Option<Event>;
}
