//! Platform-specific unpacking engines.

pub mod android;
mod findings;
mod panic_capture;
pub mod profile;
pub mod progress;
mod threading;
pub mod windows;

pub use panic_capture::catch_unwind_quiet;
pub use profile::{
    AttemptOutcome, LayoutAttempt, LayoutKind, ObservedTarget, PROFILE_FORMAT_VERSION, Platform,
    ProtectionEvidence, ProtectionProfile, RecognitionStatus, RecoveryStatus, TargetFormat,
    ValidationStatus,
};
pub use threading::{thread_cap, with_thread_cap};

pub use windows::{
    AddressSpace, Detected, InspectionLimits, IntegrityFinding, IntegrityReport, IntegritySeverity,
    Kind, ResearchEvent, ResearchStage, ResearchTrace, TraceAddress, TraceValue, UnpackError,
    WindowsInspection, check_integrity, detect, inspect_profile, inspect_research,
    inspect_research_with_limits, unpack_auto, unpack_auto_profiled, unpack_auto_profiled_v,
    unpack_auto_v, unpack_dll, unpack_dll_v, unpack_exe, unpack_exe_profiled,
    unpack_exe_profiled_v, unpack_exe_v, with_research_trace, with_research_trace_limited,
};
