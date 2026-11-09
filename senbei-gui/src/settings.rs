//! Settings the window keeps between sessions.

use std::num::NonZeroUsize;
use std::path::PathBuf;

use senbei_engine::android::ResourceLimits;
use senbei_i18n::Lang;
use serde::{Deserialize, Serialize};

use crate::backend::{Output, RunOptions};

const MIB: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// A language tag, or `None` to follow `SENBEI_LANG` and the system.
    pub language: Option<String>,
    pub output: Output,
    /// The last folder chosen for outputs, offered again in the output menu.
    pub recent_output: Option<PathBuf>,
    pub write_log: bool,
    /// `0` is automatic.
    pub threads: usize,
    pub scan_all: bool,
    pub max_entry_mib: u64,
    pub max_total_mib: u64,
    pub max_entries: usize,
    pub max_depth: usize,
    pub keep_bytes: bool,
    pub keep_cap_mib: u64,
    pub legal_accepted: bool,
}

impl Default for Settings {
    fn default() -> Self {
        let limits = ResourceLimits::default();
        Self {
            language: None,
            output: Output::Beside,
            recent_output: None,
            write_log: true,
            threads: 0,
            scan_all: false,
            max_entry_mib: limits.max_entry_bytes / MIB,
            max_total_mib: limits.max_total_bytes / MIB,
            max_entries: limits.max_entries,
            max_depth: limits.max_depth,
            keep_bytes: true,
            keep_cap_mib: 512,
            legal_accepted: false,
        }
    }
}

impl Settings {
    /// Everything but the legal notice and the language back to defaults.
    pub fn reset(&mut self) {
        *self = Settings {
            language: self.language.clone(),
            legal_accepted: self.legal_accepted,
            recent_output: self.recent_output.clone(),
            ..Settings::default()
        };
    }

    pub fn lang(&self, detected: Lang) -> Lang {
        self.language
            .as_deref()
            .and_then(Lang::from_tag)
            .unwrap_or(detected)
    }

    pub fn limits(&self) -> ResourceLimits {
        ResourceLimits {
            max_entry_bytes: self.max_entry_mib.max(1).saturating_mul(MIB),
            max_total_bytes: self.max_total_mib.max(1).saturating_mul(MIB),
            max_entries: self.max_entries.max(1),
            max_depth: self.max_depth,
        }
    }

    pub fn run_options(&self) -> RunOptions {
        RunOptions {
            write_log: self.write_log,
            threads: NonZeroUsize::new(self.threads),
            scan_all: self.scan_all,
            limits: self.limits(),
            keep_bytes: self.keep_bytes,
            keep_cap: self.keep_cap_mib.max(1).saturating_mul(MIB),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_command_line() {
        let settings = Settings::default();
        assert_eq!(settings.limits(), ResourceLimits::default());
        assert_eq!(settings.keep_cap_mib, 512);
        assert!(settings.write_log);
    }

    #[test]
    fn reset_keeps_the_language_and_the_notice() {
        let mut settings = Settings {
            language: Some("ja".into()),
            legal_accepted: true,
            threads: 4,
            ..Settings::default()
        };
        settings.reset();
        assert_eq!(settings.language.as_deref(), Some("ja"));
        assert!(settings.legal_accepted);
        assert_eq!(settings.threads, 0);
    }
}
