use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct Log {
    path: PathBuf,
    file: Mutex<File>,
}

impl Log {
    pub fn create(dir: &Path) -> std::io::Result<Self> {
        let ts = local_stamp_compact();
        // The stamp has one-second granularity and `File::create` truncates, so
        // two runs into the same out dir within a second would clobber each
        // other's log. Probe for a free name with create_new instead.
        let mut path = dir.join(format!("senbei-{ts}.log"));
        let mut file = File::create_new(&path);
        for n in 2..100 {
            if !matches!(&file, Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists) {
                break;
            }
            path = dir.join(format!("senbei-{ts}-{n}.log"));
            file = File::create_new(&path);
        }
        let file = Mutex::new(file?);
        Ok(Self { path, file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn step(&self, msg: &str) {
        if let Ok(mut f) = self.file.lock() {
            let _ = writeln!(f, "{msg}");
        }
    }
}

/// Local wall-clock `YYYYMMDD-HHMMSS` for log filenames.
pub fn local_stamp_compact() -> String {
    let t = local_parts();
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

/// Local wall-clock `YYYY-MM-DD HH:MM:SS` for log header.
pub fn local_stamp_display() -> String {
    let t = local_parts();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

struct LocalParts {
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

fn local_parts() -> LocalParts {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::GetLocalTime;
        let st = unsafe { GetLocalTime() };
        LocalParts {
            year: st.wYear as u32,
            month: st.wMonth as u32,
            day: st.wDay as u32,
            hour: st.wHour as u32,
            minute: st.wMinute as u32,
            second: st.wSecond as u32,
        }
    }
    #[cfg(all(not(windows), not(target_arch = "wasm32")))]
    {
        // Local wall clock via POSIX localtime_r — same semantics as Windows GetLocalTime.
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs_u = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let t: libc::time_t = secs_u as libc::time_t;
        let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
        let ok = unsafe { libc::localtime_r(&t, &mut tm) };
        if ok.is_null() {
            return utc_parts(secs_u); // emergency only if localtime_r fails
        }
        LocalParts {
            year: (tm.tm_year + 1900) as u32,
            month: (tm.tm_mon + 1) as u32,
            day: tm.tm_mday as u32,
            hour: tm.tm_hour as u32,
            minute: tm.tm_min as u32,
            second: tm.tm_sec as u32,
        }
    }
    #[cfg(all(not(windows), target_arch = "wasm32"))]
    {
        // wasm has no local timezone database and SystemTime::now() panics
        // without a JS time source. The run log is a CLI concern — the wasm
        // build never writes one — so a fixed epoch stamp suffices.
        utc_parts(0)
    }
}

/// Convert Unix UTC seconds to civil Y-M-D h:m:s (Howard Hinnant).
/// Used as non-Windows fallback; keep pub(crate) if unit-tested.
fn utc_parts(secs: u64) -> LocalParts {
    let s = secs as i64;
    let time_of_day = s.rem_euclid(86400) as u32;
    let days = s.div_euclid(86400);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    LocalParts {
        year: y as u32,
        month: m,
        day: d,
        hour: time_of_day / 3600,
        minute: (time_of_day % 3600) / 60,
        second: time_of_day % 60,
    }
}

/// UTC civil stamp helper (used only as emergency fallback path via `utc_parts`).
#[allow(dead_code)] // retained for unit-style reuse / non-Windows emergency path symmetry
pub(crate) fn fmt_stamp(secs: u64) -> String {
    let t = utc_parts(secs);
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}
