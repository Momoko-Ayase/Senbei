//! The native backend: files, folders, runs, dialogs, and system fonts.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use senbei_engine::android::ResourceLimits;
use senbei_i18n::{Lang, Message, Msg};
use senbei_io::job;
use senbei_io::logfile::local_clock;
use senbei_io::observe::{CancelToken, RunObserver};
use senbei_io::report::{
    Collector, CompanionState, InputReport, InputStatus, Mode, OutputFile, Role,
};
use senbei_io::scan::{InputClass, classify_input};

use crate::backend::{
    Backend, Capabilities, Event, Identity, Job, LoadError, Pick, Produced, Request, Source, Unit,
};
use crate::theme::{Face, FontSet};

/// Hands events to the window and wakes it.
#[derive(Clone)]
struct Sink {
    events: Sender<Event>,
    ctx: egui::Context,
}

impl Sink {
    fn send(&self, event: Event) {
        // The window is gone only when the process is closing.
        let _ = self.events.send(event);
        self.ctx.request_repaint();
    }
}

pub struct NativeBackend {
    requests: Sender<Request>,
    events: Mutex<Receiver<Event>>,
}

impl NativeBackend {
    pub fn new(ctx: egui::Context) -> Self {
        let (requests, incoming) = channel::<Request>();
        let (events, outgoing) = channel::<Event>();
        let sink = Sink { events, ctx };
        std::thread::Builder::new()
            .name("senbei-dispatch".into())
            .spawn(move || dispatch(incoming, sink))
            .expect("spawn the dispatch thread");
        Self {
            requests,
            events: Mutex::new(outgoing),
        }
    }
}

impl Backend for NativeBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            folders: true,
            unpack: true,
            reveal: true,
        }
    }

    fn send(&self, request: Request) {
        let _ = self.requests.send(request);
    }

    fn poll(&self) -> Option<Event> {
        self.events.lock().ok()?.try_recv().ok()
    }
}

/// Route each request: jobs run one at a time on the job thread, everything
/// else on a short-lived thread of its own so the window never waits.
fn dispatch(incoming: Receiver<Request>, sink: Sink) {
    let (jobs, queue) = channel::<Job>();
    let cancel: Arc<Mutex<CancelToken>> = Arc::default();
    // Cancel stops the running job and drops every job queued behind it.
    let cancelled_through = Arc::new(AtomicU64::new(0));
    let mut last_submitted = 0;
    {
        let sink = sink.clone();
        let cancel = cancel.clone();
        let cancelled_through = cancelled_through.clone();
        spawn("senbei-jobs", move || {
            for job in queue {
                if job.id <= cancelled_through.load(Ordering::SeqCst) {
                    sink.send(Event::JobFinished {
                        job: job.id,
                        cancelled: true,
                    });
                    continue;
                }
                let token = CancelToken::new();
                if let Ok(mut current) = cancel.lock() {
                    *current = token.clone();
                }
                // A cancel that raced the token swap still stops this job.
                if job.id <= cancelled_through.load(Ordering::SeqCst) {
                    token.cancel();
                }
                run_job(&job, &sink, &token);
            }
        });
    }
    for request in incoming {
        let sink = sink.clone();
        match request {
            Request::Run(job) => {
                last_submitted = last_submitted.max(job.id);
                let _ = jobs.send(*job);
            }
            Request::Cancel => {
                cancelled_through.fetch_max(last_submitted, Ordering::SeqCst);
                if let Ok(current) = cancel.lock() {
                    current.cancel();
                }
            }
            Request::Identify { items, limits } => spawn("senbei-identify", move || {
                for (id, path) in items {
                    sink.send(Event::Identified(id, Box::new(identify(&path, &limits))));
                }
            }),
            Request::Scan {
                group,
                root,
                scan_all,
                limits,
            } => spawn("senbei-scan", move || {
                scan(group, &root, scan_all, &limits, &sink)
            }),
            Request::Load { source, limits } => spawn("senbei-load", move || {
                let result = load(&source, &limits);
                sink.send(Event::Loaded { source, result });
            }),
            Request::Pick(pick) => spawn("senbei-dialog", move || {
                let paths = match pick {
                    Pick::Files => rfd::FileDialog::new().pick_files().unwrap_or_default(),
                    Pick::Folder | Pick::Output => {
                        rfd::FileDialog::new().pick_folder().into_iter().collect()
                    }
                };
                sink.send(Event::Picked(pick, paths));
            }),
            Request::Reveal(path) => spawn("senbei-reveal", move || {
                if let Err(error) = reveal(&path) {
                    sink.send(Event::Failed(error.to_string()));
                }
            }),
            Request::Save { name, contents } => spawn("senbei-save", move || {
                let Some(path) = rfd::FileDialog::new().set_file_name(&name).save_file() else {
                    return;
                };
                let result = std::fs::write(&path, contents)
                    .map(|()| path)
                    .map_err(|error| error.to_string());
                sink.send(Event::Saved(result));
            }),
        }
    }
}

fn spawn(name: &str, work: impl FnOnce() + Send + 'static) {
    if let Err(error) = std::thread::Builder::new().name(name.into()).spawn(work) {
        eprintln!("senbei-gui: cannot start a worker thread: {error}");
    }
}

// --------------------------------------------------------------- runs

/// Sends a run's progress to the window.
struct Observer {
    job: u64,
    unit: usize,
    mode: Mode,
    keep_bytes: bool,
    keep_cap: u64,
    sink: Sink,
}

impl Observer {
    fn produced_file(&self, output: &OutputFile) -> Produced {
        let path = PathBuf::from(&output.path);
        if self.mode == Mode::Unpack {
            return Produced::OnDisk(path);
        }
        if !self.keep_bytes {
            return Produced::NotKept;
        }
        if output.size > self.keep_cap {
            return Produced::TooLarge(output.size);
        }
        match std::fs::read(&path) {
            Ok(bytes) => Produced::Kept(bytes.into()),
            Err(_) => Produced::NotKept,
        }
    }
}

impl RunObserver for Observer {
    fn scanned(&self, inputs: usize) {
        self.sink.send(Event::UnitScanned {
            job: self.job,
            unit: self.unit,
            inputs,
            at: local_clock(),
        });
    }

    fn input_started(&self, path: &Path) {
        self.sink.send(Event::InputStarted {
            job: self.job,
            unit: self.unit,
            path: path.to_path_buf(),
            at: local_clock(),
        });
    }

    fn progress(&self, event: &senbei_engine::progress::Event) {
        use senbei_engine::progress::Event as Progress;
        let at = local_clock();
        self.sink.send(match event {
            Progress::Step { step, position } => Event::Step {
                job: self.job,
                step: step.clone(),
                position: *position,
                at,
            },
            Progress::Detail(text) => Event::Detail {
                job: self.job,
                text: text.trim().to_owned(),
                at,
            },
        });
    }

    fn produced(&self, input: &InputReport) {
        let restored = input
            .outputs
            .first()
            .map(|output| self.produced_file(output));
        let entries = input
            .entries
            .iter()
            .filter_map(|entry| {
                let output = entry.output.as_ref()?;
                Some((entry.name.clone(), self.produced_file(output)))
            })
            .collect();
        self.sink.send(Event::Produced {
            job: self.job,
            path: PathBuf::from(&input.path),
            restored,
            entries,
        });
    }

    fn input_finished(&self, input: &InputReport) {
        self.sink.send(Event::InputFinished {
            job: self.job,
            unit: self.unit,
            report: Box::new(input.clone()),
            at: local_clock(),
        });
    }
}

fn run_job(job: &Job, sink: &Sink, cancel: &CancelToken) {
    for (index, unit) in job.units.iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        sink.send(Event::UnitStarted {
            job: job.id,
            unit: index,
            at: local_clock(),
        });
        let observer = Arc::new(Observer {
            job: job.id,
            unit: index,
            mode: job.mode,
            keep_bytes: job.options.keep_bytes,
            keep_cap: job.options.keep_cap,
            sink: sink.clone(),
        });
        let mut collector = Collector::new(job.mode)
            .with_observer(observer)
            .with_cancel(cancel.clone());
        let result = run_unit(job, unit, &mut collector);
        if let Err(error) = &result {
            let message = match error.downcast_ref::<Panicked>() {
                Some(Panicked(message)) => message.clone(),
                None => senbei_io::message::of_error(error),
            };
            // A file unit that never reached its input still gets a row.
            if let Unit::File { path, .. } = unit
                && collector.summary_mut().inputs == 0
            {
                let mut input = InputReport::new(path, Role::Content);
                input.status = InputStatus::Error;
                input.errors.push(message.clone());
                collector.push(input);
            } else {
                collector.push_error(message);
            }
        }
        let mut report = collector.finish();
        report.inputs.clear();
        sink.send(Event::UnitFinished {
            job: job.id,
            unit: index,
            report: Box::new(report),
            at: local_clock(),
        });
    }
    sink.send(Event::JobFinished {
        job: job.id,
        cancelled: cancel.is_cancelled(),
    });
}

/// A panic caught around a run, with its catalog message.
#[derive(Debug)]
struct Panicked(Message);

impl std::fmt::Display for Panicked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0.text())
    }
}

impl std::error::Error for Panicked {}

/// Run one unit the way the command line would, with the window's settings.
fn run_unit(job: &Job, unit: &Unit, collector: &mut Collector) -> anyhow::Result<()> {
    let options = &job.options;
    // Inspections and dry runs write into a workspace that is dropped after
    // the run; the observer reads what it keeps before that.
    let workspace = match job.mode {
        Mode::Unpack => None,
        Mode::Inspect | Mode::DryRun => Some(tempfile::tempdir()?),
    };
    let no_log = job.mode != Mode::Unpack || !options.write_log;
    let mut run = || -> anyhow::Result<()> {
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match unit {
            Unit::File { path, out_dir } => {
                let out_dir = workspace
                    .as_ref()
                    .map_or(out_dir.as_path(), |dir| dir.path());
                job::run_file_reported(
                    path,
                    Some(out_dir),
                    2,
                    true,
                    no_log,
                    &options.limits,
                    collector,
                )
                .map(drop)
            }
            Unit::Folder { root, out_dir } => {
                let out_dir = workspace
                    .as_ref()
                    .map_or(out_dir.as_path(), |dir| dir.path());
                job::run_folder_reported(
                    root,
                    Some(out_dir),
                    2,
                    true,
                    no_log,
                    options.scan_all,
                    &options.limits,
                    collector,
                )
                .map(drop)
            }
        }));
        match caught {
            Ok(result) => result,
            Err(payload) => {
                let text = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| {
                        payload
                            .downcast_ref::<&str>()
                            .map(|text| (*text).to_owned())
                    })
                    .unwrap_or_default();
                Err(anyhow::Error::new(Panicked(Message::new(
                    Msg::UnexpectedPanic { message: text },
                ))))
            }
        }
    };
    match options.threads {
        Some(count) => senbei_engine::with_thread_cap(count, run),
        None => run(),
    }
}

// ------------------------------------------------------- identification

/// How much of a file identification reads: headers, the key table, and the
/// section table all sit well inside it.
const IDENTIFY_PREFIX: u64 = 1024 * 1024;

fn read_prefix(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut buffer = Vec::new();
    file.take(max).read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// What `path` is, without recovering anything.
pub fn identify(path: &Path, limits: &ResourceLimits) -> Identity {
    let size = match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => meta.len(),
        Ok(_) => return Identity::NotAFile,
        Err(error) => return Identity::Unreadable(error.to_string()),
    };
    let class = match classify_input(path, limits) {
        Ok(class) => class,
        Err(error) => return Identity::Unreadable(error.to_string()),
    };
    match class {
        InputClass::Metadata => {
            let identity = read_prefix(path, 64)
                .ok()
                .and_then(|head| senbei_metadata::identify(&head));
            Identity::Metadata { size, identity }
        }
        InputClass::AndroidLibrary => Identity::AndroidLibrary { size },
        InputClass::AndroidPackage => Identity::Package {
            size,
            container: senbei_io::android::inspect_package(path, limits)
                .map(Box::new)
                .map_err(|error| senbei_io::message::of_error(&error).text().to_owned()),
        },
        InputClass::Windows | InputClass::NotTarget => match windows_identity(path, size) {
            Some(identity) => identity,
            None => Identity::NotTarget { size },
        },
    }
}

/// The header-level profile of a PE and its companion state. `None` when the
/// file is not a PE at all.
fn windows_identity(path: &Path, size: u64) -> Option<Identity> {
    let stub = read_prefix(path, IDENTIFY_PREFIX).ok()?;
    if !stub.starts_with(b"MZ") {
        return None;
    }
    let sibling = companion_path(path);
    let (companion, companion_bytes) = match &sibling {
        Some(sibling) => match read_prefix(sibling, IDENTIFY_PREFIX) {
            Ok(bytes) => (CompanionState::Unmatched, Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (CompanionState::Absent, None)
            }
            Err(_) => (CompanionState::Unreadable, None),
        },
        None => (CompanionState::Absent, None),
    };
    let spliced = companion_bytes
        .as_deref()
        .and_then(|payload| senbei_io::windows::splice_companion(&stub, payload));
    let (profile, companion) = match &spliced {
        Some(view) => {
            let mut profile = senbei_engine::inspect_profile(view);
            profile.record_companion_spliced();
            (profile, CompanionState::Spliced)
        }
        None => (senbei_engine::inspect_profile(&stub), companion),
    };
    Some(Identity::Windows {
        size,
        profile: Box::new(profile),
        companion,
        companion_path: (companion != CompanionState::Absent)
            .then(|| sibling.map(|sibling| sibling.display().to_string()))
            .flatten(),
    })
}

/// `<input>._`, the companion payload a loader may declare.
pub fn companion_path(input: &Path) -> Option<PathBuf> {
    let mut name = input.file_name()?.to_os_string();
    name.push("._");
    Some(input.with_file_name(name))
}

/// Scan a folder the way a folder run does, reporting the count as it grows.
fn scan(group: u64, root: &Path, scan_all: bool, limits: &ResourceLimits, sink: &Sink) {
    let found = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        // Report the growing count a few times a second until the scan ends.
        let found = found.clone();
        let done = done.clone();
        let sink = sink.clone();
        spawn("senbei-scan-progress", move || {
            let mut last = usize::MAX;
            while !done.load(Ordering::Relaxed) {
                let now = found.load(Ordering::Relaxed);
                if now != last {
                    sink.send(Event::ScanProgress { group, found: now });
                    last = now;
                }
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
        });
    }
    let result = senbei_io::scan::find_targets_counted(root, scan_all, limits, &found);
    done.store(true, Ordering::Relaxed);
    let mut paths: Vec<PathBuf> = result
        .crackproof
        .into_iter()
        .chain(result.metadata)
        .chain(result.android_so)
        .chain(result.android_packages)
        .collect();
    paths.sort();
    let targets = paths
        .into_iter()
        .map(|path| {
            let identity = identify(&path, limits);
            (path, Box::new(identity))
        })
        .collect();
    let stats = result.stats;
    sink.send(Event::Scanned {
        group,
        targets,
        scan: senbei_io::report::ScanReport {
            non_target_skipped: stats.skipped,
            walk_errors: stats.walk_errors,
            probe_errors: stats.probe_errors,
        },
    });
}

// ---------------------------------------------------------------- bytes

/// Largest file the hex view loads.
const LOAD_LIMIT: u64 = 2 * 1024 * 1024 * 1024;

fn read_whole(path: &Path) -> Result<Vec<u8>, LoadError> {
    let system = |error: std::io::Error| LoadError::Message(Message::raw(error.to_string()));
    let size = std::fs::metadata(path).map_err(system)?.len();
    if size > LOAD_LIMIT {
        return Err(LoadError::TooLarge {
            size,
            limit: LOAD_LIMIT,
        });
    }
    std::fs::read(path).map_err(system)
}

fn load(source: &Source, limits: &ResourceLimits) -> Result<Arc<[u8]>, LoadError> {
    match source {
        Source::File(path) => read_whole(path).map(Into::into),
        Source::Spliced { stub, companion } => {
            let stub = read_whole(stub)?;
            let payload = read_whole(companion)?;
            senbei_io::windows::splice_companion(&stub, &payload)
                .map(Into::into)
                .ok_or(LoadError::Message(Message::new(Msg::CompanionMismatch)))
        }
        Source::Entry { package, label } => {
            senbei_io::android::read_package_entry(package, label, limits)
                .map(Into::into)
                .map_err(|error| LoadError::Message(senbei_io::message::of_error(&error)))
        }
    }
}

// ----------------------------------------------------------- the desktop

fn reveal(path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let mut select = std::ffi::OsString::from("/select,");
        select.push(path);
        std::process::Command::new("explorer.exe")
            .arg(select)
            .spawn()?;
    }
    #[cfg(not(windows))]
    {
        let folder = path.parent().unwrap_or(path);
        std::process::Command::new("xdg-open").arg(folder).spawn()?;
    }
    Ok(())
}

/// Debug environment variables that change how inputs are decoded.
pub fn debug_variables() -> Vec<String> {
    ["DD8_SHIFT", "SEL_DIAG"]
        .into_iter()
        .filter(|name| std::env::var_os(name).is_some())
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------- fonts

/// System fonts, found by family name.
pub struct SystemFonts {
    collection: fontique::Collection,
    cache: fontique::SourceCache,
}

impl Default for SystemFonts {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemFonts {
    pub fn new() -> Self {
        Self {
            collection: fontique::Collection::new(fontique::CollectionOptions {
                shared: false,
                system_fonts: true,
            }),
            cache: fontique::SourceCache::default(),
        }
    }

    fn face(&mut self, family: &str, weight: fontique::FontWeight) -> Option<Face> {
        let info = self.collection.family_by_name(family)?;
        let font = info
            .match_font(
                fontique::FontWidth::NORMAL,
                fontique::FontStyle::Normal,
                weight,
                false,
            )?
            .clone();
        let blob = font.load(Some(&mut self.cache))?;
        let (data, _) = blob.into_raw_parts();
        Some(Face {
            name: format!("{family}:{}:{}", font.weight().value(), font.index()),
            data: Arc::new(egui::FontData::from_blob(data, font.index())),
        })
    }

    fn faces(&mut self, families: &[&str], weight: fontique::FontWeight) -> Vec<Face> {
        let mut faces: Vec<Face> = Vec::new();
        for family in families {
            if let Some(face) = self.face(family, weight)
                && !faces.iter().any(|known| known.name == face.name)
            {
                faces.push(face);
            }
        }
        faces
    }

    /// The UI, semibold, and monospace faces for `lang`: the language's own
    /// font first (so shared punctuation takes its shape), the other CJK
    /// fonts after it for names in other scripts.
    pub fn set_for(&mut self, lang: Lang) -> FontSet {
        const LATIN: [&str; 3] = ["Segoe UI", "Noto Sans", "DejaVu Sans"];
        let own: &[&str] = match lang {
            Lang::En => &[],
            Lang::ZhCn => &["Microsoft YaHei UI", "Microsoft YaHei", "Noto Sans CJK SC"],
            Lang::ZhTw => &[
                "Microsoft JhengHei UI",
                "Microsoft JhengHei",
                "Noto Sans CJK TC",
            ],
            Lang::Ja => &["Yu Gothic UI", "Meiryo UI", "Meiryo", "Noto Sans CJK JP"],
            Lang::Ko => &["Malgun Gothic", "Noto Sans CJK KR"],
        };
        let others = [
            "Yu Gothic UI",
            "Microsoft YaHei UI",
            "Microsoft JhengHei UI",
            "Malgun Gothic",
            "Noto Sans CJK JP",
            "Noto Sans CJK SC",
        ];
        // Symbols the window draws itself: ⚙ ▶ ✓ ✕ ● ★ → and the like.
        const SYMBOLS: [&str; 3] = [
            "Segoe UI Symbol",
            "Noto Sans Symbols 2",
            "Noto Sans Symbols",
        ];
        let mut ui: Vec<&str> = own.to_vec();
        ui.extend(LATIN);
        ui.extend(others);
        ui.extend(SYMBOLS);
        let mono = ["Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Menlo"];
        FontSet {
            ui: self.faces(&ui, fontique::FontWeight::NORMAL),
            strong: self.faces(&ui, fontique::FontWeight::SEMI_BOLD),
            mono: self.faces(&mono, fontique::FontWeight::NORMAL),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::time::Duration;

    use zip::write::SimpleFileOptions;

    use super::*;

    #[test]
    fn package_identification_honors_requested_limits() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("app.apk");
        let mut archive = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        archive.start_file("AndroidManifest.xml", options).unwrap();
        archive
            .write_all(br#"<manifest package="example.test" />"#)
            .unwrap();
        archive
            .start_file("lib/arm64-v8a/libexample.so", options)
            .unwrap();
        archive.write_all(b"library").unwrap();
        archive.finish().unwrap();

        let backend = NativeBackend::new(egui::Context::default());
        let receive = |id| {
            let event = backend
                .events
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .expect("identification must finish");
            let Event::Identified(actual, identity) = event else {
                panic!("expected an identification result");
            };
            assert_eq!(actual, id);
            let Identity::Package { container, .. } = *identity else {
                panic!("expected an Android package");
            };
            container
        };
        backend.send(Request::Identify {
            items: vec![(1, path.clone())],
            limits: ResourceLimits {
                max_entries: 1,
                ..ResourceLimits::default()
            },
        });
        let error = receive(1).expect_err("two entries must exceed the one-entry limit");
        let expected = Message::new(Msg::LimitEntries {
            requested: 2,
            limit: 1,
        });
        assert!(error.contains(expected.text()), "{error}");

        backend.send(Request::Identify {
            items: vec![(2, path)],
            limits: ResourceLimits {
                max_entries: 2,
                ..ResourceLimits::default()
            },
        });
        let report = receive(2).expect("raising the entry limit must allow identification");
        assert_eq!(report.candidate_entries.len(), 1);
    }
}
