//! A front end follows a run through an observer and can stop it between
//! inputs. The CLI uses neither, so its output and reports are unaffected.

#[path = "support/fixtures.rs"]
mod fixtures;

use std::path::Path;
use std::sync::{Arc, Mutex};

use senbei_engine::android::ResourceLimits;
use senbei_io::job::{self, Collector, Mode};
use senbei_io::observe::{CancelToken, RunObserver};
use senbei_io::report::InputReport;

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<String>>,
    /// Cancelled when the first input finishes.
    stop_after_first: Option<CancelToken>,
}

impl Recorder {
    fn push(&self, event: String) {
        self.events.lock().unwrap().push(event);
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

fn parent_name(path: &Path) -> String {
    path.parent()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl RunObserver for Recorder {
    fn scanned(&self, inputs: usize) {
        self.push(format!("scanned {inputs}"));
    }

    fn input_started(&self, path: &Path) {
        self.push(format!("started {}", parent_name(path)));
    }

    fn progress(&self, event: &senbei_engine::progress::Event) {
        if let senbei_engine::progress::Event::Step { step, .. } = event {
            self.push(
                format!("step {step:?}")
                    .split(' ')
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
    }

    fn input_finished(&self, input: &InputReport) {
        self.push(format!("finished {}", parent_name(Path::new(&input.path))));
        if let Some(cancel) = &self.stop_after_first {
            cancel.cancel();
        }
    }
}

/// Two applications, each with its own obfuscated metadata blob.
fn two_apps(root: &Path) {
    for app in ["a", "b"] {
        let dir = root.join(app);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("global-metadata.dat"),
            fixtures::obfuscated_metadata(),
        )
        .unwrap();
    }
}

fn run(root: &Path, out: &Path, collector: &mut Collector) {
    job::run_folder_reported(
        root,
        Some(out),
        2,
        true,
        true,
        true,
        &ResourceLimits::default(),
        collector,
    )
    .unwrap();
}

#[test]
fn an_observer_sees_each_input_start_progress_and_finish() {
    let temp = tempfile::tempdir().unwrap();
    two_apps(temp.path());
    let recorder = Arc::new(Recorder::default());
    let mut collector = Collector::new(Mode::Unpack).with_observer(recorder.clone());
    run(temp.path(), &temp.path().join("out"), &mut collector);
    assert_eq!(
        recorder.events(),
        [
            "scanned 2",
            "started a",
            "step WriteTo",
            "finished a",
            "started b",
            "step WriteTo",
            "finished b",
        ]
    );
    let report = collector.finish();
    assert_eq!(report.inputs.len(), 2);
    assert!(!report.cancelled);
    assert!(!report.to_json().contains("cancelled"));
}

#[test]
fn cancelling_stops_before_the_next_input_and_is_reported() {
    let temp = tempfile::tempdir().unwrap();
    two_apps(temp.path());
    let cancel = CancelToken::new();
    let recorder = Arc::new(Recorder {
        stop_after_first: Some(cancel.clone()),
        ..Recorder::default()
    });
    let mut collector = Collector::new(Mode::Unpack)
        .with_observer(recorder.clone())
        .with_cancel(cancel);
    let out = temp.path().join("out");
    run(temp.path(), &out, &mut collector);
    assert_eq!(
        recorder.events(),
        ["scanned 2", "started a", "step WriteTo", "finished a"]
    );
    let report = collector.finish();
    assert_eq!(report.inputs.len(), 1);
    assert!(report.cancelled);
    assert!(report.to_json().contains("\"cancelled\":true"));
    assert!(out.join("a").join("global-metadata.unpack.dat").is_file());
    assert!(!out.join("b").exists());
}

#[test]
fn a_run_cancelled_before_it_starts_processes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    two_apps(temp.path());
    let cancel = CancelToken::new();
    cancel.cancel();
    let mut collector = Collector::new(Mode::DryRun).with_cancel(cancel);
    run(temp.path(), &temp.path().join("out"), &mut collector);
    let report = collector.finish();
    assert!(report.inputs.is_empty());
    assert!(report.cancelled);
}
