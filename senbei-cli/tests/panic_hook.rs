use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

#[test]
fn folder_runs_preserve_the_host_panic_hook() {
    const CHILD: &str = "SENBEI_PANIC_HOOK_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "folder_runs_preserve_the_host_panic_hook",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    std::panic::set_hook(Box::new(|_| {
        CALLS.fetch_add(1, Ordering::SeqCst);
    }));
    let root = tempfile::tempdir().unwrap();
    // Exercise repeated job lifetimes both before and after engine capture.
    for _ in 0..2 {
        senbei_io::job::run_folder_opts(root.path(), None, 2, false, true, false).unwrap();
        assert!(senbei_engine::catch_unwind_quiet(|| panic!("captured")).is_err());
        assert!(std::panic::catch_unwind(|| panic!("host")).is_err());
    }
    assert_eq!(CALLS.load(Ordering::SeqCst), 2);

    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = barrier.clone();
    let worker = std::thread::spawn(move || {
        senbei_engine::catch_unwind_quiet(|| {
            worker_barrier.wait();
            worker_barrier.wait();
            panic!("captured in another thread");
        })
        .unwrap_err();
    });
    barrier.wait();
    // A quiet capture in another thread must not silence unrelated panics.
    assert!(std::panic::catch_unwind(|| panic!("unrelated host panic")).is_err());
    barrier.wait();
    worker.join().unwrap();
    assert_eq!(CALLS.load(Ordering::SeqCst), 3);

    std::thread::scope(|scope| {
        for _ in 0..4 {
            let path = root.path();
            scope.spawn(move || {
                senbei_io::job::run_folder_opts(path, None, 2, false, true, false).unwrap();
                assert!(
                    senbei_engine::catch_unwind_quiet(|| panic!("after concurrent job")).is_err()
                );
            });
        }
    });
    assert_eq!(CALLS.load(Ordering::SeqCst), 3);
}
