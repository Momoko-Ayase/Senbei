//! Run-scoped worker limits without changing the process environment.

use std::cell::Cell;
use std::num::NonZeroUsize;

thread_local! {
    static OVERRIDE: Cell<Option<NonZeroUsize>> = const { Cell::new(None) };
}

/// Deterministic worker-thread cap shared by filesystem scanning and engines.
/// A scoped override takes precedence over `SENBEI_THREADS` and host parallelism.
pub fn thread_cap() -> usize {
    if let Some(count) = OVERRIDE.get() {
        return count.get();
    }
    if let Ok(value) = std::env::var("SENBEI_THREADS")
        && let Some(count) = parse_cap(&value)
    {
        return count.get();
    }
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

fn parse_cap(value: &str) -> Option<NonZeroUsize> {
    value.trim().parse().ok()
}

/// Run a synchronous job with an explicit worker cap on the calling thread.
///
/// The scanner and unpacker choose their worker counts before spawning workers.
/// This does not mutate the environment or affect unrelated caller threads. A
/// nested scope or unwinding restores the previous cap. Callers that spawn new
/// top-level jobs must apply the scope on those threads as well.
pub fn with_thread_cap<R>(count: NonZeroUsize, run: impl FnOnce() -> R) -> R {
    struct Restore(Option<NonZeroUsize>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OVERRIDE.set(self.0);
        }
    }
    let _restore = Restore(OVERRIDE.replace(Some(count)));
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    #[test]
    fn preserves_environment_parsing() {
        assert_eq!(parse_cap(" 3 "), Some(count(3)));
        for value in [
            "",
            "0",
            "-1",
            "1.5",
            "many",
            "999999999999999999999999999999",
        ] {
            assert_eq!(parse_cap(value), None);
        }
    }

    #[test]
    fn nested_scopes_restore_the_previous_cap() {
        let before = thread_cap();
        let result = with_thread_cap(count(3), || {
            assert_eq!(thread_cap(), 3);
            with_thread_cap(count(1), || assert_eq!(thread_cap(), 1));
            assert_eq!(thread_cap(), 3);
            42
        });
        assert_eq!(result, 42);
        assert_eq!(thread_cap(), before);
    }

    #[test]
    fn unwind_restores_the_previous_cap() {
        with_thread_cap(count(2), || {
            let result = std::panic::catch_unwind(|| {
                with_thread_cap(count(7), || panic!("test unwind"));
            });
            assert!(result.is_err());
            assert_eq!(thread_cap(), 2);
        });
    }

    #[test]
    fn sequential_and_parallel_blocks_produce_identical_bytes() {
        fn run(workers: usize) -> Vec<u8> {
            let mut bytes = vec![0; 256];
            let spans: Vec<_> = (0..16).map(|i| (i * 16, (i + 1) * 16)).collect();
            let caller = std::thread::current().id();
            with_thread_cap(count(workers), || {
                crate::windows::parallel::parallel_for(
                    &mut bytes,
                    &spans,
                    1,
                    |index, base, span| {
                        assert_eq!(std::thread::current().id() == caller, workers == 1);
                        for (offset, byte) in span.iter_mut().enumerate() {
                            *byte = (index ^ (base + offset)) as u8;
                        }
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
            });
            bytes
        }
        assert_eq!(run(1), run(4));
    }

    #[test]
    fn concurrent_callers_keep_independent_caps() {
        with_thread_cap(count(2), || {
            std::thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    with_thread_cap(count(5), || assert_eq!(thread_cap(), 5));
                });
                assert_eq!(thread_cap(), 2);
                worker.join().unwrap();
            });
            assert_eq!(thread_cap(), 2);
        });
    }
}
