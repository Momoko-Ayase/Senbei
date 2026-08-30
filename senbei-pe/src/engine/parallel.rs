//! Deterministic block-parallel fan-out for the section decrypt/decompress
//! loops.
//!
//! Each block writes a disjoint output span and reads only immutable input plus
//! snapshotted key tables, so distributing blocks across worker threads
//! produces byte-identical output regardless of thread count or scheduling.
//!
//! # Soundness
//!
//! This module contains **no `unsafe`**. The output buffer is carved into the
//! per-block spans with safe `split_at_mut` chains, so Rust itself guarantees
//! no two workers can hold aliasing `&mut` slices — an earlier version handed
//! every worker a whole-buffer `&mut [u8]` reconstructed from a raw pointer,
//! which is UB under Stacked/Tree Borrows even when the concrete writes never
//! overlap. The shared data the blocks read (AES key schedule, Huffman table)
//! is copied out by the caller before the fan-out and captured by the closure,
//! so no shared borrow of the output buffer is needed either.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Worker-thread cap. `SENBEI_THREADS` overrides it (`1` forces the sequential
/// path); otherwise the host's available parallelism; otherwise 1.
pub fn thread_cap() -> usize {
    if let Ok(v) = std::env::var("SENBEI_THREADS")
        && let Ok(n) = v.trim().parse::<usize>()
        && n >= 1
    {
        return n;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Run `f(i, span_base, span)` for every block `i`, fanning out across worker
/// threads when the spans are disjoint and worthwhile, else sequentially.
///
/// `spans[i]` is the `[start, end)` region of `buf` block `i` writes. The
/// closure receives `span_base = spans[i].0` and the disjoint
/// `&mut buf[start..end]`; any shared data it needs must be captured by value
/// before the call. When the spans overlap (only possible on corrupt input),
/// the whole thing degrades to a sequential whole-buffer pass (`span_base = 0`,
/// `span = buf`), which preserves the deterministic last-writer-wins behavior
/// the pipeline had before parallelization.
///
/// Returns the first `Err` any block produces; re-raises the first block panic
/// on the calling thread (so the pipeline's existing `catch_unpack` still
/// converts it to `UnpackError::InternalPanic`).
pub(crate) fn parallel_for<E, F>(
    buf: &mut [u8],
    spans: &[(usize, usize)],
    min_per_thread: usize,
    f: F,
) -> Result<(), E>
where
    E: Send,
    F: Fn(usize, usize, &mut [u8]) -> Result<(), E> + Sync,
{
    let n = spans.len();
    if n == 0 {
        return Ok(());
    }

    // Verify the spans are in-bounds and mutually disjoint. Overlapping spans
    // only arise from corrupt block descriptors; the sequential whole-buffer
    // fallback handles them exactly as the pre-parallel pipeline did.
    let mut sorted: Vec<(u64, u64)> = spans.iter().map(|&(s, e)| (s as u64, e as u64)).collect();
    let in_bounds = spans.iter().all(|&(s, e)| s <= e && e <= buf.len());
    let disjoint = in_bounds && spans_disjoint(&mut sorted);

    if !disjoint {
        for i in 0..n {
            f(i, 0, &mut *buf)?;
        }
        return Ok(());
    }

    // Carve the disjoint span pieces out of `buf` with safe splits. Rust's
    // borrow checker proves the pieces never alias.
    //
    // Sort by the whole span, not just its start: `spans_disjoint` compares
    // `(start, end)` tuples, so it accepts an empty span that shares a start
    // with a non-empty one (`(100,100)` and `(100,200)`). Ordering by start
    // alone would then carve them in input order, and a `(100,100)` arriving
    // after `(100,200)` makes `s - base` underflow — a panic instead of the
    // documented degrade-to-sequential fallback.
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| spans[i]);
    let mut pieces: Vec<Option<&mut [u8]>> = Vec::new();
    pieces.resize_with(n, || None);
    {
        let mut rest: &mut [u8] = buf;
        let mut base = 0usize;
        for &i in &order {
            let (s, e) = spans[i];
            let (_, tail) = rest.split_at_mut(s - base);
            let (piece, tail2) = tail.split_at_mut(e - s);
            pieces[i] = Some(piece);
            rest = tail2;
            base = e;
        }
    }

    let cap = thread_cap();
    let per = min_per_thread.max(1);
    let workers = if cap > 1 && n >= per.saturating_mul(2) {
        cap.min(n / per)
    } else {
        1
    };

    if workers <= 1 {
        // Fully safe baseline: sequential on the current thread; panics and
        // `Err`s propagate exactly as they did before parallelization.
        for (i, piece) in pieces.into_iter().enumerate() {
            f(i, spans[i].0, piece.unwrap())?;
        }
        return Ok(());
    }

    // Hand each span piece to exactly one worker through a shared iterator:
    // the `&mut [u8]` is moved, never aliased.
    let iter = Mutex::new(pieces.into_iter().enumerate());
    let stop = AtomicBool::new(false);
    let first_err: Mutex<Option<E>> = Mutex::new(None);
    let first_panic: Mutex<Option<Box<dyn std::any::Any + Send>>> = Mutex::new(None);
    let panic_capture = super::current_panic_capture();

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let iter = &iter;
            let stop = &stop;
            let first_err = &first_err;
            let first_panic = &first_panic;
            let f = &f;
            let panic_capture = panic_capture.clone();
            scope.spawn(move || {
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let next = iter.lock().unwrap().next();
                    let Some((i, piece)) = next else { break };
                    let span = piece.unwrap();
                    // Keep details local until this panic wins `first_panic`;
                    // otherwise simultaneous workers could pair one worker's
                    // location with another worker's propagated payload.
                    let block_capture = panic_capture.as_ref().map(|_| super::PanicCapture::new());
                    let r = super::with_panic_capture(block_capture.clone(), || {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            f(i, spans[i].0, span)
                        }))
                    });
                    match r {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            let mut slot = first_err.lock().unwrap();
                            if slot.is_none() {
                                *slot = Some(e);
                            }
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                        Err(panic) => {
                            let mut slot = first_panic.lock().unwrap();
                            if slot.is_none() {
                                if let (Some(parent), Some(block)) =
                                    (&panic_capture, &block_capture)
                                {
                                    parent.merge_from(block);
                                }
                                *slot = Some(panic);
                            }
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            });
        }
    });

    if let Some(panic) = first_panic.into_inner().unwrap() {
        std::panic::resume_unwind(panic);
    }
    match first_err.into_inner().unwrap() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// True if the half-open spans are mutually disjoint. Spans are
/// `[write_base, write_base + max(compressed_len, decompressed_len))` so a block
/// whose decompressed output exceeds its compressed size is fully covered. A
/// conservative (larger) span can only push a borderline case onto the safe
/// sequential path, never the reverse, so it cannot change output.
pub(crate) fn spans_disjoint(spans: &mut [(u64, u64)]) -> bool {
    spans.sort_unstable();
    for w in spans.windows(2) {
        if w[1].0 < w[0].1 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review regression: an empty span sharing a start with a non-empty one
    /// passes `spans_disjoint` (it genuinely overlaps nothing), so the carve
    /// runs. Ordering the carve by start alone put `(100,100)` after
    /// `(100,200)` — `s - base` then underflowed and panicked instead of doing
    /// the work. Reachable from a corrupt descriptor chain whose block size is
    /// negative and whose expected length is zero.
    #[test]
    fn carves_empty_span_sharing_a_start() {
        let mut buf = vec![0u8; 512];
        // Non-empty span first in input order, empty span second: the order
        // that used to underflow.
        let spans = [(100usize, 200usize), (100, 100)];
        let seen: Mutex<Vec<(usize, usize, usize)>> = Mutex::new(Vec::new());
        let r: Result<(), ()> = parallel_for(&mut buf, &spans, 1, |i, base, span| {
            seen.lock().unwrap().push((i, base, span.len()));
            for b in span.iter_mut() {
                *b = 0xAB;
            }
            Ok(())
        });
        assert!(r.is_ok());
        let mut seen = seen.into_inner().unwrap();
        seen.sort_unstable();
        assert_eq!(seen, vec![(0, 100, 100), (1, 100, 0)]);
        assert!(buf[100..200].iter().all(|&b| b == 0xAB));
        assert!(buf[..100].iter().all(|&b| b == 0));
        assert!(buf[200..].iter().all(|&b| b == 0));
    }
}
