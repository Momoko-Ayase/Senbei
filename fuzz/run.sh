#!/bin/sh
# cargo-fuzz runner with explicit per-target input ceilings.
#
# The project pins stable Rust in rust-toolchain.toml, while cargo-fuzz and
# libFuzzer require nightly. The toolchain is therefore selected explicitly on
# every invocation (`cargo +nightly fuzz ...`) so installing nightly does not
# change the repository's active toolchain and is not confused with it.
#
#   rustup toolchain install nightly
#   ./fuzz/run.sh                      # 60 seconds per target
#   ./fuzz/run.sh pe_detect 300        # one target, 300 seconds
#
# libFuzzer execution was not verified in the development environment used for
# this harness (`cargo fuzz` was not installed); only the crate build and the
# deterministic `smoke` binary were exercised. `--runs`/`-max_total_time` are
# passed through unchanged so a caller can choose bounded smoke runs.
set -eu

# Run from the repository root so the script works when invoked by absolute or
# relative path from any working directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(dirname -- "$script_dir")
cd "$repo_root"

target=${1:-all}
seconds=${2:-60}

# Ceilings keep one iteration cheap and prevent crafted headers from asking for
# a large allocation. They are intentionally generous for real inputs.
common="-max_len=2097152 -timeout=10 -rss_limit_mb=4096 -runs=1000000"

run() {
    name=$1
    shift
    echo "== $name"
    cargo +nightly fuzz run "$name" -- $common "$@"
}

case "$target" in
    all)
        run pe_detect -max_total_time="$seconds"
        run pe_integrity -max_total_time="$seconds"
        run pe_parse -max_total_time="$seconds"
        run elf_layout -max_total_time="$seconds"
        run metadata_parse -max_total_time="$seconds"
        run metadata_restore -max_total_time="$seconds"
        ;;
    pe_detect | pe_integrity | pe_parse | elf_layout | metadata_parse | metadata_restore)
        run "$target" -max_total_time="$seconds"
        ;;
    *)
        echo "unknown target: $target" >&2
        exit 2
        ;;
esac
