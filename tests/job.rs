use senbei::job::{default_out_root_for_file, out_name};
use std::path::Path;

#[test]
fn out_name_inserts_unpack_before_last_dot() {
    assert_eq!(out_name(Path::new("foo.exe")), Path::new("foo.unpack.exe"));
    assert_eq!(
        out_name(Path::new("a/b/bar.dll")),
        Path::new("a/b/bar.unpack.dll")
    );
    assert_eq!(out_name(Path::new("x.y.dll")), Path::new("x.y.unpack.dll"));
}

#[test]
fn out_name_no_dot_appends_unpack() {
    assert_eq!(out_name(Path::new("nodot")), Path::new("nodot.unpack"));
}

#[test]
fn default_out_root_for_file_is_parent_unpack() {
    assert_eq!(
        default_out_root_for_file(Path::new("a/b/foo.exe")),
        Path::new("a/b/unpack")
    );
}

#[test]
fn default_out_root_for_file_cwd_when_no_parent() {
    let p = default_out_root_for_file(Path::new("foo.exe"));
    assert_eq!(p, Path::new(".").join("unpack"));
}
