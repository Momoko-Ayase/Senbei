//! Every piece of text the desktop front end shows, in each display language.
//!
//! Engine messages come from `senbei-i18n`; this catalog covers the window
//! itself. English is the approved wording; a translation that names a
//! placeholder its English lacks does not compile.
#![deny(unused_variables)]

use std::borrow::Cow;

use senbei_i18n::{Lang, Localize};

mod catalog;
mod en;
mod ja;
mod ko;
mod zh_cn;
mod zh_tw;

pub use catalog::Text;

/// The display language of this window.
pub fn lang() -> Lang {
    senbei_i18n::current()
}

/// `text` in the display language.
pub fn t(text: Text) -> Cow<'static, str> {
    text.localize(lang())
}

/// Split text marked with `<strong>…</strong>` into plain and strong runs.
pub fn strong_runs(text: &str) -> Vec<(bool, &str)> {
    let mut runs = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<strong>") {
        if start > 0 {
            runs.push((false, &rest[..start]));
        }
        let after = &rest[start + "<strong>".len()..];
        let end = after.find("</strong>").unwrap_or(after.len());
        runs.push((true, &after[..end]));
        rest = after.get(end + "</strong>".len()..).unwrap_or("");
    }
    if !rest.is_empty() {
        runs.push((false, rest));
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_markup_splits_into_runs() {
        assert_eq!(
            strong_runs("a <strong>b</strong> c"),
            vec![(false, "a "), (true, "b"), (false, " c")]
        );
        assert_eq!(strong_runs("plain"), vec![(false, "plain")]);
        assert_eq!(strong_runs("<strong>x</strong>"), vec![(true, "x")]);
    }

    #[test]
    fn every_language_renders_every_text() {
        for lang in Lang::ALL {
            assert!(!Text::TbAddFiles.localize(lang).is_empty());
            let step = Text::RunStep {
                i: "5".into(),
                n: "9".into(),
                s: "x".into(),
            }
            .localize(lang);
            assert!(step.contains('5') && step.contains('9'), "{lang:?}: {step}");
        }
    }
}
