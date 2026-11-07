//! User-facing text for Senbei.
//!
//! Every piece of text a person reads is a variant of [`Msg`] (engine and
//! driver messages), [`Step`] (verbose pipeline progress), [`Term`] (report
//! values such as statuses and kinds), or [`Cli`] (command-line wording).
//! Each language module renders every variant, so the compiler rejects a
//! missing translation, a placeholder that is not an argument, and (through
//! `deny(unused_variables)`) an argument a translation leaves out.
//!
//! English is the wording the engine has always produced. Reports, logs, and
//! `--json` output stay English; only console and GUI text is localized.
#![deny(unused_variables)]
#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::sync::atomic::{AtomicU8, Ordering};

mod catalog;
mod en;
mod ja;
mod ko;
mod message;
mod zh_cn;
mod zh_tw;

pub use catalog::{Cli, Msg, Step, Term};
pub use message::Message;

/// A language Senbei can display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Lang {
    #[default]
    En,
    ZhCn,
    ZhTw,
    Ja,
    Ko,
}

impl Lang {
    /// Every supported language, English first.
    pub const ALL: [Lang; 5] = [Lang::En, Lang::ZhCn, Lang::ZhTw, Lang::Ja, Lang::Ko];

    /// The BCP 47 tag, as accepted by `SENBEI_LANG`.
    pub const fn tag(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::ZhCn => "zh-CN",
            Lang::ZhTw => "zh-TW",
            Lang::Ja => "ja",
            Lang::Ko => "ko",
        }
    }

    /// The language's own name, for a language picker.
    pub const fn native_name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::ZhCn => "简体中文",
            Lang::ZhTw => "繁體中文",
            Lang::Ja => "日本語",
            Lang::Ko => "한국어",
        }
    }

    /// Parse a BCP 47 tag (`zh-Hant-HK`), a POSIX locale (`ja_JP.UTF-8`),
    /// or a Windows locale name (`ko-KR`).
    ///
    /// Chinese follows the script when one is given, then the region:
    /// Taiwan, Hong Kong, and Macau read Traditional Chinese; every other
    /// Chinese locale reads Simplified. `C`, `POSIX`, and unknown languages
    /// return `None` so the caller can fall back.
    pub fn from_tag(tag: &str) -> Option<Lang> {
        let tag = tag.split(['.', '@']).next().unwrap_or_default();
        let lower = tag.trim().to_ascii_lowercase().replace('_', "-");
        let mut parts = lower.split('-').filter(|part| !part.is_empty());
        match parts.next()? {
            "en" => Some(Lang::En),
            "ja" => Some(Lang::Ja),
            "ko" => Some(Lang::Ko),
            "zh" => {
                let rest: Vec<&str> = parts.collect();
                if rest.contains(&"hant") {
                    Some(Lang::ZhTw)
                } else if rest.contains(&"hans") {
                    Some(Lang::ZhCn)
                } else if rest.iter().any(|part| matches!(*part, "tw" | "hk" | "mo")) {
                    Some(Lang::ZhTw)
                } else {
                    Some(Lang::ZhCn)
                }
            }
            _ => None,
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

/// The language console text uses in this process. English until a front
/// end calls [`set_current`].
pub fn current() -> Lang {
    match CURRENT.load(Ordering::Relaxed) {
        1 => Lang::ZhCn,
        2 => Lang::ZhTw,
        3 => Lang::Ja,
        4 => Lang::Ko,
        _ => Lang::En,
    }
}

/// Choose the language for console text in this process.
pub fn set_current(lang: Lang) {
    let index = match lang {
        Lang::En => 0,
        Lang::ZhCn => 1,
        Lang::ZhTw => 2,
        Lang::Ja => 3,
        Lang::Ko => 4,
    };
    CURRENT.store(index, Ordering::Relaxed);
}

/// Text that can be shown in any supported language.
pub trait Localize {
    fn localize(&self, lang: Lang) -> Cow<'static, str>;
}

macro_rules! dispatch {
    ($ty:ty, $func:ident) => {
        impl Localize for $ty {
            fn localize(&self, lang: Lang) -> Cow<'static, str> {
                match lang {
                    Lang::En => en::$func(self),
                    Lang::ZhCn => zh_cn::$func(self),
                    Lang::ZhTw => zh_tw::$func(self),
                    Lang::Ja => ja::$func(self),
                    Lang::Ko => ko::$func(self),
                }
            }
        }
    };
}

dispatch!(Msg, msg);
dispatch!(Step, step);
dispatch!(Term, term);
dispatch!(Cli, cli);

#[cfg(test)]
mod tests;
