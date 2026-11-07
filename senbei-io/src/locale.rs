//! The display language for console output.
//!
//! Only console text follows it. Logs and `--json` reports are English in every
//! language, so their contents never depend on the machine they ran on.

use senbei_i18n::Lang;

/// Environment variable that overrides the system display language.
pub const LANG_VAR: &str = "SENBEI_LANG";

/// The display language: `SENBEI_LANG` when it is set, otherwise the system's
/// preferred UI language, otherwise English.
///
/// A `SENBEI_LANG` value that names no supported language selects English, so
/// `SENBEI_LANG=C` behaves as it does for other tools.
pub fn detect() -> Lang {
    match std::env::var(LANG_VAR) {
        Ok(value) if !value.trim().is_empty() => Lang::from_tag(&value).unwrap_or_default(),
        _ => system().unwrap_or_default(),
    }
}

/// The first supported language among the user's preferred UI languages.
#[cfg(windows)]
fn system() -> Option<Lang> {
    use windows::Win32::Globalization::{GetUserPreferredUILanguages, MUI_LANGUAGE_NAME};
    use windows::core::PWSTR;

    let mut count = 0u32;
    let mut len = 0u32;
    // SAFETY: the first call only reports the buffer length; the second writes
    // at most `len` UTF-16 units into a buffer of exactly that length.
    unsafe { GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &mut count, None, &mut len) }.ok()?;
    let mut buffer = vec![0u16; len as usize];
    unsafe {
        GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME,
            &mut count,
            Some(PWSTR(buffer.as_mut_ptr())),
            &mut len,
        )
    }
    .ok()?;
    first_supported(String::from_utf16_lossy(&buffer).split('\0'))
}

/// The language of the POSIX message locale. `LANGUAGE` is a GNU priority
/// list that applies unless the locale is `C` or `POSIX`.
#[cfg(all(not(windows), not(target_arch = "wasm32")))]
fn system() -> Option<Lang> {
    let var = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let locale = var("LC_ALL")
        .or_else(|| var("LC_MESSAGES"))
        .or_else(|| var("LANG"))?;
    let base = locale.split(['.', '@']).next().unwrap_or_default();
    if base == "C" || base == "POSIX" {
        return Some(Lang::En);
    }
    var("LANGUAGE")
        .and_then(|list| first_supported(list.split(':')))
        .or_else(|| Lang::from_tag(&locale))
}

#[cfg(target_arch = "wasm32")]
fn system() -> Option<Lang> {
    None
}

#[cfg(any(test, not(target_arch = "wasm32")))]
fn first_supported<'a>(tags: impl IntoIterator<Item = &'a str>) -> Option<Lang> {
    tags.into_iter()
        .filter(|tag| !tag.is_empty())
        .find_map(Lang::from_tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_supported_preference_wins() {
        assert_eq!(
            first_supported(["fr-FR", "zh-TW", "en-US", ""]),
            Some(Lang::ZhTw)
        );
        assert_eq!(first_supported(["fr-FR", "de-DE"]), None);
        assert_eq!(first_supported([]), None);
    }
}
