//! Translatable messages for errors that reach the I/O layer.
//!
//! Reports and `--json` keep an error's English as `{error:#}` prints its
//! chain, less any link that only repeats the one before it. A front end
//! showing another language translates the first cause in the chain that has a
//! message code, and keeps the English as detail.

use std::fmt;

use senbei_i18n::{Message, Msg};

/// An error raised by the I/O layer itself, carrying its message code.
#[derive(Debug)]
pub(crate) struct Coded(Message);

impl Coded {
    pub(crate) fn new(msg: Msg) -> Self {
        Self(Message::new(msg))
    }

    /// A panic caught while `context` ran (for example " during de-obfuscation",
    /// or "" when nothing more specific is known).
    pub(crate) fn panic(context: &str, payload: String) -> Self {
        let text = format!("unexpected panic{context}: {payload}");
        Self(Message::with_text(
            Msg::UnexpectedPanic { message: payload },
            text,
        ))
    }

    /// A message whose English differs from the catalog wording for `msg`.
    pub(crate) fn with_text(msg: Msg, text: String) -> Self {
        Self(Message::with_text(msg, text))
    }
}

impl fmt::Display for Coded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.text())
    }
}

impl std::error::Error for Coded {}

/// The message for `error`: its English chain, translated through the first
/// cause that has a message code.
pub fn of_error(error: &anyhow::Error) -> Message {
    let text = chain_text(error);
    match error.chain().find_map(code) {
        Some(msg) => Message::with_text(msg, text),
        None => Message::raw(text),
    }
}

/// `{error:#}`, without a link that only repeats the one before it: a wrapper
/// that shows its inner error's message and also returns that error as its
/// source would otherwise print the message twice.
fn chain_text(error: &anyhow::Error) -> String {
    let mut links: Vec<String> = Vec::new();
    for cause in error.chain() {
        let text = cause.to_string();
        if links.last() != Some(&text) {
            links.push(text);
        }
    }
    links.join(": ")
}

fn code(cause: &(dyn std::error::Error + 'static)) -> Option<Msg> {
    use senbei_engine::android::{ExtractionError, LimitExceeded, RestoreError};
    use senbei_metadata::android::{Error as TokenError, MethodIndexError};

    if let Some(coded) = cause.downcast_ref::<Coded>() {
        return coded.0.msg().cloned();
    }
    if let Some(error) = cause.downcast_ref::<senbei_engine::windows::UnpackError>() {
        return error.message().msg().cloned();
    }
    let limit = cause.downcast_ref::<LimitExceeded>().or_else(|| {
        match cause.downcast_ref::<ExtractionError>() {
            Some(ExtractionError::Limit(limit)) => Some(limit),
            _ => match cause.downcast_ref::<RestoreError>() {
                Some(RestoreError::Limit(limit)) => Some(limit),
                _ => None,
            },
        }
    });
    if let Some(limit) = limit {
        return limit.message().msg().cloned();
    }
    if let Some(error) = cause.downcast_ref::<senbei_pe::Error>() {
        return match error {
            senbei_pe::Error::Invalid => Some(Msg::NotPe),
            senbei_pe::Error::OutOfBounds => None,
        };
    }
    if let Some(error) = cause.downcast_ref::<senbei_elf::Error>() {
        return match error {
            senbei_elf::Error::NotElf64 => Some(Msg::NotElf64),
            senbei_elf::Error::NotAarch64 => Some(Msg::NotAarch64),
            _ => None,
        };
    }
    if let Some(error) = cause.downcast_ref::<senbei_metadata::Error>() {
        return Some(match error {
            senbei_metadata::Error::NotMetadata => Msg::NotMetadata,
            senbei_metadata::Error::UnsupportedVersion(version) => {
                Msg::UnsupportedMetadataVersion { version: *version }
            }
            senbei_metadata::Error::Malformed => Msg::MetadataTransformFailed,
        });
    }
    if let Some(error) = cause.downcast_ref::<TokenError>() {
        return Some(match error {
            TokenError::NotMetadata => Msg::NotIl2cppMetadata,
            TokenError::UnsupportedVersion(version) => {
                Msg::UnsupportedMetadataVersion { version: *version }
            }
            TokenError::Malformed(_) | TokenError::Validation(_) => Msg::MetadataTransformFailed,
        });
    }
    if let Some(error) = cause.downcast_ref::<MethodIndexError>() {
        return Some(match error {
            MethodIndexError::NotMetadata => Msg::NotIl2cppMetadata,
            MethodIndexError::UnsupportedVersion(version) => {
                Msg::UnsupportedMetadataVersion { version: *version }
            }
            _ => Msg::MetadataTransformFailed,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use senbei_i18n::Lang;

    #[test]
    fn the_english_is_the_whole_chain_and_the_code_its_first_known_cause() {
        let error = anyhow::Error::new(senbei_engine::android::LimitExceeded::Entry {
            requested: 10,
            limit: 4,
        })
        .context("extract `a.so`");
        let message = of_error(&error);
        assert_eq!(message.text(), format!("{error:#}"));
        assert_eq!(
            message.msg(),
            Some(&Msg::LimitEntry {
                requested: 10,
                limit: 4
            })
        );
        assert_eq!(message.detail(Lang::En), None);
        assert_eq!(message.detail(Lang::Ko), Some(message.text()));
    }

    #[test]
    fn unknown_chains_stay_raw_and_io_codes_survive_anyhow() {
        let raw = of_error(&anyhow::anyhow!("couldn't read companion x"));
        assert_eq!(raw.msg(), None);
        assert_eq!(raw.text(), "couldn't read companion x");

        let panic = anyhow::Error::new(Coded::panic(" during de-obfuscation", "boom".into()));
        let message = of_error(&panic);
        assert_eq!(
            message.text(),
            "unexpected panic during de-obfuscation: boom"
        );
        assert_eq!(
            message.msg(),
            Some(&Msg::UnexpectedPanic {
                message: "boom".into()
            })
        );

        let unpack = anyhow::Error::new(senbei_engine::windows::UnpackError::NotCrackProof);
        assert_eq!(of_error(&unpack).msg(), Some(&Msg::NotProtected));
        let metadata = anyhow::Error::new(senbei_metadata::Error::UnsupportedVersion(27))
            .context("\"global-metadata.dat\"");
        assert_eq!(
            of_error(&metadata).msg(),
            Some(&Msg::UnsupportedMetadataVersion { version: 27 })
        );
    }

    #[test]
    fn a_wrapper_that_repeats_its_source_is_printed_once() {
        // Shows its inner error's message and returns that error as its source.
        #[derive(Debug)]
        struct Wrapper(anyhow::Error);
        impl std::fmt::Display for Wrapper {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(formatter)
            }
        }
        impl std::error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(self.0.as_ref())
            }
        }
        let inner = anyhow::anyhow!("6 unresolved slots").context("restore library");
        let error = anyhow::Error::new(Wrapper(inner));
        assert_eq!(
            format!("{error:#}"),
            "restore library: restore library: 6 unresolved slots"
        );
        assert_eq!(
            of_error(&error).text(),
            "restore library: 6 unresolved slots"
        );
    }
}
