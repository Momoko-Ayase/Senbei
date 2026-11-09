//! Report values, engine messages, and research notes as the window shows them.
//!
//! Report enums are looked up by their wire spelling (`layout.exe_style`), as
//! the approved mockup did, so a value without a label still reads as text.
//! Engine messages keep their own translations except the three the window
//! words differently; research notes the engine writes in English are matched
//! to translated notes where one exists.

use std::borrow::Cow;

use senbei_i18n::{Message, Msg, Step};
use serde::Serialize;

use crate::text::{Text, lang, t};

/// The wire spelling of a report enum value, such as `not_attempted`.
pub fn wire(value: &impl Serialize) -> Option<String> {
    match serde_json::to_value(value).ok()? {
        serde_json::Value::String(text) => Some(text),
        _ => None,
    }
}

/// The label of a report value: the catalog entry `prefix.value`, or the
/// value itself with spaces when the catalog has none.
pub fn tv(prefix: &str, value: &impl Serialize) -> Cow<'static, str> {
    match wire(value) {
        Some(value) => tv_str(prefix, &value),
        None => "—".into(),
    }
}

/// [`tv`] for a value that is already a wire string.
pub fn tv_str(prefix: &str, value: &str) -> Cow<'static, str> {
    match Text::by_key(&format!("{prefix}.{value}")) {
        Some(text) => t(text),
        None => value.replace('_', " ").into(),
    }
}

/// An engine message ready to show: the text in the display language, the
/// recorded English when the text leaves part of it out, and whether the
/// window hides it because it says nothing about the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub text: String,
    pub technical: Option<String>,
    pub quiet: bool,
}

/// How the window shows `message`.
/// Why a view has no bytes, in the display language.
pub fn load_error(error: &crate::backend::LoadError) -> String {
    match error {
        crate::backend::LoadError::Message(shown) => message(shown).text,
        crate::backend::LoadError::TooLarge { size, limit } => t(Text::HexTooLarge {
            size: crate::format::bytes(*size),
            limit: crate::format::bytes(*limit),
        })
        .into_owned(),
    }
}

pub fn message(message: &Message) -> Shown {
    let quiet = matches!(
        message.msg(),
        Some(Msg::OutputNotRetained | Msg::DryRunDiscarded | Msg::CompanionUnmatched)
    );
    let shown = |text: String, technical: Option<String>| Shown {
        text,
        technical,
        quiet,
    };
    match message.msg() {
        // The three messages the window words for itself.
        Some(Msg::CompanionMissing) => shown(t(Text::MsgCompanionMissing).into_owned(), None),
        Some(Msg::InternalPanic {
            file, line, column, ..
        }) => shown(
            t(Text::MsgInternalPanic {
                loc: format!("{file}:{line}:{column}"),
            })
            .into_owned(),
            Some(message.text().to_owned()),
        ),
        Some(Msg::LimitEntry { requested, limit }) => match limited_entry(message.text()) {
            Some(entry) => shown(
                t(Text::MsgLimitEntry {
                    entry: entry.to_owned(),
                    size: requested.to_string(),
                    limit: limit.to_string(),
                })
                .into_owned(),
                Some(message.text().to_owned()),
            ),
            None => engine(message, quiet),
        },
        Some(_) => engine(message, quiet),
        None => note(message.text()),
    }
}

/// An engine message in its own translation, with the English it leaves out.
fn engine(message: &Message, quiet: bool) -> Shown {
    let lang = lang();
    Shown {
        text: message.localized(lang).into_owned(),
        technical: message.detail(lang).map(str::to_owned),
        quiet,
    }
}

/// The entry an `extract `…`` context names, as a limit error records it.
fn limited_entry(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("extract `")?;
    Some(&rest[..rest.find('`')?])
}

/// How the window shows a research note the engine wrote in English.
pub fn note(text: &str) -> Shown {
    let (translated, quiet) = match_note(text);
    Shown {
        text: translated
            .map(|text| t(text).into_owned())
            .unwrap_or_else(|| text.to_owned()),
        technical: None,
        quiet,
    }
}

/// True when the window hides this note.
pub fn is_quiet(text: &str) -> bool {
    match_note(text).1
}

fn match_note(text: &str) -> (Option<Text>, bool) {
    let exact = match text {
        "research inspection: no output file was retained" => Some((None, true)),
        "dry run: the produced output was discarded" => Some((None, true)),
        "a sibling `._` exists but is not this stub's payload" => Some((None, true)),
        "prefix decoded in scratch; later stages still require a full recovery" => {
            Some((Some(Text::NotePrefixScratch), true))
        }
        "anchor and stage1 descriptor validate; full stage decryption requires recovery" => {
            Some((Some(Text::NoteAnchorValidates), true))
        }
        "bounded anchor probe only" => Some((Some(Text::NoteBoundedAnchor), true)),
        "bounded prefix only; not a recovered image" => Some((Some(Text::NoteBoundedPrefix), true)),
        "candidates reported without stage validation" => {
            Some((Some(Text::NoteCandidatesUnvalidated), true))
        }
        "shell table shape matches the declared image; second-stage decryption requires recovery" => {
            Some((Some(Text::NoteShellTableMatches), true))
        }
        "certificate directory uses a file offset, not an RVA" => {
            Some((Some(Text::NoteCertFileOffset), false))
        }
        "no import table" => Some((Some(Text::NoteNoImportTable), false)),
        "header magic is not a supported protection header" => {
            Some((Some(Text::NoteMagicNotSupported), false))
        }
        "no anchor field in the decoded payload window" => {
            Some((Some(Text::NoteNoAnchorField), false))
        }
        "no shell table shape in the decoded payload window" => {
            Some((Some(Text::NoteNoShellTable), false))
        }
        "shell discovery needs a decoded payload prefix" => {
            Some((Some(Text::NoteShellNeedsPrefix), false))
        }
        _ => None,
    };
    if let Some(found) = exact {
        return found;
    }
    (shaped_note(text), false)
}

/// Notes that carry values.
fn shaped_note(text: &str) -> Option<Text> {
    if let Some(rva) = text
        .strip_prefix("entry point ")
        .and_then(|rest| rest.strip_suffix(" lies in this section"))
    {
        return Some(Text::NoteEntryPointInside {
            rva: rva.to_owned(),
        });
    }
    if let Some((end, len)) = text
        .strip_prefix("raw range ends at ")
        .and_then(|rest| rest.split_once(", input is "))
        && let Some(len) = len.strip_suffix(" bytes")
    {
        return Some(Text::NoteRawPastEof {
            end: end.to_owned(),
            len: len.to_owned(),
        });
    }
    if let Some(value) = text
        .strip_prefix("header table decoded but info[1] is ")
        .and_then(|rest| rest.strip_suffix(", not the supported magic"))
    {
        return Some(Text::NoteMagicUnsupportedValue {
            value: value.to_owned(),
        });
    }
    let block = text.strip_prefix("relocation block ")?;
    if let Some((block, rest)) = block.split_once(" entry ")
        && let Some((entry, ty)) = rest.split_once(" has unsupported type ")
    {
        return Some(Text::NoteRelocUnsupportedType {
            block: block.to_owned(),
            entry: entry.to_owned(),
            ty: ty.to_owned(),
        });
    }
    if let Some((block, rest)) = block.split_once(" declares size ")
        && let Some(size) = rest.strip_suffix(", which does not fit the directory")
    {
        return Some(Text::NoteRelocBadSize {
            block: block.to_owned(),
            size: size.to_owned(),
        });
    }
    None
}

/// The window's title for a recovery step.
pub fn step_title(step: &Step) -> Cow<'static, str> {
    let text = match step {
        Step::DecryptHeader => Text::StepDecryptHeader,
        Step::DecryptPayload => Text::StepDecryptPayload,
        Step::LocateConfig | Step::Pe32LocateConfig => Text::StepLocateConfig,
        Step::DecryptStage2 => Text::StepDecryptStage2,
        Step::DecryptStages3To5 => Text::StepDecryptStages35,
        Step::DecryptSections | Step::DecryptSectionsNewLayout => Text::StepDecryptSections,
        Step::LoadSections => Text::StepLoadSections,
        Step::DecryptImports | Step::Pe32Imports => Text::StepDecryptImports,
        Step::RebuildHeaders => Text::StepRebuildHeaders,
        Step::Pe32Stages => Text::StepPe32Stages,
        Step::Pe32EighthStage => Text::StepPe32Eighth,
        Step::Pe32Load => Text::StepPe32Load,
        Step::Pe32Text { .. } => Text::StepPe32Text,
        Step::Pe32TextSkip => Text::StepPe32TextSkip,
        Step::Pe32Rebuild => Text::StepPe32Rebuild,
        Step::InitKeys => Text::StepInitKeys,
        Step::DecryptKeyTable => Text::StepDecryptKeyTable,
        Step::DecryptPrimary => Text::StepDecryptPrimary,
        Step::RelocsParams => Text::StepRelocsParams,
        Step::DecryptBlock1 => Text::StepDecryptBlock1,
        Step::DecryptBlocks2To3 => Text::StepDecryptBlock23,
        Step::DecryptBlock4 => Text::StepDecryptBlock4,
        Step::DllSections => Text::StepDllSections,
        Step::FixHeaders => Text::StepFixHeaders,
        Step::AndroidPrimary => Text::StepAndroidPrimary,
        Step::AndroidAuxiliary => Text::StepAndroidAux,
        Step::AndroidTables => Text::StepAndroidTables,
        other => {
            use senbei_i18n::Localize;
            return other.localize(lang()).into_owned().into();
        }
    };
    t(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_values_use_their_wire_spelling() {
        assert_eq!(
            wire(&senbei_engine::LayoutKind::ExeStyle).as_deref(),
            Some("exe_style")
        );
        assert_eq!(
            tv("layout", &senbei_engine::LayoutKind::ExeStyle),
            "EXE-style loader"
        );
        assert_eq!(tv_str("layout", "brand_new"), "brand new");
    }

    #[test]
    fn research_notes_are_matched_with_their_values() {
        let shown = note("entry point 0x1B5C lies in this section");
        assert_eq!(shown.text, "entry point 0x1B5C lies in this section");
        assert!(!shown.quiet);
        assert_eq!(
            shaped_note("raw range ends at 0x2000, input is 0x1000 bytes"),
            Some(Text::NoteRawPastEof {
                end: "0x2000".into(),
                len: "0x1000".into()
            })
        );
        assert_eq!(
            shaped_note("relocation block 3 entry 7 has unsupported type 9"),
            Some(Text::NoteRelocUnsupportedType {
                block: "3".into(),
                entry: "7".into(),
                ty: "9".into()
            })
        );
        assert!(is_quiet("bounded anchor probe only"));
        assert!(!is_quiet("something new"));
        assert_eq!(note("something new").text, "something new");
    }

    #[test]
    fn the_window_words_three_messages_itself() {
        let missing = message(&Message::new(Msg::CompanionMissing));
        assert!(!missing.text.contains("browser"), "{}", missing.text);
        let limit = Message::with_text(
            Msg::LimitEntry {
                requested: 9000,
                limit: 4096,
            },
            "extract `lib/arm64-v8a/libx.so`: resource limit: entry of 9000 bytes exceeds the 4096-byte ceiling",
        );
        let shown = message(&limit);
        assert!(
            shown
                .text
                .starts_with("lib/arm64-v8a/libx.so is 9000 bytes"),
            "{}",
            shown.text
        );
        assert!(shown.technical.is_some());
        assert!(message(&Message::new(Msg::OutputNotRetained)).quiet);
    }
}
