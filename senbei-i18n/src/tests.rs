use crate::{Cli, Lang, Localize, Message, Msg, Step, Term};

#[test]
fn tags_resolve_by_language_script_and_region() {
    for (tag, lang) in [
        ("en", Lang::En),
        ("en_US.UTF-8", Lang::En),
        ("ja_JP.UTF-8", Lang::Ja),
        ("ko-KR", Lang::Ko),
        ("zh", Lang::ZhCn),
        ("zh-CN", Lang::ZhCn),
        ("zh_SG", Lang::ZhCn),
        ("zh-Hans-HK", Lang::ZhCn),
        ("zh-TW", Lang::ZhTw),
        ("zh_HK.Big5", Lang::ZhTw),
        ("zh-MO", Lang::ZhTw),
        ("zh-Hant", Lang::ZhTw),
        ("zh-Hant-CN", Lang::ZhTw),
        ("ZH-tw", Lang::ZhTw),
    ] {
        assert_eq!(Lang::from_tag(tag), Some(lang), "{tag}");
    }
    for tag in ["", "C", "POSIX", "fr_FR.UTF-8", "-", "C.UTF-8"] {
        assert_eq!(Lang::from_tag(tag), None, "{tag}");
    }
}

#[test]
fn every_language_round_trips_through_its_own_tag() {
    for lang in Lang::ALL {
        assert_eq!(Lang::from_tag(lang.tag()), Some(lang));
    }
}

#[test]
fn current_language_can_change() {
    for lang in Lang::ALL {
        crate::set_current(lang);
        assert_eq!(crate::current(), lang);
    }
    crate::set_current(Lang::En);
}

#[test]
fn messages_keep_recorded_english_and_serialize_it() {
    let coded = Message::new(Msg::NotProtected);
    assert_eq!(coded.text(), "not a CrackProof-protected file");
    assert_eq!(coded, "not a CrackProof-protected file");
    assert_eq!(
        serde_json::to_string(&coded).unwrap(),
        "\"not a CrackProof-protected file\""
    );
    assert_eq!(coded.detail(Lang::ZhCn), None);

    let chained = Message::with_text(
        Msg::LimitEntry {
            requested: 10,
            limit: 4,
        },
        "extract `a.so`: resource limit: entry of 10 bytes exceeds the 4-byte ceiling",
    );
    assert_eq!(chained.localized(Lang::En), chained.text());
    assert_eq!(chained.detail(Lang::En), None);
    assert_eq!(chained.detail(Lang::Ja), Some(chained.text()));

    let raw = Message::raw("os error 5");
    for lang in Lang::ALL {
        assert_eq!(raw.localized(lang), "os error 5");
        assert_eq!(raw.detail(lang), None);
    }
    let joined = [coded, raw].join("; ");
    assert_eq!(joined, "not a CrackProof-protected file; os error 5");
}

#[test]
fn terms_map_every_wire_value_back_to_its_english() {
    let values = [
        "ok",
        "suspect",
        "recognized",
        "not_recognized",
        "skipped",
        "error",
        "restored",
        "duplicate",
        "not_target",
        "unchanged",
        "inventoried",
        "failed",
        "blocked",
        "not_attempted",
        "succeeded",
        "rejected",
        "clean",
        "warnings",
        "not_run",
        "absent",
        "spliced",
        "unmatched",
        "unreadable",
        "detection",
        "manifest_inventory",
        "entry_probe",
        "recovery",
        "static_validation",
        "output_write",
        "shared_library",
        "metadata",
        "exe_style",
        "dll",
        "android_staged",
        "metadata_seeded",
        "metadata_structural",
        "metadata_method_indices",
        "windows_pe",
        "android_elf",
        "il2cpp_metadata",
        "native_exe",
        "managed_exe",
        "native_dll",
        "managed_dll",
        "header_magic",
        "external_companion_declaration",
        "companion_spliced",
        "private_section",
        "aes_schedule",
        "validated_metadata_transform",
        "known",
        "context_required",
        "unverified",
        "original",
        "spliced_companion",
    ];
    for value in values {
        let term = Term::from_value(value).unwrap_or_else(|| panic!("{value}"));
        assert_eq!(term.localize(Lang::En), value.replace('_', " "));
    }
    assert_eq!(Term::from_value("no_such_value"), None);
}

/// The values a rendering carries: numbers, hex values, and marked arguments.
fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .filter(|word| word.chars().any(|c| c.is_ascii_digit()) || word.starts_with("ARG"))
        .map(str::to_owned)
        .collect()
}

/// Every value of the English rendering survives in the translation, as
/// often as English shows it. A translation may add digits of its own, such
/// as a 0 for "zeros".
fn assert_keeps_values(translated: &str, english: &str, context: &str) {
    let mut left = tokens(translated);
    for token in tokens(english) {
        match left.iter().position(|have| *have == token) {
            Some(index) => {
                left.swap_remove(index);
            }
            None => panic!("{context}: `{token}` is missing from {translated:?}"),
        }
    }
}

fn sample_msgs() -> Vec<Msg> {
    vec![
        Msg::InputTooShort {
            actual: 1201,
            required: 4128,
        },
        Msg::InvalidPeOffset {
            offset: -7,
            input_len: 4097,
        },
        Msg::DllNeedsPe32Plus { found: 0x10B },
        Msg::InternalPanic {
            file: "ARGfile".into(),
            line: 1363,
            column: 59,
            message: "ARGmessage".into(),
        },
        Msg::UnsupportedMetadataVersion { version: 27 },
        Msg::LimitEntry {
            requested: 260043504,
            limit: 67108864,
        },
        Msg::LimitTotal {
            requested: 900,
            adding: 300,
            limit: 800,
        },
        Msg::LimitEntries {
            requested: 100001,
            limit: 100000,
        },
        Msg::LimitDepth {
            requested: 33,
            limit: 32,
        },
        Msg::CompanionUnreadable {
            reason: "ARGreason".into(),
        },
        Msg::MetadataLeftUntouched { version: 27 },
        Msg::UnexpectedPanic {
            message: "ARGpanic".into(),
        },
        Msg::UnsafePackageEntry {
            package: "ARGpackage".into(),
        },
        Msg::UnsafeNestedEntry {
            path: "ARGpath".into(),
        },
        Msg::EntryStubTargetOutsideCode {
            branch: "ARGbranch",
            target: 0x1234,
        },
        Msg::MissingPeSignature { offset: 0x80 },
        Msg::BadOptionalMagic { magic: 0x20C },
        Msg::ImplausibleSectionCount { count: 97 },
        Msg::SectionRawPastEof {
            index: 3,
            start: 0x400,
            end: 0x9000,
            file_len: 0x8000,
        },
        Msg::EntryUnmapped { rva: 0x1B5C },
        Msg::EntryAllZeros { rva: 0x1B5D },
        Msg::EntryAllInt3 { rva: 0x1B5E },
        Msg::EntryNotExecutable { rva: 0x1B5F },
        Msg::ImportDirectoryUnmapped { rva: 0x2000 },
        Msg::ImportNameUnmapped {
            index: 4,
            rva: 0x2100,
        },
        Msg::ImportNameUnreadable {
            index: 5,
            rva: 0x2200,
        },
        Msg::ClrDirectoryUnmapped { rva: 0x3000 },
        Msg::ClrHeaderBadSize {
            rva: 0x3100,
            size: 0x40,
        },
        Msg::ClrMetadataUnmapped { rva: 0x3200 },
        Msg::ClrMetadataNoBsjb { rva: 0x3300 },
    ]
}

#[test]
fn translations_keep_every_argument() {
    for lang in Lang::ALL {
        for msg in sample_msgs() {
            assert_keeps_values(
                &msg.localize(lang),
                &msg.localize(Lang::En),
                &format!("{lang:?} {msg:?}"),
            );
        }
        let step = Step::Pe32Text {
            formula: "ARGformula",
        };
        assert!(step.localize(lang).contains("ARGformula"), "{lang:?}");
        let step = Step::WriteTo {
            dest: "ARGdest".into(),
        };
        assert!(step.localize(lang).contains("ARGdest"), "{lang:?}");
        let summary = Cli::Summary {
            unpacked: "ARGa".into(),
            skipped: "ARGb".into(),
            errors: "ARGc".into(),
            suspect: "ARGd".into(),
            metadata: "ARGe".into(),
        };
        assert_keeps_values(
            &summary.localize(lang),
            &summary.localize(Lang::En),
            &format!("{lang:?} summary"),
        );
        let limits = Cli::HelpLimits {
            entry_mib: 2048,
            total_mib: 8192,
            entries: 100000,
            depth: 32,
        };
        for value in ["2048", "8192", "100000", "32"] {
            assert!(limits.localize(lang).contains(value), "{lang:?} {value}");
        }
    }
}
