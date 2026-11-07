use std::borrow::{Borrow, Cow};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use crate::{Lang, Localize, Msg};

/// A message as recorded in a report, with the catalog entry it came from.
///
/// `text` is the English the engine produced, kept byte for byte: reports,
/// logs, and `--json` output write it unchanged. `msg`, when present, is the
/// same message as a catalog entry, so a front end can show it in another
/// language. A message without a catalog entry (a deep error chain, a value
/// that is not prose) is shown as recorded in every language.
///
/// Equality, hashing, ordering of the borrowed form, and serialization all
/// use `text` alone.
#[derive(Debug, Clone)]
pub struct Message {
    text: Cow<'static, str>,
    msg: Option<Msg>,
}

impl Message {
    /// A catalog entry recorded in its English wording.
    pub fn new(msg: Msg) -> Self {
        Self {
            text: msg.localize(Lang::En),
            msg: Some(msg),
        }
    }

    /// A catalog entry whose recorded English carries more than the entry,
    /// such as the context chain around an engine error.
    pub fn with_text(msg: Msg, text: impl Into<Cow<'static, str>>) -> Self {
        Self {
            text: text.into(),
            msg: Some(msg),
        }
    }

    /// Text with no catalog entry. It reads the same in every language.
    pub fn raw(text: impl Into<Cow<'static, str>>) -> Self {
        Self {
            text: text.into(),
            msg: None,
        }
    }

    /// The recorded English.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The catalog entry, when there is one.
    pub fn msg(&self) -> Option<&Msg> {
        self.msg.as_ref()
    }

    /// The message to show in `lang`.
    ///
    /// English is the recorded text, so English output never changes. Other
    /// languages use the catalog entry when there is one.
    pub fn localized(&self, lang: Lang) -> Cow<'_, str> {
        match &self.msg {
            Some(msg) if lang != Lang::En => msg.localize(lang),
            _ => Cow::Borrowed(self.text()),
        }
    }

    /// The recorded English, when the localized message in `lang` leaves
    /// part of it out (a context chain, an internal error's specifics).
    pub fn detail(&self, lang: Lang) -> Option<&str> {
        let msg = self.msg.as_ref()?;
        (lang != Lang::En && msg.localize(Lang::En) != self.text()).then(|| self.text())
    }
}

impl From<Msg> for Message {
    fn from(msg: Msg) -> Self {
        Self::new(msg)
    }
}

impl From<String> for Message {
    fn from(text: String) -> Self {
        Self::raw(text)
    }
}

impl From<&'static str> for Message {
    fn from(text: &'static str) -> Self {
        Self::raw(text)
    }
}

impl Deref for Message {
    type Target = str;

    fn deref(&self) -> &str {
        self.text()
    }
}

impl AsRef<str> for Message {
    fn as_ref(&self) -> &str {
        self.text()
    }
}

impl Borrow<str> for Message {
    fn borrow(&self) -> &str {
        self.text()
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

impl PartialEq for Message {
    fn eq(&self, other: &Self) -> bool {
        self.text() == other.text()
    }
}

impl Eq for Message {}

impl Hash for Message {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.text().hash(state);
    }
}

impl PartialEq<str> for Message {
    fn eq(&self, other: &str) -> bool {
        self.text() == other
    }
}

impl PartialEq<&str> for Message {
    fn eq(&self, other: &&str) -> bool {
        self.text() == *other
    }
}

impl PartialEq<String> for Message {
    fn eq(&self, other: &String) -> bool {
        self.text() == other
    }
}

impl serde::Serialize for Message {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.text())
    }
}
