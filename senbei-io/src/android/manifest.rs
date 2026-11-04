//! Bounded identity of one Android manifest.
//!
//! The only result is `(package, version)`. Version is `android:versionCode`,
//! with `android:versionCodeMajor` prefixed when it is present and non-zero.
//! `android:versionName` is not an identity. A truncated or corrupt manifest
//! returns `None` rather than a partial guess.
//!
//! Chunk layout follows `androidfw/ResourceTypes.h`: a start element is a
//! `ResXMLTree_node` (`headerSize` is normally 16) followed by `ResXMLTree_attrExt`
//! at that header size. Attribute records begin at `headerSize + attributeStart`.
//! `Res_value::dataType` is the byte immediately before the data word.

/// `(package, version)` when the root element is `manifest` and carries a
/// package plus a version code. Truncated probes never supply a binding.
pub(super) fn identity(bytes: &[u8], truncated: bool) -> Option<(String, String)> {
    if truncated {
        return None;
    }
    if bytes.len() >= 8 && u16::from_le_bytes([bytes[0], bytes[1]]) == 0x0003 {
        return binary_identity(bytes);
    }
    plain_identity(bytes, truncated)
}

const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const VERSION_CODE: u32 = 0x0101_021b;
const VERSION_CODE_MAJOR: u32 = 0x0101_0576;
const NO_STRING: u32 = 0xffff_ffff;

fn binary_identity(bytes: &[u8]) -> Option<(String, String)> {
    if bytes.len() < 8 {
        return None;
    }
    let file_size = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?) as usize;
    if file_size < 8 || file_size > bytes.len() {
        return None;
    }
    let bytes = bytes.get(..file_size)?;
    let mut offset = read_u16(bytes, 2)? as usize;
    if offset < 8 || offset > bytes.len() {
        return None;
    }
    let mut pool: Option<StringPool<'_>> = None;
    let mut resource_map = Vec::new();
    while offset + 8 <= bytes.len() {
        let kind = read_u16(bytes, offset)?;
        let header = read_u16(bytes, offset + 2)? as usize;
        let size = read_u32(bytes, offset + 4)? as usize;
        if header < 8 || size < header || offset.checked_add(size)? > bytes.len() {
            return None;
        }
        let chunk = bytes.get(offset..offset + size)?;
        match kind {
            0x0001 => pool = Some(StringPool::parse(chunk)?),
            0x0180 => resource_map = resource_map_of(chunk)?,
            0x0102 => return start_element_identity(chunk, pool.as_ref()?, &resource_map),
            _ => {}
        }
        offset += size;
    }
    None
}

fn start_element_identity(
    chunk: &[u8],
    pool: &StringPool<'_>,
    resource_map: &[u32],
) -> Option<(String, String)> {
    let header = read_u16(chunk, 2)? as usize;
    // ResXMLTree_attrExt sits headerSize bytes after the chunk start.
    if header < 16 || chunk.len() < header.checked_add(20)? {
        return None;
    }
    let ext = header;
    let name = read_u32(chunk, ext + 4)?;
    if pool.get(name)?.as_str() != "manifest" {
        return None;
    }
    let attribute_start = read_u16(chunk, ext + 8)? as usize;
    let attribute_size = read_u16(chunk, ext + 10)? as usize;
    let attribute_count = read_u16(chunk, ext + 12)? as usize;
    if attribute_size < 20 || attribute_start < 20 {
        return None;
    }
    let base = header.checked_add(attribute_start)?;
    let bytes = attribute_count.checked_mul(attribute_size)?;
    if base.checked_add(bytes)? > chunk.len() {
        return None;
    }
    let mut package = None;
    let mut version_code = None;
    let mut version_major = None;
    for index in 0..attribute_count {
        let at = base + index * attribute_size;
        let record = chunk.get(at..at + 20)?;
        let namespace = read_u32(record, 0)?;
        let name = read_u32(record, 4)?;
        let raw = read_u32(record, 8)?;
        // Res_value: size u16, res0 u8, dataType u8, data u32.
        let data_type = *record.get(15)?;
        let data = read_u32(record, 16)?;
        let name_text = pool.get(name)?;
        let resource = resource_map.get(name as usize).copied();
        // `package` is the un-namespaced attribute. A resource id is never
        // used for it: `0x01010003` is `android:name`, not the package.
        if namespace == NO_STRING && name_text == "package" {
            package = Some(attribute_text(pool, raw, data_type, data)?);
        } else if name_text == "versionCode" || resource == Some(VERSION_CODE) {
            version_code = Some(version_number(pool, raw, data_type, data)?);
        } else if name_text == "versionCodeMajor" || resource == Some(VERSION_CODE_MAJOR) {
            version_major = Some(version_number(pool, raw, data_type, data)?);
        }
    }
    finish_identity(package?, version_code, version_major)
}

fn attribute_text(pool: &StringPool<'_>, raw: u32, data_type: u8, data: u32) -> Option<String> {
    if data_type == TYPE_STRING {
        return pool.get(data);
    }
    if raw != NO_STRING {
        return pool.get(raw);
    }
    None
}

fn version_number(pool: &StringPool<'_>, raw: u32, data_type: u8, data: u32) -> Option<String> {
    match data_type {
        TYPE_INT_DEC | TYPE_INT_HEX => Some(data.to_string()),
        TYPE_STRING => normalize_version(&pool.get(data)?),
        _ if raw != NO_STRING => normalize_version(&pool.get(raw)?),
        _ => None,
    }
}

fn finish_identity(
    package: String,
    version_code: Option<String>,
    version_major: Option<String>,
) -> Option<(String, String)> {
    if !is_package_token(&package) {
        return None;
    }
    let code = version_code?;
    let version = match version_major {
        Some(major) if major != "0" => format!("{major}.{code}"),
        _ => code,
    };
    if !is_version_token(&version) {
        return None;
    }
    Some((package, version))
}

struct StringPool<'a> {
    bytes: &'a [u8],
    offsets: Vec<u32>,
    strings_start: usize,
    utf8: bool,
}

impl<'a> StringPool<'a> {
    fn parse(chunk: &'a [u8]) -> Option<Self> {
        if chunk.len() < 28 {
            return None;
        }
        let count = read_u32(chunk, 8)? as usize;
        let flags = read_u32(chunk, 16)?;
        let strings_start = read_u32(chunk, 20)? as usize;
        // Offsets begin after the 28-byte pool header. A count whose offset
        // table does not fit is corrupt. There is no fixed cap on the count:
        // the bound is that the table fits and later decoding stays within
        // twice the chunk.
        let table = 28_usize.checked_add(count.checked_mul(4)?)?;
        if table > chunk.len() || strings_start < table || strings_start > chunk.len() {
            return None;
        }
        let mut offsets = Vec::new();
        offsets.try_reserve_exact(count).ok()?;
        for index in 0..count {
            offsets.push(read_u32(chunk, 28 + index * 4)?);
        }
        Some(Self {
            bytes: chunk,
            offsets,
            strings_start,
            utf8: flags & (1 << 8) != 0,
        })
    }

    fn get(&self, index: u32) -> Option<String> {
        if index == NO_STRING {
            return None;
        }
        let start = self
            .strings_start
            .checked_add(*self.offsets.get(index as usize)? as usize)?;
        let text = if self.utf8 {
            utf8_at(self.bytes, start)?.to_owned()
        } else {
            utf16_at(self.bytes, start)?
        };
        // One looked-up string cannot be larger than the pool that holds it.
        if text.len() > self.bytes.len().saturating_mul(2) {
            return None;
        }
        Some(text)
    }
}

fn utf8_at(bytes: &[u8], mut offset: usize) -> Option<&str> {
    let (_, next) = utf8_len(bytes, offset)?;
    offset = next;
    let (byte_len, next) = utf8_len(bytes, offset)?;
    offset = next;
    let end = offset.checked_add(byte_len)?;
    let text = bytes.get(offset..end)?;
    // The character after the bytes is a NUL terminator.
    if *bytes.get(end)? != 0 {
        return None;
    }
    std::str::from_utf8(text).ok()
}

fn utf8_len(bytes: &[u8], offset: usize) -> Option<(usize, usize)> {
    let first = *bytes.get(offset)?;
    if first & 0x80 == 0 {
        Some((first as usize, offset + 1))
    } else {
        let second = *bytes.get(offset + 1)? as usize;
        Some((((first as usize & 0x7f) << 8) | second, offset + 2))
    }
}

fn utf16_at(bytes: &[u8], offset: usize) -> Option<String> {
    let first = read_u16(bytes, offset)?;
    let (len, data_at) = if first & 0x8000 == 0 {
        (first as usize, offset + 2)
    } else {
        let second = read_u16(bytes, offset + 2)? as usize;
        ((((first as usize) & 0x7fff) << 16) | second, offset + 4)
    };
    let end = data_at.checked_add(len.checked_mul(2)?)?;
    if read_u16(bytes, end)? != 0 {
        return None;
    }
    let raw = bytes.get(data_at..end)?;
    let units = raw.as_chunks::<2>().0;
    // Avoid allocating a UTF-16 copy larger than the chunk that holds it.
    if units.len().saturating_mul(2) > bytes.len().saturating_mul(2) {
        return None;
    }
    let owned: Vec<u16> = units.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    String::from_utf16(&owned).ok()
}

fn resource_map_of(chunk: &[u8]) -> Option<Vec<u32>> {
    let body = chunk.get(8..)?;
    let mut ids = Vec::new();
    ids.try_reserve_exact(body.len() / 4).ok()?;
    for item in body.as_chunks::<4>().0 {
        ids.push(u32::from_le_bytes(*item));
    }
    Some(ids)
}

fn plain_identity(bytes: &[u8], truncated: bool) -> Option<(String, String)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let rest = skip_preamble(text)?;
    if !rest.starts_with("<manifest") {
        return None;
    }
    let mut cursor = &rest["<manifest".len()..];
    if cursor.starts_with(|ch: char| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':')) {
        return None;
    }
    let mut package = None;
    let mut version_code = None;
    let mut version_major = None;
    let mut closed = false;
    loop {
        cursor = cursor.trim_start();
        if cursor.is_empty() {
            break;
        }
        if cursor.starts_with('>') || cursor.starts_with("/>") {
            closed = true;
            break;
        }
        if cursor.starts_with("<!--") {
            let close = cursor.find("-->")?;
            cursor = &cursor[close + 3..];
            continue;
        }
        let name_end = cursor
            .find(|ch: char| ch.is_whitespace() || ch == '=')
            .unwrap_or(cursor.len());
        let name = &cursor[..name_end];
        if name.is_empty() {
            return None;
        }
        cursor = cursor[name_end..].trim_start();
        if !cursor.starts_with('=') {
            return None;
        }
        cursor = cursor[1..].trim_start();
        let quote = cursor.chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        cursor = &cursor[quote.len_utf8()..];
        let value_end = cursor.find(quote)?;
        let value = &cursor[..value_end];
        cursor = &cursor[value_end + quote.len_utf8()..];
        match name {
            "package" => package = Some(value.to_owned()),
            "android:versionCode" => version_code = normalize_version(value),
            "android:versionCodeMajor" => version_major = normalize_version(value),
            _ => {}
        }
    }
    if !closed || truncated {
        return None;
    }
    finish_identity(package?, version_code, version_major)
}

/// Skip a BOM (already removed), XML declarations, and comments. A comment
/// that contains `<manifest` is not the root.
fn skip_preamble(mut text: &str) -> Option<&str> {
    loop {
        text = text.trim_start();
        if text.starts_with("<?") {
            let close = text.find("?>")?;
            text = &text[close + 2..];
            continue;
        }
        if text.starts_with("<!--") {
            let close = text.find("-->")?;
            text = &text[close + 3..];
            continue;
        }
        break;
    }
    Some(text)
}

fn normalize_version(value: &str) -> Option<String> {
    if value.starts_with(['-', '+']) {
        return None;
    }
    let number = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        value.parse::<u32>().ok()?
    };
    Some(number.to_string())
}

fn is_package_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn is_version_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | '-' | 'x' | 'a'..='f'))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(body: &str) -> Vec<u8> {
        body.as_bytes().to_vec()
    }

    #[test]
    fn plain_requires_version_code_and_skips_comments() {
        let text = plain(
            "<?xml version=\"1.0\"?>\n<!-- <manifest package=\"fake.comment\" android:versionCode=\"9\"/> -->\n<manifest package='example.game' android:versionName=\"same\" android:versionCode=\"12\" android:versionCodeMajor=\"3\">\n</manifest>\n",
        );
        assert_eq!(
            identity(&text, false),
            Some(("example.game".to_owned(), "3.12".to_owned()))
        );
        let named = plain("<manifest package=\"example.game\" android:versionName=\"1\"/>");
        assert_eq!(identity(&named, false), None);
        let substring = plain("<notmanifest package=\"example.game\" android:versionCode=\"1\"/>");
        assert_eq!(identity(&substring, false), None);
    }

    #[test]
    fn plain_truncated_root_is_not_an_identity() {
        let cut = plain("<manifest package=\"example.game\" android:versionCode=\"4\"");
        assert_eq!(identity(&cut, false), None);
        assert_eq!(identity(&cut, true), None);
    }

    #[test]
    fn plain_hex_version_normalizes() {
        let text = plain("<manifest package=\"example.game\" android:versionCode=\"0x10\"/>");
        assert_eq!(
            identity(&text, false),
            Some(("example.game".to_owned(), "16".to_owned()))
        );
    }

    #[test]
    fn binary_typed_package_and_nonzero_major() {
        // rawValue is 0xFFFFFFFF. The package exists only as a TYPE_STRING
        // data index, and versionCodeMajor is a real non-zero integer.
        let bytes = axml_with_data(
            "manifest",
            &[
                ("package", NO_STRING, "example.typed", TYPE_STRING, 0),
                ("versionCode", NO_STRING, "", TYPE_INT_DEC, 7),
                ("versionCodeMajor", NO_STRING, "", TYPE_INT_DEC, 2),
            ],
            Encoding::Utf8,
        );
        assert_eq!(
            identity(&bytes, false),
            Some(("example.typed".to_owned(), "2.7".to_owned()))
        );
    }

    #[test]
    fn binary_utf16_and_hex_version() {
        let bytes = axml_with_data(
            "manifest",
            &[
                ("package", NO_STRING, "example.utf16", 0, 0),
                ("versionCode", NO_STRING, "", TYPE_INT_HEX, 0x20),
            ],
            Encoding::Utf16,
        );
        assert_eq!(
            identity(&bytes, false),
            Some(("example.utf16".to_owned(), "32".to_owned()))
        );
        let _ = bytes;
    }

    #[test]
    fn binary_rejects_other_root_and_android_name_resource() {
        let other = axml(
            "application",
            &[
                attr(NO_STRING, "package", "example.nope", 0, ""),
                attr(NO_STRING, "versionCode", "1", 0, ""),
            ],
            Encoding::Utf8,
        );
        assert_eq!(identity(&other, false), None);
        // Resource id 0x01010003 is android:name. It must not become the package
        // even when its string is a package-looking value.
        let named = axml_resources(
            "manifest",
            &[("name", 0x0101_0003, "example.fake", TYPE_STRING)],
            &[],
            Encoding::Utf8,
        );
        assert_eq!(identity(&named, false), None);
    }

    #[test]
    fn binary_truncated_and_corrupt_ranges() {
        let bytes = axml(
            "manifest",
            &[
                attr(NO_STRING, "package", "example.cut", 0, ""),
                attr(NO_STRING, "versionCode", "1", 0, ""),
            ],
            Encoding::Utf8,
        );
        let mut short = bytes.clone();
        short.truncate(20);
        assert_eq!(identity(&short, true), None);
        let mut bad = bytes.clone();
        bad[4..8].copy_from_slice(&4_u32.to_le_bytes());
        assert_eq!(identity(&bad, false), None);
    }

    #[test]
    fn zero_major_is_omitted() {
        let bytes = axml_with_data(
            "manifest",
            &[
                ("package", NO_STRING, "example.zero", TYPE_STRING, 0),
                ("versionCode", NO_STRING, "", TYPE_INT_DEC, 9),
                ("versionCodeMajor", NO_STRING, "", TYPE_INT_DEC, 0),
            ],
            Encoding::Utf8,
        );
        assert_eq!(
            identity(&bytes, false),
            Some(("example.zero".to_owned(), "9".to_owned()))
        );
    }

    struct BuiltAttr {
        name: &'static str,
        raw: u32,
        raw_text: &'static str,
        data_type: u8,
        data_text: &'static str,
    }

    fn attr(
        _namespace: u32,
        name: &'static str,
        raw_text: &'static str,
        data_type: u8,
        data_text: &'static str,
    ) -> BuiltAttr {
        BuiltAttr {
            name,
            raw: if raw_text.is_empty() { NO_STRING } else { 0 },
            raw_text,
            data_type,
            data_text,
        }
    }

    #[derive(Clone, Copy)]
    enum Encoding {
        Utf8,
        Utf16,
    }

    fn axml(root: &str, attributes: &[BuiltAttr], encoding: Encoding) -> Vec<u8> {
        let specs: Vec<(&str, u32, &str, u8, u32)> = attributes
            .iter()
            .map(|item| {
                let data = if item.data_type == TYPE_INT_DEC || item.data_type == TYPE_INT_HEX {
                    item.data_text.parse().unwrap_or(0)
                } else {
                    0
                };
                (item.name, item.raw, item.raw_text, item.data_type, data)
            })
            .collect();
        axml_with_data(root, &specs, encoding)
    }

    fn axml_with_data(
        root: &str,
        attributes: &[(&str, u32, &str, u8, u32)],
        encoding: Encoding,
    ) -> Vec<u8> {
        axml_resources(root, &[], attributes, encoding)
    }

    fn axml_resources(
        root: &str,
        named_resources: &[(&str, u32, &str, u8)],
        attributes: &[(&str, u32, &str, u8, u32)],
        encoding: Encoding,
    ) -> Vec<u8> {
        let mut strings = vec![root.to_owned()];
        let mut specs: Vec<(u32, u32, u32, u8, u32)> = Vec::new();
        for (name, raw, raw_text, data_type, data) in attributes {
            let name_index = push_string(&mut strings, name);
            let raw_index = if raw_text.is_empty() {
                *raw
            } else {
                push_string(&mut strings, raw_text)
            };
            let data_index = if *data_type == TYPE_STRING {
                if raw_text.is_empty() {
                    *data
                } else {
                    push_string(&mut strings, raw_text)
                }
            } else {
                *data
            };
            specs.push((NO_STRING, name_index, raw_index, *data_type, data_index));
        }
        for (name, _resource, text, data_type) in named_resources {
            let name_index = push_string(&mut strings, name);
            let value_index = push_string(&mut strings, text);
            specs.push((NO_STRING, name_index, NO_STRING, *data_type, value_index));
        }
        let resources: Vec<u32> = {
            let mut ids = vec![0_u32; strings.len()];
            for (name, resource, _, _) in named_resources {
                if let Some(index) = strings.iter().position(|item| item == name) {
                    ids[index] = *resource;
                }
            }
            ids
        };
        let pool = encode_pool(&strings, encoding);
        let mut map = Vec::new();
        map.extend(u16::to_le_bytes(0x0180));
        map.extend(u16::to_le_bytes(8));
        map.extend(u32::to_le_bytes((8 + resources.len() * 4) as u32));
        for id in &resources {
            map.extend(u32::to_le_bytes(*id));
        }
        let mut element = Vec::new();
        element.extend(u16::to_le_bytes(0x0102));
        element.extend(u16::to_le_bytes(16));
        let attribute_bytes = specs.len() * 20;
        let size = 16 + 20 + attribute_bytes;
        element.extend(u32::to_le_bytes(size as u32));
        element.extend(u32::to_le_bytes(1)); // line
        element.extend(u32::to_le_bytes(NO_STRING)); // comment
        element.extend(u32::to_le_bytes(NO_STRING)); // namespace
        element.extend(u32::to_le_bytes(0)); // name = root
        element.extend(u16::to_le_bytes(20)); // attributeStart from attrExt
        element.extend(u16::to_le_bytes(20));
        element.extend(u16::to_le_bytes(specs.len() as u16));
        element.extend(u16::to_le_bytes(0));
        element.extend(u16::to_le_bytes(0));
        element.extend(u16::to_le_bytes(0));
        for (namespace, name, raw, data_type, data) in specs {
            element.extend(u32::to_le_bytes(namespace));
            element.extend(u32::to_le_bytes(name));
            element.extend(u32::to_le_bytes(raw));
            element.extend(u16::to_le_bytes(8));
            element.push(0);
            element.push(data_type);
            element.extend(u32::to_le_bytes(data));
        }
        let mut bytes = Vec::new();
        bytes.extend(u16::to_le_bytes(0x0003));
        bytes.extend(u16::to_le_bytes(8));
        bytes.extend(u32::to_le_bytes(
            (8 + pool.len() + map.len() + element.len()) as u32,
        ));
        bytes.extend(pool);
        bytes.extend(map);
        bytes.extend(element);
        bytes
    }

    fn push_string(strings: &mut Vec<String>, value: &str) -> u32 {
        if let Some(index) = strings.iter().position(|item| item == value) {
            return index as u32;
        }
        strings.push(value.to_owned());
        (strings.len() - 1) as u32
    }

    fn encode_pool(strings: &[String], encoding: Encoding) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for value in strings {
            offsets.push(data.len() as u32);
            match encoding {
                Encoding::Utf8 => {
                    data.push(value.chars().count() as u8);
                    data.push(value.len() as u8);
                    data.extend(value.as_bytes());
                    data.push(0);
                }
                Encoding::Utf16 => {
                    let units: Vec<u16> = value.encode_utf16().collect();
                    data.extend(u16::to_le_bytes(units.len() as u16));
                    for unit in units {
                        data.extend(u16::to_le_bytes(unit));
                    }
                    data.extend(u16::to_le_bytes(0));
                }
            }
        }
        let mut chunk = Vec::new();
        chunk.extend(u16::to_le_bytes(0x0001));
        chunk.extend(u16::to_le_bytes(28));
        let size = 28 + strings.len() * 4 + data.len();
        chunk.extend(u32::to_le_bytes(size as u32));
        chunk.extend(u32::to_le_bytes(strings.len() as u32));
        chunk.extend(u32::to_le_bytes(0));
        let flags: u32 = match encoding {
            Encoding::Utf8 => 1 << 8,
            Encoding::Utf16 => 0,
        };
        chunk.extend(u32::to_le_bytes(flags));
        chunk.extend(u32::to_le_bytes((28 + strings.len() * 4) as u32));
        chunk.extend(u32::to_le_bytes(0));
        for offset in offsets {
            chunk.extend(u32::to_le_bytes(offset));
        }
        chunk.extend(data);
        chunk
    }
}
