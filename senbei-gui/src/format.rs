//! Number, size, and time formatting shared by every view.

/// `0x1A2B`, upper-case, at least `width` digits.
pub fn hex(value: u64) -> String {
    format!("0x{value:X}")
}

/// `0x0000_1A2B`-style fixed width, without separators.
pub fn hex_w(value: u64, width: usize) -> String {
    format!("0x{value:0width$X}")
}

/// `12,345` with thousands separators.
pub fn num(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Binary size: `512 B`, `1.5 KiB`, `24.9 MiB`, `1.02 GiB`.
pub fn bytes(value: u64) -> String {
    const KIB: f64 = 1024.0;
    let v = value as f64;
    if value < 1024 {
        format!("{value} B")
    } else if v < KIB * KIB {
        format!("{:.1} KiB", v / KIB)
    } else if v < KIB * KIB * KIB {
        format!("{:.1} MiB", v / (KIB * KIB))
    } else {
        format!("{:.2} GiB", v / (KIB * KIB * KIB))
    }
}

/// `15 ms` or `1.42 s`.
pub fn ms(value: u64) -> String {
    if value >= 1000 {
        format!("{:.2} s", value as f64 / 1000.0)
    } else {
        format!("{value} ms")
    }
}

/// `0:01.4` — minutes, seconds, tenths, for a running clock.
pub fn clock(elapsed_ms: u64) -> String {
    let tenths = elapsed_ms / 100;
    format!("{}:{:02}.{}", tenths / 600, (tenths / 10) % 60, tenths % 10)
}

/// The final path component, accepting either separator.
pub fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// `head…tail` of a hash for display.
pub fn short_hash(sha256: &str) -> String {
    if sha256.len() <= 24 {
        return sha256.to_owned();
    }
    format!("{}…{}", &sha256[..16], &sha256[sha256.len() - 8..])
}

/// Parse `0x14E0`, `14E0`, or `14e0` as hexadecimal.
pub fn parse_hex(text: &str) -> Option<u64> {
    let text = text.trim();
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(&digits.replace('_', ""), 16).ok()
}

/// Bytes to search for: `4D 5A` or `0x4D5A` as hex, anything else as text.
pub fn parse_needle(text: &str) -> Vec<u8> {
    let trimmed = text.trim();
    let hexish: String = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    if hexish.len() >= 2
        && hexish.len().is_multiple_of(2)
        && hexish.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return (0..hexish.len())
            .step_by(2)
            .filter_map(|index| u8::from_str_radix(&hexish[index..index + 2], 16).ok())
            .collect();
    }
    trimmed.bytes().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_match_the_mockup() {
        assert_eq!(hex(0x14E0), "0x14E0");
        assert_eq!(hex_w(0x8664, 4), "0x8664");
        assert_eq!(hex_w(0x1000, 8), "0x00001000");
        assert_eq!(num(1234567), "1,234,567");
        assert_eq!(num(999), "999");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(2048), "2.0 KiB");
        assert_eq!(bytes(3 * 1024 * 1024), "3.0 MiB");
        assert_eq!(ms(15), "15 ms");
        assert_eq!(ms(1420), "1.42 s");
        assert_eq!(clock(1400), "0:01.4");
        assert_eq!(clock(61_000), "1:01.0");
        assert_eq!(base_name(r"D:\a\b.dll"), "b.dll");
        assert_eq!(base_name("a/b.so"), "b.so");
    }

    #[test]
    fn parses_offsets_and_needles() {
        assert_eq!(parse_hex("0x14E0"), Some(0x14E0));
        assert_eq!(parse_hex("14e0"), Some(0x14E0));
        assert_eq!(parse_hex("zz"), None);
        assert_eq!(parse_needle("4D 5A"), vec![0x4D, 0x5A]);
        assert_eq!(parse_needle("0x4D5A"), vec![0x4D, 0x5A]);
        assert_eq!(parse_needle("MZ"), b"MZ".to_vec());
        assert_eq!(parse_needle("abc"), b"abc".to_vec());
    }
}
