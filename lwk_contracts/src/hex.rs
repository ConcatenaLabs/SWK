//! Lowercase hex of exact width.

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Bytes from lowercase hex of exactly `width` bytes.
pub fn unhex(s: &str, width: usize) -> Result<Vec<u8>, String> {
    if s.len() != 2 * width {
        return Err(format!("{s:?} is not {width} bytes of hex"));
    }
    if !s
        .bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(format!("{s:?} is not lowercase hex"));
    }
    (0..width)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Bytes from lowercase hex of any even length.
pub fn unhex_any(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("{s:?} has an odd length"));
    }
    unhex(s, s.len() / 2)
}
