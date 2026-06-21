//! Small helpers with no external runtime dependencies.

use std::fs::File;
use std::io::{self, Read};

/// Lowercase hex encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// A fresh random identifier (128 bits, hex). Used as the immutable config id and
/// connection id. Reads the kernel CSPRNG directly to avoid pulling an RNG crate.
pub fn random_id() -> io::Result<String> {
    let mut buf = [0u8; 16];
    let mut f = File::open("/dev/urandom")?;
    f.read_exact(&mut buf)?;
    Ok(to_hex(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encoding() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
    }

    #[test]
    fn random_id_is_32_hex_chars_and_unique() {
        let a = random_id().unwrap();
        let b = random_id().unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
