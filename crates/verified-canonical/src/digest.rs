//! SHA-256 commitments.

use std::fmt;
use std::str::FromStr;

use sha2::{Digest as _, Sha256};

/// A SHA-256 digest.
///
/// On the wire a digest is 64 lowercase hexadecimal characters; [`FromStr`]
/// accepts exactly that and [`fmt::Display`] writes it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// The algorithm name the protocol uses for this digest.
    pub const ALGORITHM: &'static str = "sha-256";

    /// The digest of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// The 32 digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The digest as 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha-256:{self}")
    }
}

/// The text is not 64 lowercase hexadecimal characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a SHA-256 digest is 64 lowercase hexadecimal characters")]
pub struct DigestParseError;

impl FromStr for Sha256Digest {
    type Err = DigestParseError;

    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        let hex = hex.as_bytes();
        if hex.len() != 64 {
            return Err(DigestParseError);
        }
        let nibble = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(DigestParseError),
        };
        let mut bytes = [0u8; 32];
        let (pairs, _) = hex.as_chunks::<2>();
        for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
            *byte = nibble(*high)? << 4 | nibble(*low)?;
        }
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-4 known answers.
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn known_answers() {
        assert_eq!(Sha256Digest::of(b"").to_hex(), EMPTY);
        assert_eq!(Sha256Digest::of(b"abc").to_hex(), ABC);
    }

    #[test]
    fn hex_round_trips() {
        let digest: Sha256Digest = ABC.parse().expect("valid hex");
        assert_eq!(digest, Sha256Digest::of(b"abc"));
        assert_eq!(digest.to_hex(), ABC);
        assert_eq!(format!("{digest:?}"), format!("sha-256:{ABC}"));
    }

    #[test]
    fn refuses_anything_but_64_lowercase_hex() {
        for bad in [
            "",
            &ABC[..63],
            &format!("{ABC}0"),
            &ABC.to_uppercase(),
            &ABC.replace('b', "g"),
            &format!(" {}", &ABC[1..]),
        ] {
            assert_eq!(
                bad.parse::<Sha256Digest>(),
                Err(DigestParseError),
                "{bad:?}"
            );
        }
    }
}
