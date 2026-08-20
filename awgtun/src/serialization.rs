use base64::Engine as _;

/// A 32-byte WireGuard key parsed from its text form.
///
/// Accepts both spellings the tooling produces: 64 hex characters, or 43 to 44
/// characters of base64. A `.conf` and `awg` write base64; the UAPI socket
/// uses hex.
///
/// ```
/// use awgtun::serialization::KeyBytes;
///
/// let key: KeyBytes = "0000000000000000000000000000000000000000000000000000000000000000"
///     .parse()
///     .expect("64 hex characters is a valid key");
/// assert_eq!(key.0, [0u8; 32]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBytes(pub [u8; 32]);

impl std::str::FromStr for KeyBytes {
    type Err = &'static str;

    /// Can parse a secret key from a hex or base64 encoded string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut internal = [0u8; 32];

        match s.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| "Illegal character in key")?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                if let Ok(decoded_key) = base64::engine::general_purpose::STANDARD.decode(s) {
                    if decoded_key.len() == internal.len() {
                        internal[..].copy_from_slice(&decoded_key);
                    } else {
                        return Err("Illegal character in key");
                    }
                }
            }
            _ => return Err("Illegal key size"),
        }

        Ok(KeyBytes(internal))
    }
}
