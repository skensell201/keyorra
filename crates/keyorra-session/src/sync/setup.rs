//! The setup code the main device shows to add a device (plan A1d; A3 also renders it as a
//! QR code). It carries the Secret Key and pins the main device (its id and key code), so the
//! new device needs only the master password and refuses a header that names another main
//! device. It is as secret as the Secret Key.

use data_encoding::BASE32_NOPAD;
use keyorra_sync::account::RootPin;
use keyorra_sync::secret_key::SecretKey;
use keyorra_sync::{DeviceId, Error, Result};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const PREFIX: &str = "KEYORRA-SETUP-1-";
const ID_LEN: usize = 4;
/// id (4 ASCII) | secret key (16) | main device id (16) | key code (6) | check (2)
const BODY: usize = ID_LEN + 16 + 16 + 6;

pub struct SetupCode {
    pub secret_key_id: String,
    pub secret_key: SecretKey,
    pub pin: RootPin,
}

fn check(body: &[u8]) -> [u8; 2] {
    let d = Sha256::digest([b"keyorra-setup-code-v1".as_slice(), body].concat());
    [d[0], d[1]]
}

fn bad() -> Error {
    Error::Malformed("setup code".into())
}

impl SetupCode {
    pub fn to_text(&self) -> Zeroizing<String> {
        let fp: Vec<u8> = data_encoding::HEXLOWER
            .decode(self.pin.key_fingerprint.replace('-', "").as_bytes())
            .expect("key codes are hex");
        let mut body = Zeroizing::new(Vec::with_capacity(BODY + 2));
        body.extend_from_slice(self.secret_key_id.as_bytes());
        body.extend_from_slice(self.secret_key.as_bytes());
        body.extend_from_slice(&self.pin.device);
        body.extend_from_slice(&fp);
        let c = check(&body);
        body.extend_from_slice(&c);
        Zeroizing::new(format!("{PREFIX}{}", BASE32_NOPAD.encode(&body)))
    }

    pub fn parse(text: &str) -> Result<SetupCode> {
        let compact: Zeroizing<String> = Zeroizing::new(
            text.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_ascii_uppercase(),
        );
        let rest = compact.strip_prefix(PREFIX).ok_or_else(bad)?;
        let body = Zeroizing::new(BASE32_NOPAD.decode(rest.as_bytes()).map_err(|_| bad())?);
        if body.len() != BODY + 2 || check(&body[..BODY]) != body[BODY..] {
            return Err(bad());
        }
        let secret_key_id = std::str::from_utf8(&body[..ID_LEN])
            .map_err(|_| bad())?
            .to_owned();
        let mut sk = [0u8; 16];
        sk.copy_from_slice(&body[ID_LEN..ID_LEN + 16]);
        let mut device: DeviceId = [0; 16];
        device.copy_from_slice(&body[ID_LEN + 16..ID_LEN + 32]);
        let hex = data_encoding::HEXLOWER.encode(&body[ID_LEN + 32..BODY]);
        Ok(SetupCode {
            secret_key_id,
            secret_key: SecretKey::from_bytes(sk),
            pin: RootPin {
                device,
                key_fingerprint: format!("{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12]),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SetupCode {
        SetupCode {
            secret_key_id: "A3KX".into(),
            secret_key: SecretKey::from_bytes([9; 16]),
            pin: RootPin {
                device: [4; 16],
                key_fingerprint: "0a1b-2c3d-4e5f".into(),
            },
        }
    }

    #[test]
    fn round_trips_and_tolerates_spaces_and_case() {
        let text = sample().to_text();
        let spaced = format!(" {} ", text.to_lowercase());
        let back = SetupCode::parse(&spaced).unwrap();
        assert_eq!(back.secret_key_id, "A3KX");
        assert_eq!(back.secret_key.as_bytes(), &[9; 16]);
        assert_eq!(back.pin.device, [4; 16]);
        assert_eq!(back.pin.key_fingerprint, "0a1b-2c3d-4e5f");
    }

    #[test]
    fn a_mistyped_code_is_refused() {
        let text = sample().to_text();
        let mut chars: Vec<char> = text.chars().collect();
        let i = PREFIX.len() + 5;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(SetupCode::parse(&typo).is_err());
        assert!(SetupCode::parse("KEYORRA-SETUP-1-").is_err());
        assert!(SetupCode::parse("hello").is_err());
    }
}
