use hmac::{Hmac, Mac};
use percent_encoding::percent_decode_str;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Totp {
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl Totp {
    /// Accepts an `otpauth://totp/...` URI or a bare base32 secret.
    pub fn parse(input: &str) -> Result<Totp> {
        let s = input.trim();
        if s.to_ascii_lowercase().starts_with("otpauth://") {
            parse_uri(s)
        } else {
            Ok(Totp {
                secret: decode_base32(s)?,
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                issuer: None,
                account: None,
            })
        }
    }

    pub fn code_at(&self, unix: u64) -> String {
        let counter = (unix / self.period).to_be_bytes();
        let hash = hmac(self.algorithm, &self.secret, &counter);
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        let binary = u32::from_be_bytes([
            hash[offset] & 0x7f,
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
        ]);
        let code = binary % 10u32.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    pub fn seconds_left(&self, unix: u64) -> u64 {
        self.period - unix % self.period
    }
}

fn hmac(algorithm: Algorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    const ANY_KEY: &str = "HMAC accepts keys of any length";
    match algorithm {
        Algorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).expect(ANY_KEY);
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).expect(ANY_KEY);
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key).expect(ANY_KEY);
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn decode_base32(s: &str) -> Result<Vec<u8>> {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if clean.is_empty() {
        return Err(Error::Invalid("empty TOTP secret".into()));
    }
    // Authenticator apps ignore non-zero trailing bits; so do we.
    let mut spec = data_encoding::BASE32_NOPAD.specification();
    spec.check_trailing_bits = false;
    let encoding = spec.encoding().expect("valid base32 spec");
    encoding
        .decode(clean.as_bytes())
        .map_err(|e| Error::Invalid(format!("TOTP secret is not base32: {e}")))
}

fn parse_uri(s: &str) -> Result<Totp> {
    let invalid = |msg: &str| Error::Invalid(format!("otpauth URI: {msg}"));
    let url = url::Url::parse(s).map_err(|e| invalid(&e.to_string()))?;
    if url.host_str().map(|h| h.to_ascii_lowercase()).as_deref() != Some("totp") {
        return Err(invalid("only totp is supported"));
    }
    let label = percent_decode_str(url.path().trim_start_matches('/'))
        .decode_utf8_lossy()
        .into_owned();
    let (issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_owned()), Some(a.trim().to_owned())),
        None if label.is_empty() => (None, None),
        None => (None, Some(label)),
    };
    let mut totp = Totp {
        secret: Vec::new(),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: 30,
        issuer,
        account,
    };
    let mut secret = None;
    for (key, value) in url.query_pairs() {
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(decode_base32(&value)?),
            "algorithm" => {
                totp.algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    other => return Err(invalid(&format!("unsupported algorithm {other}"))),
                }
            }
            "digits" => totp.digits = value.parse().map_err(|_| invalid("bad digits"))?,
            "period" => totp.period = value.parse().map_err(|_| invalid("bad period"))?,
            "issuer" => totp.issuer = Some(value.into_owned()),
            _ => {}
        }
    }
    totp.secret = secret.ok_or_else(|| invalid("missing secret"))?;
    if !(6..=8).contains(&totp.digits) || totp.period == 0 {
        return Err(invalid("digits must be 6-8 and period above 0"));
    }
    Ok(totp)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn rfc(alg: Algorithm, secret: &[u8]) -> Totp {
        Totp {
            secret: secret.to_vec(),
            algorithm: alg,
            digits: 8,
            period: 30,
            issuer: None,
            account: None,
        }
    }

    /// RFC 6238 Appendix B.
    #[test]
    fn rfc6238_vectors() {
        let sha1 = rfc(Algorithm::Sha1, b"12345678901234567890");
        let sha256 = rfc(Algorithm::Sha256, b"12345678901234567890123456789012");
        let sha512 = rfc(
            Algorithm::Sha512,
            b"1234567890123456789012345678901234567890123456789012345678901234",
        );
        let cases: [(&Totp, u64, &str); 10] = [
            (&sha1, 59, "94287082"),
            (&sha1, 1111111109, "07081804"),
            (&sha1, 1111111111, "14050471"),
            (&sha1, 1234567890, "89005924"),
            (&sha1, 2000000000, "69279037"),
            (&sha1, 20000000000, "65353130"),
            (&sha256, 59, "46119246"),
            (&sha256, 1111111109, "68084774"),
            (&sha512, 59, "90693936"),
            (&sha512, 1111111109, "25091201"),
        ];
        for (totp, t, expected) in cases {
            assert_eq!(totp.code_at(t), expected, "{:?} at {t}", totp.algorithm);
        }
    }

    #[test]
    fn six_digit_code_is_last_six_of_truncation() {
        let mut totp = rfc(Algorithm::Sha1, b"12345678901234567890");
        totp.digits = 6;
        assert_eq!(totp.code_at(59), "287082");
    }

    #[test]
    fn seconds_left_in_period() {
        let totp = rfc(Algorithm::Sha1, b"x");
        assert_eq!(totp.seconds_left(0), 30);
        assert_eq!(totp.seconds_left(59), 1);
        assert_eq!(totp.seconds_left(60), 30);
    }

    #[test]
    fn parses_google_style_uri() {
        let t = Totp::parse(
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        )
        .unwrap();
        assert_eq!(t.secret, b"Hello!\xDE\xAD\xBE\xEF");
        assert_eq!(t.issuer.as_deref(), Some("Example"));
        assert_eq!(t.account.as_deref(), Some("alice@google.com"));
        assert_eq!((t.algorithm, t.digits, t.period), (Algorithm::Sha1, 6, 30));
    }

    #[test]
    fn parses_uri_parameters_and_encoded_label() {
        let t = Totp::parse(
            "otpauth://totp/ACME%20Co:john%40example.com?secret=jbswy3dpehpk3pxp&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(t.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(t.account.as_deref(), Some("john@example.com"));
        assert_eq!(
            (t.algorithm, t.digits, t.period),
            (Algorithm::Sha256, 8, 60)
        );
    }

    #[test]
    fn parses_bare_secret_with_spaces_and_lowercase() {
        let t = Totp::parse("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(t.secret, b"Hello!\xDE\xAD\xBE\xEF");
        assert_eq!(t.issuer, None);
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            "not base32 !!!",
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        ] {
            assert!(
                matches!(Totp::parse(bad), Err(Error::Invalid(_))),
                "{bad:?} should fail"
            );
        }
    }
}
