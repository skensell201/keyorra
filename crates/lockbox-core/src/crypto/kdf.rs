use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::Key;
use crate::{Error, Result};

const ALGORITHM: Algorithm = Algorithm::Argon2id;
const VERSION: Version = Version::V0x13;

/// Argon2id cost parameters, stored in the vault header so they can be raised later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

impl KdfParams {
    pub const DEFAULT: Self = Self { m_kib: 64 * 1024, t: 3, p: 1 };
    /// Cheap parameters for tests only. Never use for a real vault.
    pub const INSECURE_FAST: Self = Self { m_kib: 8, t: 1, p: 1 };
}

/// Derives the key-encryption key from the master password.
pub fn derive_kek(password: &str, salt: &[u8; 16], params: KdfParams) -> Result<Key> {
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| Error::Invalid(format!("kdf params: {e}")))?;
    let mut out = [0u8; 32];
    Argon2::new(ALGORITHM, VERSION, argon_params)
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| Error::Invalid(format!("kdf: {e}")))?;
    let key = Key::from_bytes(out);
    out.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 16] = [2u8; 16];

    #[test]
    fn same_inputs_same_key() {
        let a = derive_kek("pw", &SALT, KdfParams::INSECURE_FAST).unwrap();
        let b = derive_kek("pw", &SALT, KdfParams::INSECURE_FAST).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn password_salt_and_params_all_matter() {
        let base = derive_kek("pw", &SALT, KdfParams::INSECURE_FAST).unwrap();
        let other_pw = derive_kek("pw2", &SALT, KdfParams::INSECURE_FAST).unwrap();
        let other_salt = derive_kek("pw", &[3u8; 16], KdfParams::INSECURE_FAST).unwrap();
        let other_params =
            derive_kek("pw", &SALT, KdfParams { t: 2, ..KdfParams::INSECURE_FAST }).unwrap();
        assert_ne!(base.as_bytes(), other_pw.as_bytes());
        assert_ne!(base.as_bytes(), other_salt.as_bytes());
        assert_ne!(base.as_bytes(), other_params.as_bytes());
    }

    #[test]
    fn rejects_invalid_params() {
        let bad = KdfParams { m_kib: 1, t: 1, p: 1 };
        assert!(matches!(derive_kek("pw", &SALT, bad), Err(crate::Error::Invalid(_))));
    }

    #[test]
    fn default_params_match_spec() {
        assert_eq!(KdfParams::DEFAULT, KdfParams { m_kib: 65536, t: 3, p: 1 });
    }

    /// RFC 9106 §5.3 known-answer test: guards that the dependency is Argon2id v1.3.
    #[test]
    fn rfc9106_argon2id_vector() {
        use argon2::{AssociatedData, ParamsBuilder};
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(AssociatedData::new(&[4u8; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let argon = Argon2::new_with_secret(&[3u8; 8], ALGORITHM, VERSION, params).unwrap();
        let mut out = [0u8; 32];
        argon.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out).unwrap();
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    }
}
