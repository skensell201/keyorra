use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

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
    pub const DEFAULT: Self = Self {
        m_kib: 64 * 1024,
        t: 3,
        p: 1,
    };
    /// Cheap parameters for tests only. Never use for a real vault.
    #[cfg(any(test, feature = "test-utils"))]
    pub const INSECURE_FAST: Self = Self {
        m_kib: 8,
        t: 1,
        p: 1,
    };

    const MAX_M_KIB: u32 = 4 * 1024 * 1024;
    const MAX_T: u32 = 20;
    const MAX_P: u32 = 8;

    /// Rejects values that would hang or abort the process (e.g. from a tampered header).
    pub fn validate(&self) -> Result<()> {
        if self.m_kib > Self::MAX_M_KIB
            || self.t == 0
            || self.t > Self::MAX_T
            || self.p == 0
            || self.p > Self::MAX_P
        {
            return Err(Error::Invalid("kdf params out of bounds".into()));
        }
        Ok(())
    }
}

/// Derives the key-encryption key from the master password.
pub fn derive_kek(password: &str, salt: &[u8; 16], params: KdfParams) -> Result<Key> {
    params.validate()?;
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| Error::Invalid(format!("kdf params: {e}")))?;
    // Own the memory blocks so they are wiped on drop; otherwise the Argon2 working
    // memory (derived from the password) would linger on the heap after deallocation.
    // No test can catch a regression here.
    let mut blocks = Zeroizing::new(vec![argon2::Block::default(); argon_params.block_count()]);
    let mut out = [0u8; 32];
    Argon2::new(ALGORITHM, VERSION, argon_params)
        .hash_password_into_with_memory(password.as_bytes(), salt, &mut out, blocks.as_mut_slice())
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
        let other_params = derive_kek(
            "pw",
            &SALT,
            KdfParams {
                t: 2,
                ..KdfParams::INSECURE_FAST
            },
        )
        .unwrap();
        assert_ne!(base.as_bytes(), other_pw.as_bytes());
        assert_ne!(base.as_bytes(), other_salt.as_bytes());
        assert_ne!(base.as_bytes(), other_params.as_bytes());
    }

    #[test]
    fn rejects_invalid_params() {
        let bad = KdfParams {
            m_kib: 1,
            t: 1,
            p: 1,
        };
        assert!(matches!(
            derive_kek("pw", &SALT, bad),
            Err(crate::Error::Invalid(_))
        ));
    }

    #[test]
    fn rejects_out_of_bounds_params_quickly() {
        let fast = KdfParams::INSECURE_FAST;
        let bad = [
            KdfParams {
                m_kib: u32::MAX,
                ..fast
            },
            KdfParams {
                m_kib: 4 * 1024 * 1024 + 1,
                ..fast
            },
            KdfParams {
                t: u32::MAX,
                ..fast
            },
            KdfParams { t: 21, ..fast },
            KdfParams { t: 0, ..fast },
            KdfParams { p: 9, ..fast },
            KdfParams { p: 0, ..fast },
        ];
        let start = std::time::Instant::now();
        for params in bad {
            assert!(
                matches!(params.validate(), Err(crate::Error::Invalid(_))),
                "{params:?}"
            );
            assert!(matches!(
                derive_kek("pw", &SALT, params),
                Err(crate::Error::Invalid(_))
            ));
        }
        assert!(start.elapsed().as_secs() < 2);
    }

    #[test]
    fn default_params_are_valid() {
        assert!(KdfParams::DEFAULT.validate().is_ok());
    }

    #[test]
    fn default_params_match_spec() {
        assert_eq!(
            KdfParams::DEFAULT,
            KdfParams {
                m_kib: 65536,
                t: 3,
                p: 1
            }
        );
    }

    /// RFC 9106 §5.3 known-answer test: guards that the dependency is Argon2id v1.3.
    /// It exercises the dependency via the shared ALGORITHM/VERSION constants, not `derive_kek`.
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
        argon
            .hash_password_into(&[1u8; 32], &[2u8; 16], &mut out)
            .unwrap();
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }
}
