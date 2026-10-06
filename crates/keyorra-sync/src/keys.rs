//! Keys for sync, derived from the master password, the Secret Key and the account key.
//!
//! ```text
//! U        = Argon2id(master password, header salt, header kdf)     (keyorra-core derive_kek)
//! M        = HKDF-Extract(salt = Secret Key, ikm = U)
//! KEK_sync = HKDF-Expand(M, "keyorra/sync/v1/kek\0" ‖ account_id, 32)
//! AUTH     = HKDF-Expand(M, "keyorra/sync/v1/server-auth\0" ‖ account_id, 32)
//! K_seg    = HKDF-SHA256(ikm = AK, salt = account_id, info = "keyorra/sync/v1/segment-key\0")
//! ```

use hkdf::Hkdf;
use keyorra_core::crypto::{derive_kek, KdfParams, Key};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{malformed, Result};
use crate::labels::{self, tagged};
use crate::secret_key::SecretKey;
use crate::AccountId;

/// Bounds for KDF parameters read from a synced header, checked before running Argon2:
/// stricter than the local bounds, because anyone with write access to the folder or server
/// can put parameters there.
pub const MAX_REMOTE_M_KIB: u32 = 1024 * 1024;
pub const MAX_REMOTE_T: u32 = 10;
pub const MAX_REMOTE_P: u32 = 4;

/// Floor for KDF parameters read from a synced header: the app's own default minimum. Without
/// it, whoever can write the folder or server could replace the header by one with a trivial
/// KDF and brute-force the password offline from the (public) wrapped key.
pub const MIN_REMOTE_M_KIB: u32 = 64 * 1024;
pub const MIN_REMOTE_T: u32 = 2;

/// Upper bounds only (`validate` plus the remote maxima). Used where the caller chose the
/// parameters itself, e.g. when creating an account or in tests with cheap parameters.
fn check_kdf_ceiling(kdf: &KdfParams) -> Result<()> {
    kdf.validate()?;
    if kdf.m_kib > MAX_REMOTE_M_KIB || kdf.t > MAX_REMOTE_T || kdf.p > MAX_REMOTE_P {
        return Err(malformed(
            "kdf parameters out of bounds for a synced header",
        ));
    }
    Ok(())
}

/// Full check for parameters that come from a synced header: ceiling and floor.
pub fn check_remote_kdf(kdf: &KdfParams) -> Result<()> {
    check_kdf_ceiling(kdf)?;
    if kdf.m_kib < MIN_REMOTE_M_KIB || kdf.t < MIN_REMOTE_T {
        return Err(malformed(
            "kdf parameters below the minimum for a synced header",
        ));
    }
    Ok(())
}

/// What the master password and the Secret Key unlock for one account.
pub struct SyncKeys {
    /// Unwraps the account key from the synced header.
    pub kek: Key,
    /// Proves knowledge of password and Secret Key to a sync server (phase B).
    pub auth: Key,
}

pub fn derive_sync_keys(
    password: &str,
    salt: &[u8; 16],
    kdf: KdfParams,
    secret_key: &SecretKey,
    account_id: &AccountId,
) -> Result<SyncKeys> {
    check_kdf_ceiling(&kdf)?;
    let u = derive_kek(password, salt, kdf)?;
    let hk = extract(Some(secret_key.as_bytes()), u.as_bytes());
    Ok(SyncKeys {
        kek: expand(&hk, &tagged(labels::KEK, &[account_id])),
        auth: expand(&hk, &tagged(labels::SERVER_AUTH, &[account_id])),
    })
}

/// The key that seals segments and snapshots of one account.
pub fn segment_key(account_key: &Key, account_id: &AccountId) -> Key {
    let hk = extract(Some(account_id), account_key.as_bytes());
    expand(&hk, &tagged(labels::SEGMENT_KEY, &[]))
}

/// `HKDF-Extract`, wiping the returned PRK copy. (The `Hkdf` value keeps its own keyed state
/// until dropped; the crate offers no way to wipe that.)
fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Hkdf<Sha256> {
    let (mut prk, hk) = Hkdf::<Sha256>::extract(salt, ikm);
    prk.as_mut_slice().zeroize();
    hk
}

fn expand(hk: &Hkdf<Sha256>, info: &[u8]) -> Key {
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut out[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Key::from_bytes(*out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    const FAST: KdfParams = KdfParams::INSECURE_FAST;
    const SALT: [u8; 16] = [0x20; 16];
    const ACCOUNT: AccountId = [0x10; 16];

    fn sk(b: u8) -> SecretKey {
        SecretKey::from_bytes([b; 16])
    }

    fn keys(pw: &str, salt: [u8; 16], secret: u8, account: AccountId) -> SyncKeys {
        derive_sync_keys(pw, &salt, FAST, &sk(secret), &account).unwrap()
    }

    /// RFC 5869 test case 1: pins the HKDF dependency.
    #[test]
    fn hkdf_sha256_rfc5869_case_1() {
        let hex = |s: &str| data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap();
        let hk = Hkdf::<Sha256>::new(Some(&hex("000102030405060708090a0b0c")), &[0x0b; 22]);
        let mut okm = [0u8; 42];
        hk.expand(&hex("f0f1f2f3f4f5f6f7f8f9"), &mut okm).unwrap();
        assert_eq!(
            data_encoding::HEXLOWER.encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn same_inputs_same_keys_and_kek_differs_from_auth() {
        let a = keys("pw", SALT, 1, ACCOUNT);
        let b = keys("pw", SALT, 1, ACCOUNT);
        assert_eq!(a.kek.as_bytes(), b.kek.as_bytes());
        assert_eq!(a.auth.as_bytes(), b.auth.as_bytes());
        assert_ne!(a.kek.as_bytes(), a.auth.as_bytes());
    }

    #[test]
    fn every_input_matters() {
        let base = keys("pw", SALT, 1, ACCOUNT);
        for other in [
            keys("pw2", SALT, 1, ACCOUNT),
            keys("pw", [0x21; 16], 1, ACCOUNT),
            keys("pw", SALT, 2, ACCOUNT),
            keys("pw", SALT, 1, [0x11; 16]),
        ] {
            assert_ne!(base.kek.as_bytes(), other.kek.as_bytes());
            assert_ne!(base.auth.as_bytes(), other.auth.as_bytes());
        }
    }

    #[test]
    fn remote_kdf_bounds_are_checked_before_argon2() {
        let start = std::time::Instant::now();
        for kdf in [
            KdfParams {
                m_kib: MAX_REMOTE_M_KIB + 1,
                ..FAST
            },
            KdfParams {
                t: MAX_REMOTE_T + 1,
                ..FAST
            },
            KdfParams {
                p: MAX_REMOTE_P + 1,
                ..FAST
            },
            KdfParams { t: 0, ..FAST },
        ] {
            let r = derive_sync_keys("pw", &SALT, kdf, &sk(1), &ACCOUNT);
            assert!(
                matches!(r, Err(Error::Malformed(_) | Error::Core(_))),
                "{kdf:?}"
            );
        }
        assert!(start.elapsed().as_secs() < 2);
        assert!(check_remote_kdf(&KdfParams::DEFAULT).is_ok());
    }

    #[test]
    fn remote_kdf_floor_is_enforced_for_headers_but_not_for_local_derivation() {
        assert!(check_remote_kdf(&KdfParams::DEFAULT).is_ok());
        for weak in [
            KdfParams {
                m_kib: MIN_REMOTE_M_KIB - 1,
                ..KdfParams::DEFAULT
            },
            KdfParams {
                t: MIN_REMOTE_T - 1,
                ..KdfParams::DEFAULT
            },
            FAST,
        ] {
            assert!(
                matches!(check_remote_kdf(&weak), Err(Error::Malformed(_))),
                "{weak:?}"
            );
        }
        // Deriving with cheap parameters the caller chose itself still works (vectors, tests).
        assert!(derive_sync_keys("pw", &SALT, FAST, &sk(1), &ACCOUNT).is_ok());
    }

    #[test]
    fn segment_key_depends_on_account_key_and_id() {
        let ak = Key::from_bytes([0x30; 32]);
        let base = segment_key(&ak, &ACCOUNT);
        assert_eq!(base.as_bytes(), segment_key(&ak, &ACCOUNT).as_bytes());
        assert_ne!(
            base.as_bytes(),
            segment_key(&Key::from_bytes([0x31; 32]), &ACCOUNT).as_bytes()
        );
        assert_ne!(base.as_bytes(), segment_key(&ak, &[0x11; 16]).as_bytes());
        assert_ne!(base.as_bytes(), ak.as_bytes());
    }
}
