//! Joining an existing account from the header files in the store (spec §4.7).
//!
//! Only the highest epoch present is used. If several files share it (two devices changed
//! the master password concurrently), they are tried in ascending author order. There is no
//! fallback to a lower epoch, even if the password fails: an old password must not open the
//! account. A header that unlocks still counts only once the joined device finds the same
//! header as a signed log entry of its author ([`Engine::header_confirmed`]).
//!
//! [`Engine::header_confirmed`]: crate::engine::Engine::header_confirmed

use ed25519_dalek::VerifyingKey;
use keyorra_core::crypto::Key;

use crate::error::{Error, Result};
use crate::header::{Header, HeaderFile};
use crate::secret_key::SecretKey;
use crate::transport::Fetched;
use crate::DeviceId;

/// The header files a joining device may try, best first: well-formed, stored under their
/// proper name, highest epoch only, ascending author.
pub fn join_candidates(files: &[(String, Fetched<Vec<u8>>)]) -> Vec<HeaderFile> {
    let mut decoded: Vec<HeaderFile> = files
        .iter()
        .filter_map(|(name, f)| match f {
            Fetched::Ready(bytes) => HeaderFile::decode(bytes)
                .ok()
                .filter(|h| h.file_name() == *name),
            _ => None,
        })
        .collect();
    let Some(top) = decoded.iter().map(|h| h.header.epoch).max() else {
        return Vec::new();
    };
    decoded.retain(|h| h.header.epoch == top);
    decoded.sort_by_key(|h| h.author);
    decoded
}

/// The main device as the setup code shown by an existing device names it (its id and the
/// code of its key). Joining with it ignores headers naming another main device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootPin {
    pub device: DeviceId,
    pub key_fingerprint: String,
}

fn names(h: &Header, pin: &RootPin) -> bool {
    h.root_device == pin.device
        && VerifyingKey::from_bytes(&h.root_key)
            .is_ok_and(|k| crate::trust::key_fingerprint(&k) == pin.key_fingerprint)
}

/// The header a device joined with, its account key, and whether the header files in the
/// store disagree about the main device (shown as a warning: someone with the password and
/// Secret Key may have published a header naming another main device).
pub struct Joined {
    pub file: HeaderFile,
    pub account_key: Key,
    pub roots_disagree: bool,
}

/// Tries the candidates with `unlock`; the first that opens wins. With a `pin` (from the
/// setup code of an existing device) only headers naming that main device are considered,
/// the highest such epoch first. Without one (joining with the Emergency Kit alone) the
/// newest header is trusted, whichever main device it names.
pub fn unlock_join_with(
    files: &[(String, Fetched<Vec<u8>>)],
    pin: Option<&RootPin>,
    mut unlock: impl FnMut(&Header) -> Result<Key>,
) -> Result<Joined> {
    let all: Vec<HeaderFile> = files
        .iter()
        .filter_map(|(name, f)| match f {
            Fetched::Ready(bytes) => HeaderFile::decode(bytes)
                .ok()
                .filter(|h| h.file_name() == *name),
            _ => None,
        })
        .collect();
    let candidates = match pin {
        None => join_candidates(files),
        Some(pin) => {
            let matching: Vec<(String, Fetched<Vec<u8>>)> = files
                .iter()
                .filter(|(_, f)| match f {
                    Fetched::Ready(b) => HeaderFile::decode(b).is_ok_and(|h| names(&h.header, pin)),
                    _ => false,
                })
                .cloned()
                .collect();
            join_candidates(&matching)
        }
    };
    if candidates.is_empty() {
        return Err(Error::NotFound("no account header in this location".into()));
    }
    for candidate in candidates {
        if let Ok(account_key) = unlock(&candidate.header) {
            let roots_disagree = all.iter().any(|h| {
                h.header.root_device != candidate.header.root_device
                    || h.header.root_key != candidate.header.root_key
            });
            return Ok(Joined {
                file: candidate,
                account_key,
                roots_disagree,
            });
        }
    }
    Err(Error::WrongPassword)
}

/// Joins with the master password and the Secret Key.
pub fn unlock_join(
    files: &[(String, Fetched<Vec<u8>>)],
    pin: Option<&RootPin>,
    password: &str,
    secret_key: &SecretKey,
) -> Result<Joined> {
    unlock_join_with(files, pin, |h| {
        h.unlock(password, secret_key).map(|(k, _)| k)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::tests::sample_header;
    use ed25519_dalek::SigningKey;

    fn file(epoch: u32, author: u8, tag: u8) -> (String, Fetched<Vec<u8>>) {
        let mut header = sample_header();
        header.epoch = epoch;
        header.salt = [tag; 16];
        let f = HeaderFile::sign(header, [author; 16], &SigningKey::from_bytes(&[author; 32]));
        (f.file_name(), Fetched::Ready(f.encode()))
    }

    fn salt_of(h: &HeaderFile) -> u8 {
        h.header.salt[0]
    }

    #[test]
    fn only_the_highest_epoch_in_author_order() {
        let files = vec![
            file(1, 1, 10),
            file(2, 3, 23),
            file(2, 2, 22),
            file(1, 4, 14),
        ];
        let c = join_candidates(&files);
        assert_eq!(c.iter().map(salt_of).collect::<Vec<_>>(), vec![22, 23]);
    }

    #[test]
    fn junk_renamed_and_pending_files_are_ignored() {
        let (_, good) = file(1, 1, 10);
        let files = vec![
            ("00000009-ff.hdr".to_owned(), good),
            ("x".to_owned(), Fetched::Ready(b"junk".to_vec())),
            ("00000005-aa.hdr".to_owned(), Fetched::Pending),
            file(1, 2, 12),
        ];
        assert_eq!(
            join_candidates(&files)
                .iter()
                .map(salt_of)
                .collect::<Vec<_>>(),
            vec![12]
        );
    }

    #[test]
    fn no_fallback_to_an_older_epoch() {
        let files = vec![file(1, 1, 10), file(2, 1, 20)];
        // Only the epoch-1 header would open (the old password): joining must fail.
        let result = unlock_join_with(&files, None, |h| {
            if h.salt[0] == 10 {
                Ok(Key::from_bytes([1; 32]))
            } else {
                Err(Error::WrongPassword)
            }
        });
        assert!(matches!(result, Err(Error::WrongPassword)));
        let chosen = unlock_join_with(&files, None, |h| {
            if h.salt[0] == 20 {
                Ok(Key::from_bytes([2; 32]))
            } else {
                Err(Error::WrongPassword)
            }
        })
        .unwrap();
        assert_eq!(chosen.file.header.epoch, 2);
        assert!(matches!(
            unlock_join_with(&[], None, |_| unreachable!()),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn concurrent_epochs_try_the_next_author() {
        let files = vec![file(2, 1, 21), file(2, 2, 22)];
        let chosen = unlock_join_with(&files, None, |h| {
            if h.salt[0] == 22 {
                Ok(Key::from_bytes([2; 32]))
            } else {
                Err(Error::WrongPassword)
            }
        })
        .unwrap();
        assert_eq!(chosen.file.author, [2; 16]);
    }

    fn file_with_root(epoch: u32, author: u8, root_key: [u8; 32]) -> (String, Fetched<Vec<u8>>) {
        let mut header = sample_header();
        header.epoch = epoch;
        header.root_device = [author; 16];
        header.root_key = root_key;
        header.salt = [epoch as u8; 16];
        let f = HeaderFile::sign(header, [author; 16], &SigningKey::from_bytes(&[author; 32]));
        (f.file_name(), Fetched::Ready(f.encode()))
    }

    #[test]
    fn review_i2_a_pin_from_the_setup_code_skips_headers_naming_another_root() {
        let real = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        let thief = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let files = vec![file_with_root(1, 1, real), file_with_root(5, 9, thief)];
        let pin = RootPin {
            device: [1; 16],
            key_fingerprint: crate::trust::key_fingerprint(
                &ed25519_dalek::VerifyingKey::from_bytes(&real).unwrap(),
            ),
        };
        let joined =
            unlock_join_with(&files, Some(&pin), |_| Ok(Key::from_bytes([1; 32]))).unwrap();
        assert_eq!(joined.file.header.epoch, 1);
        assert!(joined.roots_disagree);
        // Without a pin (Emergency Kit only) the newest header wins, with a warning.
        let joined = unlock_join_with(&files, None, |_| Ok(Key::from_bytes([1; 32]))).unwrap();
        assert_eq!(joined.file.header.root_device, [9; 16]);
        assert!(joined.roots_disagree);
        let agreeing = vec![file_with_root(1, 1, real), file_with_root(2, 1, real)];
        let joined = unlock_join_with(&agreeing, None, |_| Ok(Key::from_bytes([1; 32]))).unwrap();
        assert!(!joined.roots_disagree);
    }

    #[test]
    fn the_real_unlock_refuses_cheap_kdf_parameters_from_storage() {
        // `sample_header` uses test-only Argon2 parameters, below the floor for synced headers.
        let files = vec![file(1, 1, 10)];
        let sk = SecretKey::from_bytes([1; 16]);
        assert!(unlock_join(&files, None, "pw", &sk).is_err());
    }
}
