//! Joining an existing account from the header files in the store (spec §4.7).
//!
//! Only the highest epoch present is used. If several files share it (two devices changed
//! the master password concurrently), they are tried in ascending author order. There is no
//! fallback to a lower epoch, even if the password fails: an old password must not open the
//! account. A header that unlocks still counts only once the joined device finds the same
//! header as a signed log entry of its author ([`Engine::header_confirmed`]).
//!
//! [`Engine::header_confirmed`]: crate::engine::Engine::header_confirmed

use keyorra_core::crypto::Key;

use crate::error::{Error, Result};
use crate::header::{Header, HeaderFile};
use crate::secret_key::SecretKey;
use crate::transport::Fetched;

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

/// Tries the candidates with `unlock`; the first that opens wins.
pub fn unlock_join_with(
    files: &[(String, Fetched<Vec<u8>>)],
    mut unlock: impl FnMut(&Header) -> Result<Key>,
) -> Result<(HeaderFile, Key)> {
    let candidates = join_candidates(files);
    if candidates.is_empty() {
        return Err(Error::NotFound("no account header in this location".into()));
    }
    for candidate in candidates {
        if let Ok(key) = unlock(&candidate.header) {
            return Ok((candidate, key));
        }
    }
    Err(Error::WrongPassword)
}

/// Joins with the master password and the Secret Key.
pub fn unlock_join(
    files: &[(String, Fetched<Vec<u8>>)],
    password: &str,
    secret_key: &SecretKey,
) -> Result<(HeaderFile, Key)> {
    unlock_join_with(files, |h| h.unlock(password, secret_key).map(|(k, _)| k))
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
        let result = unlock_join_with(&files, |h| {
            if h.salt[0] == 10 {
                Ok(Key::from_bytes([1; 32]))
            } else {
                Err(Error::WrongPassword)
            }
        });
        assert!(matches!(result, Err(Error::WrongPassword)));
        let (chosen, _) = unlock_join_with(&files, |h| {
            if h.salt[0] == 20 {
                Ok(Key::from_bytes([2; 32]))
            } else {
                Err(Error::WrongPassword)
            }
        })
        .unwrap();
        assert_eq!(chosen.header.epoch, 2);
        assert!(matches!(
            unlock_join_with(&[], |_| unreachable!()),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn concurrent_epochs_try_the_next_author() {
        let files = vec![file(2, 1, 21), file(2, 2, 22)];
        let (chosen, _) = unlock_join_with(&files, |h| {
            if h.salt[0] == 22 {
                Ok(Key::from_bytes([2; 32]))
            } else {
                Err(Error::WrongPassword)
            }
        })
        .unwrap();
        assert_eq!(chosen.author, [2; 16]);
    }

    #[test]
    fn the_real_unlock_refuses_cheap_kdf_parameters_from_storage() {
        // `sample_header` uses test-only Argon2 parameters, below the floor for synced headers.
        let files = vec![file(1, 1, 10)];
        let sk = SecretKey::from_bytes([1; 16]);
        assert!(unlock_join(&files, "pw", &sk).is_err());
    }
}
