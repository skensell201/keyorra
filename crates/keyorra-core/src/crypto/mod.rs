mod aead;
mod kdf;
mod key;
mod keys;

#[cfg(any(test, feature = "test-utils"))]
pub use aead::seal_with_nonce;
pub use aead::{open, seal, seal_with_rng, NONCE_LEN};
pub use kdf::{derive_kek, KdfParams};
pub use key::Key;
pub use keys::{
    attachment_aad, change_password, create_header, header_for_account, item_aad, unlock,
    unwrap_vault_key, wrap_vault_key, Header, FORMAT_VERSION,
};
