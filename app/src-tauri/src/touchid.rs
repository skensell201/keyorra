//! Safe wrappers over swift/TouchId.swift: the Secure Enclave key and the keychain item.

use std::ffi::CString;

use zeroize::Zeroizing;

/// Keychain service of the Touch ID record. Debug builds are signed ad hoc and can't read the
/// release app's item (or the other way round), so they keep their own.
pub const SERVICE: &str = if cfg!(debug_assertions) {
    "app.keyorra.mac.touchid.dev"
} else {
    "app.keyorra.mac.touchid"
};

/// Why a call failed; mirrors the status codes in TouchId.swift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Cancelled,
    Lockout,
    /// Fingerprints changed or the key is damaged: Touch ID must be set up again.
    Invalid,
    Unavailable,
    NotFound,
    Failed,
}

fn check(code: i32) -> Result<(), Failure> {
    match code {
        0 => Ok(()),
        1 => Err(Failure::Cancelled),
        2 => Err(Failure::Lockout),
        3 => Err(Failure::Invalid),
        4 => Err(Failure::Unavailable),
        5 => Err(Failure::NotFound),
        _ => Err(Failure::Failed),
    }
}

const MAX_BLOB: usize = 4096;
const MAX_RECORD: usize = 16 * 1024;

#[cfg(target_os = "macos")]
mod ffi {
    use std::os::raw::c_char;

    extern "C" {
        pub fn ks_biometry_available() -> bool;
        pub fn ks_enclave_create(
            blob: *mut u8,
            cap: usize,
            len: *mut usize,
            public: *mut u8,
        ) -> i32;
        pub fn ks_device_enclave_create(
            blob: *mut u8,
            cap: usize,
            len: *mut usize,
            public: *mut u8,
        ) -> i32;
        pub fn ks_enclave_agree(
            blob: *const u8,
            len: usize,
            peer: *const u8,
            reason: *const c_char,
            shared: *mut u8,
        ) -> i32;
        pub fn ks_keychain_save(service: *const c_char, data: *const u8, len: usize) -> i32;
        pub fn ks_keychain_load(
            service: *const c_char,
            out: *mut u8,
            cap: usize,
            len: *mut usize,
        ) -> i32;
        pub fn ks_keychain_delete(service: *const c_char) -> i32;
    }
}

/// Without macOS there is no Touch ID: every call reports it unavailable.
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
mod ffi {
    use std::os::raw::c_char;

    pub unsafe fn ks_biometry_available() -> bool {
        false
    }
    pub unsafe fn ks_enclave_create(_: *mut u8, _: usize, _: *mut usize, _: *mut u8) -> i32 {
        4
    }
    pub unsafe fn ks_device_enclave_create(_: *mut u8, _: usize, _: *mut usize, _: *mut u8) -> i32 {
        4
    }
    pub unsafe fn ks_enclave_agree(
        _: *const u8,
        _: usize,
        _: *const u8,
        _: *const c_char,
        _: *mut u8,
    ) -> i32 {
        4
    }
    pub unsafe fn ks_keychain_save(_: *const c_char, _: *const u8, _: usize) -> i32 {
        4
    }
    pub unsafe fn ks_keychain_load(_: *const c_char, _: *mut u8, _: usize, _: *mut usize) -> i32 {
        5
    }
    pub unsafe fn ks_keychain_delete(_: *const c_char) -> i32 {
        0
    }
}

/// This Mac has Touch ID with enrolled fingers. Never prompts.
pub fn available() -> bool {
    // SAFETY: no arguments.
    unsafe { ffi::ks_biometry_available() }
}

/// A new enclave key: (opaque blob, 65-byte public key). Never prompts.
pub fn create_key() -> Result<(Vec<u8>, [u8; 65]), Failure> {
    let mut blob = vec![0u8; MAX_BLOB];
    let mut len = 0usize;
    let mut public = [0u8; 65];
    // SAFETY: the buffers are as large as we say; Swift writes at most `cap` and 65 bytes.
    check(unsafe {
        ffi::ks_enclave_create(blob.as_mut_ptr(), blob.len(), &mut len, public.as_mut_ptr())
    })?;
    blob.truncate(len);
    Ok((blob, public))
}

/// A new enclave key for sync device keys (no Touch ID, this Mac only). Never prompts.
pub fn create_device_key() -> Result<(Vec<u8>, [u8; 65]), Failure> {
    let mut blob = vec![0u8; MAX_BLOB];
    let mut len = 0usize;
    let mut public = [0u8; 65];
    // SAFETY: the buffers are as large as we say; Swift writes at most `cap` and 65 bytes.
    check(unsafe {
        ffi::ks_device_enclave_create(blob.as_mut_ptr(), blob.len(), &mut len, public.as_mut_ptr())
    })?;
    blob.truncate(len);
    Ok((blob, public))
}

/// Shows the Touch ID prompt and returns the ECDH secret. Blocks until the user answers:
/// never call it while holding the session lock.
pub fn agree(blob: &[u8], peer: &[u8; 65], reason: &str) -> Result<Zeroizing<[u8; 32]>, Failure> {
    let reason = CString::new(reason).map_err(|_| Failure::Failed)?;
    let mut shared = Zeroizing::new([0u8; 32]);
    // SAFETY: pointers and lengths come from live buffers; Swift writes exactly 32 bytes.
    check(unsafe {
        ffi::ks_enclave_agree(
            blob.as_ptr(),
            blob.len(),
            peer.as_ptr(),
            reason.as_ptr(),
            shared.as_mut_ptr(),
        )
    })?;
    Ok(shared)
}

fn service(name: &str) -> CString {
    CString::new(name).expect("service names have no NUL")
}

pub fn keychain_save(name: &str, data: &[u8]) -> Result<(), Failure> {
    // SAFETY: a live C string and slice.
    check(unsafe { ffi::ks_keychain_save(service(name).as_ptr(), data.as_ptr(), data.len()) })
}

pub fn keychain_load(name: &str) -> Result<Vec<u8>, Failure> {
    let mut out = vec![0u8; MAX_RECORD];
    let mut len = 0usize;
    // SAFETY: Swift writes at most `cap` bytes.
    check(unsafe {
        ffi::ks_keychain_load(
            service(name).as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            &mut len,
        )
    })?;
    out.truncate(len);
    Ok(out)
}

pub fn keychain_delete(name: &str) -> Result<(), Failure> {
    // SAFETY: a live C string.
    check(unsafe { ffi::ks_keychain_delete(service(name).as_ptr()) })
}

/// A keychain read as the session wants it: no item is `Ok(None)`, any other failure is an
/// error (review A1d-2 I3).
fn found(result: Result<Vec<u8>, Failure>) -> Result<Option<Vec<u8>>, String> {
    match result {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Failure::NotFound) => Ok(None),
        Err(e) => Err(format!("{e:?}")),
    }
}

/// The login keychain as the session's Touch ID store.
pub struct MacKeyring;

impl keyorra_session::touchid::Keyring for MacKeyring {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        found(keychain_load(SERVICE))
    }
    fn save(&self, data: &[u8]) -> Result<(), String> {
        keychain_save(SERVICE, data).map_err(|e| format!("{e:?}"))
    }
    fn delete(&self) {
        let _ = keychain_delete(SERVICE);
    }
}

/// Keychain service of the sealed sync device keys (debug builds keep their own).
pub const DEVICE_KEYS_SERVICE: &str = if cfg!(debug_assertions) {
    "app.keyorra.mac.device-keys.dev"
} else {
    "app.keyorra.mac.device-keys"
};

/// The login-keychain item holding the sealed device keys.
pub struct DeviceKeysKeyring;

impl keyorra_session::touchid::Keyring for DeviceKeysKeyring {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        found(keychain_load(DEVICE_KEYS_SERVICE))
    }
    fn save(&self, data: &[u8]) -> Result<(), String> {
        keychain_save(DEVICE_KEYS_SERVICE, data).map_err(|e| format!("{e:?}"))
    }
    fn delete(&self) {
        let _ = keychain_delete(DEVICE_KEYS_SERVICE);
    }
}

/// This Mac's Secure Enclave for sync device keys (no prompts: the keys carry no Touch ID).
pub struct MacEnclave;

impl keyorra_session::sync::Enclave for MacEnclave {
    fn create(&self) -> Result<(Vec<u8>, [u8; 65]), String> {
        create_device_key().map_err(|e| format!("{e:?}"))
    }
    fn agree(
        &self,
        blob: &[u8],
        peer: &[u8; 65],
    ) -> Result<Zeroizing<[u8; 32]>, keyorra_session::sync::EnclaveError> {
        use keyorra_session::sync::EnclaveError;
        agree(blob, peer, "Keyorra sync").map_err(|e| match e {
            // The key is not this Mac's (restored from another one) or is gone.
            Failure::Invalid | Failure::NotFound => EnclaveError::Invalid,
            other => EnclaveError::Failed(format!("{other:?}")),
        })
    }
}

/// Sync device keys sealed to this Mac (plan A1d), handed to sync by the folder link.
pub fn device_keys() -> keyorra_session::sync::EnclaveDeviceKeys {
    keyorra_session::sync::EnclaveDeviceKeys::new(
        std::sync::Arc::new(DeviceKeysKeyring),
        std::sync::Arc::new(MacEnclave),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_map_to_failures() {
        assert_eq!(check(0), Ok(()));
        assert_eq!(check(1), Err(Failure::Cancelled));
        assert_eq!(check(2), Err(Failure::Lockout));
        assert_eq!(check(3), Err(Failure::Invalid));
        assert_eq!(check(4), Err(Failure::Unavailable));
        assert_eq!(check(5), Err(Failure::NotFound));
        assert_eq!(check(99), Err(Failure::Failed));
    }

    #[test]
    fn availability_never_prompts() {
        let _ = available();
    }

    /// Run by hand: `cargo test -p keyorra-app -- --ignored`. Creates a Secure Enclave key and a
    /// keychain item under a test service, then removes the item. Never shows a prompt.
    /// Run by hand: `cargo test -p keyorra-app -- --ignored`. Seals a device key to the
    /// Secure Enclave under a test service, reads it back without a prompt, removes it.
    #[test]
    #[ignore = "touches the Secure Enclave and the login keychain"]
    fn a_device_key_sealed_to_the_enclave_comes_back() {
        use keyorra_session::sync::{DeviceKeyStore, EnclaveDeviceKeys};
        struct TestItem;
        impl keyorra_session::touchid::Keyring for TestItem {
            fn load(&self) -> Result<Option<Vec<u8>>, String> {
                found(keychain_load("app.keyorra.mac.device-keys.test"))
            }
            fn save(&self, data: &[u8]) -> Result<(), String> {
                keychain_save("app.keyorra.mac.device-keys.test", data)
                    .map_err(|e| format!("{e:?}"))
            }
            fn delete(&self) {
                let _ = keychain_delete("app.keyorra.mac.device-keys.test");
            }
        }
        let mut keys = EnclaveDeviceKeys::new(
            std::sync::Arc::new(TestItem),
            std::sync::Arc::new(MacEnclave),
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        keys.store([1; 16], &key).unwrap();
        assert_eq!(keys.load(&[1; 16]).unwrap().unwrap().to_bytes(), [7; 32]);
        keychain_delete("app.keyorra.mac.device-keys.test").unwrap();
    }

    #[test]
    #[ignore = "touches the Secure Enclave and the login keychain"]
    fn enclave_key_and_keychain_round_trip() {
        const TEST: &str = "app.keyorra.mac.touchid.test";
        let (blob, public) = create_key().unwrap();
        assert!(!blob.is_empty());
        assert_eq!(public[0], 4, "uncompressed X9.63 point");
        keychain_save(TEST, &blob).unwrap();
        keychain_save(TEST, b"replaced").unwrap();
        assert_eq!(keychain_load(TEST).unwrap(), b"replaced");
        keychain_delete(TEST).unwrap();
        assert_eq!(keychain_load(TEST), Err(Failure::NotFound));
        keychain_delete(TEST).unwrap();
    }
}
