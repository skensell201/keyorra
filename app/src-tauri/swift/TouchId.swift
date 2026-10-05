// Touch ID for Keepsake: a Secure Enclave key that only the current Touch ID set can use, and a
// login-keychain item for the wrapped account key. Called from Rust (src/touchid.rs) through C.
//
// Why this shape (see docs/superpowers/plans/2026-10-05-keepsake-desktop-2c.md, "Touch ID"):
// a Personal Team app can't get a provisioning profile, so the data-protection keychain and
// biometric keychain ACLs are unavailable (errSecMissingEntitlement). CryptoKit Secure Enclave
// keys need no entitlement, and the enclave itself enforces .biometryCurrentSet.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

// Status codes; keep in sync with `Status` in src/touchid.rs.
private let OK: Int32 = 0
private let CANCELLED: Int32 = 1
private let LOCKOUT: Int32 = 2
private let INVALID: Int32 = 3
private let UNAVAILABLE: Int32 = 4
private let NOT_FOUND: Int32 = 5
private let FAILED: Int32 = 6

private let account = "account-key"

@_cdecl("ks_biometry_available")
public func ks_biometry_available() -> Bool {
    LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
}

/// New enclave key usable only after Touch ID with the fingerprints enrolled right now.
/// Writes the key blob (`*blobLen` bytes) and its 65-byte X9.63 public key. Never prompts.
@_cdecl("ks_enclave_create")
public func ks_enclave_create(
    _ blobOut: UnsafeMutablePointer<UInt8>, _ blobCap: Int, _ blobLen: UnsafeMutablePointer<Int>,
    _ publicOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return UNAVAILABLE }
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], nil)
    else { return FAILED }
    guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access) else { return FAILED }
    let blob = key.dataRepresentation
    guard blob.count <= blobCap else { return FAILED }
    blob.copyBytes(to: blobOut, count: blob.count)
    blobLen.pointee = blob.count
    key.publicKey.x963Representation.copyBytes(to: publicOut, count: 65)
    return OK
}

/// ECDH between the enclave key and `peer` (65-byte X9.63). Shows the Touch ID prompt with
/// `reason`; blocks until the user answers. Writes the 32-byte shared secret.
@_cdecl("ks_enclave_agree")
public func ks_enclave_agree(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int, _ peer: UnsafePointer<UInt8>,
    _ reason: UnsafePointer<CChar>, _ sharedOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let context = LAContext()
    context.localizedReason = String(cString: reason)
    context.localizedFallbackTitle = "Use Password"
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: blobLen), authenticationContext: context)
        let peerKey = try P256.KeyAgreement.PublicKey(x963Representation: Data(bytes: peer, count: 65))
        let shared = try key.sharedSecretFromKeyAgreement(with: peerKey)
        shared.withUnsafeBytes { raw in
            sharedOut.update(from: raw.bindMemory(to: UInt8.self).baseAddress!, count: 32)
        }
        return OK
    } catch let error as LAError {
        switch error.code {
        case .userCancel, .appCancel, .systemCancel, .userFallback, .notInteractive: return CANCELLED
        case .biometryLockout: return LOCKOUT
        case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet: return UNAVAILABLE
        default: return INVALID
        }
    } catch {
        // Fingerprints changed (the key is gone for good) or the blob is damaged.
        return INVALID
    }
}

private func baseQuery(_ service: UnsafePointer<CChar>) -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: String(cString: service),
        kSecAttrAccount as String: account,
        // The file-based login keychain: its default access list trusts only the app that
        // created the item (its designated requirement), so other apps get a password dialog.
        kSecUseDataProtectionKeychain as String: false,
    ]
}

/// Keychain dialogs are never shown: an item this build may not touch makes the call fail.
private func withoutDialogs<T>(_ body: () -> T) -> T {
    SecKeychainSetUserInteractionAllowed(false)
    defer { SecKeychainSetUserInteractionAllowed(true) }
    return body()
}

@_cdecl("ks_keychain_save")
public func ks_keychain_save(_ service: UnsafePointer<CChar>, _ data: UnsafePointer<UInt8>, _ len: Int) -> Int32 {
    withoutDialogs {
        SecItemDelete(baseQuery(service) as CFDictionary)
        var add = baseQuery(service)
        add[kSecAttrLabel as String] = "Keepsake Touch ID"
        add[kSecValueData as String] = Data(bytes: data, count: len)
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess ? OK : FAILED
    }
}

/// Reads the item. A build signed differently gets FAILED instead of a password dialog.
@_cdecl("ks_keychain_load")
public func ks_keychain_load(
    _ service: UnsafePointer<CChar>, _ out: UnsafeMutablePointer<UInt8>, _ cap: Int,
    _ len: UnsafeMutablePointer<Int>
) -> Int32 {
    var query = baseQuery(service)
    query[kSecReturnData as String] = true
    let context = LAContext()
    context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let status = withoutDialogs { SecItemCopyMatching(query as CFDictionary, &result) }
    if status == errSecItemNotFound { return NOT_FOUND }
    guard status == errSecSuccess, let data = result as? Data, data.count <= cap else { return FAILED }
    data.copyBytes(to: out, count: data.count)
    len.pointee = data.count
    return OK
}

@_cdecl("ks_keychain_delete")
public func ks_keychain_delete(_ service: UnsafePointer<CChar>) -> Int32 {
    let status = withoutDialogs { SecItemDelete(baseQuery(service) as CFDictionary) }
    return status == errSecSuccess || status == errSecItemNotFound ? OK : FAILED
}
