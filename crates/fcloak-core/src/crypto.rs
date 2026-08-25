use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngExt;

use crate::error::FcloakError;

pub const NONCE_SIZE: usize = 12;
pub const DEK_SIZE: usize = 32;

const FILE_AAD: &[u8] = b"FCLOAK-FILE-v1";
const DEK_AAD: &[u8] = b"FCLOAK-DEK-v1";

#[derive(Debug)]
pub struct EncryptedData {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub struct WrappedKey {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

/// Encrypt file data using a 256-bit DEK.
pub fn encrypt_file(dek: &[u8; DEK_SIZE], plaintext: &[u8]) -> Result<EncryptedData, FcloakError> {
    encrypt_with_aad(dek, plaintext, FILE_AAD)
}

/// Decrypt file data using a 256-bit DEK.
pub fn decrypt_file(
    dek: &[u8; DEK_SIZE],
    nonce_bytes: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, FcloakError> {
    decrypt_with_aad(dek, nonce_bytes, ciphertext, FILE_AAD)
}

/// Encrypt file data using caller-provided AAD.
pub fn encrypt_file_with_aad(
    dek: &[u8; DEK_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedData, FcloakError> {
    encrypt_with_aad(dek, plaintext, aad)
}

/// Encrypt file data using an explicitly supplied nonce and AAD.
pub fn encrypt_file_with_nonce(
    dek: &[u8; DEK_SIZE],
    plaintext: &[u8],
    nonce_bytes: &[u8; NONCE_SIZE],
    aad: &[u8],
) -> Result<EncryptedData, FcloakError> {
    encrypt_with_nonce(dek, plaintext, nonce_bytes, aad)
}

/// Decrypt file data using caller-provided AAD.
pub fn decrypt_file_with_aad(
    dek: &[u8; DEK_SIZE],
    nonce_bytes: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, FcloakError> {
    decrypt_with_aad(dek, nonce_bytes, ciphertext, aad)
}

/// Wrap a file DEK using the user's KEK.
pub fn wrap_dek(kek: &[u8; DEK_SIZE], dek: &[u8; DEK_SIZE]) -> Result<WrappedKey, FcloakError> {
    let mut nonce_bytes = [0u8; NONCE_SIZE];

    rand::rng().fill(&mut nonce_bytes);

    wrap_dek_with_nonce(kek, dek, &nonce_bytes)
}

/// Wrap a DEK using an explicitly supplied nonce.
pub fn wrap_dek_with_nonce(
    kek: &[u8; DEK_SIZE],
    dek: &[u8; DEK_SIZE],
    nonce_bytes: &[u8; NONCE_SIZE],
) -> Result<WrappedKey, FcloakError> {
    let encrypted = encrypt_with_nonce(kek, dek, nonce_bytes, DEK_AAD)?;

    Ok(WrappedKey {
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
    })
}

/// Unwrap a file DEK using the user's KEK.
pub fn unwrap_dek(
    kek: &[u8; DEK_SIZE],
    nonce_bytes: &[u8; NONCE_SIZE],
    wrapped_dek: &[u8],
) -> Result<[u8; DEK_SIZE], FcloakError> {
    let plaintext = decrypt_with_aad(kek, nonce_bytes, wrapped_dek, DEK_AAD)?;

    if plaintext.len() != DEK_SIZE {
        return Err(FcloakError::Crypto);
    }

    let mut dek = [0u8; DEK_SIZE];

    dek.copy_from_slice(&plaintext);

    Ok(dek)
}

/// Internal encryption helper using a randomly generated nonce.
fn encrypt_with_aad(
    key_bytes: &[u8; DEK_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedData, FcloakError> {
    let mut nonce_bytes = [0u8; NONCE_SIZE];

    rand::rng().fill(&mut nonce_bytes);

    encrypt_with_nonce(key_bytes, plaintext, &nonce_bytes, aad)
}

/// Internal encryption helper using an explicit nonce.
fn encrypt_with_nonce(
    key_bytes: &[u8; DEK_SIZE],
    plaintext: &[u8],
    nonce_bytes: &[u8; NONCE_SIZE],
    aad: &[u8],
) -> Result<EncryptedData, FcloakError> {
    let key = Key::<Aes256Gcm>::try_from(key_bytes.as_slice()).map_err(|_| FcloakError::Crypto)?;

    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| FcloakError::Crypto)?;

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| FcloakError::Crypto)?;

    Ok(EncryptedData {
        nonce: *nonce_bytes,
        ciphertext,
    })
}

/// Internal AES-256-GCM decryption helper.
fn decrypt_with_aad(
    key_bytes: &[u8; DEK_SIZE],
    nonce_bytes: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, FcloakError> {
    let key = Key::<Aes256Gcm>::try_from(key_bytes.as_slice()).map_err(|_| FcloakError::Crypto)?;

    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| FcloakError::Crypto)?;

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| FcloakError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_file_key;

    #[test]
    fn file_encrypt_then_decrypt() {
        let dek = generate_file_key();

        let plaintext = b"FCLOAK secret data";

        let encrypted = encrypt_file(&dek, plaintext).unwrap();

        let decrypted = decrypt_file(&dek, &encrypted.nonce, &encrypted.ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn file_encryption_produces_different_nonces() {
        let dek = generate_file_key();

        let plaintext = b"same plaintext";

        let first = encrypt_file(&dek, plaintext).unwrap();

        let second = encrypt_file(&dek, plaintext).unwrap();

        assert_ne!(first.nonce, second.nonce);
    }

    #[test]
    fn modified_file_ciphertext_is_rejected() {
        let dek = generate_file_key();

        let encrypted = encrypt_file(&dek, b"FCLOAK secret data").unwrap();

        let mut modified = encrypted.ciphertext.clone();

        modified[0] ^= 0x01;

        let result = decrypt_file(&dek, &encrypted.nonce, &modified);

        assert!(result.is_err());
    }

    #[test]
    fn wrong_file_key_is_rejected() {
        let dek = generate_file_key();
        let wrong_dek = generate_file_key();

        let encrypted = encrypt_file(&dek, b"FCLOAK secret data").unwrap();

        let result = decrypt_file(&wrong_dek, &encrypted.nonce, &encrypted.ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn wrap_then_unwrap_dek() {
        let kek = generate_file_key();
        let dek = generate_file_key();

        let wrapped = wrap_dek(&kek, &dek).unwrap();

        let recovered = unwrap_dek(&kek, &wrapped.nonce, &wrapped.ciphertext).unwrap();

        assert_eq!(recovered, dek);
    }

    #[test]
    fn wrong_kek_cannot_unwrap_dek() {
        let kek = generate_file_key();
        let wrong_kek = generate_file_key();
        let dek = generate_file_key();

        let wrapped = wrap_dek(&kek, &dek).unwrap();

        let result = unwrap_dek(&wrong_kek, &wrapped.nonce, &wrapped.ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn modified_wrapped_dek_is_rejected() {
        let kek = generate_file_key();
        let dek = generate_file_key();

        let wrapped = wrap_dek(&kek, &dek).unwrap();

        let mut modified = wrapped.ciphertext.clone();

        modified[0] ^= 0x01;

        let result = unwrap_dek(&kek, &wrapped.nonce, &modified);

        assert!(result.is_err());
    }

    #[test]
    fn wrapped_dek_uses_different_nonce_each_time() {
        let kek = generate_file_key();
        let dek = generate_file_key();

        let first = wrap_dek(&kek, &dek).unwrap();

        let second = wrap_dek(&kek, &dek).unwrap();

        assert_ne!(first.nonce, second.nonce);
    }

    #[test]
    fn file_and_dek_domains_are_separated() {
        let key = generate_file_key();

        let data = b"FCLOAK secret";

        let file_encrypted = encrypt_file(&key, data).unwrap();

        let result = unwrap_dek(&key, &file_encrypted.nonce, &file_encrypted.ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn modified_aad_is_rejected() {
        let dek = generate_file_key();

        let plaintext = b"FCLOAK secret data";

        let aad = b"FCLOAK-HEADER-v1";

        let encrypted = encrypt_file_with_aad(&dek, plaintext, aad).unwrap();

        let modified_aad = b"FCLOAK-HEADER-v2";

        let result =
            decrypt_file_with_aad(&dek, &encrypted.nonce, &encrypted.ciphertext, modified_aad);

        assert!(result.is_err());
    }

    #[test]
    fn correct_aad_allows_decryption() {
        let dek = generate_file_key();

        let plaintext = b"FCLOAK secret data";

        let aad = b"FCLOAK-HEADER-v1";

        let encrypted = encrypt_file_with_aad(&dek, plaintext, aad).unwrap();

        let decrypted =
            decrypt_file_with_aad(&dek, &encrypted.nonce, &encrypted.ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn explicit_nonce_is_preserved() {
        let dek = generate_file_key();

        let nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"FCLOAK explicit nonce";

        let encrypted =
            encrypt_file_with_nonce(&dek, plaintext, &nonce, b"FCLOAK-FILE-v1").unwrap();

        assert_eq!(encrypted.nonce, nonce);

        let decrypted =
            decrypt_file_with_aad(&dek, &nonce, &encrypted.ciphertext, b"FCLOAK-FILE-v1").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn explicit_dek_wrap_nonce_is_preserved() {
        let kek = generate_file_key();
        let dek = generate_file_key();

        let nonce = [0x37u8; NONCE_SIZE];

        let wrapped = wrap_dek_with_nonce(&kek, &dek, &nonce).unwrap();

        assert_eq!(wrapped.nonce, nonce);

        let recovered = unwrap_dek(&kek, &nonce, &wrapped.ciphertext).unwrap();

        assert_eq!(recovered, dek);
    }
}
