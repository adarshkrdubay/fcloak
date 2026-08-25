use rand::RngExt;

use crate::{
    crypto::{
        NONCE_SIZE, decrypt_file_with_aad, encrypt_file_with_nonce, unwrap_dek, wrap_dek_with_nonce,
    },
    error::FcloakError,
    format::{HEADER_SIZE, Header, WRAPPED_DEK_SIZE},
    keys::{derive_key, generate_file_key, generate_salt},
};

/// Complete encrypted FCLOAK container.
///
/// Binary layout:
///
/// ```text
/// +----------------------+
/// | FCLOAK Header        |
/// | 77 bytes             |
/// +----------------------+
/// | Wrapped DEK          |
/// | 48 bytes             |
/// +----------------------+
/// | File Ciphertext      |
/// | variable             |
/// +----------------------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcloakContainer {
    /// FCLOAK format metadata.
    pub header: Header,

    /// Password-protected file encryption key.
    pub wrapped_dek: [u8; WRAPPED_DEK_SIZE],

    /// AES-256-GCM encrypted file contents.
    pub ciphertext: Vec<u8>,
}

impl FcloakContainer {
    /// Encrypt plaintext into a FCLOAK container.
    ///
    /// Encryption flow:
    ///
    /// ```text
    /// password
    ///    │
    ///    ▼
    /// Argon2id
    ///    │
    ///    ▼
    /// KEK
    ///    │
    ///    │
    ///    ├───────────────┐
    ///    │               │
    ///    ▼               │
    /// wrap DEK           │
    ///    │               │
    ///    ▼               │
    /// wrapped DEK        │
    ///
    /// random DEK ────────┘
    ///    │
    ///    ▼
    /// AES-256-GCM
    ///    │
    ///    ▼
    /// ciphertext
    /// ```
    pub fn encrypt(password: &[u8], plaintext: &[u8]) -> Result<Self, FcloakError> {
        // Generate a unique salt for this container.
        let salt = generate_salt();

        // Generate a random 256-bit DEK.
        //
        // The DEK encrypts the actual file.
        let dek = generate_file_key();

        // Generate independent nonces.
        //
        // These nonces are generated here because the container
        // header owns the nonce values.
        let mut dek_wrap_nonce = [0u8; NONCE_SIZE];
        let mut file_nonce = [0u8; NONCE_SIZE];

        rand::rng().fill(&mut dek_wrap_nonce);
        rand::rng().fill(&mut file_nonce);

        // Build the container header.
        let header = Header::new(salt, dek_wrap_nonce, file_nonce);

        // Derive the key-encryption key from the password.
        //
        // KEK = Argon2id(password, salt)
        let kek = derive_key(password, &salt)?;

        // Wrap the random DEK using the KEK.
        //
        // The nonce comes directly from the header.
        let wrapped = wrap_dek_with_nonce(&kek, &dek, &header.dek_wrap_nonce)?;

        // The AES-GCM authentication data is the complete
        // serialized header.
        //
        // This means modifying any authenticated header field
        // causes file decryption to fail.
        let header_bytes = header.encode();

        // Encrypt the actual file using the random DEK.
        //
        // Again, the nonce comes directly from the header.
        let encrypted =
            encrypt_file_with_nonce(&dek, plaintext, &header.file_nonce, &header_bytes)?;

        // AES-256-GCM adds a 16-byte authentication tag.
        //
        // DEK is 32 bytes, therefore:
        //
        // 32 + 16 = 48 bytes.
        if wrapped.ciphertext.len() != WRAPPED_DEK_SIZE {
            return Err(FcloakError::Crypto);
        }

        let mut wrapped_dek = [0u8; WRAPPED_DEK_SIZE];

        wrapped_dek.copy_from_slice(&wrapped.ciphertext);

        Ok(Self {
            header,
            wrapped_dek,
            ciphertext: encrypted.ciphertext,
        })
    }

    /// Decrypt a FCLOAK container using the password.
    pub fn decrypt(&self, password: &[u8]) -> Result<Vec<u8>, FcloakError> {
        // Derive the same KEK from the stored salt.
        let kek = derive_key(password, &self.header.salt)?;

        // Recover the DEK.
        //
        // If the password is wrong, AES-GCM authentication
        // fails here.
        let dek = unwrap_dek(&kek, &self.header.dek_wrap_nonce, &self.wrapped_dek)?;

        // Reconstruct the exact header bytes.
        //
        // Because these bytes are used as AAD, modifying the
        // header causes authentication failure.
        let header_bytes = self.header.encode();

        // Decrypt and authenticate the file.
        decrypt_file_with_aad(
            &dek,
            &self.header.file_nonce,
            &self.ciphertext,
            &header_bytes,
        )
    }

    /// Serialize the complete container into binary form.
    ///
    /// Layout:
    ///
    /// ```text
    /// [HEADER]
    /// [WRAPPED_DEK]
    /// [CIPHERTEXT]
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let header = self.header.encode();

        let mut output = Vec::with_capacity(HEADER_SIZE + WRAPPED_DEK_SIZE + self.ciphertext.len());

        output.extend_from_slice(&header);

        output.extend_from_slice(&self.wrapped_dek);

        output.extend_from_slice(&self.ciphertext);

        output
    }

    /// Parse a serialized FCLOAK container.
    pub fn decode(input: &[u8]) -> Result<Self, FcloakError> {
        // We need at least:
        //
        // header + wrapped DEK
        if input.len() < HEADER_SIZE + WRAPPED_DEK_SIZE {
            return Err(FcloakError::InvalidFormat);
        }

        // Parse and validate the header.
        let header =
            Header::decode(&input[..HEADER_SIZE]).map_err(|_| FcloakError::InvalidFormat)?;

        // Wrapped DEK starts immediately after header.
        let wrapped_start = HEADER_SIZE;

        let wrapped_end = wrapped_start + WRAPPED_DEK_SIZE;

        let mut wrapped_dek = [0u8; WRAPPED_DEK_SIZE];

        wrapped_dek.copy_from_slice(&input[wrapped_start..wrapped_end]);

        // Everything remaining is encrypted file data.
        let ciphertext = input[wrapped_end..].to_vec();

        // AES-256-GCM ciphertext must contain
        // at least the 16-byte authentication tag.
        if ciphertext.len() < 16 {
            return Err(FcloakError::InvalidFormat);
        }

        Ok(Self {
            header,
            wrapped_dek,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt() {
        let password = b"correct horse battery staple";

        let plaintext = b"FCLOAK secret document";

        let container = FcloakContainer::encrypt(password, plaintext).unwrap();

        let recovered = container.decrypt(password).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let password = b"correct password";

        let wrong_password = b"wrong password";

        let container = FcloakContainer::encrypt(password, b"secret data").unwrap();

        let result = container.decrypt(wrong_password);

        assert!(result.is_err());
    }

    #[test]
    fn container_round_trip() {
        let password = b"FCLOAK password";

        let plaintext = b"serialized FCLOAK data";

        let original = FcloakContainer::encrypt(password, plaintext).unwrap();

        let encoded = original.encode();

        let decoded = FcloakContainer::decode(&encoded).unwrap();

        let recovered = decoded.decrypt(password).unwrap();

        assert_eq!(recovered, plaintext);

        assert_eq!(decoded.header, original.header);

        assert_eq!(decoded.wrapped_dek, original.wrapped_dek);

        assert_eq!(decoded.ciphertext, original.ciphertext);
    }

    #[test]
    fn modified_header_is_rejected() {
        let password = b"FCLOAK password";

        let mut container = FcloakContainer::encrypt(password, b"secret").unwrap();

        // Changing an authenticated header field
        // must invalidate the file.
        container.header.memory_kib += 1;

        let result = container.decrypt(password);

        assert!(result.is_err());
    }

    #[test]
    fn modified_wrapped_dek_is_rejected() {
        let password = b"FCLOAK password";

        let mut container = FcloakContainer::encrypt(password, b"secret").unwrap();

        container.wrapped_dek[0] ^= 0x01;

        let result = container.decrypt(password);

        assert!(result.is_err());
    }

    #[test]
    fn modified_ciphertext_is_rejected() {
        let password = b"FCLOAK password";

        let mut container = FcloakContainer::encrypt(password, b"secret").unwrap();

        container.ciphertext[0] ^= 0x01;

        let result = container.decrypt(password);

        assert!(result.is_err());
    }

    #[test]
    fn encrypted_containers_use_different_deks() {
        let password = b"same password";

        let plaintext = b"same plaintext";

        let first = FcloakContainer::encrypt(password, plaintext).unwrap();

        let second = FcloakContainer::encrypt(password, plaintext).unwrap();

        // Different random DEKs mean the wrapped DEKs
        // should also differ.
        assert_ne!(first.wrapped_dek, second.wrapped_dek);

        // Different salts.
        assert_ne!(first.header.salt, second.header.salt);

        // Different file nonces.
        assert_ne!(first.header.file_nonce, second.header.file_nonce);

        // Different DEK wrapping nonces.
        assert_ne!(first.header.dek_wrap_nonce, second.header.dek_wrap_nonce);
    }

    #[test]
    fn encoded_container_has_expected_structure() {
        let container = FcloakContainer::encrypt(b"password", b"hello FCLOAK").unwrap();

        let encoded = container.encode();

        assert!(encoded.len() >= HEADER_SIZE + WRAPPED_DEK_SIZE + 16);

        assert_eq!(&encoded[..6], b"FCLOAK");
    }

    #[test]
    fn truncated_container_is_rejected() {
        let result = FcloakContainer::decode(&[0u8; 10]);

        assert!(result.is_err());
    }

    #[test]
    fn modified_serialized_header_is_rejected() {
        let password = b"FCLOAK password";

        let mut encoded = FcloakContainer::encrypt(password, b"important data")
            .unwrap()
            .encode();

        // Modify a header byte after serialization.
        //
        // Offset 0 is part of MAGIC, so this also verifies
        // header validation.
        encoded[0] ^= 0x01;

        let result = FcloakContainer::decode(&encoded);

        assert!(result.is_err());
    }
}
