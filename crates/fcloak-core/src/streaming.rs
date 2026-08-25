use crate::{crypto::DEK_SIZE, error::FcloakError, format::NONCE_SIZE};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

/// Default streaming chunk size: 4 MiB.
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// AES-GCM authentication tag size.
pub const GCM_TAG_SIZE: usize = 16;

/// Maximum plaintext chunk size.
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Derive the AES-GCM nonce for a streaming chunk.
///
/// Layout:
///
/// ```text
/// [ 4-byte container prefix ][ 8-byte counter ]
/// ```
///
/// The prefix comes from a randomly generated container nonce.
/// The counter is incremented for each chunk.
///
/// `chunk_index == 0` returns the original counter unchanged.
///
/// Counter overflow is rejected instead of wrapping around, because
/// nonce reuse with AES-GCM would be catastrophic.
pub fn derive_chunk_nonce(
    base_nonce: &[u8; NONCE_SIZE],
    chunk_index: u64,
) -> Result<[u8; NONCE_SIZE], &'static str> {
    let mut nonce = *base_nonce;

    let mut counter_bytes = [0u8; 8];

    counter_bytes.copy_from_slice(&base_nonce[4..12]);

    let base_counter = u64::from_be_bytes(counter_bytes);

    let counter = base_counter
        .checked_add(chunk_index)
        .ok_or("chunk nonce counter overflow")?;

    nonce[4..12].copy_from_slice(&counter.to_be_bytes());

    Ok(nonce)
}
/// Size of the fixed chunk record prefix.
///
/// Layout:
///
/// ```text
/// [ 8 bytes chunk index ]
/// [ 4 bytes plaintext length ]
/// ```
///
/// Both values are stored in little-endian format.
pub const CHUNK_PREFIX_SIZE: usize = 8 + 4;

/// Maximum ciphertext size for one chunk.
///
/// AES-GCM adds a 16-byte authentication tag.
pub const MAX_CHUNK_CIPHERTEXT_SIZE: usize = MAX_CHUNK_SIZE + GCM_TAG_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkPrefix {
    pub index: u64,
    pub plaintext_len: u32,
}

impl ChunkPrefix {
    pub const SIZE: usize = CHUNK_PREFIX_SIZE;

    pub fn new(index: u64, plaintext_len: usize) -> Result<Self, &'static str> {
        if plaintext_len > MAX_CHUNK_SIZE {
            return Err("chunk is too large");
        }

        let plaintext_len = u32::try_from(plaintext_len).map_err(|_| "chunk length exceeds u32")?;

        Ok(Self {
            index,
            plaintext_len,
        })
    }

    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut output = [0u8; Self::SIZE];

        output[0..8].copy_from_slice(&self.index.to_le_bytes());

        output[8..12].copy_from_slice(&self.plaintext_len.to_le_bytes());

        output
    }

    pub fn decode(input: &[u8]) -> Result<Self, &'static str> {
        if input.len() < Self::SIZE {
            return Err("truncated chunk prefix");
        }

        let index = u64::from_le_bytes(input[0..8].try_into().map_err(|_| "invalid chunk index")?);

        let plaintext_len = u32::from_le_bytes(
            input[8..12]
                .try_into()
                .map_err(|_| "invalid chunk length")?,
        );

        if plaintext_len as usize > MAX_CHUNK_SIZE {
            return Err("chunk is too large");
        }

        Ok(Self {
            index,
            plaintext_len,
        })
    }
}
const CHUNK_AAD_DOMAIN: &[u8] = b"FCLOAK-CHUNK-v1";

/// Build authenticated metadata for a chunk.
///
/// The chunk index and plaintext length are authenticated by AES-GCM.
/// This prevents an attacker from safely changing chunk ordering or
/// chunk length without causing authentication failure.
pub fn build_chunk_aad(prefix: &ChunkPrefix) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHUNK_AAD_DOMAIN.len() + 8 + 4);

    aad.extend_from_slice(CHUNK_AAD_DOMAIN);
    aad.extend_from_slice(&prefix.index.to_le_bytes());
    aad.extend_from_slice(&prefix.plaintext_len.to_le_bytes());

    aad
}
/// Encrypt one plaintext chunk using AES-256-GCM.
///
/// The chunk index and plaintext length are authenticated through AAD.
/// The nonce is deterministically derived from the container base nonce
/// and the chunk index.
pub fn encrypt_chunk(
    dek: &[u8; DEK_SIZE],
    base_nonce: &[u8; NONCE_SIZE],
    index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, FcloakError> {
    let prefix = ChunkPrefix::new(index, plaintext.len()).map_err(|_| FcloakError::Crypto)?;

    let nonce_bytes = derive_chunk_nonce(base_nonce, index).map_err(|_| FcloakError::Crypto)?;

    let aad = build_chunk_aad(&prefix);

    let key = Key::<Aes256Gcm>::try_from(dek.as_slice()).map_err(|_| FcloakError::Crypto)?;

    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| FcloakError::Crypto)?;

    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| FcloakError::Crypto)
}
/// Decrypt one encrypted chunk.
///
/// The supplied chunk prefix is authenticated together with the
/// ciphertext. The expected chunk index must therefore match the
/// nonce and AAD used during encryption.
pub fn decrypt_chunk(
    dek: &[u8; DEK_SIZE],
    base_nonce: &[u8; NONCE_SIZE],
    prefix: &ChunkPrefix,
    ciphertext: &[u8],
) -> Result<Vec<u8>, FcloakError> {
    if ciphertext.len() < GCM_TAG_SIZE {
        return Err(FcloakError::Crypto);
    }

    let nonce_bytes =
        derive_chunk_nonce(base_nonce, prefix.index).map_err(|_| FcloakError::Crypto)?;

    let aad = build_chunk_aad(prefix);

    let key = Key::<Aes256Gcm>::try_from(dek.as_slice()).map_err(|_| FcloakError::Crypto)?;

    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| FcloakError::Crypto)?;

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| FcloakError::Crypto)?;

    if plaintext.len() != prefix.plaintext_len as usize {
        return Err(FcloakError::Crypto);
    }

    Ok(plaintext)
}
/// Encrypt a file using chunked AES-256-GCM.
///
/// The entire file is never loaded into memory. Only one chunk is
/// processed at a time.
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    dek: &[u8; DEK_SIZE],
    base_nonce: &[u8; NONCE_SIZE],
    chunk_size: usize,
) -> Result<u64, FcloakError> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(FcloakError::Crypto);
    }

    let mut buffer = vec![0u8; chunk_size];
    let mut chunk_index = 0u64;
    let mut total_plaintext = 0u64;

    loop {
        let bytes_read = reader.read(&mut buffer).map_err(|_| FcloakError::Crypto)?;

        if bytes_read == 0 {
            break;
        }

        let plaintext = &buffer[..bytes_read];

        let ciphertext = encrypt_chunk(dek, base_nonce, chunk_index, plaintext)?;

        let prefix = ChunkPrefix::new(chunk_index, bytes_read).map_err(|_| FcloakError::Crypto)?;

        writer
            .write_all(&prefix.encode())
            .map_err(|_| FcloakError::Crypto)?;

        writer
            .write_all(&ciphertext)
            .map_err(|_| FcloakError::Crypto)?;

        total_plaintext = total_plaintext
            .checked_add(bytes_read as u64)
            .ok_or(FcloakError::Crypto)?;

        chunk_index = chunk_index.checked_add(1).ok_or(FcloakError::Crypto)?;
    }

    writer.flush().map_err(|_| FcloakError::Crypto)?;

    Ok(total_plaintext)
}
/// Encrypt a file from disk using streaming I/O.
pub fn encrypt_file_stream(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    dek: &[u8; DEK_SIZE],
    base_nonce: &[u8; NONCE_SIZE],
    chunk_size: usize,
) -> Result<u64, FcloakError> {
    let mut reader = File::open(input).map_err(|_| FcloakError::Crypto)?;

    let mut writer = File::create(output).map_err(|_| FcloakError::Crypto)?;

    encrypt_stream(&mut reader, &mut writer, dek, base_nonce, chunk_size)
}
/// Decrypt a chunked FCLOAK stream.
///
/// Each chunk is authenticated before its plaintext is written to
/// the output stream.
fn read_first_byte<R: Read>(reader: &mut R) -> Result<Option<u8>, FcloakError> {
    let mut byte = [0u8; 1];

    match reader.read(&mut byte) {
        Ok(0) => Ok(None),
        Ok(1) => Ok(Some(byte[0])),
        Ok(_) => Err(FcloakError::Crypto),
        Err(_) => Err(FcloakError::Crypto),
    }
}
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    dek: &[u8; DEK_SIZE],
    base_nonce: &[u8; NONCE_SIZE],
) -> Result<u64, FcloakError> {
    let mut expected_index = 0u64;
    let mut total_plaintext = 0u64;

    loop {
        let mut prefix_bytes = [0u8; CHUNK_PREFIX_SIZE];

        let first_byte = read_first_byte(reader)?;

        match first_byte {
            None => break,
            Some(byte) => {
                prefix_bytes[0] = byte;
            }
        }

        reader
            .read_exact(&mut prefix_bytes[1..])
            .map_err(|_| FcloakError::Crypto)?;

        let prefix = ChunkPrefix::decode(&prefix_bytes).map_err(|_| FcloakError::Crypto)?;

        if prefix.index != expected_index {
            return Err(FcloakError::Crypto);
        }

        let ciphertext_len = prefix.plaintext_len as usize + GCM_TAG_SIZE;

        if ciphertext_len > MAX_CHUNK_CIPHERTEXT_SIZE {
            return Err(FcloakError::Crypto);
        }

        let mut ciphertext = vec![0u8; ciphertext_len];

        reader
            .read_exact(&mut ciphertext)
            .map_err(|_| FcloakError::Crypto)?;

        let plaintext = decrypt_chunk(dek, base_nonce, &prefix, &ciphertext)?;

        if plaintext.len() != prefix.plaintext_len as usize {
            return Err(FcloakError::Crypto);
        }

        writer
            .write_all(&plaintext)
            .map_err(|_| FcloakError::Crypto)?;

        total_plaintext = total_plaintext
            .checked_add(plaintext.len() as u64)
            .ok_or(FcloakError::Crypto)?;

        expected_index = expected_index.checked_add(1).ok_or(FcloakError::Crypto)?;
    }

    writer.flush().map_err(|_| FcloakError::Crypto)?;

    Ok(total_plaintext)
}
/// Decrypt a chunked FCLOAK file using streaming I/O.
pub fn decrypt_file_stream(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    dek: &[u8; DEK_SIZE],
    base_nonce: &[u8; NONCE_SIZE],
) -> Result<u64, FcloakError> {
    let mut reader = File::open(input).map_err(|_| FcloakError::Crypto)?;

    let mut writer = File::create(output).map_err(|_| FcloakError::Crypto)?;

    decrypt_stream(&mut reader, &mut writer, dek, base_nonce)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_zero_uses_base_counter() {
        let base_nonce = [
            0xAA, 0xBB, 0xCC, 0xDD, //
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x10,
        ];

        let nonce = derive_chunk_nonce(&base_nonce, 0).unwrap();

        assert_eq!(nonce, base_nonce);
    }

    #[test]
    fn chunk_index_increments_counter() {
        let base_nonce = [
            0xAA, 0xBB, 0xCC, 0xDD, //
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x10,
        ];

        let nonce = derive_chunk_nonce(&base_nonce, 5).unwrap();

        // The 4-byte prefix must remain unchanged.
        assert_eq!(&nonce[0..4], &base_nonce[0..4]);

        // 0x10 + 5 = 0x15.
        assert_eq!(&nonce[4..12], &0x15u64.to_be_bytes());
    }

    #[test]
    fn different_chunks_have_different_nonces() {
        let base_nonce = [
            0x01, 0x02, 0x03, 0x04, //
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x10,
        ];

        let first = derive_chunk_nonce(&base_nonce, 0).unwrap();
        let second = derive_chunk_nonce(&base_nonce, 1).unwrap();
        let third = derive_chunk_nonce(&base_nonce, 2).unwrap();

        assert_ne!(first, second);
        assert_ne!(second, third);
        assert_ne!(first, third);
    }

    #[test]
    fn nonce_prefix_is_preserved() {
        let base_nonce = [
            0xDE, 0xAD, 0xBE, 0xEF, //
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x20,
        ];

        let nonce = derive_chunk_nonce(&base_nonce, 1234).unwrap();

        assert_eq!(&nonce[0..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn counter_overflow_is_rejected() {
        let base_nonce = [
            0x00, 0x00, 0x00, 0x00, //
            0xFF, 0xFF, 0xFF, 0xFF, //
            0xFF, 0xFF, 0xFF, 0xFF,
        ];

        let result = derive_chunk_nonce(&base_nonce, 1);

        assert!(result.is_err());
    }
    #[test]
    fn chunk_prefix_round_trip() {
        let prefix = ChunkPrefix::new(42, 4096).unwrap();

        let encoded = prefix.encode();

        assert_eq!(encoded.len(), CHUNK_PREFIX_SIZE);

        let decoded = ChunkPrefix::decode(&encoded).unwrap();

        assert_eq!(decoded, prefix);
    }

    #[test]
    fn chunk_prefix_preserves_large_index() {
        let prefix = ChunkPrefix::new(u64::MAX - 1, 1234).unwrap();

        let encoded = prefix.encode();

        let decoded = ChunkPrefix::decode(&encoded).unwrap();

        assert_eq!(decoded.index, u64::MAX - 1);
        assert_eq!(decoded.plaintext_len, 1234);
    }

    #[test]
    fn chunk_prefix_rejects_truncated_input() {
        let result = ChunkPrefix::decode(&[0u8; 11]);

        assert!(result.is_err());
    }

    #[test]
    fn chunk_prefix_rejects_oversized_chunk() {
        let result = ChunkPrefix::new(0, MAX_CHUNK_SIZE + 1);

        assert!(result.is_err());
    }

    #[test]
    fn chunk_prefix_accepts_empty_chunk() {
        let prefix = ChunkPrefix::new(0, 0).unwrap();

        let encoded = prefix.encode();

        let decoded = ChunkPrefix::decode(&encoded).unwrap();

        assert_eq!(decoded.index, 0);
        assert_eq!(decoded.plaintext_len, 0);
    }
    #[test]
    fn chunk_aad_is_deterministic() {
        let prefix = ChunkPrefix::new(7, 4096).unwrap();

        let first = build_chunk_aad(&prefix);
        let second = build_chunk_aad(&prefix);

        assert_eq!(first, second);
    }

    #[test]
    fn different_chunk_indices_produce_different_aad() {
        let first_prefix = ChunkPrefix::new(0, 4096).unwrap();

        let second_prefix = ChunkPrefix::new(1, 4096).unwrap();

        let first = build_chunk_aad(&first_prefix);

        let second = build_chunk_aad(&second_prefix);

        assert_ne!(first, second);
    }

    #[test]
    fn different_chunk_lengths_produce_different_aad() {
        let first_prefix = ChunkPrefix::new(0, 4096).unwrap();

        let second_prefix = ChunkPrefix::new(0, 4097).unwrap();

        let first = build_chunk_aad(&first_prefix);

        let second = build_chunk_aad(&second_prefix);

        assert_ne!(first, second);
    }

    #[test]
    fn chunk_aad_contains_domain() {
        let prefix = ChunkPrefix::new(42, 1024).unwrap();

        let aad = build_chunk_aad(&prefix);

        assert!(aad.starts_with(CHUNK_AAD_DOMAIN));
    }

    #[test]
    fn chunk_aad_contains_index_and_length() {
        let prefix = ChunkPrefix::new(42, 1024).unwrap();

        let aad = build_chunk_aad(&prefix);

        let domain_len = CHUNK_AAD_DOMAIN.len();

        assert_eq!(&aad[domain_len..domain_len + 8], &42u64.to_le_bytes());

        assert_eq!(
            &aad[domain_len + 8..domain_len + 12],
            &1024u32.to_le_bytes()
        );
    }
    #[test]
    fn chunk_encrypt_then_decrypt() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"FCLOAK streaming chunk";

        let ciphertext = encrypt_chunk(&dek, &base_nonce, 0, plaintext).unwrap();

        let prefix = ChunkPrefix::new(0, plaintext.len()).unwrap();

        let decrypted = decrypt_chunk(&dek, &base_nonce, &prefix, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_chunks_produce_different_ciphertext() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"same plaintext";

        let first = encrypt_chunk(&dek, &base_nonce, 0, plaintext).unwrap();

        let second = encrypt_chunk(&dek, &base_nonce, 1, plaintext).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn modified_chunk_ciphertext_is_rejected() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"FCLOAK secret chunk";

        let mut ciphertext = encrypt_chunk(&dek, &base_nonce, 0, plaintext).unwrap();

        ciphertext[0] ^= 0x01;

        let prefix = ChunkPrefix::new(0, plaintext.len()).unwrap();

        let result = decrypt_chunk(&dek, &base_nonce, &prefix, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn modified_chunk_index_is_rejected() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"FCLOAK secret chunk";

        let ciphertext = encrypt_chunk(&dek, &base_nonce, 0, plaintext).unwrap();

        let modified_prefix = ChunkPrefix::new(1, plaintext.len()).unwrap();

        let result = decrypt_chunk(&dek, &base_nonce, &modified_prefix, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn modified_chunk_length_is_rejected() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"FCLOAK secret chunk";

        let ciphertext = encrypt_chunk(&dek, &base_nonce, 0, plaintext).unwrap();

        let modified_prefix = ChunkPrefix::new(0, plaintext.len() + 1).unwrap();

        let result = decrypt_chunk(&dek, &base_nonce, &modified_prefix, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn wrong_dek_is_rejected() {
        let dek = crate::keys::generate_file_key();

        let wrong_dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"FCLOAK secret chunk";

        let ciphertext = encrypt_chunk(&dek, &base_nonce, 0, plaintext).unwrap();

        let prefix = ChunkPrefix::new(0, plaintext.len()).unwrap();

        let result = decrypt_chunk(&wrong_dek, &base_nonce, &prefix, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn wrong_base_nonce_is_rejected() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let wrong_base_nonce = [0x43u8; NONCE_SIZE];

        let plaintext = b"FCLOAK secret chunk";

        let ciphertext = encrypt_chunk(&dek, &base_nonce, 0, plaintext).unwrap();

        let prefix = ChunkPrefix::new(0, plaintext.len()).unwrap();

        let result = decrypt_chunk(&dek, &wrong_base_nonce, &prefix, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn empty_chunk_can_be_encrypted() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"";

        let ciphertext = encrypt_chunk(&dek, &base_nonce, 0, plaintext).unwrap();

        assert_eq!(ciphertext.len(), GCM_TAG_SIZE);

        let prefix = ChunkPrefix::new(0, 0).unwrap();

        let decrypted = decrypt_chunk(&dek, &base_nonce, &prefix, &ciphertext).unwrap();

        assert!(decrypted.is_empty());
    }
    #[test]
    fn stream_encrypts_multiple_chunks() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        let mut reader = std::io::Cursor::new(plaintext.to_vec());

        let mut output = Vec::new();

        let total = encrypt_stream(&mut reader, &mut output, &dek, &base_nonce, 8).unwrap();

        assert_eq!(total, plaintext.len() as u64);

        assert!(!output.is_empty());
    }

    #[test]
    fn stream_rejects_invalid_chunk_size() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let mut reader = std::io::Cursor::new(b"test".to_vec());

        let mut output = Vec::new();

        let result = encrypt_stream(&mut reader, &mut output, &dek, &base_nonce, 0);

        assert!(result.is_err());
    }

    #[test]
    fn stream_rejects_oversized_chunk_size() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let mut reader = std::io::Cursor::new(b"test".to_vec());

        let mut output = Vec::new();

        let result = encrypt_stream(
            &mut reader,
            &mut output,
            &dek,
            &base_nonce,
            MAX_CHUNK_SIZE + 1,
        );

        assert!(result.is_err());
    }

    #[test]
    fn stream_encrypt_then_decrypt() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"FCLOAK streaming encryption test data";

        let mut input = std::io::Cursor::new(plaintext.to_vec());

        let mut encrypted = Vec::new();

        let encrypted_size =
            encrypt_stream(&mut input, &mut encrypted, &dek, &base_nonce, 8).unwrap();

        assert_eq!(encrypted_size, plaintext.len() as u64);

        let mut encrypted_input = std::io::Cursor::new(encrypted);

        let mut decrypted = Vec::new();

        let decrypted_size =
            decrypt_stream(&mut encrypted_input, &mut decrypted, &dek, &base_nonce).unwrap();

        assert_eq!(decrypted_size, plaintext.len() as u64);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn stream_handles_empty_input() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let mut input = std::io::Cursor::new(Vec::<u8>::new());

        let mut encrypted = Vec::new();

        encrypt_stream(&mut input, &mut encrypted, &dek, &base_nonce, 4096).unwrap();

        assert!(encrypted.is_empty());

        let mut encrypted_input = std::io::Cursor::new(encrypted);

        let mut decrypted = Vec::new();

        let size = decrypt_stream(&mut encrypted_input, &mut decrypted, &dek, &base_nonce).unwrap();

        assert_eq!(size, 0);

        assert!(decrypted.is_empty());
    }

    #[test]
    fn stream_rejects_modified_ciphertext() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"FCLOAK protected stream";

        let mut input = std::io::Cursor::new(plaintext.to_vec());

        let mut encrypted = Vec::new();

        encrypt_stream(&mut input, &mut encrypted, &dek, &base_nonce, 4096).unwrap();

        // Prefix is 12 bytes. The next byte belongs
        // to the ciphertext.
        encrypted[CHUNK_PREFIX_SIZE] ^= 0x01;

        let mut encrypted_input = std::io::Cursor::new(encrypted);

        let mut output = Vec::new();

        let result = decrypt_stream(&mut encrypted_input, &mut output, &dek, &base_nonce);

        assert!(result.is_err());

        assert!(output.is_empty());
    }

    #[test]
    fn stream_rejects_wrong_chunk_index() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"FCLOAK protected stream";

        let mut input = std::io::Cursor::new(plaintext.to_vec());

        let mut encrypted = Vec::new();

        encrypt_stream(&mut input, &mut encrypted, &dek, &base_nonce, 4096).unwrap();

        // Modify chunk index from 0 to 1.
        encrypted[0] = 1;

        let mut encrypted_input = std::io::Cursor::new(encrypted);

        let mut output = Vec::new();

        let result = decrypt_stream(&mut encrypted_input, &mut output, &dek, &base_nonce);

        assert!(result.is_err());

        assert!(output.is_empty());
    }

    #[test]
    fn stream_rejects_truncated_prefix() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let mut input = std::io::Cursor::new(vec![0u8; CHUNK_PREFIX_SIZE - 1]);

        let mut output = Vec::new();

        let result = decrypt_stream(&mut input, &mut output, &dek, &base_nonce);

        assert!(result.is_err());

        assert!(output.is_empty());
    }

    #[test]
    fn stream_rejects_truncated_ciphertext() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"FCLOAK protected stream";

        let mut input = std::io::Cursor::new(plaintext.to_vec());

        let mut encrypted = Vec::new();

        encrypt_stream(&mut input, &mut encrypted, &dek, &base_nonce, 4096).unwrap();

        encrypted.pop();

        let mut encrypted_input = std::io::Cursor::new(encrypted);

        let mut output = Vec::new();

        let result = decrypt_stream(&mut encrypted_input, &mut output, &dek, &base_nonce);

        assert!(result.is_err());

        assert!(output.is_empty());
    }

    #[test]
    fn stream_rejects_wrong_dek() {
        let dek = crate::keys::generate_file_key();

        let wrong_dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let plaintext = b"FCLOAK protected stream";

        let mut input = std::io::Cursor::new(plaintext.to_vec());

        let mut encrypted = Vec::new();

        encrypt_stream(&mut input, &mut encrypted, &dek, &base_nonce, 4096).unwrap();

        let mut encrypted_input = std::io::Cursor::new(encrypted);

        let mut output = Vec::new();

        let result = decrypt_stream(&mut encrypted_input, &mut output, &wrong_dek, &base_nonce);

        assert!(result.is_err());

        assert!(output.is_empty());
    }

    #[test]
    fn stream_rejects_wrong_base_nonce() {
        let dek = crate::keys::generate_file_key();

        let base_nonce = [0x42u8; NONCE_SIZE];

        let wrong_base_nonce = [0x43u8; NONCE_SIZE];

        let plaintext = b"FCLOAK protected stream";

        let mut input = std::io::Cursor::new(plaintext.to_vec());

        let mut encrypted = Vec::new();

        encrypt_stream(&mut input, &mut encrypted, &dek, &base_nonce, 4096).unwrap();

        let mut encrypted_input = std::io::Cursor::new(encrypted);

        let mut output = Vec::new();

        let result = decrypt_stream(&mut encrypted_input, &mut output, &dek, &wrong_base_nonce);

        assert!(result.is_err());

        assert!(output.is_empty());
    }
}
