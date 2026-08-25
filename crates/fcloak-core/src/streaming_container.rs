use std::{
    io::Write,
    path::{Path, PathBuf},
};

use rand::RngExt;

use crate::error::FcloakError;

/// Build a temporary output path next to the final destination.
///
/// Example:
///     output.txt
/// becomes:
///     .output.txt.fcloak-tmp
fn temporary_output_path(output: &Path) -> PathBuf {
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("output");

    let temp_name = format!(".{file_name}.fcloak-tmp");

    output
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(temp_name)
}

/// Encrypt a file using the FCLOAK streaming container format.
///
/// The implementation will:
/// - derive a KEK from the password using Argon2id
/// - generate a random DEK
/// - wrap the DEK using AES-256-GCM
/// - encrypt the input in authenticated chunks
/// - write the resulting FCLOAK streaming container
pub fn encrypt_file_streaming(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    password: &str,
) -> Result<u64, FcloakError> {
    const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

    let input_path = input.as_ref();
    let output_path = output.as_ref();

    let mut reader = std::fs::File::open(input_path).map_err(|_| FcloakError::Crypto)?;

    let mut writer = std::fs::File::create(output_path).map_err(|_| FcloakError::Crypto)?;

    // 1. Generate password salt.
    let salt = crate::keys::generate_salt();

    // 2. Derive KEK from password.
    let kek =
        crate::keys::derive_key(password.as_bytes(), &salt).map_err(|_| FcloakError::Crypto)?;

    // 3. Generate random file DEK.
    let dek = crate::keys::generate_file_key();

    // 4. Generate the base nonce used by the streaming chunks.
    let mut base_nonce = [0u8; crate::format::NONCE_SIZE];
    rand::rng().fill(&mut base_nonce);

    // 5. Generate nonce for DEK wrapping.
    let mut dek_wrap_nonce = [0u8; crate::format::NONCE_SIZE];
    rand::rng().fill(&mut dek_wrap_nonce);

    // 6. Wrap the DEK using the password-derived KEK.
    let wrapped_dek = crate::crypto::wrap_dek_with_nonce(&kek, &dek, &dek_wrap_nonce)?;

    // 7. Construct the streaming header.
    let header = crate::format::StreamingHeader::new(salt, dek_wrap_nonce, base_nonce);

    // 8. Write header.
    writer
        .write_all(&header.encode())
        .map_err(|_| FcloakError::Crypto)?;

    // 9. Write wrapped DEK.
    writer
        .write_all(&wrapped_dek.ciphertext)
        .map_err(|_| FcloakError::Crypto)?;

    // 10. Stream-encrypt the file.
    let plaintext_size =
        crate::streaming::encrypt_stream(&mut reader, &mut writer, &dek, &base_nonce, CHUNK_SIZE)?;

    writer.flush().map_err(|_| FcloakError::Crypto)?;

    Ok(plaintext_size)
}

/// Decrypt a FCLOAK streaming container.
///
/// The implementation will:
/// - read and validate the streaming header
/// - derive the KEK from the supplied password
/// - unwrap the file DEK
/// - authenticate and decrypt every chunk
/// - write plaintext to a temporary file
/// - rename the temporary file only after successful authentication
pub fn decrypt_file_streaming(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    password: &str,
) -> Result<u64, FcloakError> {
    let input_path = input.as_ref();
    let output_path = output.as_ref();

    let mut reader = std::fs::File::open(input_path).map_err(|_| FcloakError::Crypto)?;

    // Read and validate the fixed streaming header.
    let mut header_bytes = vec![0u8; crate::format::STREAMING_HEADER_SIZE];

    std::io::Read::read_exact(&mut reader, &mut header_bytes).map_err(|_| FcloakError::Crypto)?;

    let header = crate::format::StreamingHeader::decode(&header_bytes)
        .map_err(|_| FcloakError::InvalidFormat)?;

    // Derive the KEK from the password.
    let kek = crate::keys::derive_key(password.as_bytes(), &header.salt)
        .map_err(|_| FcloakError::Crypto)?;

    // Read the wrapped DEK.
    let mut wrapped_dek = vec![0u8; crate::format::WRAPPED_DEK_SIZE];

    std::io::Read::read_exact(&mut reader, &mut wrapped_dek).map_err(|_| FcloakError::Crypto)?;

    // Authenticate and unwrap the DEK.
    let dek = crate::crypto::unwrap_dek(&kek, &header.dek_wrap_nonce, &wrapped_dek)?;

    // Never write plaintext directly to the final destination.
    let temp_path = temporary_output_path(output_path);

    // Remove stale temporary output from a previous failed run.
    if temp_path.exists() {
        std::fs::remove_file(&temp_path).map_err(|_| FcloakError::Crypto)?;
    }

    let result = (|| -> Result<u64, FcloakError> {
        let mut writer = std::fs::File::create(&temp_path).map_err(|_| FcloakError::Crypto)?;

        // Decrypt and authenticate every chunk.
        let plaintext_size =
            crate::streaming::decrypt_stream(&mut reader, &mut writer, &dek, &header.base_nonce)?;

        // Ensure all plaintext is flushed before rename.
        writer.flush().map_err(|_| FcloakError::Crypto)?;

        // Release the file handle before Windows rename.
        drop(writer);

        // Only expose plaintext after the entire stream
        // has successfully authenticated.
        std::fs::rename(&temp_path, output_path).map_err(|_| FcloakError::Crypto)?;

        Ok(plaintext_size)
    })();

    // Never leave plaintext behind after a failed operation.
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_api_exists() {
        let input = Path::new("input");
        let output = Path::new("output");

        let _ = encrypt_file_streaming(input, output, "test-password");

        let _ = decrypt_file_streaming(input, output, "test-password");
    }

    #[test]
    fn streaming_file_encrypts_successfully() {
        use std::fs;

        let base =
            std::env::temp_dir().join(format!("fcloak-streaming-test-{}", std::process::id()));

        let input = base.with_extension("input");
        let output = base.with_extension("fcloak");

        let plaintext = b"FCLOAK streaming container test data";

        fs::write(&input, plaintext).unwrap();

        let written = encrypt_file_streaming(&input, &output, "correct-password").unwrap();

        assert_eq!(written, plaintext.len() as u64);

        assert!(output.exists());

        let encrypted = fs::read(&output).unwrap();

        assert!(encrypted.len() > plaintext.len());

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn streaming_file_encrypt_then_decrypt() {
        use std::fs;

        let base =
            std::env::temp_dir().join(format!("fcloak-streaming-roundtrip-{}", std::process::id()));

        let input = base.with_extension("input");
        let encrypted = base.with_extension("fcloak");
        let output = base.with_extension("output");

        let plaintext = b"FCLOAK streaming encryption round-trip test";

        fs::write(&input, plaintext).unwrap();

        let encrypted_size =
            encrypt_file_streaming(&input, &encrypted, "correct-password").unwrap();

        assert_eq!(encrypted_size, plaintext.len() as u64);

        let decrypted_size =
            decrypt_file_streaming(&encrypted, &output, "correct-password").unwrap();

        assert_eq!(decrypted_size, plaintext.len() as u64);

        let recovered = fs::read(&output).unwrap();

        assert_eq!(recovered, plaintext);

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&encrypted);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn streaming_wrong_password_does_not_create_output() {
        use std::fs;

        let base = std::env::temp_dir().join(format!(
            "fcloak-streaming-wrong-password-{}",
            std::process::id()
        ));

        let input = base.with_extension("input");
        let encrypted = base.with_extension("fcloak");
        let output = base.with_extension("output");

        let plaintext = b"FCLOAK protected streaming data";

        fs::write(&input, plaintext).unwrap();

        encrypt_file_streaming(&input, &encrypted, "correct-password").unwrap();

        let result = decrypt_file_streaming(&encrypted, &output, "wrong-password");

        assert!(result.is_err());
        assert!(!output.exists());

        let temp_path = temporary_output_path(&output);

        assert!(!temp_path.exists());

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&encrypted);
        let _ = fs::remove_file(&output);
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn streaming_modified_header_is_rejected() {
        use std::fs;

        let base = std::env::temp_dir().join(format!(
            "fcloak-streaming-header-tamper-{}",
            std::process::id()
        ));

        let input = base.with_extension("input");
        let encrypted = base.with_extension("fcloak");
        let output = base.with_extension("output");

        fs::write(&input, b"FCLOAK header tamper test").unwrap();

        encrypt_file_streaming(&input, &encrypted, "correct-password").unwrap();

        let mut data = fs::read(&encrypted).unwrap();

        // Corrupt the streaming header.
        data[0] ^= 0x01;

        fs::write(&encrypted, &data).unwrap();

        let result = decrypt_file_streaming(&encrypted, &output, "correct-password");

        assert!(result.is_err());
        assert!(!output.exists());

        let temp_path = temporary_output_path(&output);

        assert!(!temp_path.exists());

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&encrypted);
        let _ = fs::remove_file(&output);
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn streaming_modified_wrapped_dek_is_rejected() {
        use std::fs;

        let base = std::env::temp_dir().join(format!(
            "fcloak-streaming-dek-tamper-{}",
            std::process::id()
        ));

        let input = base.with_extension("input");
        let encrypted = base.with_extension("fcloak");
        let output = base.with_extension("output");

        fs::write(&input, b"FCLOAK wrapped DEK tamper test").unwrap();

        encrypt_file_streaming(&input, &encrypted, "correct-password").unwrap();

        let mut data = fs::read(&encrypted).unwrap();

        let offset = crate::format::STREAMING_HEADER_SIZE;

        data[offset] ^= 0x01;

        fs::write(&encrypted, &data).unwrap();

        let result = decrypt_file_streaming(&encrypted, &output, "correct-password");

        assert!(result.is_err());
        assert!(!output.exists());

        let temp_path = temporary_output_path(&output);

        assert!(!temp_path.exists());

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&encrypted);
        let _ = fs::remove_file(&output);
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn streaming_modified_ciphertext_is_rejected() {
        use std::fs;

        let base = std::env::temp_dir().join(format!(
            "fcloak-streaming-ciphertext-tamper-{}",
            std::process::id()
        ));

        let input = base.with_extension("input");
        let encrypted = base.with_extension("fcloak");
        let output = base.with_extension("output");

        fs::write(&input, b"FCLOAK ciphertext authentication test data").unwrap();

        encrypt_file_streaming(&input, &encrypted, "correct-password").unwrap();

        let mut data = fs::read(&encrypted).unwrap();

        let ciphertext_offset =
            crate::format::STREAMING_HEADER_SIZE + crate::format::WRAPPED_DEK_SIZE;

        assert!(data.len() > ciphertext_offset);

        data[ciphertext_offset] ^= 0x01;

        fs::write(&encrypted, &data).unwrap();

        let result = decrypt_file_streaming(&encrypted, &output, "correct-password");

        assert!(result.is_err());
        assert!(!output.exists());

        let temp_path = temporary_output_path(&output);

        assert!(!temp_path.exists());

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&encrypted);
        let _ = fs::remove_file(&output);
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn streaming_truncated_container_is_rejected() {
        use std::fs;

        let base =
            std::env::temp_dir().join(format!("fcloak-streaming-truncated-{}", std::process::id()));

        let input = base.with_extension("input");
        let encrypted = base.with_extension("fcloak");
        let output = base.with_extension("output");

        fs::write(&input, b"FCLOAK truncated container test data").unwrap();

        encrypt_file_streaming(&input, &encrypted, "correct-password").unwrap();

        let mut data = fs::read(&encrypted).unwrap();

        // Remove the final bytes from the container.
        data.truncate(data.len().saturating_sub(5));

        fs::write(&encrypted, &data).unwrap();

        let result = decrypt_file_streaming(&encrypted, &output, "correct-password");

        assert!(result.is_err());
        assert!(!output.exists());

        let temp_path = temporary_output_path(&output);

        assert!(!temp_path.exists());

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&encrypted);
        let _ = fs::remove_file(&output);
        let _ = fs::remove_file(&temp_path);
    }
}
