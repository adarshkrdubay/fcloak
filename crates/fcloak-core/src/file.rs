use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    container::FcloakContainer,
    error::FcloakError,
    format::{ContainerFormat, detect_container_format},
};

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

/// Encrypt a file into a `.fcloak` container.
pub fn encrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    password: &[u8],
) -> Result<(), FcloakError> {
    let input_path = input_path.as_ref();
    let output_path = output_path.as_ref();

    let plaintext = fs::read(input_path)?;

    let container = FcloakContainer::encrypt(password, &plaintext)?;

    let encoded = container.encode();

    let temp_path = temporary_output_path(output_path);

    // Never overwrite an existing temporary file.
    if temp_path.exists() {
        fs::remove_file(&temp_path)?;
    }

    let result = (|| {
        fs::write(&temp_path, encoded)?;

        fs::rename(&temp_path, output_path)?;

        Ok::<(), FcloakError>(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    result
}

/// Decrypt a `.fcloak` container.
///
/// The container format is detected automatically:
///
/// - FCLOAK v1 -> standard container decryption
/// - FCLOAK v2 -> streaming container decryption
pub fn decrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    password: &[u8],
) -> Result<(), FcloakError> {
    let input_path = input_path.as_ref();
    let output_path = output_path.as_ref();

    // Read only enough bytes to identify the container format.
    //
    // FCLOAK prefix:
    //   6 bytes magic + 1 byte version
    let mut input_file = fs::File::open(input_path)?;

    let mut prefix = [0u8; 7];

    use std::io::Read;

    input_file.read_exact(&mut prefix)?;

    match detect_container_format(&prefix)? {
        ContainerFormat::Standard => decrypt_standard_file(input_path, output_path, password),

        ContainerFormat::Streaming => {
            let password =
                std::str::from_utf8(password).map_err(|_| FcloakError::InvalidPassword)?;

            crate::streaming_container::decrypt_file_streaming(input_path, output_path, password)
                .map(|_| ())
        }
    }
}

/// Decrypt a standard FCLOAK v1 container.
fn decrypt_standard_file(
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
) -> Result<(), FcloakError> {
    let encoded = fs::read(input_path)?;

    let container = FcloakContainer::decode(&encoded)?;

    let plaintext = container.decrypt(password)?;

    let temp_path = temporary_output_path(output_path);

    if temp_path.exists() {
        fs::remove_file(&temp_path)?;
    }

    let result = (|| {
        fs::write(&temp_path, plaintext)?;

        fs::rename(&temp_path, output_path)?;

        Ok::<(), FcloakError>(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temporary_path(name: &str) -> std::path::PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        std::env::temp_dir().join(format!("fcloak-{timestamp}-{name}"))
    }

    #[test]
    fn file_encrypt_then_decrypt() {
        let input = temporary_path("input.txt");

        let encrypted = temporary_path("encrypted.fcloak");

        let output = temporary_path("output.txt");

        let plaintext = b"FCLOAK file encryption test";

        fs::write(&input, plaintext).unwrap();

        encrypt_file(&input, &encrypted, b"correct password").unwrap();

        decrypt_file(&encrypted, &output, b"correct password").unwrap();

        let recovered = fs::read(&output).unwrap();

        assert_eq!(recovered, plaintext);

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&encrypted);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn wrong_password_does_not_create_output() {
        let input = temporary_path("wrong-password-input.txt");

        let encrypted = temporary_path("wrong-password.fcloak");

        let output = temporary_path("wrong-password-output.txt");

        fs::write(&input, b"secret data").unwrap();

        encrypt_file(&input, &encrypted, b"correct password").unwrap();

        let result = decrypt_file(&encrypted, &output, b"wrong password");

        assert!(result.is_err());

        assert!(!output.exists());

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&encrypted);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn corrupted_container_is_rejected() {
        let input = temporary_path("corrupt-input.txt");

        let encrypted = temporary_path("corrupt.fcloak");

        let output = temporary_path("corrupt-output.txt");

        fs::write(&input, b"important data").unwrap();

        encrypt_file(&input, &encrypted, b"password").unwrap();

        let mut data = fs::read(&encrypted).unwrap();

        data[0] ^= 0x01;

        fs::write(&encrypted, data).unwrap();

        let result = decrypt_file(&encrypted, &output, b"password");

        assert!(result.is_err());

        assert!(!output.exists());

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&encrypted);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn binary_file_round_trip() {
        let input = temporary_path("binary-input.bin");

        let encrypted = temporary_path("binary.fcloak");

        let output = temporary_path("binary-output.bin");

        let data: Vec<u8> = (0u8..=255).cycle().take(8192).collect();

        fs::write(&input, &data).unwrap();

        encrypt_file(&input, &encrypted, b"binary password").unwrap();

        decrypt_file(&encrypted, &output, b"binary password").unwrap();

        let recovered = fs::read(&output).unwrap();

        assert_eq!(recovered, data);

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&encrypted);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn decrypt_dispatches_streaming_container() {
        let input = temporary_path("dispatch-input.txt");

        let encrypted = temporary_path("dispatch.fcloak");

        let output = temporary_path("dispatch-output.txt");

        let plaintext = b"automatic streaming dispatch";

        fs::write(&input, plaintext).unwrap();

        crate::streaming_container::encrypt_file_streaming(&input, &encrypted, "dispatch-password")
            .unwrap();

        decrypt_file(&encrypted, &output, b"dispatch-password").unwrap();

        assert_eq!(fs::read(&output).unwrap(), plaintext);

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&encrypted);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn decrypt_dispatch_rejects_wrong_streaming_password() {
        let input = temporary_path("dispatch-wrong-input.txt");

        let encrypted = temporary_path("dispatch-wrong.fcloak");

        let output = temporary_path("dispatch-wrong-output.txt");

        fs::write(&input, b"secret").unwrap();

        crate::streaming_container::encrypt_file_streaming(&input, &encrypted, "correct-password")
            .unwrap();

        let result = decrypt_file(&encrypted, &output, b"wrong-password");

        assert!(result.is_err());

        assert!(!output.exists());

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&encrypted);
        let _ = fs::remove_file(&output);
    }
}
