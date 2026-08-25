use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngExt;

pub const KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 32;

/// FCLOAK Argon2id memory cost in KiB.
///
/// 65,536 KiB = 64 MiB.
// pub const ARGON2_MEMORY_KIB: u32 = 65_536;

// /// Number of Argon2id iterations.
// pub const ARGON2_ITERATIONS: u32 = 3;

// /// Number of parallel lanes.
// pub const ARGON2_PARALLELISM: u32 = 1;
pub const ARGON2_MEMORY_KIB: u32 = 32_768;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 1;
/// Create the Argon2id instance used by FCLOAK.
///
/// Parameters are explicit so the FCLOAK format does not
/// silently depend on library defaults.
fn fcloak_argon2() -> Result<Argon2<'static>, argon2::Error> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_SIZE),
    )?;

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Generate a cryptographically secure random 256-bit file key.
///
/// This is the per-file Data Encryption Key (DEK).
pub fn generate_file_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];

    rand::rng().fill(&mut key);

    key
}

/// Generate a cryptographically secure random 256-bit salt.
///
/// The salt is not secret and will eventually be stored
/// in the FCLOAK file header.
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];

    rand::rng().fill(&mut salt);

    salt
}

/// Derive a 256-bit Key Encryption Key (KEK) from a password
/// using the FCLOAK Argon2id configuration.
///
/// The password itself is never stored by this function.
pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
) -> Result<[u8; KEY_SIZE], argon2::Error> {
    let mut key = [0u8; KEY_SIZE];

    let argon2 = fcloak_argon2()?;

    argon2.hash_password_into(password, salt, &mut key)?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_file_key_has_correct_size() {
        let key = generate_file_key();

        assert_eq!(key.len(), KEY_SIZE);
    }

    #[test]
    fn generated_file_keys_are_different() {
        let key_a = generate_file_key();
        let key_b = generate_file_key();

        assert_ne!(key_a, key_b);
    }

    #[test]
    fn generated_salt_has_correct_size() {
        let salt = generate_salt();

        assert_eq!(salt.len(), SALT_SIZE);
    }

    #[test]
    fn generated_salts_are_different() {
        let salt_a = generate_salt();
        let salt_b = generate_salt();

        assert_ne!(salt_a, salt_b);
    }

    #[test]
    fn same_password_and_salt_produce_same_key() {
        let password = b"test-password";
        let salt = [0x42u8; SALT_SIZE];

        let key_a = derive_key(password, &salt).unwrap();
        let key_b = derive_key(password, &salt).unwrap();

        assert_eq!(key_a, key_b);
    }

    #[test]
    fn different_passwords_produce_different_keys() {
        let salt = [0x42u8; SALT_SIZE];

        let key_a = derive_key(b"password-one", &salt).unwrap();
        let key_b = derive_key(b"password-two", &salt).unwrap();

        assert_ne!(key_a, key_b);
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let password = b"test-password";

        let salt_a = [0x11u8; SALT_SIZE];
        let salt_b = [0x22u8; SALT_SIZE];

        let key_a = derive_key(password, &salt_a).unwrap();
        let key_b = derive_key(password, &salt_b).unwrap();

        assert_ne!(key_a, key_b);
    }

    #[test]
    fn argon2_parameters_are_expected() {
        assert_eq!(ARGON2_MEMORY_KIB, 32_768);
        assert_eq!(ARGON2_ITERATIONS, 3);
        assert_eq!(ARGON2_PARALLELISM, 1);
        assert_eq!(KEY_SIZE, 32);
        assert_eq!(SALT_SIZE, 32);
    }

    #[test]
    fn derived_key_has_correct_size() {
        let password = b"FCLOAK test password";
        let salt = generate_salt();

        let key = derive_key(password, &salt).unwrap();

        assert_eq!(key.len(), KEY_SIZE);
    }
}
