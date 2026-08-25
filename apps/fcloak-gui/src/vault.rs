use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use directories::ProjectDirs;
use rand::Rng;

use fcloak_core::{
    file::{decrypt_file, encrypt_file},
    format::{ContainerFormat, detect_container_format},
    streaming_container::{decrypt_file_streaming, encrypt_file_streaming},
};

const CONFIG_FILE: &str = "vault.conf";
const VAULT_DIR: &str = "vault";

pub struct Vault {
    root: PathBuf,
    vault_dir: PathBuf,
}

impl Vault {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let dirs = ProjectDirs::from("com", "fcloak", "FCLOAK")
            .ok_or("could not determine application data directory")?;

        let root = dirs.data_dir().to_path_buf();
        let vault_dir = root.join(VAULT_DIR);

        fs::create_dir_all(&vault_dir)?;

        Ok(Self { root, vault_dir })
    }

    fn config_path(&self) -> PathBuf {
        self.root.join(CONFIG_FILE)
    }

    pub fn is_initialized(&self) -> bool {
        self.config_path().exists()
    }

    pub fn initialize(&self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        if password.is_empty() {
            return Err("password cannot be empty".into());
        }

        if self.is_initialized() {
            return Err("FCLOAK is already initialized".into());
        }

        // Generate a cryptographically secure random salt.
        let mut salt_bytes = [0u8; 16];
        rand::rng().fill(&mut salt_bytes);

        let salt =
            SaltString::encode_b64(&salt_bytes).map_err(|_| "failed to encode password salt")?;

        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| "failed to create password verifier")?
            .to_string();

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.config_path())?;

        file.write_all(password_hash.as_bytes())?;
        file.flush()?;

        Ok(())
    }

    pub fn verify_password(&self, password: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let stored = fs::read_to_string(self.config_path())?;

        let parsed =
            PasswordHash::new(&stored).map_err(|_| "invalid FCLOAK password configuration")?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }

    pub fn import_file(
        &self,
        source: &Path,
        password: &[u8],
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        if !source.is_file() {
            return Err("selected path is not a file".into());
        }

        let file_name = source.file_name().ok_or("source file has no filename")?;

        let encrypted_name = format!("{}.fcloak", file_name.to_string_lossy());

        let output = self.vault_dir.join(encrypted_name);

        if output.exists() {
            return Err("a file with the same name already exists in the vault".into());
        }

        let metadata = fs::metadata(source)?;

        // Files >= 64 MiB use the streaming container.
        const STREAMING_THRESHOLD: u64 = 64 * 1024 * 1024;

        if metadata.len() >= STREAMING_THRESHOLD {
            let password_string = String::from_utf8(password.to_vec())?;

            encrypt_file_streaming(source, &output, &password_string)?;
        } else {
            encrypt_file(source, &output, password)?;
        }

        Ok(output)
    }

    pub fn export_file(
        &self,
        encrypted: &Path,
        destination: &Path,
        password: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !encrypted.is_file() {
            return Err("vault file does not exist".into());
        }

        let encoded = fs::read(encrypted)?;

        let format = detect_container_format(&encoded).map_err(|_| "invalid FCLOAK container")?;

        match format {
            ContainerFormat::Standard => {
                decrypt_file(encrypted, destination, password)?;
            }

            ContainerFormat::Streaming => {
                let password_string = String::from_utf8(password.to_vec())?;

                decrypt_file_streaming(encrypted, destination, &password_string)?;
            }
        }

        Ok(())
    }

    pub fn delete_file(&self, encrypted: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if !encrypted.is_file() {
            return Err("vault file does not exist".into());
        }

        fs::remove_file(encrypted)?;

        Ok(())
    }

    pub fn list_files(&self) -> Result<Vec<VaultFile>, Box<dyn std::error::Error>> {
        let mut files = Vec::new();

        for entry in fs::read_dir(&self.vault_dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let name = match path.file_name().and_then(|x| x.to_str()) {
                Some(name) => name,
                None => continue,
            };

            if !name.ends_with(".fcloak") {
                continue;
            }

            let metadata = fs::metadata(&path)?;

            let display_name = name.strip_suffix(".fcloak").unwrap_or(name).to_string();

            files.push(VaultFile {
                encrypted_path: path,
                name: display_name,
                size: metadata.len(),
            });
        }

        files.sort_by_key(|file| file.name.to_lowercase());

        Ok(files)
    }
}

pub struct VaultFile {
    pub encrypted_path: PathBuf,
    pub name: String,
    pub size: u64,
}

pub fn format_size(size: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let size_f = size as f64;

    if size_f >= GB {
        format!("{:.2} GB", size_f / GB)
    } else if size_f >= MB {
        format!("{:.2} MB", size_f / MB)
    } else if size_f >= KB {
        format!("{:.2} KB", size_f / KB)
    } else {
        format!("{size} B")
    }
}
