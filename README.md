# FCLOAK

**Local-first encrypted desktop vault with optional cloud storage.**

FCLOAK is a Windows desktop application designed to encrypt files locally and optionally synchronize the resulting encrypted containers with cloud-storage providers.

> **Current release:** Alpha 1 — `v0.1.0-alpha.1`

## Why FCLOAK?

FCLOAK follows a simple principle:

> **Encrypt first. Store second.**

Your original file is encrypted locally before it is uploaded to a cloud provider.

```text
                 FCLOAK
                    |
          +---------+---------+
          |                   |
     Local Vault         Cloud Storage
          |                   |
          |          +--------+--------+
          |          |        |        |
          |       Google   OneDrive  Future
          |       Drive              providers
          |
          v
    .fcloak container
          |
          v
   Local decryption/export
```

The cloud-storage layer is designed to be provider-independent. Google Drive is the first provider implemented in Alpha 1, with additional providers planned for future releases.

## Alpha 1 features

- Local encrypted vault
- Argon2 password verification
- Encrypted `.fcloak` containers
- Standard and streaming file encryption
- Google Drive OAuth integration
- Saved Google authentication session
- Upload encrypted containers to Google Drive
- Download encrypted containers from Google Drive
- Local decryption and export
- Five-minute inactivity auto-lock
- Windows desktop GUI
- Windows application icon
- CLI application
- Rust workspace architecture

## Security model

```text
Original file
     |
     v
Local encryption
     |
     v
Encrypted .fcloak container
     |
     +-----------> Local vault
     |
     +-----------> Cloud provider
                         |
                         v
                  Encrypted storage
```

When restoring:

```text
Cloud provider
     |
     v
Encrypted .fcloak
     |
     v
Local download
     |
     v
FCLOAK password
     |
     v
Local decryption
     |
     v
Exported plaintext file
```

FCLOAK is designed so that plaintext files are not intentionally uploaded through its encrypted-container workflow.

## Cloud providers

### Current

- Google Drive

### Planned

- Microsoft OneDrive
- Dropbox
- Amazon S3
- WebDAV
- Additional providers

The provider architecture is intended to keep cloud-specific functionality separate from the core encryption layer.

## Installation

Download the latest Windows release from the GitHub Releases page.

For Alpha 1, the recommended package is:

```text
FCLOAK-v0.1.0-alpha.1-windows-x64.zip
```

Extract it and run:

```text
fcloak-gui.exe
```

## First run

1. Start FCLOAK.
2. Create a strong vault password.
3. Import a test file.
4. FCLOAK creates an encrypted `.fcloak` container.
5. Connect Google Drive if cloud storage is required.
6. Upload the encrypted container.
7. To restore a file, download the encrypted container and decrypt/export it locally.

## Developer setup

Requirements:

- Rust toolchain
- Windows development environment
- Google Cloud OAuth application for Drive testing

Build:

```powershell
cargo check --workspace
cargo build --release -p fcloak-gui
```

The release binary is:

```text
target\release\fcloak-gui.exe
```

### Google OAuth development credentials

Credentials are supplied to the build through environment variables:

```powershell
$env:FCLOAK_GOOGLE_CLIENT_ID="YOUR_CLIENT_ID"
$env:FCLOAK_GOOGLE_CLIENT_SECRET="YOUR_CLIENT_SECRET"
```

Never commit actual credentials.

The project uses `build.rs` to provide the values to the application at build time.

## Repository structure

```text
fcloak/
|
+-- apps/
|   +-- fcloak-gui/
|   +-- fcloak-cli/
|
+-- crates/
|   +-- fcloak-core/
|
+-- docs/
|
+-- .github/
|
+-- Cargo.toml
+-- Cargo.lock
+-- README.md
+-- LICENSE
+-- SECURITY.md
+-- PRIVACY.md
+-- CONTRIBUTING.md
+-- CODE_OF_CONDUCT.md
+-- CHANGELOG.md
```

## Testing

Alpha testers should use disposable test files first.

Recommended test flow:

1. Encrypt a file.
2. Verify the encrypted `.fcloak` file exists.
3. Upload it to Google Drive.
4. Download it again.
5. Decrypt/export it.
6. Compare the original and restored file hashes.

PowerShell:

```powershell
Get-FileHash .\original.txt -Algorithm SHA256
Get-FileHash .\restored.txt -Algorithm SHA256
```

The hashes should match.

## Alpha warning

FCLOAK Alpha 1 is experimental software.

It has not undergone an independent security audit.

Do not use it as the only protection for irreplaceable or highly sensitive data.

Keep independent backups.

## Contributors

- **TheWIZs** — project maintainer / lead developer
- **Sana Iqbal** — contributor

GitHub:

- https://github.com/adarshkrdubay
- https://github.com/sanaiqbal-sys

## License

FCLOAK is released under the MIT License. See [LICENSE](LICENSE).
