# FCLOAK Alpha 1 Release Checklist

Version:

```text
v0.1.0-alpha.1
```

## Build

```powershell
cargo fmt --all
cargo check --workspace
cargo build --release -p fcloak-gui
```

Expected binary:

```text
target\release\fcloak-gui.exe
```

## Verify

- [ ] Launch EXE on a clean Windows machine
- [ ] Create vault
- [ ] Encrypt a test file
- [ ] Decrypt/export it
- [ ] Verify SHA-256
- [ ] Connect Google Drive
- [ ] Upload encrypted container
- [ ] Download encrypted container
- [ ] Decrypt downloaded container
- [ ] Verify saved OAuth session
- [ ] Verify five-minute auto-lock
- [ ] Verify Windows icon

## Package

Create:

```text
FCLOAK-v0.1.0-alpha.1-windows-x64.zip
```

Include:

```text
fcloak-gui.exe
README.md
TESTER_GUIDE.md
LICENSE
SECURITY.md
SHA256SUMS.txt
```

Do not include:

```text
.env
client_secret.json
credentials.json
vault.conf
*.fcloak
```
