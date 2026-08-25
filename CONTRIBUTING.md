# Contributing to FCLOAK

Thank you for contributing to FCLOAK.

FCLOAK is currently an Alpha project, so architecture and APIs may change.

## Development

Clone the repository and enter it:

```powershell
git clone https://github.com/adarshkrdubay/fcloak.git
cd fcloak
```

Check the workspace:

```powershell
cargo check --workspace
```

Build:

```powershell
cargo build --workspace
```

Build the Windows GUI release:

```powershell
cargo build --release -p fcloak-gui
```

## Before submitting a change

Run:

```powershell
cargo fmt --all
cargo check --workspace
```

If practical, run the relevant tests:

```powershell
cargo test --workspace
```

## Pull requests

Please:

1. Keep changes focused.
2. Explain what changed.
3. Explain why it changed.
4. Include reproduction/testing steps for bug fixes.
5. Do not commit secrets or private files.
6. Do not commit `.fcloak` test containers containing sensitive information.
7. Update documentation when behavior changes.

## Security-sensitive changes

Changes involving encryption, key handling, authentication, password verification, cloud authorization, or secure storage should include additional explanation and testing.

Never submit real credentials.

## Commit messages

Prefer clear messages such as:

```text
Add OneDrive provider abstraction
Fix Drive download error handling
Improve vault auto-lock
Add encrypted container integrity test
```

## Contributors

Current contributors include:

- Adarsh Kumar
- Sana Iqbal
