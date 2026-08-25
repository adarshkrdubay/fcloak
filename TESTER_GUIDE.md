# FCLOAK Alpha 1 Tester Guide

## Test 1 — Vault

1. Start FCLOAK.
2. Create a strong password.
3. Lock the application.
4. Unlock it with the correct password.
5. Try an incorrect password.

## Test 2 — Encryption

1. Select a disposable test file.
2. Encrypt/import it.
3. Confirm the `.fcloak` container appears.
4. Decrypt/export it.
5. Compare the original and restored SHA-256 hashes.

## Test 3 — Google Drive

1. Connect Google Drive.
2. Upload an encrypted `.fcloak` container.
3. Refresh the cloud file list.
4. Download the encrypted container.
5. Decrypt/export it.
6. Compare hashes.

## Test 4 — Session persistence

1. Connect Google Drive.
2. Close FCLOAK.
3. Restart FCLOAK.
4. Verify the saved authentication session.

## Test 5 — Auto-lock

Leave the application inactive for approximately five minutes.

Expected result: the vault locks and requires authentication.

## Bug report

Include:

- Windows version
- FCLOAK version
- Steps to reproduce
- Expected result
- Actual result
- Screenshots/logs if useful

Never include passwords, OAuth tokens, refresh tokens, private documents, or private encrypted containers.
