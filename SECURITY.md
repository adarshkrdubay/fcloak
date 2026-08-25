# Security Policy

## Current status

FCLOAK is currently an Alpha 1 project and has not undergone an independent security audit.

Do not use Alpha 1 as the sole protection for highly sensitive or irreplaceable information.

## Reporting vulnerabilities

If you discover a security vulnerability, please report it privately to the project maintainer before publicly disclosing the issue.

Do not include passwords, OAuth tokens, refresh tokens, private documents, or private `.fcloak` containers in a report.

## Security principles

FCLOAK is designed around:

1. Local encryption before cloud synchronization.
2. Encrypted `.fcloak` containers in cloud storage.
3. Local decryption/export.
4. Argon2 password verification.
5. OS-backed storage for saved authentication credentials.
6. Automatic locking after inactivity.

These describe the intended Alpha 1 design and are not a security certification.
