# Security Policy

## Current status

FCLOAK is currently an Alpha 1 project and has not undergone an independent security audit.

Do not use Alpha 1 as the sole protection for highly sensitive or irreplaceable information.

## Microsoft Defender False Positive

The FCLOAK Alpha 1 Windows executable was temporarily detected
by Microsoft Defender as `Trojan:Win32/Bearfoos.B!ml`.

The executable was submitted to Microsoft Security Intelligence
for analysis.

Submission ID:

`8bd1b05f-e3d6-42f0-8775-87e006a6cb59`

Microsoft's final determination was:

**Not malware**

Microsoft's analyst confirmed that the submitted file did not
meet their criteria for malware or potentially unwanted
applications and that the detection was removed.

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
