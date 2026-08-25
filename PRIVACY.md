# Privacy Policy

FCLOAK is designed around local-first encryption.

## File contents

The normal cloud workflow uploads encrypted `.fcloak` containers rather than plaintext files.

## Cloud authentication

FCLOAK uses OAuth to authorize access to supported cloud storage.

Google Drive is the first cloud provider implemented in Alpha 1.

## Local data

Depending on the implementation and user actions, FCLOAK may store:

- encrypted vault containers
- password verifier/configuration data
- authentication credentials through the operating system credential store
- application metadata

Users should never upload passwords, OAuth tokens, refresh tokens, or private vault files when reporting issues.

## Alpha notice

FCLOAK is experimental software. Review the source code and cloud permissions before using it with sensitive information.
