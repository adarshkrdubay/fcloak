use crate::format::FormatError;

#[derive(Debug)]
pub enum FcloakError {
    Crypto,
    InvalidPassword,
    InvalidFormat,
    Io(std::io::Error),
    Kdf(argon2::Error),
}

impl std::fmt::Display for FcloakError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crypto => {
                write!(f, "cryptographic operation failed")
            }

            Self::InvalidPassword => {
                write!(f, "invalid password")
            }

            Self::InvalidFormat => {
                write!(f, "invalid FCLOAK format")
            }

            Self::Io(error) => {
                write!(f, "I/O error: {error}")
            }

            Self::Kdf(error) => {
                write!(f, "key derivation failed: {error}")
            }
        }
    }
}

impl std::error::Error for FcloakError {}

impl From<std::io::Error> for FcloakError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<argon2::Error> for FcloakError {
    fn from(error: argon2::Error) -> Self {
        Self::Kdf(error)
    }
}

impl From<FormatError> for FcloakError {
    fn from(_: FormatError) -> Self {
        Self::InvalidFormat
    }
}
