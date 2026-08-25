pub const MAGIC: &[u8; 6] = b"FCLOAK";
pub const FORMAT_VERSION: u8 = 1;

pub const NONCE_SIZE: usize = 12;
pub const SALT_SIZE: usize = 32;
pub const DEK_SIZE: usize = 32;
pub const WRAPPED_DEK_SIZE: usize = DEK_SIZE + 16;

/// Size of the fixed FCLOAK header.
///
/// Layout:
/// MAGIC          6 bytes
/// VERSION        1 byte
/// CIPHER         1 byte
/// KDF            1 byte
/// MEMORY         4 bytes
/// ITERATIONS     4 bytes
/// PARALLELISM    4 bytes
/// SALT           32 bytes
/// DEK NONCE      12 bytes
/// FILE NONCE     12 bytes
///
/// Total: 77 bytes.
pub const HEADER_SIZE: usize = 6 + 1 + 1 + 1 + 4 + 4 + 4 + SALT_SIZE + NONCE_SIZE + NONCE_SIZE;
/// FCLOAK streaming container version.
pub const STREAMING_FORMAT_VERSION: u8 = 2;

/// Default plaintext chunk size for streaming encryption.
pub const STREAMING_CHUNK_SIZE: u32 = 4 * 1024 * 1024;

/// Size of the FCLOAK v2 streaming header.
///
/// Layout:
/// magic             6
/// version           1
/// cipher            1
/// kdf               1
/// memory_kib        4
/// iterations        4
/// parallelism       4
/// salt             32
/// dek_wrap_nonce   12
/// base_nonce       12
/// chunk_size        4
///
/// Total = 81 bytes.
pub const STREAMING_HEADER_SIZE: usize =
    6 + 1 + 1 + 1 + 4 + 4 + 4 + SALT_SIZE + NONCE_SIZE + NONCE_SIZE + 4;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cipher {
    Aes256Gcm = 1,
}

impl TryFrom<u8> for Cipher {
    type Error = FormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Aes256Gcm),
            other => Err(FormatError::UnsupportedCipher(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kdf {
    Argon2id = 1,
}

impl TryFrom<u8> for Kdf {
    type Error = FormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Argon2id),
            other => Err(FormatError::UnsupportedKdf(other)),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FormatError {
    InvalidMagic,
    UnsupportedVersion(u8),
    UnsupportedCipher(u8),
    UnsupportedKdf(u8),
    InvalidChunkSize(u32),
    Truncated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub cipher: Cipher,
    pub kdf: Kdf,

    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,

    pub salt: [u8; SALT_SIZE],

    pub dek_wrap_nonce: [u8; NONCE_SIZE],
    pub file_nonce: [u8; NONCE_SIZE],
}

impl Header {
    /// Create a default FCLOAK v1 header.
    pub fn new(
        salt: [u8; SALT_SIZE],
        dek_wrap_nonce: [u8; NONCE_SIZE],
        file_nonce: [u8; NONCE_SIZE],
    ) -> Self {
        Self {
            version: FORMAT_VERSION,
            cipher: Cipher::Aes256Gcm,
            kdf: Kdf::Argon2id,

            memory_kib: 32_768,
            iterations: 3,
            parallelism: 1,

            salt,

            dek_wrap_nonce,
            file_nonce,
        }
    }

    /// Serialize the header into the canonical FCLOAK binary format.
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut output = [0u8; HEADER_SIZE];

        let mut offset = 0;

        // MAGIC
        output[offset..offset + 6].copy_from_slice(MAGIC);
        offset += 6;

        // VERSION
        output[offset] = self.version;
        offset += 1;

        // CIPHER
        output[offset] = self.cipher as u8;
        offset += 1;

        // KDF
        output[offset] = self.kdf as u8;
        offset += 1;

        // ARGON2 MEMORY
        output[offset..offset + 4].copy_from_slice(&self.memory_kib.to_le_bytes());
        offset += 4;

        // ARGON2 ITERATIONS
        output[offset..offset + 4].copy_from_slice(&self.iterations.to_le_bytes());
        offset += 4;

        // ARGON2 PARALLELISM
        output[offset..offset + 4].copy_from_slice(&self.parallelism.to_le_bytes());
        offset += 4;

        // SALT
        output[offset..offset + SALT_SIZE].copy_from_slice(&self.salt);
        offset += SALT_SIZE;

        // DEK WRAP NONCE
        output[offset..offset + NONCE_SIZE].copy_from_slice(&self.dek_wrap_nonce);
        offset += NONCE_SIZE;

        // FILE NONCE
        output[offset..offset + NONCE_SIZE].copy_from_slice(&self.file_nonce);

        output
    }

    /// Decode and validate a FCLOAK header.
    pub fn decode(input: &[u8]) -> Result<Self, FormatError> {
        if input.len() < HEADER_SIZE {
            return Err(FormatError::Truncated);
        }

        let mut offset = 0;

        // MAGIC
        if &input[offset..offset + 6] != MAGIC {
            return Err(FormatError::InvalidMagic);
        }

        offset += 6;

        // VERSION
        let version = input[offset];
        offset += 1;

        if version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }

        // CIPHER
        let cipher = Cipher::try_from(input[offset])?;
        offset += 1;

        // KDF
        let kdf = Kdf::try_from(input[offset])?;
        offset += 1;

        // ARGON2 MEMORY
        let memory_kib = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // ARGON2 ITERATIONS
        let iterations = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // ARGON2 PARALLELISM
        let parallelism = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // SALT
        let mut salt = [0u8; SALT_SIZE];

        salt.copy_from_slice(&input[offset..offset + SALT_SIZE]);
        offset += SALT_SIZE;

        // DEK WRAP NONCE
        let mut dek_wrap_nonce = [0u8; NONCE_SIZE];

        dek_wrap_nonce.copy_from_slice(&input[offset..offset + NONCE_SIZE]);
        offset += NONCE_SIZE;

        // FILE NONCE
        let mut file_nonce = [0u8; NONCE_SIZE];

        file_nonce.copy_from_slice(&input[offset..offset + NONCE_SIZE]);

        Ok(Self {
            version,
            cipher,
            kdf,

            memory_kib,
            iterations,
            parallelism,

            salt,

            dek_wrap_nonce,
            file_nonce,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingHeader {
    pub version: u8,
    pub cipher: Cipher,
    pub kdf: Kdf,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; SALT_SIZE],
    pub dek_wrap_nonce: [u8; NONCE_SIZE],
    pub base_nonce: [u8; NONCE_SIZE],
    pub chunk_size: u32,
}

impl StreamingHeader {
    /// Create a default FCLOAK v2 streaming header.
    pub fn new(
        salt: [u8; SALT_SIZE],
        dek_wrap_nonce: [u8; NONCE_SIZE],
        base_nonce: [u8; NONCE_SIZE],
    ) -> Self {
        Self {
            version: STREAMING_FORMAT_VERSION,
            cipher: Cipher::Aes256Gcm,
            kdf: Kdf::Argon2id,
            memory_kib: 32_768,
            iterations: 3,
            parallelism: 1,
            salt,
            dek_wrap_nonce,
            base_nonce,
            chunk_size: STREAMING_CHUNK_SIZE,
        }
    }

    /// Serialize the v2 streaming header.
    pub fn encode(&self) -> [u8; STREAMING_HEADER_SIZE] {
        let mut output = [0u8; STREAMING_HEADER_SIZE];

        let mut offset = 0;

        output[offset..offset + 6].copy_from_slice(MAGIC);
        offset += 6;

        output[offset] = self.version;
        offset += 1;

        output[offset] = self.cipher as u8;
        offset += 1;

        output[offset] = self.kdf as u8;
        offset += 1;

        output[offset..offset + 4].copy_from_slice(&self.memory_kib.to_le_bytes());
        offset += 4;

        output[offset..offset + 4].copy_from_slice(&self.iterations.to_le_bytes());
        offset += 4;

        output[offset..offset + 4].copy_from_slice(&self.parallelism.to_le_bytes());
        offset += 4;

        output[offset..offset + SALT_SIZE].copy_from_slice(&self.salt);
        offset += SALT_SIZE;

        output[offset..offset + NONCE_SIZE].copy_from_slice(&self.dek_wrap_nonce);
        offset += NONCE_SIZE;

        output[offset..offset + NONCE_SIZE].copy_from_slice(&self.base_nonce);
        offset += NONCE_SIZE;

        output[offset..offset + 4].copy_from_slice(&self.chunk_size.to_le_bytes());

        output
    }

    /// Decode and validate a v2 streaming header.
    pub fn decode(input: &[u8]) -> Result<Self, FormatError> {
        if input.len() < STREAMING_HEADER_SIZE {
            return Err(FormatError::Truncated);
        }

        let mut offset = 0;

        if &input[offset..offset + 6] != MAGIC {
            return Err(FormatError::InvalidMagic);
        }

        offset += 6;

        let version = input[offset];
        offset += 1;

        if version != STREAMING_FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }

        let cipher = Cipher::try_from(input[offset])?;
        offset += 1;

        let kdf = Kdf::try_from(input[offset])?;
        offset += 1;

        let memory_kib = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let iterations = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let parallelism = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let mut salt = [0u8; SALT_SIZE];

        salt.copy_from_slice(&input[offset..offset + SALT_SIZE]);

        offset += SALT_SIZE;

        let mut dek_wrap_nonce = [0u8; NONCE_SIZE];

        dek_wrap_nonce.copy_from_slice(&input[offset..offset + NONCE_SIZE]);

        offset += NONCE_SIZE;

        let mut base_nonce = [0u8; NONCE_SIZE];

        base_nonce.copy_from_slice(&input[offset..offset + NONCE_SIZE]);

        offset += NONCE_SIZE;

        let chunk_size = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap());

        if chunk_size == 0 || chunk_size > STREAMING_CHUNK_SIZE {
            return Err(FormatError::InvalidChunkSize(chunk_size));
        }

        Ok(Self {
            version,
            cipher,
            kdf,
            memory_kib,
            iterations,
            parallelism,
            salt,
            dek_wrap_nonce,
            base_nonce,
            chunk_size,
        })
    }
}
/// Identifies which FCLOAK container format is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerFormat {
    /// FCLOAK v1 fixed-size container.
    Standard,

    /// FCLOAK v2 streaming container.
    Streaming,
}

/// Detect the FCLOAK container format from its prefix.
///
/// This only identifies the format. It does not fully validate the
/// container. Full validation must still be performed by the
/// corresponding header decoder.
pub fn detect_container_format(input: &[u8]) -> Result<ContainerFormat, FormatError> {
    if input.len() < MAGIC.len() + 1 {
        return Err(FormatError::Truncated);
    }

    if &input[..MAGIC.len()] != MAGIC {
        return Err(FormatError::InvalidMagic);
    }

    match input[MAGIC.len()] {
        FORMAT_VERSION => Ok(ContainerFormat::Standard),
        STREAMING_FORMAT_VERSION => Ok(ContainerFormat::Streaming),
        version => Err(FormatError::UnsupportedVersion(version)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header() -> Header {
        Header::new(
            [0x42u8; SALT_SIZE],
            [0x11u8; NONCE_SIZE],
            [0x22u8; NONCE_SIZE],
        )
    }

    #[test]
    fn header_round_trip() {
        let original = test_header();

        let encoded = original.encode();

        assert_eq!(encoded.len(), HEADER_SIZE);

        let decoded = Header::decode(&encoded).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]

    fn header_size_is_77_bytes() {
        assert_eq!(HEADER_SIZE, 77);
    }

    #[test]
    fn invalid_magic_is_rejected() {
        let header = test_header();

        let mut encoded = header.encode();

        encoded[0] = b'X';

        let result = Header::decode(&encoded);

        assert_eq!(result, Err(FormatError::InvalidMagic));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let header = test_header();

        let mut encoded = header.encode();

        encoded[6] = 99;

        let result = Header::decode(&encoded);

        assert_eq!(result, Err(FormatError::UnsupportedVersion(99)));
    }

    #[test]
    fn unsupported_cipher_is_rejected() {
        let header = test_header();

        let mut encoded = header.encode();

        encoded[7] = 99;

        let result = Header::decode(&encoded);

        assert_eq!(result, Err(FormatError::UnsupportedCipher(99)));
    }

    #[test]
    fn unsupported_kdf_is_rejected() {
        let header = test_header();

        let mut encoded = header.encode();

        encoded[8] = 99;

        let result = Header::decode(&encoded);

        assert_eq!(result, Err(FormatError::UnsupportedKdf(99)));
    }

    #[test]
    fn truncated_header_is_rejected() {
        let header = test_header();

        let encoded = header.encode();

        let result = Header::decode(&encoded[..10]);

        assert_eq!(result, Err(FormatError::Truncated));
    }

    #[test]
    fn salt_survives_round_trip() {
        let salt = [0xAAu8; SALT_SIZE];

        let header = Header::new(salt, [0x11u8; NONCE_SIZE], [0x22u8; NONCE_SIZE]);

        let encoded = header.encode();
        let decoded = Header::decode(&encoded).unwrap();

        assert_eq!(decoded.salt, salt);
    }

    #[test]
    fn nonces_survive_round_trip() {
        let dek_nonce = [0x11u8; NONCE_SIZE];
        let file_nonce = [0x22u8; NONCE_SIZE];

        let header = Header::new([0x42u8; SALT_SIZE], dek_nonce, file_nonce);

        let encoded = header.encode();
        let decoded = Header::decode(&encoded).unwrap();

        assert_eq!(decoded.dek_wrap_nonce, dek_nonce);
        assert_eq!(decoded.file_nonce, file_nonce);
    }
    #[test]
    fn streaming_header_round_trip() {
        let header = StreamingHeader::new(
            [0x42u8; SALT_SIZE],
            [0x11u8; NONCE_SIZE],
            [0x22u8; NONCE_SIZE],
        );

        let encoded = header.encode();

        assert_eq!(encoded.len(), STREAMING_HEADER_SIZE);

        let decoded = StreamingHeader::decode(&encoded).unwrap();

        assert_eq!(decoded, header);
    }

    #[test]
    fn streaming_header_size_is_81_bytes() {
        assert_eq!(STREAMING_HEADER_SIZE, 81);
    }

    #[test]
    fn streaming_header_rejects_invalid_chunk_size() {
        let mut header = StreamingHeader::new(
            [0x42u8; SALT_SIZE],
            [0x11u8; NONCE_SIZE],
            [0x22u8; NONCE_SIZE],
        );

        header.chunk_size = 0;

        let encoded = header.encode();

        let result = StreamingHeader::decode(&encoded);

        assert_eq!(result, Err(FormatError::InvalidChunkSize(0)));
    }

    #[test]
    fn streaming_header_rejects_wrong_version() {
        let header = StreamingHeader::new(
            [0x42u8; SALT_SIZE],
            [0x11u8; NONCE_SIZE],
            [0x22u8; NONCE_SIZE],
        );

        let mut encoded = header.encode();

        encoded[6] = 99;

        let result = StreamingHeader::decode(&encoded);

        assert_eq!(result, Err(FormatError::UnsupportedVersion(99)));
    }
    #[test]
    fn detects_standard_container() {
        let header = test_header();
        let encoded = header.encode();

        let detected = detect_container_format(&encoded).unwrap();

        assert_eq!(detected, ContainerFormat::Standard);
    }

    #[test]
    fn detects_streaming_container() {
        let header = StreamingHeader::new(
            [0x42u8; SALT_SIZE],
            [0x11u8; NONCE_SIZE],
            [0x22u8; NONCE_SIZE],
        );

        let encoded = header.encode();

        let detected = detect_container_format(&encoded).unwrap();

        assert_eq!(detected, ContainerFormat::Streaming);
    }

    #[test]
    fn detection_rejects_invalid_magic() {
        let mut input = [0u8; 7];

        input[..MAGIC.len()].copy_from_slice(MAGIC);
        input[0] = b'X';

        let result = detect_container_format(&input);

        assert_eq!(result, Err(FormatError::InvalidMagic));
    }

    #[test]
    fn detection_rejects_unsupported_version() {
        let mut input = [0u8; 7];

        input[..MAGIC.len()].copy_from_slice(MAGIC);
        input[MAGIC.len()] = 99;

        let result = detect_container_format(&input);

        assert_eq!(result, Err(FormatError::UnsupportedVersion(99)));
    }

    #[test]
    fn detection_rejects_truncated_prefix() {
        let input = b"FCLOA";

        let result = detect_container_format(input);

        assert_eq!(result, Err(FormatError::Truncated));
    }
}
