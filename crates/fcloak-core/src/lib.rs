pub mod container;
pub mod crypto;
pub mod error;
pub mod file;
pub mod format;
pub mod keys;
pub mod streaming;
pub mod streaming_container;

pub const NAME: &str = "FCLOAK";

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
