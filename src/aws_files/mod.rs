//! The AWS CLI's files: where they are, how they are read, and the only way gac writes them.

pub mod guards;
pub mod managed_block;
pub mod paths;
pub mod read;

pub use paths::AwsPaths;
pub use read::{AwsFiles, LegacySsoProfile, SsoSessionConfig};
