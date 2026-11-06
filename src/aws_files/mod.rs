//! The AWS CLI's files: where they are, how they are read, and the only way gac writes them.

pub mod default_block;
pub mod guards;
pub mod managed_block;
pub mod paths;
pub mod read;
pub mod section;

pub use paths::AwsPaths;
pub use read::{AwsFiles, LegacySsoProfile, SsoSessionConfig};
