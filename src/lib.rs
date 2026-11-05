//! gac: short-lived AWS credentials through IAM Identity Center.
//!
//! The library exists to serve the `gac` binary; its API stays private until 1.0.
//!
//! These modules carry no AWS types, so a future tool for another cloud could share them:
//! `fsx`, `secret`, `oauth`, `inventory`, `ui` and the `doctor` framework.

mod auth;
mod aws_files;
mod cli;
mod doctor;
mod domain;
mod error;
mod fsx;
mod inventory;
mod oauth;
mod portal;
mod profiles;
mod sdk;
mod secret;
mod ui;

pub use cli::run;
pub use error::Error;
