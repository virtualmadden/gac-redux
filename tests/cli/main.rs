//! End-to-end tests of the `gac` binary against the mock Identity Center, each in its own
//! sandbox HOME.

#[path = "../support/mod.rs"]
mod support;

mod commands;
mod login;
mod roles;
mod select;
mod status_doctor;
mod sync;
#[cfg(unix)]
mod terminal;
mod tokens;

use predicates::prelude::*;
use serde_json::{Value, json};
use support::mock_idc::account;
use support::{
    SESSION, START_URL, Sandbox, assert_no_secrets, exit_with, find_timestamp, login_device,
    stderr, stdout,
};

fn login_device_for(sandbox: &Sandbox, session: &str) {
    sandbox
        .gac()
        .args([
            "login",
            "--session",
            session,
            "--device-code",
            "--no-browser",
        ])
        .assert()
        .success();
}

fn login_pkce(sandbox: &Sandbox, extra: &[&str]) -> std::process::Output {
    let mut args = vec!["login", "--no-browser"];
    args.extend_from_slice(extra);
    support::drive_browser(sandbox.spawn_gac(&args))
}

/// The `corp` session plus a second one, so a command has to be told which to use.
fn two_sessions() -> Sandbox {
    let sandbox = Sandbox::new();
    sandbox.write_config(&format!(
        "{SESSION}\n[sso-session other]\nsso_start_url = https://other.awsapps.com/start\nsso_region = us-east-1\n"
    ));
    sandbox
}

/// The default block `gac select` appends for an account and role of `corp`.
fn default_block(account: &str, role: &str) -> String {
    format!(
        "# BEGIN gac-redux default\n\
         # Managed by gac-redux: `gac select` replaces this block.\n\
         [default]\n\
         sso_session = corp\n\
         sso_account_id = {account}\n\
         sso_role_name = {role}\n\
         # END gac-redux default\n"
    )
}

/// A command that prints its environment as `NAME=value` lines.
fn print_env() -> Vec<&'static str> {
    if cfg!(windows) {
        vec!["cmd", "/C", "set"]
    } else {
        vec!["env"]
    }
}

fn parse_env(output: &str) -> std::collections::BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_uppercase(), value.to_owned()))
        .collect()
}

/// The path botocore caches the credentials of a `corp` account and role at.
fn role_cache_path(sandbox: &Sandbox, account: &str, role: &str) -> std::path::PathBuf {
    use sha1::Digest;
    let args = format!(r#"{{"accountId":"{account}","roleName":"{role}","sessionName":"corp"}}"#);
    let key = hex::encode(sha1::Sha1::digest(args.as_bytes()));
    sandbox
        .home()
        .join(".aws/cli/cache")
        .join(format!("{key}.json"))
}

/// A `[default]` block without a region, and a `dev` profile with one.
fn role_profiles_config(sandbox: &Sandbox) {
    sandbox.write_config(&format!(
        "{SESSION}\n{}\n[profile dev]\nsso_session = corp\nsso_account_id = 777788889999\nsso_role_name = PowerUser\nregion = eu-west-1\n",
        default_block("111122223333", "ReadOnly")
    ));
}

/// The environment `gac exec --profile PROFILE` gives a command.
fn exec_env(sandbox: &Sandbox, profile: &str) -> std::collections::BTreeMap<String, String> {
    let output = sandbox
        .gac()
        .args(["exec", "--profile", profile, "--"])
        .args(print_env())
        .assert()
        .success();
    parse_env(&stdout(output.get_output()))
}

/// `gac env` output with the mock's secrets and the expiry replaced by placeholders.
fn redacted(sandbox: &Sandbox, text: &str) -> String {
    let mut text = text.to_owned();
    for secret in sandbox.mock.secrets() {
        text = text.replace(&secret, "[secret]");
    }
    let expiration = find_timestamp(&text)
        .expect("an expiration timestamp")
        .to_owned();
    text.replace(&expiration, "[expiration]")
}
