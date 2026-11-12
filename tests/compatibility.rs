//! The formats docs/compatibility.md keeps stable across 1.x: every `--json` shape, the
//! `credential_process` output, and the managed blocks gac writes. A change to one of these
//! snapshots is a change to that promise: added fields are fine, anything else needs a
//! deprecation. Free text such as messages and hints is not part of it, so it is masked.

mod support;

use serde_json::Value;
use support::{SESSION, Sandbox, stdout};

fn login_device(sandbox: &Sandbox) {
    sandbox
        .gac()
        .args(["login", "--device-code", "--no-browser"])
        .assert()
        .success();
}

/// Runs `gac` with `args` and returns its stdout as JSON, whatever the exit code.
fn json(sandbox: &Sandbox, args: &[&str]) -> Value {
    let output = sandbox.gac().args(args).output().unwrap();
    serde_json::from_slice(&output.stdout).unwrap()
}

/// Replaces the values that vary between runs, and the free text, with placeholders.
fn masked(mut value: Value) -> String {
    fn walk(key: &str, value: &mut Value) {
        match value {
            Value::Object(map) => map.iter_mut().for_each(|(k, v)| walk(k, v)),
            Value::Array(items) => items.iter_mut().for_each(|v| walk(key, v)),
            Value::String(s) => {
                let placeholder = match key {
                    "message" | "fix" | "error" | "refreshError" => Some("[text]"),
                    "configFile" => Some("[path]"),
                    "SecretAccessKey" | "SessionToken" => Some("[secret]"),
                    _ if is_timestamp(s) => Some("[timestamp]"),
                    _ => None,
                };
                if let Some(placeholder) = placeholder {
                    placeholder.clone_into(s);
                }
            }
            _ => {}
        }
    }
    walk("", &mut value);
    let mut text = serde_json::to_string_pretty(&value).unwrap();
    text.push('\n');
    text
}

fn is_timestamp(s: &str) -> bool {
    s.len() == 20
        && s.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 => b == b'-',
            10 => b == b'T',
            13 | 16 => b == b':',
            19 => b == b'Z',
            _ => b.is_ascii_digit(),
        })
}

/// The managed block of the config file that starts with `begin`, with `\n` line endings.
fn block(config: &str, begin: &str) -> String {
    let config = config.replace("\r\n", "\n");
    let start = config.find(begin).expect("the block");
    let end_marker = if begin.contains(" sync ") {
        "# END gac-redux sync "
    } else {
        "# END gac-redux default"
    };
    let end = start + config[start..].find(end_marker).unwrap();
    let end = end + config[end..].find('\n').unwrap() + 1;
    config[start..end].to_owned()
}

/// A command that exits 0, on every platform.
fn exit_0() -> [&'static str; 3] {
    if cfg!(windows) {
        ["cmd", "/C", "exit 0"]
    } else {
        ["sh", "-c", "exit 0"]
    }
}

#[test]
fn status_json() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox
        .gac()
        .args([
            "sync",
            "--include",
            "payments-prod/*",
            "--exclude",
            "*/AdministratorAccess",
            "--region",
            "eu-west-1",
        ])
        .assert()
        .success();
    sandbox
        .gac()
        .args(["select", "payments-prod/ReadOnly", "--adopt"])
        .assert()
        .success();
    insta::assert_snapshot!(masked(json(&sandbox, &["status", "--json"])));
}

#[test]
fn list_json() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    insta::assert_snapshot!(masked(json(&sandbox, &["list", "--json"])));
}

#[test]
fn whoami_json() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox
        .gac()
        .args([
            "sync",
            "--include",
            "payments-prod/*",
            "--chain",
            "*/AdministratorAccess=arn:aws:iam::{account_id}:role/Deploy",
            "--region",
            "eu-west-1",
        ])
        .assert()
        .success();
    sandbox.gac().arg("list").assert().success();
    sandbox
        .gac()
        .args(["exec", "-p", "payments-prod/Deploy", "--"])
        .args(exit_0())
        .assert()
        .success();
    insta::assert_snapshot!(masked(json(
        &sandbox,
        &["whoami", "-p", "payments-prod/Deploy", "--json"]
    )));
}

#[test]
fn doctor_json() {
    let sandbox = Sandbox::with_session();
    // A finding of every level: a profile with both SSO settings and keys fails, a session
    // without a login warns, and a legacy inline-SSO profile warns with a fix --fix can apply.
    sandbox.write_config(&format!(
        "{SESSION}\n[profile mixed]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n\n\
         [profile legacy]\nsso_start_url = https://legacy.awsapps.com/start\nsso_region = us-east-1\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n"
    ));
    sandbox
        .write_credentials("[mixed]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = x\n");
    // Windows has no file modes to check, so make them right everywhere.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let private = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(sandbox.credentials_path(), private).unwrap();
    }
    insta::assert_snapshot!(masked(json(&sandbox, &["doctor", "--json"])));
}

#[test]
fn credential_process_json() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let output = sandbox
        .gac()
        .args([
            "credential-process",
            "--session",
            "corp",
            "--account-id",
            "111122223333",
            "--role-name",
            "ReadOnly",
        ])
        .assert()
        .success();
    let json: Value = serde_json::from_str(&stdout(output.get_output())).unwrap();
    insta::assert_snapshot!(masked(json));
}

#[test]
fn sync_block_with_every_setting() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox
        .gac()
        .args([
            "sync",
            "--mode",
            "process",
            "--name",
            "{session}.{account_id}.{role}",
            "--include",
            "payments-prod/*",
            "--include",
            "sandbox/*",
            "--exclude",
            "sandbox/AdministratorAccess",
            "--region",
            "eu-west-1",
            "--chain",
            "*/AdministratorAccess=arn:aws:iam::{account_id}:role/Deploy",
        ])
        .assert()
        .success();
    insta::assert_snapshot!(block(
        &sandbox.config(),
        "# BEGIN gac-redux sync session=corp"
    ));
}

#[test]
fn default_block() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox
        .gac()
        .args(["select", "payments-prod/ReadOnly", "--adopt"])
        .assert()
        .success();
    insta::assert_snapshot!(block(&sandbox.config(), "# BEGIN gac-redux default"));
}
