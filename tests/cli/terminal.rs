//! What a person at a terminal sees: gac prompts only where stdin and stderr are terminals.

use std::process::Stdio;

use rexpect::process::WaitStatus;
use rexpect::session::{PtySession, spawn_command};

use super::*;

/// `gac` in a pseudo-terminal. `SSH_CONNECTION` makes a login use the device code flow without
/// a browser, which the mock approves on its own.
fn spawn(sandbox: &Sandbox, args: &[&str]) -> PtySession {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_gac"));
    sandbox.confine(&mut cmd);
    cmd.args(args)
        .env("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22")
        .env("TERM", "xterm")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    spawn_command(cmd, Some(30_000)).unwrap()
}

fn exit_code(session: &PtySession) -> i32 {
    match session.process().wait().unwrap() {
        WaitStatus::Exited(_, code) => code,
        status => panic!("gac did not exit: {status:?}"),
    }
}

#[test]
fn a_missing_login_is_offered_and_the_command_goes_on() {
    let sandbox = Sandbox::with_session();
    let mut session = spawn(&sandbox, &["list"]);
    session
        .exp_string("Not logged in to session `corp`. Sign in now?")
        .unwrap();
    session.send_line("").unwrap();
    session.exp_string("Logged in to session `corp`").unwrap();
    session.exp_string("payments-prod").unwrap();
    session.exp_eof().unwrap();
    assert_eq!(exit_code(&session), 0);
    assert_eq!(sandbox.mock.counter("device_authorization"), 1);
}

#[test]
fn a_declined_login_exits_3_without_signing_in() {
    let sandbox = Sandbox::with_session();
    let mut session = spawn(&sandbox, &["list"]);
    session.exp_string("Sign in now?").unwrap();
    session.send_line("n").unwrap();
    // The error, once, with its reason and hint.
    let rest = session.exp_eof().unwrap();
    assert_eq!(
        rest.matches("not logged in to session `corp`").count(),
        1,
        "{rest}"
    );
    assert!(rest.contains("no cached SSO token"), "{rest}");
    assert!(rest.contains("run `gac login --session corp`"), "{rest}");
    assert_eq!(exit_code(&session), 3);
    assert_eq!(sandbox.mock.counter("device_authorization"), 0);
}

#[test]
fn exec_offers_a_login_before_running_the_command() {
    let sandbox = Sandbox::with_session();
    sandbox.write_config(&format!(
        "{SESSION}\n[profile dev]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n"
    ));
    let mut session = spawn(
        &sandbox,
        &[
            "exec",
            "--profile",
            "dev",
            "--",
            "sh",
            "-c",
            "echo role=$GAC_REDUX_EXEC",
        ],
    );
    session.exp_string("Sign in now?").unwrap();
    session.send_line("y").unwrap();
    session.exp_string("role=profile `dev`").unwrap();
    session.exp_eof().unwrap();
    assert_eq!(exit_code(&session), 0);
    assert_eq!(sandbox.mock.counter("credentials"), 1);
}

#[test]
fn select_print_picks_from_the_list_and_writes_nothing() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox.gac().arg("sync").assert().success();
    let config = sandbox.config();
    let mut session = spawn(&sandbox, &["select", "--print"]);
    // The list is drawn, and reading keys, once its help line is.
    session.exp_string("enter to choose").unwrap();
    // The first row is payments-prod/AdministratorAccess; one down is ReadOnly.
    session.send("\x1b[B\r").unwrap();
    session.flush().unwrap();
    let rest = session.exp_eof().unwrap();
    assert!(rest.contains("payments-prod/ReadOnly\r\n"), "{rest}");
    assert_eq!(exit_code(&session), 0);
    assert_eq!(sandbox.config(), config);
}

#[test]
fn credential_process_never_prompts() {
    let sandbox = Sandbox::with_session();
    let mut session = spawn(
        &sandbox,
        &[
            "credential-process",
            "--session",
            "corp",
            "--account-id",
            "111122223333",
            "--role-name",
            "ReadOnly",
        ],
    );
    let output = session.exp_eof().unwrap();
    assert!(!output.contains("Sign in now?"), "{output}");
    assert_eq!(exit_code(&session), 3);
}

#[test]
fn no_input_never_prompts() {
    let sandbox = Sandbox::with_session();
    let mut session = spawn(&sandbox, &["--no-input", "list"]);
    let output = session.exp_eof().unwrap();
    assert!(!output.contains("Sign in now?"), "{output}");
    assert_eq!(exit_code(&session), 3);
}
