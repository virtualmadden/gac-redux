//! End-to-end tests of the `gac` binary against the mock Identity Center, each in its own
//! sandbox HOME.

mod support;

use predicates::prelude::*;
use serde_json::{Value, json};
use support::mock_idc::account;
use support::{SESSION, START_URL, Sandbox, assert_no_secrets, stderr, stdout};

fn login_device(sandbox: &Sandbox) {
    sandbox
        .gac()
        .args(["login", "--device-code", "--no-browser"])
        .assert()
        .success();
}

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

#[test]
fn bare_command_prints_help() {
    let sandbox = Sandbox::new();
    sandbox
        .gac()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage: gac"));
    let help = sandbox.gac().arg("--help").assert().success();
    insta::assert_snapshot!(String::from_utf8_lossy(&help.get_output().stdout));
}

#[test]
fn subcommand_help_lists_gac_session_inline() {
    let sandbox = Sandbox::new();
    let help = sandbox.gac().args(["logout", "--help"]).assert().success();
    insta::assert_snapshot!(String::from_utf8_lossy(&help.get_output().stdout));
}

#[test]
fn completions_print_a_script_for_every_shell_without_reading_the_aws_files() {
    let sandbox = Sandbox::new();
    sandbox.write_config("[profile broken\n");
    for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
        let output = sandbox.gac().args(["completions", shell]).output().unwrap();
        assert!(output.status.success(), "{shell}: {}", stderr(&output));
        let script = stdout(&output);
        for word in ["gac", "select", "session", "dry-run"] {
            assert!(script.contains(word), "{shell}: no `{word}` in the script");
        }
        // Check the syntax with the shell itself where it is installed; bash always is on Unix.
        // The scripts are the same on every platform, and the bash on a Windows runner cannot
        // read a Windows path, so the check runs on Unix only.
        let check = match shell {
            _ if !cfg!(unix) => None,
            "bash" | "zsh" => Some(vec![shell, "-n"]),
            "fish" => Some(vec!["fish", "--no-execute"]),
            _ => None,
        };
        let Some(check) = check else { continue };
        let script_path = sandbox.home().join(format!("gac.{shell}"));
        std::fs::write(&script_path, &script).unwrap();
        match std::process::Command::new(check[0])
            .args(&check[1..])
            .arg(&script_path)
            .output()
        {
            Ok(result) => assert!(
                result.status.success(),
                "{shell} rejects the script: {}",
                String::from_utf8_lossy(&result.stderr)
            ),
            Err(err) if shell == "bash" => panic!("cannot run bash: {err}"),
            Err(_) => {}
        }
    }
    sandbox.gac().args(["completions", "tcsh"]).assert().code(2);
}

#[test]
fn man_writes_a_page_per_command() {
    let sandbox = Sandbox::new();
    let dir = sandbox.home().join("man");
    sandbox
        .gac()
        .arg("man")
        .arg(&dir)
        .assert()
        .success()
        .stdout("");
    let mut pages: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    pages.sort();
    assert_eq!(
        pages,
        [
            "gac-completions.1",
            "gac-console.1",
            "gac-credential-process.1",
            "gac-doctor.1",
            "gac-env.1",
            "gac-exec.1",
            "gac-list.1",
            "gac-login.1",
            "gac-logout.1",
            "gac-select.1",
            "gac-setup.1",
            "gac-status.1",
            "gac-sync.1",
            "gac-whoami.1",
            "gac.1"
        ]
    );
    let root = std::fs::read_to_string(dir.join("gac.1")).unwrap();
    let version = format!("\"gac-redux {}\"", env!("CARGO_PKG_VERSION"));
    for needle in [
        ".TH gac 1",
        "gac\\-sync(1)",
        ".SH ENVIRONMENT",
        "GAC_REDUX_SESSION",
        ".SH FILES",
        ".SH \"EXIT STATUS\"",
        &version,
    ] {
        assert!(root.contains(needle), "no `{needle}` in gac.1:\n{root}");
    }
    let sync = std::fs::read_to_string(dir.join("gac-sync.1")).unwrap();
    assert!(sync.contains("\\-\\-dry\\-run"), "{sync}");
    assert!(sync.contains(&version), "{sync}");
}

/// The block `gac setup` writes for the `corp` session.
const SETUP_BLOCK: &str = "\
# BEGIN gac-redux sync session=corp
# Managed by gac-redux: edits inside this block are replaced on the next sync.
[sso-session corp]
sso_start_url = https://mock-example.awsapps.com/start
sso_region = us-west-2
sso_registration_scopes = sso:account:access
# END gac-redux sync session=corp
";

#[test]
fn setup_writes_its_session_inside_a_managed_block() {
    let sandbox = Sandbox::new();
    let original = "# my settings\n[default]\nregion = eu-west-1";
    sandbox.write_config(original);
    sandbox
        .gac()
        .args([
            "setup",
            "--session",
            "corp",
            "--start-url",
            START_URL,
            "--region",
            "us-west-2",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Added [sso-session corp]"));
    let set_up = format!("{original}\n\n{SETUP_BLOCK}");
    assert_eq!(sandbox.config(), set_up);

    // Running it again reuses the session and changes nothing.
    sandbox
        .gac()
        .args(["setup", "--session", "corp", "--start-url", START_URL])
        .assert()
        .success()
        .stderr(predicate::str::contains("reusing it"));
    // Asking for different settings under the same name is refused.
    sandbox
        .gac()
        .args(["setup", "--session", "corp", "--region", "eu-central-1"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
    assert_eq!(sandbox.config(), set_up);

    // Sync fills the same block and keeps the session in it; nothing outside the block changes.
    login_device(&sandbox);
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .success()
        .stderr(predicate::str::contains("Synced 5 profiles"));
    let synced = sandbox.config();
    let block = synced
        .strip_prefix(&format!("{original}\n\n"))
        .unwrap_or_else(|| panic!("the user's bytes are a prefix:\n{synced}"));
    let head = SETUP_BLOCK
        .replacen(
            "session=corp\n",
            "session=corp mode=sso name={account}/{role}\n",
            1,
        )
        .replace("# END gac-redux sync session=corp\n", "");
    assert!(block.starts_with(&format!("{head}\n[profile ")), "{block}");
    assert!(block.ends_with("# END gac-redux sync session=corp\n"));
    assert!(block.contains("[profile payments-prod/ReadOnly]\nsso_session = corp\n"));
    sandbox
        .gac()
        .args(["sync", "--reset"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Already up to date"));
    assert_eq!(sandbox.config(), synced);
    sandbox.gac().args(["list", "--refresh"]).assert().success();
}

#[test]
fn setup_reuses_a_session_from_aws_configure_sso() {
    let sandbox = Sandbox::with_session();
    sandbox
        .gac()
        .args(["setup", "--start-url", START_URL])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "[sso-session corp] already exists",
        ));
    assert_eq!(sandbox.config(), SESSION);
}

#[test]
fn setup_without_a_terminal_needs_its_flags() {
    let sandbox = Sandbox::new();
    sandbox
        .gac()
        .args(["setup", "--region", "us-west-2"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--start-url is required"));
}

#[test]
fn pkce_login_writes_a_token_the_aws_cli_can_use() {
    let sandbox = Sandbox::with_session();
    let output = login_pkce(&sandbox, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("Logged in to session `corp`"));
    assert_eq!(stdout(&output), "", "stdout carries only requested data");

    let text = sandbox.token_text("corp");
    assert_eq!(
        support::key_order(&text),
        [
            "startUrl",
            "region",
            "accessToken",
            "expiresAt",
            "clientId",
            "clientSecret",
            "registrationExpiresAt",
            "refreshToken"
        ]
    );
    assert!(text.starts_with(&format!(
        "{{\"startUrl\": \"{START_URL}\", \"region\": \"us-west-2\", "
    )));
    let token = sandbox.token("corp");
    assert!(token["expiresAt"].as_str().unwrap().ends_with('Z'));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(sandbox.token_path("corp"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir = std::fs::metadata(sandbox.token_path("corp").parent().unwrap()).unwrap();
        assert_eq!(dir.permissions().mode() & 0o777, 0o700);
    }
    assert_eq!(sandbox.mock.counter("token_code"), 1);

    // The registration is cached: a second login does not register again.
    let again = login_pkce(&sandbox, &[]);
    assert!(again.status.success(), "{}", stderr(&again));
    assert_eq!(sandbox.mock.counter("register"), 1);
}

#[test]
fn pkce_login_reports_a_denied_sign_in() {
    let sandbox = Sandbox::with_session();
    sandbox.mock.deny_authorize();
    let output = login_pkce(&sandbox, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("access_denied"),
        "{}",
        stderr(&output)
    );
    assert!(!sandbox.token_path("corp").exists());
}

#[test]
fn device_login_polls_until_approved() {
    let sandbox = Sandbox::with_session();
    sandbox.mock.set_pending_polls(2);
    sandbox
        .gac()
        .args(["login", "--device-code", "--no-browser"])
        .assert()
        .success()
        .stderr(predicate::str::contains("MOCK-CODE"))
        .stderr(predicate::str::contains(
            "Only approve a code you requested yourself",
        ));
    assert_eq!(sandbox.mock.counter("token_device"), 1);
    assert!(sandbox.token("corp")["refreshToken"].is_string());
}

#[test]
fn ssh_sessions_default_to_the_device_code_flow() {
    let sandbox = Sandbox::with_session();
    sandbox
        .gac()
        .env("SSH_CONNECTION", "10.0.0.1 50000 10.0.0.2 22")
        .args(["login", "--no-browser"])
        .assert()
        .success()
        .stderr(predicate::str::contains("SSH session detected"));
    assert_eq!(sandbox.mock.counter("token_device"), 1);
    assert_eq!(sandbox.mock.counter("token_code"), 0);
}

#[test]
fn port_never_picks_the_flow() {
    let sandbox = Sandbox::with_session();
    sandbox
        .gac()
        .env("SSH_CONNECTION", "10.0.0.1 50000 10.0.0.2 22")
        .args(["login", "--no-browser", "--port", "8400"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("device code flow"))
        .stderr(predicate::str::contains("--pkce"));
    sandbox
        .gac()
        .args(["login", "--device-code", "--no-browser", "--port", "8400"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--pkce"));
    assert_eq!(sandbox.mock.counter("register"), 0);
    assert!(!sandbox.token_path("corp").exists());
}

#[test]
fn legacy_profiles_log_in_with_a_start_url_key() {
    let sandbox = Sandbox::new();
    sandbox.write_config(&format!(
        "[profile old]\nsso_start_url = {START_URL}\nsso_region = us-west-2\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n"
    ));
    // Like the AWS CLI, legacy profiles sign in with the device code flow only: their client is
    // registered without scopes, which a PKCE /authorize request cannot match.
    sandbox
        .gac()
        .args(["login", "--pkce", "--no-browser", "--profile", "old"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("inline start URL"));
    assert_eq!(sandbox.mock.counter("register"), 0);
    sandbox
        .gac()
        .args(["login", "--no-browser", "--profile", "old"])
        .assert()
        .success()
        .stderr(predicate::str::contains("inline start URL"));
    assert_eq!(sandbox.mock.counter("token_code"), 0);
    assert_eq!(sandbox.mock.counter("token_device"), 1);
    let token = sandbox.token(START_URL);
    assert!(
        token.get("refreshToken").is_none(),
        "legacy logins are not refreshable"
    );
    let status = sandbox.gac().args(["status", "--json"]).assert().success();
    let status: Value = serde_json::from_slice(&status.get_output().stdout).unwrap();
    assert_eq!(status["sessions"][0]["kind"], "legacy-profile");
    assert_eq!(status["sessions"][0]["token"]["state"], "valid");
}

#[test]
fn several_sessions_need_a_choice() {
    let sandbox = Sandbox::new();
    sandbox.write_config(&format!(
        "{SESSION}\n[sso-session other]\nsso_start_url = https://other.awsapps.com/start\nsso_region = us-east-1\n"
    ));
    sandbox
        .gac()
        .args(["list"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("corp, other"))
        .stderr(predicate::str::contains("gac select"))
        .stderr(predicate::str::contains("--session"));
    sandbox
        .gac()
        .env("GAC_REDUX_SESSION", "corp")
        .args(["list"])
        .assert()
        .code(3);
}

#[test]
fn an_exported_gac_session_yields_to_profile_and_all() {
    let sandbox = Sandbox::new();
    sandbox.write_config(&format!(
        "{SESSION}\n[sso-session other]\nsso_start_url = https://other.awsapps.com/start\nsso_region = us-east-1\n\n[profile dev]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n"
    ));
    sandbox
        .gac()
        .env("GAC_REDUX_SESSION", "other")
        .args(["login", "--device-code", "--no-browser", "--profile", "dev"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Logged in to session `corp`"));
    assert!(sandbox.token_path("corp").exists());
    sandbox
        .gac()
        .env("GAC_REDUX_SESSION", "other")
        .args(["logout", "--all"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Logged out of session `corp`."));
    assert!(!sandbox.token_path("corp").exists());
    // A --session typed on the command line still conflicts.
    sandbox
        .gac()
        .args(["login", "--session", "other", "--profile", "dev"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
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

#[test]
fn select_writes_the_default_profile() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox
        .gac()
        .args(["select", "sandbox/PowerUser"])
        .assert()
        .success()
        .stdout("")
        .stderr(predicate::str::contains(
            "The default profile is now sandbox/PowerUser (account 777788889999, session `corp`).",
        ));
    let selected = sandbox.config();
    assert_eq!(
        selected,
        format!("{SESSION}\n{}", default_block("777788889999", "PowerUser"))
    );

    // Choosing the same row again writes nothing; another row replaces the block in place.
    sandbox
        .gac()
        .args(["select", "777788889999/poweruser"])
        .assert()
        .success();
    assert_eq!(sandbox.config(), selected);
    sandbox
        .gac()
        .args(["select", "shared-services/ReadOnly"])
        .assert()
        .success();
    assert_eq!(
        sandbox.config(),
        format!("{SESSION}\n{}", default_block("444455556666", "ReadOnly"))
    );

    let status = sandbox.gac().arg("status").assert().success();
    let status = stdout(status.get_output());
    assert!(status.contains("session corp (default)\n"), "{status}");
    assert!(status.contains("  [default]     account 444455556666, role ReadOnly\n"));
    let json = sandbox.gac().args(["status", "--json"]).assert().success();
    let json: Value = serde_json::from_slice(&json.get_output().stdout).unwrap();
    assert_eq!(
        json["sessions"][0]["defaultProfile"],
        json!({"accountId": "444455556666", "roleName": "ReadOnly"})
    );
    sandbox
        .gac()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "[default] uses account 444455556666, role ReadOnly",
        ));

    sandbox
        .gac()
        .args(["select", "--clear"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Cleared the account and role from [default]",
        ));
    assert_eq!(
        sandbox.config(),
        format!(
            "{SESSION}\n# BEGIN gac-redux default\n\
             # Managed by gac-redux: `gac select` replaces this block.\n\
             [default]\nsso_session = corp\n# END gac-redux default\n"
        )
    );
    sandbox
        .gac()
        .args(["select", "--clear"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Nothing to clear."));
}

#[test]
fn select_print_names_the_roles_profile_and_writes_nothing() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox.gac().arg("sync").assert().success();
    // A hand-written profile for the same role: the synced one is preferred.
    let mut config = sandbox.config();
    config.push_str(
        "\n[profile aaa]\nsso_session = corp\nsso_account_id = 777788889999\nsso_role_name = PowerUser\n",
    );
    sandbox.write_config(&config);

    sandbox
        .gac()
        .args(["select", "--print", "sandbox/PowerUser"])
        .assert()
        .success()
        .stdout("sandbox/PowerUser\n");
    assert_eq!(sandbox.config(), config);

    // Without a synced profile, a hand-written one is printed.
    sandbox
        .gac()
        .args(["sync", "--exclude", "sandbox/*"])
        .assert()
        .success();
    let config = sandbox.config();
    sandbox
        .gac()
        .args(["select", "--print", "777788889999/PowerUser"])
        .assert()
        .success()
        .stdout("aaa\n");

    // With none at all, the hint points to sync.
    sandbox
        .gac()
        .args(["select", "--print", "sandbox/ReadOnly"])
        .assert()
        .code(1)
        .stdout("")
        .stderr(predicate::str::contains(
            "no profile in the AWS config file signs in as sandbox/ReadOnly",
        ))
        .stderr(predicate::str::contains("gac sync --session corp"));
    assert_eq!(sandbox.config(), config);

    sandbox
        .gac()
        .args(["select", "--print", "--clear"])
        .assert()
        .code(2);
}

#[test]
fn select_adopts_a_hand_written_default_only_with_consent() {
    let sandbox = Sandbox::new();
    let before = format!("{SESSION}\n# No account on purpose.\n");
    let hand = "[default]\nsso_session = corp\nregion      = us-west-2\n";
    let after = "\n# the next one\n[profile mine]\nregion = eu-west-1\n";
    sandbox.write_config(&format!("{before}{hand}{after}"));
    login_device(&sandbox);
    let original = sandbox.config();

    sandbox
        .gac()
        .args(["select", "sandbox/ReadOnly"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "a [default] section that gac did not write",
        ))
        .stderr(predicate::str::contains("--adopt"));
    assert_eq!(
        sandbox.config(),
        original,
        "nothing is written without consent"
    );

    sandbox
        .gac()
        .args(["select", "sandbox/ReadOnly", "--adopt"])
        .assert()
        .success();
    assert_eq!(
        sandbox.config(),
        format!(
            "{before}# BEGIN gac-redux default\n\
             # Managed by gac-redux: `gac select` replaces this block.\n\
             [default]\n\
             sso_session    = corp\n\
             region         = us-west-2\n\
             sso_account_id = 777788889999\n\
             sso_role_name  = ReadOnly\n\
             # END gac-redux default\n{after}"
        ),
        "the section is replaced in place, in its own alignment"
    );

    sandbox.gac().args(["select", "--clear"]).assert().success();
    assert_eq!(
        sandbox.config(),
        format!(
            "{before}# BEGIN gac-redux default\n\
             # Managed by gac-redux: `gac select` replaces this block.\n\
             {hand}# END gac-redux default\n{after}"
        ),
        "clearing restores the section as it was written"
    );
}

#[test]
fn select_without_a_terminal_needs_a_target() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox
        .gac()
        .arg("select")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("interactive terminal"))
        .stderr(predicate::str::contains("ACCOUNT/ROLE"));
    sandbox
        .gac()
        .args(["select", "nope/ReadOnly"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "no account and role match `nope/ReadOnly`",
        ));
    sandbox
        .gac()
        .args(["select", "sandbox/ReadOnly", "--clear"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
    sandbox.write_credentials(
        "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = x\n",
    );
    sandbox
        .gac()
        .args(["select", "sandbox/ReadOnly"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("would hide its keys"));
    assert_eq!(sandbox.config(), SESSION);
}

#[test]
fn select_lists_every_session_and_the_default_picks_the_session() {
    let sandbox = two_sessions();
    login_device_for(&sandbox, "corp");
    sandbox
        .gac()
        .args(["select", "sandbox/ReadOnly"])
        .assert()
        .success()
        .stderr(predicate::str::contains("skipping session `other`"));
    sandbox
        .gac()
        .args(["--session", "other", "select", "sandbox/ReadOnly"])
        .assert()
        .code(3);

    // With two sessions, commands now use the session of [default].
    sandbox.gac().arg("list").assert().success();
    sandbox
        .gac()
        .env("GAC_REDUX_SESSION", "other")
        .arg("list")
        .assert()
        .code(3);
}

#[test]
fn state_and_blocks_from_before_the_rename_are_migrated() {
    let sandbox = Sandbox::new();
    let legacy_block = "# BEGIN gac sync session=corp mode=sso name={account}/{role}\n\
                        # Managed by gac: edits inside this block are replaced on the next sync.\n\
                        [profile old/Role]\n\
                        sso_session = corp\n\
                        sso_account_id = 111122223333\n\
                        sso_role_name = Role\n\
                        # END gac sync session=corp\n";
    sandbox.write_config(&format!("{SESSION}\n{legacy_block}"));
    let legacy_state = sandbox.home().join(".aws/gac");
    std::fs::create_dir_all(legacy_state.join("inventory")).unwrap();
    login_device(&sandbox);
    assert!(!legacy_state.exists(), "the old state directory was moved");
    assert!(sandbox.home().join(".aws/gac-redux/inventory").is_dir());

    let status = sandbox.gac().arg("status").assert().success();
    assert!(stdout(status.get_output()).contains("1 profile, mode=sso, name={account}/{role}"));
    sandbox.gac().arg("sync").assert().success();
    let config = sandbox.config();
    assert!(!config.contains("# BEGIN gac sync"), "{config}");
    assert!(!config.contains("[profile old/Role]"), "{config}");
    assert!(
        config.contains("# BEGIN gac-redux sync session=corp mode=sso name={account}/{role}\n")
    );
    assert!(config.contains("# Managed by gac-redux:"));
    assert_eq!(
        config
            .matches("# END gac-redux sync session=corp\n")
            .count(),
        1
    );
}

#[test]
fn list_uses_the_inventory_cache() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let listed = sandbox.gac().arg("list").assert().success();
    insta::assert_snapshot!(String::from_utf8_lossy(&listed.get_output().stdout), @r"
    ACCOUNT ID    ACCOUNT NAME     ROLE
    111122223333  payments-prod    AdministratorAccess
    111122223333  payments-prod    ReadOnly
    777788889999  sandbox          PowerUser
    777788889999  sandbox          ReadOnly
    444455556666  Shared Services  ReadOnly
    ");
    assert_eq!(sandbox.mock.counter("accounts"), 1);

    sandbox.gac().arg("list").assert().success();
    assert_eq!(sandbox.mock.counter("accounts"), 1, "served from the cache");
    let json = sandbox
        .gac()
        .args(["list", "--json", "--refresh"])
        .assert()
        .success();
    assert_eq!(
        sandbox.mock.counter("accounts"),
        2,
        "--refresh asks the portal"
    );
    let json: Value = serde_json::from_slice(&json.get_output().stdout).unwrap();
    assert_eq!(json["session"], "corp");
    assert_eq!(json["accounts"][0]["accountId"], "111122223333");
    assert_eq!(
        json["accounts"][0]["roles"],
        json!(["AdministratorAccess", "ReadOnly"])
    );
}

#[test]
fn the_inventory_cache_is_bound_to_the_token_that_listed_it() {
    let listed_ids = |sandbox: &Sandbox| -> Vec<String> {
        let json = sandbox.gac().args(["list", "--json"]).assert().success();
        let json: Value = serde_json::from_slice(&json.get_output().stdout).unwrap();
        json["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["accountId"].as_str().unwrap().to_owned())
            .collect()
    };
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let first = sandbox.token("corp");
    assert_eq!(listed_ids(&sandbox).len(), 3);
    assert_eq!(listed_ids(&sandbox).len(), 3);
    assert_eq!(sandbox.mock.counter("accounts"), 1, "served from the cache");

    // Another identity signs in on the same portal, and another tool (the AWS CLI) replaces the
    // shared token: the listing made with the first token is not reused.
    sandbox.mock.set_accounts(vec![account(
        "444455556666",
        "Shared Services",
        &["ReadOnly"],
    )]);
    login_device(&sandbox);
    let second = sandbox.token("corp");
    sandbox.write_token("corp", &first);
    assert_eq!(listed_ids(&sandbox).len(), 3, "still the first token");
    sandbox.write_token("corp", &second);
    assert_eq!(listed_ids(&sandbox), ["444455556666"]);
    assert_eq!(sandbox.mock.counter("accounts"), 2);

    // Logged out (the token is gone, as after `aws sso logout` too): no listing is served.
    sandbox.gac().arg("logout").assert().success();
    sandbox
        .gac()
        .arg("list")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("gac login --session corp"));
    sandbox.gac().arg("sync").assert().code(3);
    assert_eq!(sandbox.mock.counter("accounts"), 2);
}

/// The slowest test, about 20s: after a few throttles the SDK's adaptive retry slows its own
/// request rate and recovers gradually. Standard retry with more attempts was faster on
/// average but erratic, and sent several times the throttled requests.
#[test]
fn the_fan_out_survives_portal_throttling() {
    let accounts: Vec<_> = (0..24)
        .map(|i| {
            account(
                &format!("{:012}", 100_000_000_000_u64 + i),
                &format!("acct-{i:02}"),
                &["Admin", "ReadOnly"],
            )
        })
        .collect();
    let sandbox = Sandbox::with_accounts(accounts);
    sandbox.write_config(SESSION);
    login_device(&sandbox);
    sandbox.mock.set_rate_limit(6);
    let listed = sandbox.gac().args(["list", "--json"]).assert().success();
    let json: Value = serde_json::from_slice(&listed.get_output().stdout).unwrap();
    let accounts = json["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 24);
    assert!(
        accounts
            .iter()
            .all(|a| a["roles"].as_array().unwrap().len() == 2)
    );
    assert!(
        sandbox.mock.counter("throttled") > 0,
        "the portal throttled the fan-out"
    );
}

#[test]
fn tokens_refresh_inside_the_fifteen_minute_window_exactly_once() {
    let sandbox = Sandbox::with_session();
    sandbox.mock.set_access_ttl(300);
    login_device(&sandbox);
    let before = sandbox.token("corp");
    sandbox.mock.set_access_ttl(8 * 3600);

    // Several processes find the token due at once; the lock lets exactly one refresh it.
    let children: Vec<_> = (0..6)
        .map(|_| sandbox.spawn_gac(&["list", "--refresh"]))
        .collect();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
    }
    assert_eq!(sandbox.mock.counter("refresh"), 1);
    assert_eq!(sandbox.mock.counter("refresh_rejected"), 0);
    let after = sandbox.token("corp");
    assert_ne!(after["accessToken"], before["accessToken"]);
    assert_ne!(
        after["refreshToken"], before["refreshToken"],
        "the refresh token rotated"
    );
    assert_eq!(after["clientSecret"], before["clientSecret"]);
    assert_eq!(after["startUrl"], START_URL);
}

#[test]
fn an_expired_token_without_refresh_requires_login() {
    let sandbox = Sandbox::with_session();
    sandbox.write_token(
        "corp",
        &json!({"startUrl": START_URL, "region": "us-west-2", "accessToken": "FAKE-OLD", "expiresAt": "2020-01-01T00:00:00Z"}),
    );
    sandbox
        .gac()
        .arg("list")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("the SSO token expired"))
        .stderr(predicate::str::contains("gac login --session corp"));
}

#[test]
fn an_expired_token_whose_refresh_is_rejected_is_not_promised_a_refresh() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    login_device(&sandbox);
    // The portal session ended: the cache still has a refresh token, but the service rejects it.
    let mut token = sandbox.token("corp");
    token["expiresAt"] = json!("2020-01-01T00:00:00Z");
    token["refreshToken"] = json!("FAKE-ENDED");
    sandbox.write_token("corp", &token);

    // whoami reads only local files, so it suits a shell prompt: it states what the next use does.
    sandbox
        .gac()
        .arg("whoami")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "expired at 2020-01-01T00:00:00Z; the next use tries a refresh",
        ));
    assert_eq!(sandbox.mock.counter("refresh_rejected"), 0);

    // status and doctor try the refresh, so they report what the next use will find.
    let output = sandbox.gac().arg("status").assert().success();
    let out = stdout(output.get_output());
    assert_eq!(sandbox.mock.counter("refresh_rejected"), 1);
    assert!(
        out.contains("expired at 2020-01-01T00:00:00Z and could not be refreshed: CreateToken failed: InvalidGrantException"),
        "{out}"
    );
    assert!(!out.contains("tries a refresh"), "{out}");
    let output = sandbox.gac().args(["status", "--json"]).assert().success();
    let json: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    let token_json = &json["sessions"][0]["token"];
    assert_eq!(token_json["state"], "expired");
    assert_eq!(token_json["refreshable"], false);
    assert!(
        token_json["refreshError"]
            .as_str()
            .unwrap()
            .contains("InvalidGrantException"),
        "{token_json}"
    );

    let output = sandbox.gac().arg("doctor").assert().success();
    let out = stdout(output.get_output());
    assert!(
        out.contains("[warn] sessions: session `corp`: the token expired at 2020-01-01T00:00:00Z and could not be refreshed: CreateToken failed: InvalidGrantException"),
        "{out}"
    );
    assert!(out.contains("fix: run `gac login --session corp`"), "{out}");
    assert!(!out.contains("tries to refresh"), "{out}");

    let output = sandbox.gac().arg("list").assert().code(3);
    let err = stderr(output.get_output());
    assert_eq!(sandbox.mock.counter("refresh_rejected"), 4);
    // At the default width of 80 the timestamp lands on the wrap point; it must stay whole.
    assert!(err.contains("2020-01-01T00:00:00Z"), "{err}");
    assert!(err.contains("could not be refreshed"), "{err}");
    assert!(err.contains("InvalidGrantException"), "{err}");
    assert!(err.contains("gac login --session corp"), "{err}");
    assert!(
        !err.contains("WARN"),
        "the reason is in the error, not a separate log line: {err}"
    );
}

#[test]
fn status_and_doctor_refresh_an_expired_token_the_service_still_accepts() {
    for command in ["status", "doctor"] {
        let sandbox = Sandbox::with_session();
        login_device(&sandbox);
        let mut token = sandbox.token("corp");
        token["expiresAt"] = json!("2020-01-01T00:00:00Z");
        sandbox.write_token("corp", &token);

        let output = sandbox.gac().arg(command).assert().success();
        let out = stdout(output.get_output());
        assert_eq!(sandbox.mock.counter("refresh"), 1, "{command}");
        let expected = match command {
            "status" => "token         valid until",
            _ => "[ok] sessions: session `corp`: logged in until",
        };
        assert!(out.contains(expected), "{command}: {out}");
        let after = sandbox.token("corp");
        assert_ne!(after["accessToken"], token["accessToken"], "{command}");
        assert_ne!(after["expiresAt"], token["expiresAt"], "{command}");
    }
}

#[test]
fn a_revoked_token_requires_login() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let token = sandbox.token("corp");
    sandbox.mock.set_accounts(vec![]);
    // Simulate a revocation the cache does not know about.
    let mut forged = token.clone();
    forged["accessToken"] = json!("FAKE-REVOKED");
    sandbox.write_token("corp", &forged);
    sandbox
        .gac()
        .args(["list", "--refresh"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("rejected the SSO token"));
}

#[test]
fn sync_writes_an_idempotent_block_and_never_touches_other_bytes() {
    let sandbox = Sandbox::new();
    let before = "# hand-written\r\n[profile mine]\r\nregion = eu-west-1\r\n\r\n";
    let after = "[profile tail]\r\nregion = us-east-2\r\n";
    // A CRLF file with the session in the middle of user content.
    let session_crlf = SESSION.replace('\n', "\r\n");
    sandbox.write_config(&format!("{before}{session_crlf}\r\n{after}"));
    let original = sandbox.config();
    login_device(&sandbox);

    let dry = sandbox.gac().args(["sync", "--dry-run"]).assert().success();
    let diff = String::from_utf8_lossy(&dry.get_output().stdout).into_owned();
    assert!(
        diff.contains("+# BEGIN gac-redux sync session=corp mode=sso name={account}/{role}"),
        "{diff}"
    );
    assert!(diff.contains("+[profile payments-prod/ReadOnly]"));
    assert_eq!(sandbox.config(), original, "a dry run writes nothing");

    sandbox
        .gac()
        .arg("sync")
        .assert()
        .success()
        .stderr(predicate::str::contains("Synced 5 profiles"));
    let synced = sandbox.config();
    assert!(
        synced.starts_with(&original),
        "the original bytes are a prefix"
    );
    let block = &synced[original.len()..];
    assert!(
        !block.replace("\r\n", "").contains('\n'),
        "the block uses the file's CRLF endings"
    );
    insta::assert_snapshot!(block.replace("\r\n", "\n"));

    // A second sync changes nothing at all.
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .success()
        .stderr(predicate::str::contains("Already up to date"));
    assert_eq!(sandbox.config(), synced);

    // The user edits around the block; a sync after the portal changes rewrites only the block.
    let edited = format!("{synced}[profile later]\r\nregion = ap-south-1\r\n");
    sandbox.write_config(&edited);
    sandbox.mock.set_accounts(vec![account(
        "111122223333",
        "payments-prod",
        &["ReadOnly"],
    )]);
    sandbox
        .gac()
        .args(["sync", "--refresh"])
        .assert()
        .success()
        .stderr(predicate::str::contains("(0 added, 4 removed)"));
    let pruned = sandbox.config();
    let begin = pruned.find("# BEGIN gac").unwrap();
    let end = pruned
        .find("# END gac-redux sync session=corp\r\n")
        .unwrap()
        + "# END gac-redux sync session=corp\r\n".len();
    assert_eq!(&pruned[..begin], &edited[..begin]);
    assert_eq!(&pruned[end..], "[profile later]\r\nregion = ap-south-1\r\n");
    assert!(!pruned.contains("AdministratorAccess"));
}

#[test]
fn sync_remembers_its_settings_in_the_begin_line() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox
        .gac()
        .args([
            "sync",
            "--include",
            "*/ReadOnly",
            "--exclude",
            "sandbox/*",
            "--region",
            "eu-west-1",
            "--name",
            "{account_id}.{role}",
        ])
        .assert()
        .success();
    let config = sandbox.config();
    assert!(config.contains(
        "# BEGIN gac-redux sync session=corp mode=sso name={account_id}.{role} region=eu-west-1 include=*/ReadOnly exclude=sandbox/*\n"
    ));
    assert!(config.contains("[profile 111122223333.ReadOnly]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\nregion = eu-west-1\n"));
    assert!(!config.contains("777788889999"));

    // A plain sync keeps the stored settings; --reset drops them.
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .success()
        .stderr(predicate::str::contains("Already up to date"));
    sandbox.gac().args(["sync", "--reset"]).assert().success();
    assert!(
        sandbox
            .config()
            .contains("# BEGIN gac-redux sync session=corp mode=sso name={account}/{role}\n")
    );
}

#[test]
fn sync_never_creates_mixed_credentials() {
    let sandbox = Sandbox::with_session();
    sandbox.write_config(&format!(
        "{SESSION}\n[profile sandbox/ReadOnly]\nregion = us-east-1\n"
    ));
    sandbox.write_credentials("[payments-prod/ReadOnly]\naws_access_key_id = AKIAEXAMPLEEXAMPLE\naws_secret_access_key = FAKE-STATIC\n");
    login_device(&sandbox);
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "skipped profile `payments-prod/ReadOnly`",
        ))
        .stderr(predicate::str::contains("would hide its keys"))
        .stderr(predicate::str::contains(
            "skipped profile `sandbox/ReadOnly`",
        ));
    let config = sandbox.config();
    assert!(!config.contains("[profile payments-prod/ReadOnly]"));
    assert_eq!(
        config.matches("[profile sandbox/ReadOnly]").count(),
        1,
        "the user's profile is not shadowed"
    );
    assert!(config.contains("[profile payments-prod/AdministratorAccess]"));
    sandbox
        .gac()
        .arg("doctor")
        .assert()
        .stdout(predicate::str::contains("[ok] mixed-credentials"));
}

#[test]
fn sync_refuses_to_write_around_broken_markers() {
    let sandbox = Sandbox::new();
    let broken = format!("{SESSION}\n# BEGIN gac-redux sync session=corp mode=sso\n[profile x]\n");
    sandbox.write_config(&broken);
    login_device(&sandbox);
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("has no END marker"));
    assert_eq!(sandbox.config(), broken);
}

#[test]
fn sync_refuses_colliding_names() {
    let sandbox = Sandbox::with_accounts(vec![
        account("111122223333", "dup", &["ReadOnly"]),
        account("444455556666", "DUP", &["ReadOnly"]),
    ]);
    sandbox.write_config(SESSION);
    login_device(&sandbox);
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("{account}-{account_id}/{role}"));
    assert_eq!(sandbox.config(), SESSION);
}

#[test]
fn status_shows_sessions_and_blocks_without_secrets() {
    let sandbox = Sandbox::with_session();
    sandbox
        .gac()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("not logged in"));
    login_device(&sandbox);
    sandbox.gac().arg("sync").assert().success();
    let human = sandbox.gac().arg("status").assert().success();
    let human = String::from_utf8_lossy(&human.get_output().stdout).into_owned();
    assert!(human.contains("session corp"));
    assert!(human.contains("refreshable"));
    assert!(human.contains("5 profiles, mode=sso, name={account}/{role}"));

    let json = sandbox.gac().args(["status", "--json"]).assert().success();
    let text = String::from_utf8_lossy(&json.get_output().stdout).into_owned();
    assert_no_secrets(&text, &sandbox.mock.secrets(), "status --json");
    let json: Value = serde_json::from_str(&text).unwrap();
    let session = &json["sessions"][0];
    assert_eq!(session["name"], "corp");
    assert_eq!(session["token"]["state"], "valid");
    assert_eq!(session["token"]["refreshable"], true);
    assert!(session["token"]["registrationExpiresAt"].is_string());
    assert_eq!(session["syncBlock"]["profiles"], 5);
}

#[test]
fn logout_revokes_and_deletes_the_token() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let access = sandbox.token("corp")["accessToken"]
        .as_str()
        .unwrap()
        .to_owned();
    sandbox
        .gac()
        .arg("logout")
        .assert()
        .success()
        .stderr(predicate::str::contains("Logged out of session `corp`."));
    assert_eq!(sandbox.mock.counter("logout"), 1);
    assert!(!sandbox.mock.is_live(&access));
    assert!(!sandbox.token_path("corp").exists());
    sandbox.gac().args(["list", "--refresh"]).assert().code(3);
    sandbox
        .gac()
        .args(["logout", "--all"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Session `corp` was not logged in.",
        ));
}

#[test]
fn logout_sweeps_the_aws_clis_sso_role_credentials_like_aws_sso_logout() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let cache = sandbox.home().join(".aws/cli/cache");
    std::fs::create_dir_all(&cache).unwrap();
    let sso = json!({"ProviderType": "sso", "Credentials": {"AccessKeyId": "ASIAMOCK"}});
    std::fs::write(cache.join("this-session.json"), sso.to_string()).unwrap();
    std::fs::write(cache.join("other-session.json"), sso.to_string()).unwrap();
    let assume_role = json!({"ProviderType": "assume-role", "Credentials": {}});
    std::fs::write(cache.join("assume-role.json"), assume_role.to_string()).unwrap();
    std::fs::write(cache.join("session.db"), "SQLite format 3\0").unwrap();

    sandbox
        .gac()
        .arg("logout")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Deleted 2 role credentials the AWS CLI had cached from SSO tokens",
        ));
    assert!(!cache.join("this-session.json").exists());
    assert!(!cache.join("other-session.json").exists());
    assert!(cache.join("assume-role.json").exists());
    assert!(cache.join("session.db").exists());

    sandbox
        .gac()
        .arg("logout")
        .assert()
        .success()
        .stderr(predicate::str::contains("Deleted").not());
}

#[test]
fn logout_owns_up_to_an_unreadable_token() {
    let sandbox = Sandbox::with_session();
    sandbox.write_token(
        "corp",
        &json!({"accessToken": "FAKE-x", "expiresAt": "soon"}),
    );
    sandbox
        .gac()
        .arg("logout")
        .assert()
        .success()
        .stderr(predicate::str::contains("unreadable token"))
        .stderr(predicate::str::contains("not logged in").not());
    assert_eq!(sandbox.mock.counter("logout"), 0);
    assert!(!sandbox.token_path("corp").exists());
}

#[test]
fn logout_all_names_what_it_could_not_log_out() {
    let sandbox = Sandbox::new();
    sandbox.write_config(&format!(
        "{SESSION}\n[sso-session broken]\nsso_start_url = https://other.awsapps.com/start\n\n[profile old]\nsso_start_url = https://old.awsapps.com/start\n"
    ));
    sandbox
        .gac()
        .args([
            "login",
            "--session",
            "corp",
            "--device-code",
            "--no-browser",
        ])
        .assert()
        .success();
    sandbox
        .gac()
        .args(["logout", "--all"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Logged out of session `corp`."))
        .stderr(predicate::str::contains(
            "[sso-session broken] has no sso_region",
        ))
        .stderr(predicate::str::contains(
            "profile `old` has sso_start_url but no sso_region",
        ));
    assert!(!sandbox.token_path("corp").exists());
}

#[test]
fn doctor_flags_problems_with_fixes() {
    let sandbox = Sandbox::new();
    sandbox.write_config(&format!(
        "{SESSION}\n[profile dev]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n"
    ));
    sandbox.write_credentials(
        "[dev]\naws_access_key_id = AKIAEXAMPLEEXAMPLE\naws_secret_access_key = FAKE-STATIC\n",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            sandbox.credentials_path(),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    let config_before = sandbox.config();
    let output = sandbox.gac().arg("doctor").assert().code(1);
    let report = String::from_utf8_lossy(&output.get_output().stdout).into_owned();
    assert!(
        report.contains("[FAIL] mixed-credentials: profile `dev` has static keys"),
        "{report}"
    );
    assert!(report.contains("fix: delete the [dev] section"));
    assert!(report.contains("session `corp` is not logged in"));
    #[cfg(unix)]
    assert!(
        report.contains("is 644: other users can read it"),
        "{report}"
    );
    assert_eq!(sandbox.config(), config_before, "doctor is read-only");

    let json = sandbox.gac().args(["doctor", "--json"]).assert().code(1);
    let json: Value = serde_json::from_slice(&json.get_output().stdout).unwrap();
    assert!(
        json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["check"] == "mixed-credentials" && f["level"] == "fail")
    );
}

#[test]
fn the_fix_for_an_orphaned_block_is_one_setup_accepts() {
    let sandbox = Sandbox::new();
    let block = "# BEGIN gac-redux sync session=corp mode=sso\n[profile dev]\nsso_session = corp\n# END gac-redux sync session=corp\n";
    sandbox.write_config(&format!("[default]\nregion = eu-west-1\n\n{block}"));
    let hint = "run `gac doctor --fix` to delete the gac block for session `corp`, then `gac setup --session corp`";

    let doctor = sandbox.gac().arg("doctor").assert();
    let report = String::from_utf8_lossy(&doctor.get_output().stdout).into_owned();
    assert!(
        report.contains("fix: delete the gac block for session `corp`, then run `gac setup --session corp` if you still use it"),
        "{report}"
    );
    assert!(
        report.contains("--fix can apply 1 of the fixes."),
        "{report}"
    );
    let sync = sandbox
        .gac()
        .args(["sync", "--session", "corp"])
        .assert()
        .failure();
    let error = stderr(sync.get_output());
    assert!(
        error
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains(hint),
        "{error}"
    );
    let setup = [
        "setup",
        "--session",
        "corp",
        "--start-url",
        START_URL,
        "--region",
        "us-west-2",
    ];
    sandbox.gac().args(setup).assert().failure();

    // Following the hint works.
    sandbox
        .gac()
        .args(["doctor", "--fix"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Fixed: remove the gac block of session `corp`, whose [sso-session] is gone",
        ));
    assert_eq!(sandbox.config(), "[default]\nregion = eu-west-1\n\n");
    sandbox.gac().args(setup).assert().success();
}

#[test]
fn doctor_fix_applies_the_safe_fixes_and_a_second_run_changes_nothing() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let orphan = "# BEGIN gac-redux sync session=gone mode=sso\n[profile old]\nsso_session = gone\n# END gac-redux sync session=gone\n";
    sandbox.write_config(&format!("{SESSION}\n{orphan}"));
    sandbox.write_credentials("[static]\naws_access_key_id = AKIAEXAMPLE\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let loosen = |path: &std::path::Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        loosen(&sandbox.credentials_path(), 0o644);
        loosen(&sandbox.token_path("corp"), 0o644);
        loosen(sandbox.token_path("corp").parent().unwrap(), 0o755);
    }

    let fixed = sandbox
        .gac()
        .args(["doctor", "--fix", "--json"])
        .assert()
        .success();
    let output = fixed.get_output();
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let fixed: Vec<&str> = json["fixed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert!(fixed.contains(&"remove the gac block of session `gone`, whose [sso-session] is gone"));
    assert_eq!(sandbox.config(), format!("{SESSION}\n"));
    assert!(
        json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["fixable"].is_null() && f["level"] != "warn"),
        "the report after the fixes has nothing left to fix: {json:#}"
    );
    let next = stderr(output);
    assert!(
        next.contains("Next: run `gac setup --session gone` if you still use that session"),
        "{next}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(fixed.len(), 4, "{fixed:?}");
        assert!(
            fixed
                .iter()
                .any(|f| f.starts_with("chmod 600 ") && f.ends_with("credentials"))
        );
        assert_eq!(mode(&sandbox.credentials_path()), 0o600);
        assert_eq!(mode(&sandbox.token_path("corp")), 0o600);
        assert_eq!(mode(sandbox.token_path("corp").parent().unwrap()), 0o700);
    }

    let config = sandbox.config();
    sandbox
        .gac()
        .args(["doctor", "--fix"])
        .assert()
        .success()
        .stderr("Nothing to fix.\n");
    assert_eq!(sandbox.config(), config);
}

const LEGACY: &str = "\
# my old profile
[profile legacy]
sso_start_url  = https://mock-example.awsapps.com/start
sso_region     = us-west-2
sso_account_id = 111122223333
sso_role_name  = ReadOnly
region         = eu-west-1
";

#[test]
fn doctor_fix_moves_a_legacy_profile_only_with_consent() {
    let sandbox = Sandbox::new();
    sandbox.write_config(LEGACY);

    // Without a terminal, a fix to the user's lines is skipped and says how to apply it.
    let skipped = sandbox.gac().args(["doctor", "--fix"]).assert().success();
    let notice = stderr(skipped.get_output());
    assert!(
        notice.contains("Skipped: move the start URL of profile `legacy` into a new [sso-session mock-example]: it edits lines you wrote"),
        "{notice}"
    );
    assert!(notice.contains("pass --yes"), "{notice}");
    assert_eq!(sandbox.config(), LEGACY);

    sandbox
        .gac()
        .args(["doctor", "--fix", "--yes"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Next: run `gac login --session mock-example`",
        ));
    insta::assert_snapshot!(sandbox.config(), @r"
    # my old profile
    [profile legacy]
    sso_session    = mock-example
    sso_account_id = 111122223333
    sso_role_name  = ReadOnly
    region         = eu-west-1

    # BEGIN gac-redux sync session=mock-example
    # Managed by gac-redux: edits inside this block are replaced on the next sync.
    [sso-session mock-example]
    sso_start_url = https://mock-example.awsapps.com/start
    sso_region = us-west-2
    sso_registration_scopes = sso:account:access
    # END gac-redux sync session=mock-example
    ");

    // The profile now logs in through the new session, with a refreshable token.
    sandbox
        .gac()
        .args(["login", "-p", "legacy", "--device-code", "--no-browser"])
        .assert()
        .success();
    assert!(sandbox.token("mock-example")["refreshToken"].is_string());
    let config = sandbox.config();
    sandbox
        .gac()
        .args(["doctor", "--fix", "--yes"])
        .assert()
        .success()
        .stderr("Nothing to fix.\n");
    assert_eq!(sandbox.config(), config);
}

#[test]
fn verbose_output_never_contains_a_secret() {
    let sandbox = Sandbox::with_session();
    sandbox.mock.set_access_ttl(300);
    let mut transcript = String::new();
    let mut run = |args: &[&str]| {
        let output = sandbox.gac().args(args).output().unwrap();
        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        transcript.push_str(&stdout(&output));
        transcript.push_str(&stderr(&output));
    };
    run(&["-vv", "login", "--device-code", "--no-browser"]);
    sandbox.mock.set_access_ttl(8 * 3600);
    run(&["-vv", "list", "--refresh"]); // refreshes the token
    run(&["-vv", "sync"]);
    run(&["-vv", "status", "--json"]);
    run(&["-vv", "doctor"]);
    run(&["-vv", "logout"]);
    let pkce = login_pkce(&sandbox, &["-vv"]);
    assert!(pkce.status.success());
    transcript.push_str(&stdout(&pkce));
    transcript.push_str(&stderr(&pkce));

    assert_eq!(
        sandbox.mock.counter("refresh"),
        1,
        "the refresh path was exercised"
    );
    assert!(
        transcript.contains("DEBUG") || transcript.contains("TRACE"),
        "-vv logs"
    );
    assert_no_secrets(&transcript, &sandbox.mock.secrets(), "-vv output");
}

/// A command that prints its environment as `NAME=value` lines.
fn print_env() -> Vec<&'static str> {
    if cfg!(windows) {
        vec!["cmd", "/C", "set"]
    } else {
        vec!["env"]
    }
}

/// A command that exits with `code`.
fn exit_with(code: &str) -> Vec<String> {
    if cfg!(windows) {
        vec!["cmd".into(), "/C".into(), format!("exit {code}")]
    } else {
        vec!["sh".into(), "-c".into(), format!("exit {code}")]
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

#[test]
fn exec_runs_a_command_as_the_default_profiles_role_and_caches_the_credentials() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox
        .gac()
        .args(["select", "sandbox/PowerUser"])
        .assert()
        .success();

    let mut args = vec!["exec", "--"];
    args.extend(print_env());
    let output = sandbox
        .gac()
        .args(&args)
        .env("AWS_PROFILE", "default")
        .env("AWS_ACCESS_KEY_ID", "AKIASTALE")
        .assert()
        .success();
    let env = parse_env(&stdout(output.get_output()));
    assert_eq!(env["AWS_ACCESS_KEY_ID"], "ASIAMOCK77778888");
    let secrets = sandbox.mock.secrets();
    assert!(secrets.contains(&env["AWS_SECRET_ACCESS_KEY"]));
    assert!(secrets.contains(&env["AWS_SESSION_TOKEN"]));
    assert!(env["AWS_CREDENTIAL_EXPIRATION"].ends_with('Z'));
    assert_eq!(env["GAC_REDUX_EXEC"], "the [default] profile");
    assert!(!env.contains_key("AWS_PROFILE"), "AWS_PROFILE is unset");
    assert!(!env.contains_key("AWS_REGION"), "no region is known");
    assert_eq!(sandbox.mock.counter("credentials"), 1);

    // The entry is where the AWS CLI looks for it, private, and reused by the next run.
    let cache = role_cache_path(&sandbox, "777788889999", "PowerUser");
    let entry: Value = serde_json::from_slice(&std::fs::read(&cache).unwrap()).unwrap();
    assert_eq!(entry["ProviderType"], "sso");
    assert_eq!(entry["Credentials"]["AccessKeyId"], "ASIAMOCK77778888");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cache).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    sandbox.gac().args(&args).assert().success();
    assert_eq!(
        sandbox.mock.counter("credentials"),
        1,
        "the second run uses the cache"
    );
    assert_no_secrets(&stderr(output.get_output()), &secrets, "exec");
}

#[test]
fn exec_takes_the_role_from_a_target_or_a_profile() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox.write_config(&format!(
        "{SESSION}\n[profile dev]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\nregion = eu-west-1\n"
    ));
    let env_of = |args: &[&str], extra: &[(&str, &str)]| {
        let mut all = args.to_vec();
        all.push("--");
        all.extend(print_env());
        let mut cmd = sandbox.gac();
        cmd.args(&all);
        for (name, value) in extra {
            cmd.env(name, value);
        }
        let output = cmd.assert().success();
        parse_env(&stdout(output.get_output()))
    };

    let env = env_of(&["exec", "shared-services/ReadOnly"], &[]);
    assert_eq!(env["AWS_ACCESS_KEY_ID"], "ASIAMOCK44445555");
    assert_eq!(env["GAC_REDUX_EXEC"], "Shared Services/ReadOnly");

    let env = env_of(&["exec", "--profile", "dev"], &[]);
    assert_eq!(env["AWS_ACCESS_KEY_ID"], "ASIAMOCK11112222");
    assert_eq!(env["AWS_REGION"], "eu-west-1");
    assert_eq!(env["AWS_DEFAULT_REGION"], "eu-west-1");

    // AWS_PROFILE picks the profile, an inherited region beats the profile's, --region beats both.
    let env = env_of(
        &["exec"],
        &[("AWS_PROFILE", "dev"), ("AWS_REGION", "us-east-2")],
    );
    assert_eq!(env["AWS_ACCESS_KEY_ID"], "ASIAMOCK11112222");
    assert_eq!(env["AWS_REGION"], "us-east-2");
    let env = env_of(
        &["exec", "--profile", "dev", "--region", "ap-south-1"],
        &[("AWS_REGION", "us-east-2")],
    );
    assert_eq!(env["AWS_REGION"], "ap-south-1");

    // Without [default], a profile or a target there is nothing to pick.
    let mut args = vec!["exec", "--"];
    args.extend(print_env());
    let output = sandbox.gac().args(&args).assert().code(1);
    assert!(
        stderr(output.get_output()).contains("there is no [default] profile"),
        "{}",
        stderr(output.get_output())
    );
    sandbox
        .gac()
        .args(["exec", "nope/ReadOnly", "--", "x"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "no account and role match `nope/ReadOnly`",
        ));
}

#[test]
fn exec_passes_the_exit_code_through_and_refuses_to_nest() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let mut args: Vec<String> = ["exec", "sandbox/ReadOnly", "--"]
        .map(String::from)
        .to_vec();
    args.extend(exit_with("7"));
    sandbox.gac().args(&args).assert().code(7);

    sandbox
        .gac()
        .args(&args)
        .env("GAC_REDUX_EXEC", "payments-prod/ReadOnly")
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "already running inside `gac exec` as payments-prod/ReadOnly",
        ));
    sandbox
        .gac()
        .args(["exec", "--force", "sandbox/ReadOnly", "--"])
        .args(exit_with("0"))
        .env("GAC_REDUX_EXEC", "payments-prod/ReadOnly")
        .assert()
        .success();

    sandbox
        .gac()
        .args(["exec", "sandbox/ReadOnly", "--", "gac-no-such-command"])
        .assert()
        .code(127)
        .stderr(predicate::str::contains(
            "could not run `gac-no-such-command`",
        ));
}

#[test]
fn exec_and_env_without_a_session_point_to_setup() {
    let sandbox = Sandbox::new();
    for command in [&["exec", "--", "x"][..], &["env"]] {
        sandbox
            .gac()
            .args(command)
            .assert()
            .code(1)
            .stderr(predicate::str::contains("there is no [default] profile"))
            .stderr(predicate::str::contains(
                "run `gac setup`, then `gac select`",
            ));
    }
}

#[test]
fn exec_without_a_login_exits_3() {
    let sandbox = Sandbox::with_session();
    sandbox.write_config(&format!(
        "{SESSION}\n[profile dev]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n"
    ));
    sandbox
        .gac()
        .args(["exec", "--profile", "dev", "--"])
        .args(exit_with("0"))
        .assert()
        .code(3)
        .stderr(predicate::str::contains("gac login --session corp"));
    assert_eq!(sandbox.mock.counter("credentials"), 0);
}

/// A `[default]` block without a region, and a `dev` profile with one.
fn role_profiles_config(sandbox: &Sandbox) {
    sandbox.write_config(&format!(
        "{SESSION}\n{}\n[profile dev]\nsso_session = corp\nsso_account_id = 777788889999\nsso_role_name = PowerUser\nregion = eu-west-1\n",
        default_block("111122223333", "ReadOnly")
    ));
}

#[test]
fn whoami_answers_from_local_files_alone() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    let portal_calls = |sandbox: &Sandbox| {
        [
            "accounts",
            "roles",
            "credentials",
            "refresh",
            "unauthorized",
        ]
        .map(|name| sandbox.mock.counter(name))
    };

    // Without a login it still answers, from the files alone.
    let output = sandbox.gac().arg("whoami").assert().success();
    let text = String::from_utf8_lossy(&output.get_output().stdout).into_owned();
    for line in [
        "profile      [default] (no --profile or AWS_PROFILE)\n",
        "session      corp\n",
        "account      111122223333\n",
        "role         ReadOnly\n",
        "region       not set\n",
        "token        not logged in; run `gac login --session corp`\n",
        "credentials  none cached; the next use fetches them\n",
    ] {
        assert!(text.contains(line), "{line:?} in\n{text}");
    }

    // After a listing and a use, the account name and both expiries come from the caches,
    // without another portal call.
    login_device(&sandbox);
    sandbox.gac().arg("list").assert().success();
    sandbox
        .gac()
        .args(["exec", "--"])
        .args(exit_with("0"))
        .assert()
        .success();
    let before = portal_calls(&sandbox);
    let output = sandbox.gac().args(["whoami", "--json"]).assert().success();
    let json: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(json["profile"], "default");
    assert_eq!(json["source"], "[default]");
    assert_eq!(json["accountId"], "111122223333");
    assert_eq!(json["accountName"], "payments-prod");
    assert_eq!(json["roleName"], "ReadOnly");
    assert_eq!(json["token"]["state"], "valid");
    assert_eq!(json["credentials"]["state"], "valid");
    assert_eq!(json["environmentCredentials"], false);
    let text = sandbox.gac().arg("whoami").output().unwrap();
    let text = String::from_utf8_lossy(&text.stdout).into_owned();
    assert!(
        text.contains("account      111122223333 (payments-prod)\n"),
        "{text}"
    );
    assert!(text.contains("credentials  cached until "), "{text}");
    assert_eq!(portal_calls(&sandbox), before);
}

#[test]
fn whoami_names_the_rule_that_picked_the_profile() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    login_device(&sandbox);
    sandbox.gac().arg("list").assert().success();
    sandbox
        .gac()
        .args(["whoami", "--profile", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "profile      dev (from --profile)\n",
        ))
        .stdout(predicate::str::contains(
            "account      777788889999 (sandbox)\n",
        ))
        .stdout(predicate::str::contains("region       eu-west-1\n"))
        .stdout(predicate::str::contains("credentials  none cached"));
    sandbox
        .gac()
        .arg("whoami")
        .env("AWS_PROFILE", "dev")
        .env("AWS_REGION", "us-east-2")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "profile      dev (from AWS_PROFILE)\n",
        ))
        .stdout(predicate::str::contains(
            "region       us-east-2 (from AWS_REGION)\n",
        ));
    sandbox
        .gac()
        .arg("whoami")
        .env("AWS_PROFILE", "nope")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "no profile `nope` in the AWS config file (from AWS_PROFILE)",
        ))
        .stderr(predicate::str::contains(
            "unset AWS_PROFILE to use [default]",
        ));

    // Inside `gac exec`, the keys in the environment win over any profile.
    sandbox
        .gac()
        .arg("whoami")
        .env("AWS_ACCESS_KEY_ID", "ASIAEXAMPLE")
        .env("GAC_REDUX_EXEC", "profile `dev`")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "AWS_ACCESS_KEY_ID is set by `gac exec` as profile `dev`: AWS tools use those keys, not this profile.",
        ));
}

#[test]
fn console_signs_in_as_the_role_through_the_federation_endpoint() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    login_device(&sandbox);
    let link = |args: &[&str]| -> url::Url {
        let output = sandbox
            .gac()
            .args(["console", "--print"])
            .args(args)
            .assert()
            .success();
        let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
        url::Url::parse(stdout.trim_end()).unwrap()
    };
    let query = |url: &url::Url, key: &str| {
        url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    };

    let url = link(&["--profile", "dev"]);
    assert_eq!(url.path(), "/federation");
    assert_eq!(query(&url, "Action").as_deref(), Some("login"));
    assert_eq!(
        query(&url, "Issuer").as_deref(),
        Some("https://mock-example.awsapps.com/start")
    );
    assert_eq!(
        query(&url, "Destination").as_deref(),
        Some("https://console.aws.amazon.com/console/home?region=eu-west-1")
    );
    let token = query(&url, "SigninToken").unwrap();
    assert!(
        sandbox.mock.secrets().contains(&token),
        "the mock's sign-in token"
    );
    assert_eq!(sandbox.mock.counter("signin_token"), 1);

    // The role credentials come from the cache the second time; the sign-in token is new.
    let url = link(&[
        "--profile",
        "dev",
        "--destination",
        "s3/home",
        "--region",
        "us-east-2",
    ]);
    assert_eq!(
        query(&url, "Destination").as_deref(),
        Some("https://console.aws.amazon.com/s3/home?region=us-east-2")
    );
    assert_eq!(sandbox.mock.counter("credentials"), 1);
    assert_eq!(sandbox.mock.counter("signin_token"), 2);
    assert_eq!(
        query(&link(&[]), "Destination").as_deref(),
        Some("https://console.aws.amazon.com/console/home"),
        "[default] names no region"
    );

    // Over SSH the link is printed for the person, on stderr.
    sandbox
        .gac()
        .args(["console", "-p", "dev"])
        .env("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22")
        .assert()
        .success()
        .stdout("")
        .stderr(predicate::str::contains(
            "Open this link to sign in to the AWS console as profile `dev`.",
        ))
        .stderr(predicate::str::contains("SigninToken="));
}

#[test]
fn console_replaces_cached_credentials_the_endpoint_refuses() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    login_device(&sandbox);
    // Credentials the mock never issued, as if revoked before they expired.
    let path = role_cache_path(&sandbox, "777788889999", "PowerUser");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        r#"{"ProviderType":"sso","Credentials":{"AccessKeyId":"ASIAREVOKED","SecretAccessKey":"x","SessionToken":"y","Expiration":"2099-01-01T00:00:00Z"}}"#,
    )
    .unwrap();
    sandbox
        .gac()
        .args(["console", "--print", "-p", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SigninToken="));
    assert_eq!(
        sandbox.mock.counter("signin_token"),
        2,
        "refused, then retried"
    );
    assert_eq!(
        sandbox.mock.counter("credentials"),
        1,
        "fetched once, fresh"
    );
    let cached = std::fs::read_to_string(&path).unwrap();
    assert!(!cached.contains("ASIAREVOKED"), "{cached}");
}

#[test]
fn console_without_a_login_exits_3() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    sandbox
        .gac()
        .args(["console", "--print"])
        .assert()
        .code(3)
        .stdout("");
    assert_eq!(sandbox.mock.counter("signin_token"), 0);
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

#[test]
fn sync_writes_chained_profiles_and_remembers_the_chains() {
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
        .success()
        .stderr(predicate::str::contains("Synced 3 profiles"));
    let config = sandbox.config();
    assert!(
        config.contains("chain=*/AdministratorAccess%3Darn:aws:iam::{account_id}:role/Deploy"),
        "{config}"
    );
    assert!(
        config.contains(
            "[profile payments-prod/Deploy]\nrole_arn = arn:aws:iam::111122223333:role/Deploy\nsource_profile = payments-prod/AdministratorAccess\nregion = eu-west-1\n"
        ),
        "{config}"
    );
    // The chains are remembered; --reset forgets them.
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .success()
        .stderr(predicate::str::contains("Already up to date: 3 profiles"));
    sandbox.gac().args(["sync", "--reset"]).assert().success();
    assert!(!sandbox.config().contains("role_arn"));

    // A chained profile is skipped with its source, and on its own when its name is taken.
    sandbox.write_credentials(
        "[payments-prod/AdministratorAccess]\naws_access_key_id = AKIAEXAMPLEEXAMPLE\naws_secret_access_key = FAKE-STATIC\n",
    );
    sandbox
        .gac()
        .args([
            "sync",
            "--chain",
            "*/AdministratorAccess=arn:aws:iam::{account_id}:role/Deploy",
            "--chain",
            "sandbox/PowerUser=arn:aws:iam::{account_id}:role/Ops",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "skipped profile `payments-prod/Deploy`: its source_profile `payments-prod/AdministratorAccess` was skipped",
        ));
    let config = sandbox.config();
    assert!(!config.contains("payments-prod/Deploy"), "{config}");
    assert!(config.contains("[profile sandbox/Ops]\nrole_arn = arn:aws:iam::777788889999:role/Ops\nsource_profile = sandbox/PowerUser\n"), "{config}");
    // Static keys under a chained profile's own name skip just that profile.
    sandbox.write_credentials(
        "[sandbox/Ops]\naws_access_key_id = AKIAEXAMPLEEXAMPLE\naws_secret_access_key = FAKE-STATIC\n",
    );
    sandbox
        .gac()
        .args([
            "sync",
            "--chain",
            "sandbox/PowerUser=arn:aws:iam::{account_id}:role/Ops",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("skipped profile `sandbox/Ops`"))
        .stderr(predicate::str::contains("would hide its keys"));
    assert!(!sandbox.config().contains("[profile sandbox/Ops]"));
    sandbox
        .gac()
        .args([
            "sync",
            "--chain",
            "*/PowerUser=arn:aws:iam::{account_id}:role/ReadOnly",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("gives `sandbox/ReadOnly` to both"));
    sandbox
        .gac()
        .args(["sync", "--chain", "*/PowerUser"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid --chain"));
}

#[test]
fn exec_follows_a_role_chain_and_caches_each_role() {
    let sandbox = Sandbox::with_session();
    sandbox.write_config(&format!(
        "{SESSION}\n\
         [profile admin]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = AdministratorAccess\n\n\
         [profile deploy]\nrole_arn = arn:aws:iam::111122223333:role/Deploy\nsource_profile = admin\n\
         role_session_name = ci\nexternal_id = ext-1\nduration_seconds = 1800\n\n\
         [profile audit]\nrole_arn = arn:aws:iam::999988887777:role/Audit\nsource_profile = deploy\nregion = eu-west-1\n"
    ));
    login_device(&sandbox);

    let env = exec_env(&sandbox, "deploy");
    let assumed = sandbox.mock.assumed();
    assert_eq!(assumed.len(), 1);
    assert_eq!(assumed[0].role_arn, "arn:aws:iam::111122223333:role/Deploy");
    assert_eq!(
        assumed[0].signed_by, "ASIAMOCK11112222",
        "signed with the SSO role's keys"
    );
    assert_eq!(assumed[0].session_name, "ci");
    assert_eq!(assumed[0].external_id.as_deref(), Some("ext-1"));
    assert_eq!(assumed[0].duration_seconds.as_deref(), Some("1800"));
    assert_eq!(env["AWS_ACCESS_KEY_ID"], assumed[0].issued);

    // Two links: the second role is assumed with the first one's keys, and both are cached.
    let env = exec_env(&sandbox, "audit");
    let assumed = sandbox.mock.assumed();
    assert_eq!(assumed.len(), 2, "deploy came from the cache");
    assert_eq!(assumed[1].role_arn, "arn:aws:iam::999988887777:role/Audit");
    assert_eq!(assumed[1].signed_by, assumed[0].issued);
    assert!(
        assumed[1].session_name.starts_with("gac-redux-"),
        "{:?}",
        assumed[1]
    );
    assert_eq!(env["AWS_ACCESS_KEY_ID"], assumed[1].issued);
    assert_eq!(env["AWS_REGION"], "eu-west-1");
    exec_env(&sandbox, "audit");
    assert_eq!(sandbox.mock.assumed().len(), 2);
    assert_eq!(sandbox.mock.counter("credentials"), 1);

    // whoami names the final role and where the chain starts, from the caches.
    sandbox
        .gac()
        .args(["whoami", "-p", "audit"])
        .assert()
        .success()
        .stdout(predicate::str::contains("account      999988887777\n"))
        .stdout(predicate::str::contains("role         Audit\n"))
        .stdout(predicate::str::contains(
            "assumed via  AdministratorAccess in 111122223333 (SSO), then arn:aws:iam::111122223333:role/Deploy\n",
        ))
        .stdout(predicate::str::contains("credentials  cached until "));

    // The console signs in with the final role's keys.
    sandbox
        .gac()
        .args(["console", "--print", "-p", "audit"])
        .assert()
        .success();
    assert_eq!(sandbox.mock.counter("signin_token"), 1);
}

#[test]
fn chains_gac_cannot_follow_say_why() {
    let sandbox = Sandbox::with_session();
    sandbox.write_config(&format!(
        "{SESSION}\n\
         [profile admin]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = AdministratorAccess\n\n\
         [profile mfa]\nrole_arn = arn:aws:iam::111122223333:role/Deploy\nsource_profile = admin\nmfa_serial = arn:aws:iam::111122223333:mfa/me\n\n\
         [profile ec2]\nrole_arn = arn:aws:iam::111122223333:role/Deploy\ncredential_source = Ec2InstanceMetadata\n\n\
         [profile loop-a]\nrole_arn = arn:aws:iam::111122223333:role/A\nsource_profile = loop-b\n\n\
         [profile loop-b]\nrole_arn = arn:aws:iam::111122223333:role/B\nsource_profile = loop-a\n\n\
         [profile orphan]\nrole_arn = arn:aws:iam::111122223333:role/Deploy\nsource_profile = gone\n"
    ));
    for (profile, message) in [
        (
            "mfa",
            "profile `mfa` uses mfa_serial (an MFA prompt), which gac does not follow",
        ),
        (
            "ec2",
            "profile `ec2` uses credential_source, which gac does not follow",
        ),
        ("loop-a", "is longer than 5 links"),
        (
            "orphan",
            "no profile `gone` in the AWS config file, though a source_profile names it",
        ),
    ] {
        sandbox
            .gac()
            .args(["exec", "--profile", profile, "--", "x"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains(message));
    }
    assert_eq!(sandbox.mock.counter("credentials"), 0);
}

/// `gac env` output with the mock's secrets and the expiry replaced by placeholders.
fn redacted(sandbox: &Sandbox, text: &str) -> String {
    let mut text = text.to_owned();
    for secret in sandbox.mock.secrets() {
        text = text.replace(&secret, "[secret]");
    }
    let expiration = regex_lite_timestamp(&text);
    text.replace(&expiration, "[expiration]")
}

/// The first `YYYY-MM-DDTHH:MM:SSZ` timestamp in `text`.
fn regex_lite_timestamp(text: &str) -> String {
    let bytes = text.as_bytes();
    (0..bytes.len().saturating_sub(20))
        .map(|i| &text[i..i + 20])
        .find(|s| {
            s.bytes().enumerate().all(|(i, b)| match i {
                4 | 7 => b == b'-',
                10 => b == b'T',
                13 | 16 => b == b':',
                19 => b == b'Z',
                _ => b.is_ascii_digit(),
            })
        })
        .expect("an expiration timestamp")
        .to_owned()
}

#[test]
fn env_prints_the_credentials_for_every_shell() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let print = |format: &str| {
        let output = sandbox
            .gac()
            .args([
                "env",
                "sandbox/ReadOnly",
                "--region",
                "eu-west-1",
                "--format",
                format,
            ])
            .assert()
            .success()
            .stderr("");
        redacted(&sandbox, &stdout(output.get_output()))
    };
    insta::assert_snapshot!(print("sh"), @r"
    export AWS_ACCESS_KEY_ID='ASIAMOCK77778888'
    export AWS_SECRET_ACCESS_KEY='[secret]'
    export AWS_SESSION_TOKEN='[secret]'
    export AWS_CREDENTIAL_EXPIRATION='[expiration]'
    unset AWS_PROFILE
    unset AWS_DEFAULT_PROFILE
    unset AWS_SECURITY_TOKEN
    export AWS_REGION='eu-west-1'
    export AWS_DEFAULT_REGION='eu-west-1'
    ");
    insta::assert_snapshot!(print("fish"), @r"
    set -gx AWS_ACCESS_KEY_ID 'ASIAMOCK77778888'
    set -gx AWS_SECRET_ACCESS_KEY '[secret]'
    set -gx AWS_SESSION_TOKEN '[secret]'
    set -gx AWS_CREDENTIAL_EXPIRATION '[expiration]'
    set -e AWS_PROFILE
    set -e AWS_DEFAULT_PROFILE
    set -e AWS_SECURITY_TOKEN
    set -gx AWS_REGION 'eu-west-1'
    set -gx AWS_DEFAULT_REGION 'eu-west-1'
    ");
    insta::assert_snapshot!(print("powershell"), @r"
    $env:AWS_ACCESS_KEY_ID = 'ASIAMOCK77778888'
    $env:AWS_SECRET_ACCESS_KEY = '[secret]'
    $env:AWS_SESSION_TOKEN = '[secret]'
    $env:AWS_CREDENTIAL_EXPIRATION = '[expiration]'
    Remove-Item -Path Env:AWS_PROFILE -ErrorAction SilentlyContinue
    Remove-Item -Path Env:AWS_DEFAULT_PROFILE -ErrorAction SilentlyContinue
    Remove-Item -Path Env:AWS_SECURITY_TOKEN -ErrorAction SilentlyContinue
    $env:AWS_REGION = 'eu-west-1'
    $env:AWS_DEFAULT_REGION = 'eu-west-1'
    ");
    insta::assert_snapshot!(print("json"), @r#"
    {
      "AWS_ACCESS_KEY_ID": "ASIAMOCK77778888",
      "AWS_CREDENTIAL_EXPIRATION": "[expiration]",
      "AWS_DEFAULT_PROFILE": null,
      "AWS_DEFAULT_REGION": "eu-west-1",
      "AWS_PROFILE": null,
      "AWS_REGION": "eu-west-1",
      "AWS_SECRET_ACCESS_KEY": "[secret]",
      "AWS_SECURITY_TOKEN": null,
      "AWS_SESSION_TOKEN": "[secret]"
    }
    "#);
    assert_eq!(
        sandbox.mock.counter("credentials"),
        1,
        "every format after the first used the cache"
    );
}

#[cfg(unix)]
#[test]
fn eval_of_env_sets_and_unset_clears_the_credentials_in_a_shell() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let set = stdout(
        sandbox
            .gac()
            .args(["env", "sandbox/ReadOnly"])
            .assert()
            .success()
            .get_output(),
    );
    let unset = stdout(
        sandbox
            .gac()
            .args(["env", "--unset"])
            .assert()
            .success()
            .get_output(),
    );
    let script = sandbox.home().join("eval.sh");
    std::fs::write(
        &script,
        "eval \"$1\"\nprintf '%s\\n' \"$AWS_ACCESS_KEY_ID\" \"$AWS_SECRET_ACCESS_KEY\" \"${AWS_PROFILE-unset}\"\neval \"$2\"\nprintf '%s\\n' \"${AWS_ACCESS_KEY_ID-cleared}\"\n",
    )
    .unwrap();
    let output = std::process::Command::new("sh")
        .arg(&script)
        .arg(&set)
        .arg(&unset)
        .env("AWS_PROFILE", "dev")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let lines: Vec<String> = stdout(&output).lines().map(str::to_owned).collect();
    assert_eq!(lines[0], "ASIAMOCK77778888");
    assert!(sandbox.mock.secrets().contains(&lines[1]));
    assert_eq!(lines[2], "unset");
    assert_eq!(lines[3], "cleared");
}

#[test]
fn env_unset_needs_no_login_and_conflicts_with_a_role() {
    let sandbox = Sandbox::new();
    sandbox
        .gac()
        .args(["env", "--unset", "--format", "fish"])
        .assert()
        .success()
        .stdout(
            "set -e AWS_ACCESS_KEY_ID\nset -e AWS_SECRET_ACCESS_KEY\nset -e AWS_SESSION_TOKEN\nset -e AWS_CREDENTIAL_EXPIRATION\n",
        );
    sandbox
        .gac()
        .args(["env", "--unset", "sandbox/ReadOnly"])
        .assert()
        .code(2);
}

/// Where PowerShell is installed (as on the CI runners), its output loads in PowerShell.
#[test]
fn env_powershell_output_loads_in_powershell() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let set = stdout(
        sandbox
            .gac()
            .args(["env", "sandbox/ReadOnly", "--format", "powershell"])
            .assert()
            .success()
            .get_output(),
    );
    let script = sandbox.home().join("load.ps1");
    std::fs::write(
        &script,
        format!(
            "{set}Write-Output $env:AWS_ACCESS_KEY_ID\nWrite-Output \"profile=$env:AWS_PROFILE\"\n"
        ),
    )
    .unwrap();
    let Ok(output) = std::process::Command::new("pwsh")
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(&script)
        .env("AWS_PROFILE", "dev")
        .output()
    else {
        return; // PowerShell is not installed
    };
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output).replace('\r', ""),
        "ASIAMOCK77778888\nprofile=\n"
    );
}

#[test]
fn credential_process_prints_the_json_credential_process_expects() {
    let sandbox = Sandbox::with_session();
    let args = [
        "credential-process",
        "--session",
        "corp",
        "--account-id",
        "111122223333",
        "--role-name",
        "ReadOnly",
    ];
    // Without a login it fails as a credential_process must: nonzero, the reason on stderr.
    sandbox
        .gac()
        .args(args)
        .assert()
        .code(3)
        .stdout("")
        .stderr(predicate::str::contains("gac login --session corp"));

    login_device(&sandbox);
    let output = sandbox.gac().args(args).assert().success();
    let json: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(json["Version"], 1);
    assert_eq!(json["AccessKeyId"], "ASIAMOCK11112222");
    assert!(
        sandbox
            .mock
            .secrets()
            .contains(&json["SecretAccessKey"].as_str().unwrap().to_owned())
    );
    assert!(json["SessionToken"].is_string());
    assert!(json["Expiration"].as_str().unwrap().ends_with('Z'));
    sandbox.gac().args(args).assert().success();
    assert_eq!(
        sandbox.mock.counter("credentials"),
        1,
        "the second call used the cache"
    );

    sandbox
        .gac()
        .args([
            "credential-process",
            "--account-id",
            "111122223333",
            "--role-name",
            "ReadOnly",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("needs --session NAME"));
}

#[test]
fn sync_switches_a_block_between_modes_with_a_clean_diff() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox
        .gac()
        .args(["sync", "--include", "sandbox/*"])
        .assert()
        .success();
    let sso = sandbox.config();

    let diff = sandbox
        .gac()
        .args(["sync", "--mode", "process", "--dry-run"])
        .assert()
        .success();
    // The header names the file by a path the platform may spell differently, e.g. 8.3 on Windows.
    let diff = stdout(diff.get_output());
    let body: Vec<&str> = diff.lines().skip(2).collect();
    insta::assert_snapshot!(
        body.join("\n"),
        @r"
    @@ -3,15 +3,11 @@
     sso_region = us-west-2
     sso_registration_scopes = sso:account:access
     
    -# BEGIN gac-redux sync session=corp mode=sso name={account}/{role} include=sandbox/*
    +# BEGIN gac-redux sync session=corp mode=process name={account}/{role} include=sandbox/*
     # Managed by gac-redux: edits inside this block are replaced on the next sync.
     [profile sandbox/PowerUser]
    -sso_session = corp
    -sso_account_id = 777788889999
    -sso_role_name = PowerUser
    +credential_process = gac credential-process --session corp --account-id 777788889999 --role-name PowerUser
     
     [profile sandbox/ReadOnly]
    -sso_session = corp
    -sso_account_id = 777788889999
    -sso_role_name = ReadOnly
    +credential_process = gac credential-process --session corp --account-id 777788889999 --role-name ReadOnly
     # END gac-redux sync session=corp
    "
    );
    assert_eq!(sandbox.config(), sso, "a dry run writes nothing");

    sandbox
        .gac()
        .args(["sync", "--mode", "process"])
        .assert()
        .success();
    // The mode is stored in the BEGIN line, so a plain sync keeps it.
    let process = sandbox.config();
    sandbox.gac().arg("sync").assert().success();
    assert_eq!(sandbox.config(), process);
    let status = sandbox.gac().arg("status").assert().success();
    assert!(
        stdout(status.get_output()).contains("2 profiles, mode=process, name={account}/{role}"),
        "{}",
        stdout(status.get_output())
    );
    let json = sandbox.gac().args(["status", "--json"]).assert().success();
    let json: Value = serde_json::from_slice(&json.get_output().stdout).unwrap();
    assert_eq!(json["sessions"][0]["syncBlock"]["mode"], "process");

    // exec and env take the role from a process-mode profile too.
    let mut args = vec!["exec", "--profile", "sandbox/PowerUser", "--"];
    args.extend(print_env());
    let output = sandbox.gac().args(&args).assert().success();
    assert_eq!(
        parse_env(&stdout(output.get_output()))["AWS_ACCESS_KEY_ID"],
        "ASIAMOCK77778888"
    );

    sandbox
        .gac()
        .args(["sync", "--mode", "sso"])
        .assert()
        .success();
    assert_eq!(
        sandbox.config(),
        sso,
        "switching back restores the same bytes"
    );
}

/// What a person at a terminal sees: gac prompts only where stdin and stderr are terminals.
#[cfg(unix)]
mod terminal {
    use std::process::Stdio;

    use rexpect::process::wait::WaitStatus;
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
        match session.process.wait().unwrap() {
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
}
