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
            "gac-doctor.1",
            "gac-list.1",
            "gac-login.1",
            "gac-logout.1",
            "gac-select.1",
            "gac-setup.1",
            "gac-status.1",
            "gac-sync.1",
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
    assert!(stdout(status.get_output()).contains("1 profile, name={account}/{role}"));
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
    login_device(&sandbox);
    // The portal session ended: the cache still has a refresh token, but the service rejects it.
    let mut token = sandbox.token("corp");
    token["expiresAt"] = json!("2020-01-01T00:00:00Z");
    token["refreshToken"] = json!("FAKE-ENDED");
    sandbox.write_token("corp", &token);

    sandbox
        .gac()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "expired at 2020-01-01T00:00:00Z; the next use tries a refresh",
        ))
        .stdout(predicate::str::contains("refreshable").not());
    sandbox
        .gac()
        .arg("doctor")
        .assert()
        .stdout(predicate::str::contains(
            "the token expired at 2020-01-01T00:00:00Z; the next use tries to refresh it",
        ));

    let output = sandbox.gac().arg("list").assert().code(3);
    let err = stderr(output.get_output());
    assert_eq!(sandbox.mock.counter("refresh_rejected"), 1);
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
    assert!(human.contains("5 profiles, name={account}/{role}"));

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
    let hint =
        "delete the gac block for session `corp` by hand, then run `gac setup --session corp`";

    let doctor = sandbox.gac().arg("doctor").assert();
    let report = String::from_utf8_lossy(&doctor.get_output().stdout).into_owned();
    assert!(report.contains(&format!("fix: {hint}")), "{report}");
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
    sandbox.write_config("[default]\nregion = eu-west-1\n");
    sandbox.gac().args(setup).assert().success();
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
