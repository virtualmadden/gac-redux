//! `gac select` and the default block.

use super::*;

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
