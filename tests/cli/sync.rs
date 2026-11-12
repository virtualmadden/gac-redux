//! `gac sync`: the managed block, its settings, modes, chains and removal.

use super::*;

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
fn sync_remove_gives_back_the_file_as_it_was_without_a_login() {
    let sandbox = Sandbox::new();
    let original = format!(
        "# hand-written\r\n[profile mine]\r\nregion = eu-west-1\r\n\r\n{}",
        SESSION.replace('\n', "\r\n")
    );
    sandbox.write_config(&original);
    login_device(&sandbox);
    sandbox
        .gac()
        .args(["sync", "--mode", "process"])
        .assert()
        .success();
    let synced = sandbox.config();
    // Removing needs no login.
    sandbox.gac().arg("logout").assert().success();

    let dry = sandbox
        .gac()
        .args(["sync", "--remove", "--dry-run"])
        .assert()
        .success()
        .stderr("Dry run: 5 profiles to remove. Nothing was written.\n");
    let diff = stdout(dry.get_output());
    assert!(
        diff.contains("-# BEGIN gac-redux sync session=corp mode=process"),
        "{diff}"
    );
    assert_eq!(sandbox.config(), synced, "a dry run writes nothing");

    sandbox
        .gac()
        .args(["sync", "--remove"])
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Removed the `corp` block and its 5 profiles from ",
        ));
    assert_eq!(sandbox.config(), original);

    sandbox
        .gac()
        .args(["sync", "--remove"])
        .assert()
        .success()
        .stderr("There is no gac block for session `corp`. Nothing to remove.\n");
    assert_eq!(sandbox.config(), original);
}

#[test]
fn sync_remove_keeps_the_session_setup_wrote_into_the_block() {
    let sandbox = Sandbox::new();
    sandbox.write_config("[default]\nregion = eu-west-1\n");
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
        .success();
    login_device(&sandbox);
    sandbox.gac().arg("sync").assert().success();
    sandbox
        .gac()
        .args(["sync", "--remove"])
        .assert()
        .success()
        .stderr(predicate::str::ends_with(
            " [sso-session corp] stays, outside the block.\n",
        ));
    assert_eq!(
        sandbox.config(),
        format!("[default]\nregion = eu-west-1\n\n{SESSION}")
    );
    // The session still works, for gac and the AWS CLI alike.
    sandbox
        .gac()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("session corp"));
}

#[test]
fn sync_remove_warns_about_profiles_that_chain_from_the_block() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox.gac().arg("sync").assert().success();
    let config = format!(
        "{}\n[profile deploy]\nrole_arn = arn:aws:iam::111122223333:role/Deploy\nsource_profile = payments-prod/ReadOnly\n",
        sandbox.config()
    );
    sandbox.write_config(&config);
    sandbox
        .gac()
        .args(["sync", "--remove"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "profile `deploy` has source_profile `payments-prod/ReadOnly`, which was in the block",
        ));
    sandbox
        .gac()
        .args(["sync", "--remove", "--include", "*"])
        .assert()
        .code(2);
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
