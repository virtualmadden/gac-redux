//! `gac status` and `gac doctor`.

use super::*;

#[test]
fn doctor_flags_and_fixes_what_a_release_before_the_rename_left() {
    let sandbox = Sandbox::new();
    let legacy_block = "# BEGIN gac sync session=corp mode=sso name={account}/{role}\n\
                        # Managed by gac: edits inside this block are replaced on the next sync.\n\
                        [profile old/Role]\n\
                        sso_session = corp\n\
                        sso_account_id = 111122223333\n\
                        sso_role_name = Role\n\
                        # END gac sync session=corp\n";
    sandbox.write_config(&format!("{SESSION}\n{legacy_block}"));
    // Both state directories: the old one is only moved when the new one is missing.
    let legacy_state = sandbox.home().join(".aws/gac");
    std::fs::create_dir_all(legacy_state.join("inventory")).unwrap();
    std::fs::create_dir_all(sandbox.home().join(".aws/gac-redux")).unwrap();
    let doctor = |args: &[&str]| {
        let output = sandbox
            .gac()
            .arg("doctor")
            .args(args)
            .env("GAC_SESSION", "corp")
            .output()
            .unwrap();
        (stdout(&output), stderr(&output))
    };

    let (report, _) = doctor(&[]);
    for line in [
        "[warn] older-release: the gac block for session `corp` has the `# BEGIN gac sync` markers from before the rename",
        "is left from before the rename;",
        "[warn] older-release: GAC_SESSION is set, but gac reads GAC_REDUX_SESSION now",
    ] {
        assert!(report.contains(line), "{line:?} in\n{report}");
    }

    let (_, notices) = doctor(&["--fix"]);
    assert!(
        notices
            .contains("give the gac block of session `corp` the `# BEGIN gac-redux sync` markers"),
        "{notices}"
    );
    assert!(!legacy_state.exists(), "the old state directory is gone");
    assert_eq!(
        sandbox.config(),
        format!(
            "{SESSION}\n# BEGIN gac-redux sync session=corp mode=sso name={{account}}/{{role}}\n\
             # Managed by gac-redux: edits inside this block are replaced on the next sync.\n\
             [profile old/Role]\n\
             sso_session = corp\n\
             sso_account_id = 111122223333\n\
             sso_role_name = Role\n\
             # END gac-redux sync session=corp\n"
        )
    );
    // Only the variable is left, which gac cannot rename for you.
    let (report, _) = doctor(&[]);
    let older: Vec<&str> = report
        .lines()
        .filter(|l| l.contains("older-release"))
        .collect();
    assert_eq!(older.len(), 1, "{report}");
    assert!(older[0].contains("GAC_SESSION"), "{report}");
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
