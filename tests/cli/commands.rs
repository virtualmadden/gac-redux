//! Help, completions, man pages, and logging.

use super::*;

#[test]
fn bare_command_prints_help() {
    let sandbox = Sandbox::new();
    let help = sandbox.gac().arg("--help").assert().success();
    let help = String::from_utf8_lossy(&help.get_output().stdout).into_owned();
    insta::assert_snapshot!(help);
    // Bare `gac` asks for help, so it prints `gac -h` and exits 0; winget's validation runs it
    // that way.
    let short = sandbox.gac().arg("-h").assert().success();
    let short = String::from_utf8_lossy(&short.get_output().stdout).into_owned();
    sandbox.gac().assert().success().stdout(short).stderr("");
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
