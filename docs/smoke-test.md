# Smoke test against a real IAM Identity Center

The automated tests use a mock. This checklist covers what only a human login can: PKCE, device
code, sync, AWS calls through synced profiles, `exec`, the console, and logout. Every release runs
it ([releasing.md](releasing.md)). It runs in a throwaway HOME, so your real `~/.aws` is never
read or changed. You need the AWS CLI v2 and an Identity Center user with at least one account
assignment.

On macOS and Linux:

```sh
cargo build --release
export GAC="$PWD/target/release/gac" SMOKE="$(mktemp -d)"
export PATH="$(dirname "$GAC"):$PATH"   # process-mode profiles run `gac` from PATH
gac() { HOME="$SMOKE" USERPROFILE="$SMOKE" "$GAC" "$@"; }
awsx() { HOME="$SMOKE" USERPROFILE="$SMOKE" aws "$@"; }
```

On Windows, in PowerShell:

```powershell
cargo build --release
$env:GAC = "$PWD\target\release\gac.exe"
$env:SMOKE = (New-Item -ItemType Directory (Join-Path $env:TEMP "gac-smoke-$(Get-Random)")).FullName
$env:PATH = "$(Split-Path $env:GAC);$env:PATH"   # process-mode profiles run `gac` from PATH
function In-Smoke($exe, $rest) {
    $home_, $profile_ = $env:HOME, $env:USERPROFILE
    $env:HOME, $env:USERPROFILE = $env:SMOKE, $env:SMOKE
    try { & $exe @rest } finally { $env:HOME, $env:USERPROFILE = $home_, $profile_ }
}
function gac { In-Smoke $env:GAC $args }
function awsx { In-Smoke aws $args }
```

1. **Setup.** `gac setup --session smoke --start-url https://<portal>.awsapps.com/start --region <region>`
   prints `Added [sso-session smoke]`.
2. **PKCE.** `gac login` opens the browser; approve. Expect ``Logged in to session `smoke` `` and
   `gac status` showing the token `valid until ...`, `refreshable`.
3. **Select.** `gac select` lists your accounts and roles as `gac list` does, the first one
   highlighted; move with the arrow keys and press Enter. Expect `The default profile is now ...`,
   then `awsx sts get-caller-identity` (no `--profile`) returns that role's ARN, and `gac whoami`
   names the same account and role, picked by `[default]`. `gac select --clear` makes the
   `awsx` call fail with `Unable to locate credentials`.
4. **Device code.** `gac login --device-code`; open the printed link, check the code matches,
   approve. Expect the same success line.
5. **List.** `gac list` prints your accounts and roles.
6. **Sync.** `gac sync --dry-run` prints a diff adding profiles to the `# BEGIN gac-redux sync session=smoke`
   block that setup created;
   `gac sync` reports `Synced N profiles`. Run `gac sync` again: `Already up to date`.
7. **AWS call.** Pick a synced profile from `gac list` (named `<account>/<role>`), then
   `awsx sts get-caller-identity --profile '<account>/<role>'` returns your assumed-role ARN.
8. **Exec.** `gac exec '<account>/<role>' -- aws sts get-caller-identity` returns the same ARN.
9. **Process mode.** `gac sync --mode process`, then the call from step 7 still returns the ARN,
   now through `gac credential-process`. `gac sync --mode sso` switches back.
10. **Console.** `gac console '<account>/<role>'` opens the AWS console signed in as that role.
11. **Doctor.** `gac doctor` reports no `[fail]`.
12. **Logout.** `gac logout` prints ``Logged out of session `smoke`. ``; `gac status` shows
    `not logged in`, `gac list --refresh --no-input` exits with code 3, and the call from step 7
    now fails: the role credentials the AWS CLI cached are gone too.
13. **Remove.** Still logged out, `gac sync --remove` reports ``Removed the `smoke` block``, and
    `[sso-session smoke]` stays: `gac status` still lists the session.

Clean up with `rm -rf "$SMOKE"`, or `Remove-Item -Recurse $env:SMOKE` in PowerShell.
