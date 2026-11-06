# Smoke test against a real IAM Identity Center

The automated tests use a mock. This checklist covers what only a human login can: PKCE, device
code, sync, an AWS call through a synced profile, and logout. It runs in a throwaway HOME, so
your real `~/.aws` is never read or changed. You need the AWS CLI v2 and an Identity Center
user with at least one account assignment.

```sh
cargo build --release
export GAC="$PWD/target/release/gac" SMOKE="$(mktemp -d)"
gac() { HOME="$SMOKE" USERPROFILE="$SMOKE" "$GAC" "$@"; }
awsx() { HOME="$SMOKE" USERPROFILE="$SMOKE" aws "$@"; }
```

1. **Setup.** `gac setup --session smoke --start-url https://<portal>.awsapps.com/start --region <region>`
   prints `Added [sso-session smoke]`.
2. **PKCE.** `gac login` opens the browser; approve. Expect ``Logged in to session `smoke` `` and
   `gac status` showing the token `valid until ...`, `refreshable`.
3. **Select.** `gac select` lists your accounts and roles as `gac list` does, the first one
   highlighted; move with the arrow keys and press Enter. Expect `The default profile is now ...`,
   then `awsx sts get-caller-identity` (no `--profile`) returns that role's ARN. `gac select --clear`
   makes the same call fail with `Unable to locate credentials`.
4. **Device code.** `gac login --device-code`; open the printed link, check the code matches,
   approve. Expect the same success line.
5. **List.** `gac list` prints your accounts and roles.
6. **Sync.** `gac sync --dry-run` prints a diff adding profiles to the `# BEGIN gac-redux sync session=smoke`
   block that setup created;
   `gac sync` reports `Synced N profiles`. Run `gac sync` again: `Already up to date`.
7. **AWS call.** Pick a synced profile from `grep '^\[profile' "$SMOKE/.aws/config"`, then
   `awsx sts get-caller-identity --profile '<account>/<role>'` returns your assumed-role ARN.
8. **Doctor.** `gac doctor` reports no `FAIL`.
9. **Logout.** `gac logout` prints ``Logged out of session `smoke`. ``; `gac status` shows
   `not logged in`, `gac list --refresh` exits with code 3, and the `awsx sts get-caller-identity`
   call from step 7 now fails: the role credentials the AWS CLI cached are gone too.

Clean up with `rm -rf "$SMOKE"`.
