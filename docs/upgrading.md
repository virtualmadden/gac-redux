# Upgrading to 1.0

Upgrading from any 0.x release needs nothing more than installing the new version. No 0.x release
removed or renamed a command, a flag or a `--json` field, and every release reads the files an
earlier one wrote. From 1.0 on, [compatibility.md](compatibility.md) says what stays stable.

After upgrading, `gac doctor` reports anything an older release left behind, under the
`older-release` check, and `gac doctor --fix` cleans up what it can.

## From the `gac` pre-release

Before 0.2.0-beta.1 the project was called `gac`, and it could only be built from source. The
command is still `gac`, but the rest was renamed:

| Before | Now | What to do |
|---|---|---|
| The `gac` crate | The `gac-redux` package | Install `gac-redux` (see the [README](../README.md#install)), then `cargo uninstall gac` |
| `GAC_SESSION` | `GAC_REDUX_SESSION` | Rename it where you set it. gac ignores the old name, and `gac doctor` warns while it is set |
| `GAC_LOG` | `GAC_REDUX_LOG` | The same |
| `# BEGIN gac sync` / `# END gac sync` markers | `# BEGIN gac-redux sync` / `# END gac-redux sync` | Nothing: gac reads the old markers, and `gac sync` or `gac doctor --fix` rewrites them |
| `~/.aws/gac/` | `~/.aws/gac-redux/` | Nothing: the first run moves it. If both exist, `gac doctor --fix` deletes the old one, which holds only caches |

## Changes in behavior during 0.x

None of these needs a change on your side, but a script may notice them.

| Release | Change |
|---|---|
| 0.3.0 | `syncBlock.mode` in `gac status --json` reports the block's real mode. It said `sso` for every block before. |
| 0.4.0 | At a terminal, a command that needs a login offers to sign in instead of exiting with code `3`. Without a terminal, with `--no-input`, and always in `gac credential-process`, it still exits with `3`. |
| 0.5.1 | `gac status` and `gac doctor` try to refresh an expired token, as the next AWS command would, so they can reach the network. When the refresh fails, `token.refreshable` is `false` and `token.refreshError` has the service's error. |
| 0.5.2 | `gac` with no arguments prints its help to stdout and exits with `0`. It printed to stderr and exited with `2` before. |
| 0.6.0 | `fetchedAt` in `gac list --json` has no fractional seconds, like every other timestamp. `gac sync --remove` deletes a sync block, and `gac doctor` gained the `older-release` check. |
| Unreleased | A call to AWS gives up after 60 seconds, retries included, and exits with `1`; one attempt waits at most 20 seconds. An endpoint that accepted the connection and never answered made gac hang before. |
