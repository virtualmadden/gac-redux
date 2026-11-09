# Contributing to gac-redux

Thanks for helping. Bug reports, fixes and ideas are all welcome. For a security problem, follow
[SECURITY.md](SECURITY.md) instead of opening an issue.

## Reporting a bug

Open a [bug report](https://github.com/virtualmadden/gac-redux/issues/new?template=bug.yml). The
form asks for `gac --version`, the platform and `gac doctor --json`, which together answer most
first questions. Leave out real tokens and credentials.

## Building and testing

You need Rust 1.94.1 or newer (the minimum supported version, checked in CI) and, for the interop
tests, the AWS CLI v2.

```console
$ cargo build
$ cargo nextest run              # or: cargo test
$ cargo clippy --all-targets -- -D warnings
$ cargo fmt --check
```

The tests run every command against a mock Identity Center (`tests/support/mock_idc.rs`) in a
throwaway HOME, so they never touch your `~/.aws` or call AWS. `tests/interop.rs` also checks
that the AWS CLI v2 and the Rust SDK read what gac writes; set `GAC_REDUX_REQUIRE_AWS_CLI=1` to
fail instead of skipping when `aws` is not on `PATH`, as CI does. `cargo deny check` runs the
license and advisory checks from `deny.toml`.

To try a change against a real Identity Center without touching your own AWS files, follow
[docs/smoke-test.md](docs/smoke-test.md).

## Pull requests

- Keep each pull request to one change, with tests for the behavior it adds or fixes. A bug fix
  starts with a test that fails without it.
- Titles follow [Conventional Commits](https://www.conventionalcommits.org): `feat:`, `fix:`,
  `docs:`, `test:`, `chore:`. Pull requests are squash-merged, so the title becomes the commit on
  `main`.
- CI runs fmt, clippy, the tests on Linux, macOS and Windows (x64 and arm64), the minimum Rust
  version and cargo-deny; all of them must pass. A change to documentation alone (the Markdown
  files at the top level, `docs/` and the issue forms) skips them.
- Output is part of the interface: messages say what happened and what to do next, and a change
  to `--json` output only adds fields.

## Releasing

Maintainers release from a pull request titled `chore: release X.Y.Z` that:

1. Bumps the version in `Cargo.toml` and `Cargo.lock`, and any version in the README's install
   commands.
2. Adds `docs/release-notes/X.Y.Z.md`: what changed for someone running `gac`, and anything they
   need to do. CI fails the pull request without it. The release workflow publishes it above the
   list of merged pull requests.

After it merges, push an annotated tag `vX.Y.Z` on the merge commit. The release workflow builds
and publishes the release, the Homebrew formula, the Scoop manifest and the winget pull request.

## Code of conduct

Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).
