# Releasing

Every step of a release, in order. A release goes out from a pull request titled
`chore: release X.Y.Z`, opened with the release template:

```sh
gh pr create --title "chore: release X.Y.Z" --template release.md
```

The template repeats the checklist below as checkboxes, with a table for the smoke-test runs.

## 1. The release pull request

On a branch named `chore/release-X.Y.Z`:

- [ ] Pick the version. Before 1.0, a new command, flag or doctor check is a minor release and a
      fix alone is a patch. From 1.0, [compatibility.md](compatibility.md) decides: a breaking
      change takes a major release.
- [ ] Set the version in `Cargo.toml`, then run `cargo check` so `Cargo.lock` follows.
- [ ] Update the version in the README's `.deb` and `.rpm` install commands, and in the
      placeholder of `.github/ISSUE_TEMPLATE/bug.yml`. CI fails the pull request when any of
      them, or the notes, are missing.
- [ ] Write `docs/release-notes/X.Y.Z.md`: what changed for someone running `gac`, and anything
      they need to do. Leave out changes to CI, tests and the repository; the release lists every
      merged pull request below the notes anyway.
- [ ] In [upgrading.md](upgrading.md), move the "Unreleased" row of the behavior changes under
      `X.Y.Z`. For 1.0.0, the release notes link to [upgrading.md](upgrading.md) and
      [compatibility.md](compatibility.md).

## 2. The smoke test

- [ ] Run [smoke-test.md](smoke-test.md) against a real Identity Center with a build of the
      release branch, on at least one platform. Record each run in the pull request: platform,
      `gac --version`, and the result. 1.0.0 needs a run on macOS, Linux and Windows.

## 3. Merge and tag

- [ ] CI passes, then squash-merge the pull request.
- [ ] Push an annotated tag on the merge commit:

      ```sh
      git switch main && git pull
      git tag -a vX.Y.Z -m "gac-redux X.Y.Z"
      git push origin vX.Y.Z
      ```

- [ ] Watch the Release workflow to the end: `gh run watch`. It builds every archive and package,
      publishes the GitHub release with the notes, updates the Homebrew formula and the Scoop
      bucket, and opens the winget pull request.

## 4. After the release

- [ ] The release page has the notes, every archive and package, and `SHA256SUMS`.
- [ ] `brew upgrade gac-redux` (or `brew install virtualmadden/tap/gac-redux`) installs the new
      version.
- [ ] The winget pull request in
      [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs/pulls?q=is%3Apr+gac-redux)
      passes validation (the `Validation-Completed` label).
- [ ] If the bot asks for the Contributor License Agreement again, comment
      `@microsoft-github-policy-service agree` on the new pull request.
- [ ] Close the winget pull request of the previous version if it is still open, with a comment
      that the new one supersedes it.
