Releases X.Y.Z: <the changes someone running `gac` will notice, with their pull requests>.

Follows [docs/releasing.md](https://github.com/virtualmadden/gac-redux/blob/main/docs/releasing.md).

**The pull request**
- [ ] Version X.Y.Z in `Cargo.toml` and `Cargo.lock`
- [ ] Version X.Y.Z in the README's `.deb` and `.rpm` commands and the bug form's placeholder
- [ ] `docs/release-notes/X.Y.Z.md`
- [ ] The "Unreleased" row in `docs/upgrading.md` moved under X.Y.Z

**Smoke test** ([docs/smoke-test.md](https://github.com/virtualmadden/gac-redux/blob/main/docs/smoke-test.md), every step)

| Platform | `gac --version` | Result |
|---|---|---|
| | | |

**After merging**
- [ ] Annotated tag `vX.Y.Z` pushed on the merge commit
- [ ] Release workflow passed; the release has the notes, archives, packages and `SHA256SUMS`
- [ ] Homebrew installs X.Y.Z
- [ ] winget pull request passes validation; CLA signed if asked; the previous version's pull request closed
