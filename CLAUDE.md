# sqlite-forensic — project notes

Rust workspace: `sqlite-core` (reader) + `sqlite-forensic` (analyzer) + `sqlite4n6` (CLI, in `cli/`).

## Releases — cut by pushing a `vX.Y.Z` tag

GitHub Releases are **tag-driven**. There is no manual button: pushing a `v*` tag
triggers `.github/workflows/release.yml`, which is the *only* thing that produces
a Release and its binaries. The repo's "tag" with only source-code archives is
GitHub's automatic tag tarball — not our Release.

```bash
git tag -a v0.1.0 -m "sqlite-forensic 0.1.0" && git push origin v0.1.0
```

The workflow builds 5 targets → `.tar.gz` + `.msi` (cargo-wix), `.deb` (cargo-deb,
amd64/arm64), a GitHub Release with `checksums.txt`, then fans out to Homebrew
(tap dispatch), apt (Cloudsmith), and winget. Channel secrets are org-level;
Homebrew/winget steps are `continue-on-error`.

Workspace-specific gotchas baked into the workflow (see `~/.claude/skills/release.md`):

- **cargo-wix:** pass the package manifest positionally (`cargo wix … cli/Cargo.toml`),
  not `--package sqlite4n6` — only the manifest form anchors the relative
  `wix\License.rtf` source to `cli/`; `--package` fails with WiX `light` error 103.
- **cargo-deb:** the `sqlite4n6` package needs an `authors` field (cargo-deb derives
  the `.deb` copyright from it) or the `deb` job fails.

Re-using a tag is safe only while nothing has published; otherwise bump the version.
