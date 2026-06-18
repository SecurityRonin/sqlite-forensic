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

- **cargo-wix:** `--package sqlite4n6` is mandatory (a positional manifest is
  rejected: "Workspace detected"). cargo-wix resolves the wxs's relative source
  paths against the repo-root CWD, so `cli/wix/main.wxs` references the license as
  `cli\wix\License.rtf` (not `wix\License.rtf`) — otherwise WiX `light` errors 103.
- **cargo-deb:** the `sqlite4n6` package needs an `authors` field (cargo-deb derives
  the `.deb` copyright from it) or the `deb` job fails.

Re-using a tag is safe only while nothing has published; otherwise bump the version.

## Distribution channels (set up for v0.1.0)

- **Homebrew:** `brew install securityronin/tap/sqlite4n6`. Backed by
  `Formula/sqlite4n6.rb` + the `update-sqlite4n6` handler in
  `SecurityRonin/homebrew-tap`; the release workflow's `repository_dispatch`
  (`event-type: update-sqlite4n6`) refreshes the formula from `checksums.txt`.
- **apt (Cloudsmith):** repo `securityronin/sqlite-forensic` (created on
  cloudsmith.io — must exist or the push 404s). Install via
  `curl -1sLf https://dl.cloudsmith.io/public/securityronin/sqlite-forensic/setup.deb.sh | sudo -E bash` then `apt install sqlite4n6`.
- **winget:** identifier `SecurityRonin.sqlite4n6`. First version is hand-authored
  (3 manifests modeled on the live `SecurityRonin.blazehash`); thereafter
  winget-releaser does updates. The MSI `ProductCode` changes every build — extract
  it per release with `msiinfo export <msi> Property`; the `UpgradeCode`
  (`{070DCA3F-F901-4736-9C5D-12F7AA00F064}`) is stable and keys winget upgrades.
