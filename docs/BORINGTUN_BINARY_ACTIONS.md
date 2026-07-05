# BoringTun Linux/macOS Binary Packaging

This repository includes `.github/workflows/boringtun-binaries.yml` for producing BoringTun binary artifacts without mixing them into the main `wg-friend` release flow.

## Current decision

Linux x64 and macOS BoringTun packaging are enabled. Windows BoringTun packaging is intentionally disabled for now.

Reason:

- `cloudflare/boringtun` currently uses `master`, not `main`; cloning `--branch main` fails.
- The BoringTun tag list includes current tags such as `boringtun-cli-0.7.1`, `boringtun-0.7.1`, `boringtun-cli-0.7.0`, and older `boringtun-cli-0.5.2`.
- `boringtun-cli` is documented by upstream as an executable for Linux and macOS; Windows support in the upstream table is library-oriented / incomplete for a turnkey CLI runtime.
- `boringtun-cli v0.7.1` currently fails to compile on `x86_64-pc-windows-msvc` in GitHub Actions, so keeping Windows in the release matrix makes the workflow red without producing a usable artifact.

Current policy:

```text
linux-x64   enabled via Docker musl-cross image
macOS x64   enabled via native macOS runner
macOS arm64 enabled via native macOS runner
Windows x64 disabled/commented out
```

## Why git tag/ref is the default

The workflow defaults to a reproducible upstream Git tag/ref:

```text
source=git
boringtun_git_ref=boringtun-cli-0.7.1
```

This avoids the broken `main` branch assumption and avoids silently picking a moving branch. The workflow still supports crates.io mode for macOS if you explicitly select it:

```text
source=crates
boringtun_cli_version=0.7.1
```

## Manual run

Open GitHub Actions → `BoringTun Binary Build` → `Run workflow`.

Recommended default:

```text
source=git
boringtun_git_ref=boringtun-cli-0.7.1
```

Fallback / test mode:

```text
source=crates
boringtun_cli_version=0.7.1
```

## Active targets

```text
linux-x64     x86_64-unknown-linux-musl runner: ubuntu-latest   build: Docker image messense/rust-musl-cross:x86_64-musl
macos-x64     x86_64-apple-darwin       runner: macos-15-intel  build: host
macos-arm64   aarch64-apple-darwin      runner: macos-15        build: host
```

## Linux build policy

Linux x64 uses Docker on the Ubuntu runner instead of host `apt-get install musl-tools`. The reason is simple: `ring`/`cc-rs` needs `x86_64-linux-musl-gcc` for the `x86_64-unknown-linux-musl` target. A musl-cross image makes that dependency explicit and keeps the runner setup stable.

The current Linux artifact is built with:

```text
target    = x86_64-unknown-linux-musl
rustflags = -C target-cpu=x86-64-v3
image     = messense/rust-musl-cross:x86_64-musl
```

Do not use Docker for macOS artifacts in this workflow. macOS artifacts are produced on native GitHub macOS runners because macOS cross-builds from Linux require a separate SDK/toolchain story and are not worth the complexity here.

## Disabled Windows template

The workflow keeps the Windows matrix block as comments so it can be restored quickly after an upstream-compatible Windows CLI build is confirmed:

```yaml
# - id: windows-x64
#   runs_on: windows-latest
#   target: x86_64-pc-windows-msvc
#   bin_ext: .exe
#   archive_format: zip
#   rustflags: -C target-feature=+crt-static
#   wintun_arch: amd64
```

When Windows is re-enabled, also restore the Wintun runtime packaging flow:

```text
url     = https://www.wintun.net/builds/wintun-0.14.1.zip
version = 0.14.1
sha256  = 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
arch    = amd64
```

The previous Wintun rule still stands: use the official signed ZIP and verify SHA-256. Do not build or redistribute an unsigned custom Wintun DLL.

## Release tags

Pushing a tag matching the following pattern uploads artifacts to a GitHub Release:

```text
boringtun-v*
```

Example:

```bash
git tag boringtun-v0.7.1-1
git push origin boringtun-v0.7.1-1
```

## Runtime boundary

`boringtun-cli` is the upstream userspace executable. Linux x64 and macOS are the current reliable binary targets for this workflow. Windows remains a future integration task because it requires both an upstream-compatible CLI build and a validated Windows TUN/runtime wrapper story.
