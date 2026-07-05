# BoringTun Windows / macOS Binary Packaging

This repository includes `.github/workflows/boringtun-binaries.yml` for producing BoringTun binary artifacts without mixing them into the main `wg-friend` release flow.

## Why crates.io is the default

Cloudflare's BoringTun repository currently warns against relying on the moving `master/main` branch during restructuring. The workflow therefore defaults to:

```text
cargo install boringtun-cli --version 0.6.0 --locked
```

The workflow still supports direct GitHub builds from `https://github.com/cloudflare/boringtun.git` through the `source=git` input when you explicitly want to test an upstream branch, tag, or commit.

## Manual run

Open GitHub Actions → `BoringTun Binary Build` → `Run workflow`.

Recommended default:

```text
source=crates
boringtun_cli_version=0.6.0
```

GitHub source mode:

```text
source=git
boringtun_git_ref=main
```

## Targets

```text
windows-x64   x86_64-pc-windows-msvc   runner: windows-latest   Wintun arch: amd64
macos-x64     x86_64-apple-darwin      runner: macos-15-intel
macos-arm64   aarch64-apple-darwin     runner: macos-15
```

## Windows runtime packaging: Wintun

The Windows artifact now includes verified Wintun runtime assets. The workflow downloads the official ZIP only in the Windows matrix job:

```text
url     = https://www.wintun.net/builds/wintun-0.14.1.zip
version = 0.14.1
sha256  = 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
arch    = amd64
```

The workflow performs a hard SHA-256 check with PowerShell `Get-FileHash`. A mismatch fails the job before packaging.

The Windows artifact layout is:

```text
boringtun-cli.exe
wintun.dll                   # convenience copy beside the executable
README.txt
wintun/
  wintun.dll                 # selected amd64 signed runtime DLL
  wintun.h                   # copied when present in the official archive
  wintun-0.14.1.zip          # original verified archive for provenance / redistribution clarity
  WINTUN-MANIFEST.txt        # url, version, sha256, selected arch
```

Operational rule:

- The artifact places `wintun.dll` beside `boringtun-cli.exe` for direct side-by-side loading, and also keeps the same DLL under `wintun/` with provenance files.
- Do not build or redistribute an unsigned custom Wintun DLL. The workflow intentionally uses the official signed ZIP and verifies the published hash.
- macOS artifacts do not include Wintun because Wintun is Windows-only.

## Release tags

Pushing a tag matching the following pattern uploads artifacts to a GitHub Release:

```text
boringtun-v*
```

Example:

```bash
git tag boringtun-v0.6.0-1
git push origin boringtun-v0.6.0-1
```

## Runtime boundary

`boringtun-cli` is the upstream userspace executable. macOS is a normal CLI target. Windows binary packaging now includes the Wintun DLL required by Windows TUN integration, but route setup, adapter lifecycle, service installation, and privilege handling still belong to the Windows-side application or wrapper.
