# Changelog

## v0.4.x
- Added `client rename`
- Added `client disable` / `client enable`
- Added `client stats`, with one-shot output and `--watch` refresh mode
- Added `doctor mtu-probe` as advisory-only diagnostics, with default interface fallback
- Added `enabled/disabled` state to the client model
- Tightened CLI argument handling to avoid treating client names as interfaces when the interface is omitted
- Reworked runtime display into a single source of truth
- Unified `last_seen`, `state`, `rx`, `tx`, and `remote_ip` under the runtime snapshot path
- Removed legacy handshake text parsing
- Fixed multiple handshake display bugs, including the incorrect `56 years ago` output
- Corrected handshake interpretation to use elapsed-seconds semantics instead of Unix epoch semantics
- Fixed build issues and cleaned up unused imports, unused variables, and redundant code paths

## v0.3.x
- Hard-cut the client model to canonical state under `/etc/wg-friend/instances/<iface>/...`
- Replaced `client adopt` with `client import`
- Restricted import to `managed_complete` assets only
- Switched `client list/show/qrcode/export` to canonical-state-driven behavior
- Improved client runtime state handling with `online / probing / stale / offline`
- Added early fixes for `last_seen` / `state` consistency
- Added stronger client management foundations
- Added `client qrcode`
- Unified project wording and CLI branding as:
  `Semantic WireGuard/BoringTun lifecycle and client helper`
- Added author information to project-facing text

## v0.2.x
- Introduced the `server / client / service / doctor` command tree
- Added structured terminal formatting for sections, tables, and key-value output
- Added `PASS / WARN / FAIL` diagnostics in `doctor`
- Added `service uninstall`
- Fixed the `internal verify` restart loop issue
- Improved systemd install messaging and command guidance

## v0.1.x
- Initial `wg-friend` release
- Established systemd + BoringTun foreground lifecycle management
- Added `preflight / configure / verify / cleanup / status / doctor`
- Replaced the earlier shell-manager / pidfile-oriented control path

---

# Current Notes

- `wg-friend` now covers the core lifecycle and client-management surface that would traditionally be split across `wg`, `wg-quick`, and PiVPN
- The current architecture is now clearly separated:
  - `wg-friend`: control plane, client management, diagnostics
  - `boringtun`: WireGuard userspace tunnel runtime
  - `flowark`: post-decryption traffic decision plane
- Canonical state, client import, runtime views, QR export, and lifecycle management are all now in place

---

# TODO

## High Priority
- Improve `client stats`
  - better online state semantics
  - aggregate totals / online / disabled counts
- Expand `doctor`
  - endpoint-learned but no valid handshake hints
  - proxy/direct decision hints
  - public endpoint mismatch hints
- Improve `server edit`
  - `listen_port`
  - `public_endpoint`
  - `dns`
  - `mtu`
  - `keepalive`

## Medium Priority
- Add `client revoke`
- Add `client rotate-psk`
- Improve disabled-client visibility
- Add `server summary`
- Add `state diff`:
  - canonical state vs rendered config vs running config

## Future
- Add `doctor flowark`
- Add WireGuard-to-FlowArk dataplane observability
- Improve import reports and drift detection
- Extend MTU diagnostics from advisory mode to explicit active probing