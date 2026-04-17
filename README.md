# wg-friend

`wg-friend` is a semantic CLI companion for WireGuard and BoringTun.

This version hard-cuts the CLI into four public command groups:

- `server`
- `client`
- `service`
- `doctor`

It keeps the same architectural stance as v0.1:

- **systemd** supervises the long-running `boringtun-cli -f` process
- **wg-friend** performs validation, configuration, verification, cleanup, diagnosis, and local client management

## Command surface

### server

```text
wg-friend server list
wg-friend server show [iface]
wg-friend server up [iface]
wg-friend server down [iface]
wg-friend server restart [iface]
wg-friend server status [iface]
wg-friend server edit [iface]
```

### client

```text
wg-friend client list [iface]
wg-friend client show [iface] [name]
wg-friend client add [iface] [name] [--address ...] [--dns ...] [--endpoint ...]
wg-friend client remove [iface] [name]
wg-friend client export [iface] [name] [--output ...]
```

### service

```text
wg-friend service install
wg-friend service status [iface]
wg-friend service enable [iface]
wg-friend service disable [iface]
```

### doctor

```text
wg-friend doctor check [iface]
wg-friend doctor run [iface]
```

## UX direction

This version does **not** add a TUI.
Instead it uses:

- short semantic commands
- string-based prompts when arguments are missing
- simple confirmation steps before destructive writes

This keeps the CLI easy to use over SSH while leaving room for future API or Cloudflare-backed client distribution.


## Output formatter

This revision adds a lightweight string formatter layer instead of a TUI:

- aligned key/value sections
- section dividers
- simple tables for lists and peer views
- ANSI color badges when stdout is a TTY
- plain output automatically when redirected or piped

The goal is to make `server status`, `client list`, and `doctor` feel like one coherent CLI instead of raw command dumps.

## Local client management model

Managed clients are tracked in two places:

1. peer blocks are written back into `/etc/wireguard/<iface>.conf`
2. exported client configs are stored under `/etc/wireguard/clients/<iface>/<name>.conf`

Managed peer blocks are marked like this:

```text
# wg-friend-client: alice
[Peer]
PublicKey = ...
AllowedIPs = ...
PresharedKey = ...
PersistentKeepalive = 25
```

This gives `wg-friend` a stable way to list, show, remove, and export its own managed clients without pretending it owns every peer in the file.

## Quick start

```bash
cargo fmt
cargo check
cargo build --release
sudo cp target/release/wg-friend /usr/local/bin/wg-friend
sudo wg-friend service install
sudo wg-friend service enable wg0
sudo wg-friend doctor check wg0
sudo wg-friend server up wg0
sudo wg-friend client add wg0 alice
sudo wg-friend client export wg0 alice --output ./alice.conf
```

## Notes

- Linux + systemd only
- assumes `wg`, `ip`, and `boringtun-cli` are installed
- assumes WireGuard configs live under `/etc/wireguard`
- this repository was prepared in an environment without a Rust toolchain, so run local formatting and compile checks before deploying


## v0.2.3 notes

- `internal verify` now treats interface admin-up via link flags instead of requiring `state UP`, which avoids false failures on WireGuard interfaces that show `state UNKNOWN`.
- `service install` now prints the resolved executable path in follow-up commands.
- `service uninstall` removes the systemd template and can also remove generated client files and the wg-friend log.
- `service up/down/restart` remain unsupported; the CLI now prints a direct hint to use `server up/down/restart`.
