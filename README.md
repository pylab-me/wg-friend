# wg-friend

**Semantic WireGuard/BoringTun lifecycle and client helper**

`wg-friend` is a modern management plane for WireGuard and BoringTun.

Rather than mirroring the legacy `wg-quick` workflow, it introduces a semantic operating model centered on lifecycle control, client identity, diagnostics, and production-grade ergonomics. Existing WireGuard peers and configurations can be **adopted** into the `wg-friend` domain, allowing historical deployments to evolve into a cleaner and more manageable system without disruptive rewrites.

## Core ideas

- Semantic lifecycle over shell-centric orchestration
- Client-aware management over raw peer-only views
- Production-friendly diagnostics over opaque output
- systemd-native supervision for predictable operations
- Safe adoption of legacy WireGuard peers into a modern control model

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
wg-friend client adopt [iface] [public_key] [--name ...]
wg-friend client qrcode [iface] [name]
wg-friend client remove [iface] [name]
wg-friend client export [iface] [name] [--output ...]
```

### service

```text
wg-friend service install
wg-friend service uninstall [iface] [--yes]
wg-friend service status [iface]
wg-friend service enable [iface]
wg-friend service disable [iface]
```

### doctor

```text
wg-friend doctor check [iface]
wg-friend doctor run [iface]
```

## Client model

`wg-friend` separates two concepts clearly:

1. **runtime peers** visible through `wg show`
2. **managed clients** that belong to the `wg-friend` domain

Managed clients are tracked by a semantic marker in `/etc/wireguard/<iface>.conf`:

```text
# wg-friend-client: alice
[Peer]
PublicKey = ...
AllowedIPs = ...
PresharedKey = ...
PersistentKeepalive = 25
```

This keeps the model explicit while still allowing legacy peer sets to be brought forward through adoption.

## client adopt

`wg-friend client adopt` brings existing WireGuard peers into the `wg-friend` client model.

Instead of forcing a destructive rebuild, it lets legacy peers be named, classified, and managed under a semantic control plane. This is the bridge between historical WireGuard state and a cleaner modern operating model.

## Output and UX

This project deliberately avoids a TUI.
Instead it uses:

- short semantic commands
- string-based prompts when arguments are missing
- aligned formatter output with section dividers and tables
- terminal colors when stdout is a TTY
- plain text when redirected or piped

Running `wg-friend` without arguments prints a compact identity banner with the project tagline and author line.

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
sudo wg-friend client list wg0
sudo wg-friend client adopt wg0
sudo wg-friend client qrcode wg0 alice
```

## Notes

- Linux + systemd only
- assumes `wg`, `ip`, and `boringtun-cli` are installed
- assumes WireGuard configs live under `/etc/wireguard`
- this repository was prepared in an environment without a Rust toolchain, so run local formatting and compile checks before deploying

---

**Author**  
Ricky · mail.me@pylab.me