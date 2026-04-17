# wg-friend

**Semantic WireGuard/BoringTun lifecycle and client helper**

`wg-friend` is a modern management plane for WireGuard and BoringTun.

Rather than mirroring the legacy `wg-quick` workflow, it introduces a semantic operating model centered on lifecycle control, complete client assets, diagnostics, and production-grade ergonomics. Local WireGuard assets can be **imported** into canonical `wg-friend` state under `/etc/wg-friend`, allowing historical deployments to evolve into a cleaner and more manageable system without disruptive rewrites.

**Author**  
Ricky · mail.me@pylab.me

## Core ideas

- Semantic lifecycle over shell-centric orchestration
- Canonical client state under `/etc/wg-friend`
- Only `managed_complete` clients enter the `wg-friend` domain
- Production-friendly diagnostics over opaque output
- systemd-native supervision for predictable operations

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
wg-friend client import [iface]
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

## Canonical client model

`wg-friend` now treats `/etc/wg-friend` as the semantic source of truth for managed clients.

```text
/etc/wg-friend/
  instances/
    wg0/
      server.toml
      clients/
        alice.toml
        macbook.toml
      exports/
        alice.conf
        macbook.conf
      import-report.json
```

A client is considered `managed_complete` only when `wg-friend` can materialize a full canonical export and metadata record. Incomplete historical assets stay outside canonical state.

## client import

`wg-friend client import` scans local WireGuard assets and imports only complete client configs into canonical `wg-friend` state.

The current import source is the local legacy client export directory:

```text
/etc/wireguard/clients/<iface>/*.conf
```

For each importable client, `wg-friend`:

- validates the client config is complete
- derives the client public key from the local private key
- matches that public key against the server peer set
- copies the export into `/etc/wg-friend/.../exports/`
- writes client metadata into `/etc/wg-friend/.../clients/*.toml`
- writes an `import-report.json`

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
sudo wg-friend client import wg0
sudo wg-friend client list wg0
sudo wg-friend client qrcode wg0 alice
```

## Notes

- Linux + systemd only
- assumes `wg`, `ip`, and `boringtun-cli` are installed
- assumes WireGuard configs live under `/etc/wireguard`
- canonical `wg-friend` client state lives under `/etc/wg-friend`
- this repository was prepared in an environment without a Rust toolchain, so run local formatting and compile checks before deploying
