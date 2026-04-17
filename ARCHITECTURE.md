# wg-friend v0.3.0 Architecture

## Positioning

`wg-friend` is a semantic WireGuard/BoringTun control plane that favors:

- user-oriented CLI verbs
- systemd-owned long-running process supervision
- explicit bring-up phases
- canonical client state under `/etc/wg-friend`
- a one-time import path from legacy WireGuard assets into a cleaner operational model

## Public command model

This version hard-cuts the public CLI into four groups.

```text
wg-friend server ...
wg-friend client ...
wg-friend service ...
wg-friend doctor ...
```

The hidden systemd phases stay internal:

```text
wg-friend internal preflight --interface <iface>
wg-friend internal configure --interface <iface>
wg-friend internal verify --interface <iface>
wg-friend internal cleanup --interface <iface>
```

## Responsibility split

### systemd

- owns the lifetime of `boringtun-cli -f`
- knows the real main process
- handles restart policy

### wg-friend

- validates host prerequisites
- applies cleaned WireGuard config via `wg setconf`
- brings the interface address and MTU up
- verifies readiness
- diagnoses service and interface state
- manages a canonical set of complete clients
- imports local legacy assets into semantic state

## Canonical state model

`/etc/wg-friend` is the semantic source of truth for managed clients.

```text
/etc/wg-friend/
  instances/
    wg0/
      server.toml
      clients/
        client-2.toml
        macbook.toml
      exports/
        client-2.conf
        macbook.conf
      import-report.json
```

### Key rule

`wg-friend` only imports and manages **managed_complete** clients.

That means a client must have enough local material to produce:

- canonical metadata (`clients/*.toml`)
- a canonical export (`exports/*.conf`)
- a QR-ready config payload

Incomplete historical assets stay outside canonical state.

## Import model

The current import path scans:

```text
/etc/wireguard/clients/<iface>/*.conf
```

For each candidate, `wg-friend`:

1. parses the legacy client config
2. validates it is complete
3. derives the client public key from the client private key
4. matches that public key against the server peer set
5. writes canonical state under `/etc/wg-friend`
6. emits an `import-report.json`

This allows `/etc/wireguard` to keep evolving while `wg-friend` progressively becomes the preferred management plane.

## Interaction style

This version intentionally avoids a TUI.

Instead it uses a two-level interaction model:

1. command-first usage for stable automation
2. string prompts when required parameters are missing

Examples:

```text
wg-friend server up wg0
wg-friend client add wg0 alice
wg-friend client import wg0
wg-friend client qrcode wg0 alice
```

## Internal module split

```text
src/
  main.rs
  cli.rs
  config.rs
  state.rs
  prompt.rs
  command_runner.rs
  systemd.rs
  util.rs
  wireguard.rs
  commands/
    server.rs
    client.rs
    service.rs
    doctor.rs
    internal.rs
```

### command layer

The command modules stay thin and express use cases.

### wireguard layer

`wireguard.rs` owns the local config model and rendering logic for:

- parsing `[Interface]`
- parsing `[Peer]` blocks
- writing config back
- suggesting the next client address
- rendering client exports

### state layer

`state.rs` owns canonical semantic state and import reporting for:

- `server.toml`
- `clients/*.toml`
- `exports/*.conf`
- `import-report.json`

## Scope boundary

Still out of scope in v0.3:

- nftables / TPROXY / routing policy orchestration
- Cloudflare-backed distribution itself
- service-user hardening and capability minimization
- structured JSON CLI output
- multi-source import beyond the current local export directory

## Author

**Ricky**  
mail.me@pylab.me
