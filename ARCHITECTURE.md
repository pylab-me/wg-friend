# wg-friend v0.2.0 Architecture

## Positioning

`wg-friend` is a semantic WireGuard/BoringTun control plane that favors:

- user-oriented CLI verbs
- systemd-owned long-running process supervision
- explicit bring-up phases
- local client management that can later be extended toward Cloudflare-backed distribution

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
- manages a local set of named client peers

## Client management model

The tool does not try to become a general-purpose WireGuard parser/editor for every possible layout.
Instead it manages only the peers it created.

Each managed peer is marked in the server config with a stable comment:

```text
# wg-friend-client: <name>
```

This lets the code:

- list managed clients
- remove managed clients
- keep non-managed peer blocks untouched at the domain level
- export a local client config under `clients/<iface>/<name>.conf`

## Interaction style

This version intentionally avoids a TUI.

Instead it uses a two-level interaction model:

1. command-first usage for stable automation
2. string prompts when required parameters are missing

Examples:

```text
wg-friend server up wg0
wg-friend client add wg0 alice
wg-friend client add
wg-friend server edit
```

The second pair falls back to textual prompts.

## Internal module split

```text
src/
  main.rs
  cli.rs
  config.rs
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

The command modules should stay thin and express use cases.

### wireguard layer

`wireguard.rs` owns the local config model and rendering logic for:

- parsing `[Interface]`
- parsing named managed `[Peer]` blocks
- writing config back
- suggesting the next client address
- rendering client exports

## Scope boundary

Still out of scope in v0.2:

- nftables / TPROXY / routing policy orchestration
- Cloudflare-backed distribution itself
- service-user hardening and capability minimization
- structured JSON output
- QR rendering

Those can land in later iterations without changing the main command groups.
