# ferrox

A userspace TCP/IP network stack implemented in Rust.

The name comes from *ferrum* (Latin: iron) + *oxide* — iron oxidises to rust.
ferrox is what happens when you build a network stack with Rust as the material.

## What it is

ferrox is a from-scratch implementation of the core TCP/IP protocol suite,
running entirely in userspace via a TAP device. It bypasses the Linux kernel's
networking stack and implements Ethernet, ARP, IPv4, IPv6, ICMP, UDP, and TCP
directly in safe Rust — with all unsafe code confined to a single platform
abstraction crate.

This is a portfolio and learning project. The goal is correctness and clarity
over production completeness: every protocol decision is RFC-sourced and every
deviation is documented.

## Status

Phase 1 in progress — workspace and CI set up, parsers not yet started.

| Phase | Description | Status |
|---|---|---|
| 1 | Scaffolding, packet I/O, Ethernet/ARP/IP/ICMP parsers | Done |
| 2 | IP forwarding, routing table, UDP | Pending |
| 3 | TCP core | Pending |
| 4 | TCP hardening — SACK, congestion control | Pending |
| 5 | Observability, benchmarks, polish | Pending |

## Workspace structure

ferrox is a Cargo workspace of eight crates, each owning one layer of the stack.

```
ferrox/
└── crates/
    ├── pal/            OS I/O — the only crate with unsafe code
    ├── proto/          packet parsers, no_std compatible
    ├── datalink/       Ethernet dispatch, ARP
    ├── network/        IPv4/IPv6, ICMP, routing
    ├── transport/      TCP, UDP
    ├── socket/         public async socket API
    ├── sim/            in-memory test harness
    └── ferrox-cli/   binary entry point
```

## Building

```bash
git clone https://github.com/Pranay224/ferrox
cd ferrox
cargo build
```

## Testing

```bash
cargo test --workspace
```

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2026 Pranay Ahluwalia
