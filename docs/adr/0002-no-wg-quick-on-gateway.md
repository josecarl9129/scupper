# 0002. No wg-quick on the gateway

Status: accepted, 2026-11-08. Design: [DESIGN.md](../DESIGN.md).

## Context

wg-quick cannot create an interface in one namespace and place it in another, runs shell `PostUp`/`PreDown` strings, applies `DNS=` lines to the host resolver, and needs one systemd unit per interface, which turns failover into a unit dance with several writers of the same state.

## Decision

From M2 scupper creates and configures all gateway WireGuard links itself: `ip link add … type wireguard` (host, down), `ip link set … netns scupper`, `wg set <if> private-key <file> peer …`, addresses, up. `exit import` reads a wg-quick file and keeps only interface/peer fields; `PostUp`, `PreDown`, `Table`, `DNS` and script lines are rejected. M1 still drives `wg-quick@proton0` for parity. The Mac does not use wg-quick either: its helper drives a pinned wireguard-go itself (ADR 0033).

## Alternatives considered

- wg-quick with a watcher on its state: overlapping owners, hard to verify.
- systemd-networkd netdevs: no namespace placement, distribution-specific.

## Consequences

- One writer for every link; boot and repair use the same ordered procedure.
- Keys are passed by path, never in argv or environment.
- Imported provider profiles lose their hooks, which is intended.
