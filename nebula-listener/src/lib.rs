//! nebula-listener: assembles a working Nebula node from `nebula-protocol`
//! (the encrypted `Session`) and `nebula-firewall` (the accept/reject
//! decision). It owns the kernel tun device and the firewall-gated
//! forwarding loop that moves real IP packets between the OS and the
//! encrypted overlay.
//!
//! Linux-only for v1. All OS handles (the UDP socket behind `Session`, and
//! the tun) are *injected* as already-created fds so a `Listener` can be
//! placed cleanly inside a network namespace and many can coexist in one
//! process with no global state. See
//! `docs/superpowers/specs/2026-07-11-nebula-listener-design.md`.

pub mod packet;
mod identity;
