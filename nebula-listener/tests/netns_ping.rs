//! Live-mesh proof (requires root + Docker; run explicitly):
//!   cargo build -p nebula-listener --example node
//!   sudo -E cargo test -p nebula-listener --test netns_ping -- --ignored --nocapture
//!
//! Brings up the Go lighthouse + Go host2 and a Rust node inside a Linux
//! netns with a veth uplink, then asserts Go host2 can ping the Rust node —
//! proving the Rust node joined the live mesh and routes real kernel traffic
//! through tun + firewall + Session.
use std::process::Command;

fn harness_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/netns")
}

#[test]
#[ignore]
fn go_host2_pings_rust_node_across_the_live_mesh() {
    // The example binary must be built first (the setup script launches it
    // from target/debug/examples/node).
    let build = Command::new("cargo")
        .args(["build", "-p", "nebula-listener", "--example", "node"])
        .status()
        .expect("cargo build should run");
    assert!(build.success(), "example node binary must build");

    let dir = harness_dir();
    // Always start clean.
    let _ = Command::new("bash").arg("teardown.sh").current_dir(&dir).status();

    let setup = Command::new("bash").arg("setup.sh").current_dir(&dir).status().expect("setup.sh should run");
    assert!(setup.success(), "netns + mesh setup failed");

    // Go host2 (10.100.0.2) pings the Rust node (10.100.0.3). Success proves
    // the full path: lighthouse-assisted handshake + tun + firewall + tunnel.
    let ping = Command::new("docker")
        .args(["exec", "nebula-protocol-interop-host2", "ping", "-c1", "-W5", "10.100.0.3"])
        .status()
        .expect("docker exec ping should run");

    // Tear down before asserting so a failure still cleans up.
    let _ = Command::new("bash").arg("teardown.sh").current_dir(&dir).status();

    assert!(ping.success(), "Go host2 should be able to ping the Rust node over the live mesh");
}
