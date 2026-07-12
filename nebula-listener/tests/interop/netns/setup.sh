#!/bin/bash
# Brings up the Go mesh (via the existing docker harness) and a Linux netns
# with a veth uplink for the Rust node, then launches the node binary inside
# the netns. Requires root and Docker. Idempotent-ish: run teardown.sh first.
set -e -x

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_HARNESS="$HERE/../../../../nebula-protocol/tests/interop/docker"
NODE_BIN="$HERE/../../../../target/debug/examples/node"
CIPHER="${CIPHER:-aes}"
NS="rust-ns"

# 1. Go lighthouse + Go host2 (also (re)builds certs incl. rust-peer.crt).
CIPHER="$CIPHER" "$DOCKER_HARNESS/run.sh"
BUILD="$DOCKER_HARNESS/build"

# 2. netns + veth uplink. veth-host stays in the root netns (shares the
#    host loopback where the Go containers listen); veth-ns lives in rust-ns.
ip netns add "$NS"
ip link add veth-host type veth peer name veth-ns
ip link set veth-ns netns "$NS"

ip addr add 10.244.0.1/24 dev veth-host
ip link set veth-host up

ip netns exec "$NS" ip addr add 10.244.0.2/24 dev veth-ns
ip netns exec "$NS" ip link set veth-ns up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default via 10.244.0.1

# 3. Let the netns reach the Go containers' UDP ports on the host loopback.
#    The Go containers listen on 127.0.0.1:4242/4243 in the root netns; NAT
#    the netns's traffic and forward it so 10.244.0.1 (from the netns) can
#    reach them. Pin both peers directly in the node's static host map so we
#    don't depend on lighthouse-advertised loopback ports (same rationale as
#    the docker interop test).
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.244.0.0/24 -o lo -j MASQUERADE || true

# 4. Launch the Rust node inside the netns.
ip netns exec "$NS" \
  env NEBULA_CA="$BUILD/ca.crt" \
      NEBULA_CERT="$BUILD/rust-peer.crt" \
      NEBULA_KEY="$BUILD/rust-peer.key" \
      NEBULA_CIPHER="$CIPHER" \
      NEBULA_BIND="0.0.0.0:4244" \
      NEBULA_LIGHTHOUSES="10.100.0.1" \
      NEBULA_STATIC_HOSTS="10.100.0.1=10.244.0.1:4242,10.100.0.2=10.244.0.1:4243" \
      NEBULA_TUN_NAME="nebula-rust" \
      NEBULA_TUN_ADDR="10.100.0.3/16" \
      NEBULA_CA_NAME="nebula-protocol interop CA" \
      "$NODE_BIN" &
echo $! >"$HERE/node.pid"

sleep 3
echo " *** rust node launched in $NS (pid $(cat "$HERE/node.pid")) ***"
