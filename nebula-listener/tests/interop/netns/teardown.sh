#!/bin/bash
# Tears down everything setup.sh created. Safe to run repeatedly.
set -x

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_HARNESS="$HERE/../../../../nebula-protocol/tests/interop/docker"
NS="rust-ns"

[ -f "$HERE/node.pid" ] && kill "$(cat "$HERE/node.pid")" 2>/dev/null
rm -f "$HERE/node.pid"

ip netns del "$NS" 2>/dev/null
ip link del veth-host 2>/dev/null
iptables -t nat -D POSTROUTING -s 10.244.0.0/24 -o lo -j MASQUERADE 2>/dev/null

"$DOCKER_HARNESS/cleanup.sh" 2>/dev/null || true
exit 0
