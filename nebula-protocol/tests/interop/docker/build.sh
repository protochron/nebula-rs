#!/bin/bash
set -e -x

VENDORED_NEBULA="/tmp/github.com/slackhq/nebula@v1.10.3"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIPHER="${CIPHER:-aes}"

rm -rf "$HERE/build"
mkdir -p "$HERE/build"

go build -C "$VENDORED_NEBULA" -o "$HERE/build/nebula" ./cmd/nebula
go build -C "$VENDORED_NEBULA" -o "$HERE/build/nebula-cert" ./cmd/nebula-cert

cd "$HERE/build"
./nebula-cert ca -curve 25519 -name "nebula-protocol interop CA"
./nebula-cert sign -name "lighthouse1" -groups "lighthouse" -ip "10.100.0.1/16"
./nebula-cert sign -name "host2" -groups "host" -ip "10.100.0.2/16"
./nebula-cert sign -name "rust-peer" -groups "host" -ip "10.100.0.3/16"

# Both containers run with --network host (see run.sh) so they share the
# same loopback namespace as each other and the host-side Rust peer — a
# published port (`-p 127.0.0.1:PORT:PORT`) only maps into the *host's*
# loopback and is NOT reachable from a sibling container's own loopback
# namespace, so lighthouse1 and host2 need distinct listen ports on the
# one shared namespace instead of both claiming 4242 behind separate
# port-publishes.
HOST="lighthouse1" AM_LIGHTHOUSE=true TUN_DISABLED=true LISTEN_PORT=4242 TUN_DEV=nebula1 CIPHER="$CIPHER" \
    "$HERE/genconfig.sh" >lighthouse1.yml
HOST="host2" LIGHTHOUSE_HOSTS="['10.100.0.1']" LISTEN_PORT=4243 TUN_DEV=nebula2 CIPHER="$CIPHER" \
    "$HERE/genconfig.sh" >host2.yml

cd "$HERE"
docker build -t nebula-protocol-interop:latest "$HERE"
