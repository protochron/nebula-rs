#!/bin/bash
set -e -x

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIPHER="${CIPHER:-aes}"

"$HERE/cleanup.sh" || true
CIPHER="$CIPHER" "$HERE/build.sh"

# --network host (not -p published ports): lighthouse1 and host2 must share
# one loopback namespace with each other and the host-side Rust peer, since
# they all address each other via 127.0.0.1. See the comment in build.sh.
docker run -d --name nebula-protocol-interop-lighthouse1 --rm \
    --network host \
    -v "$HERE/build:/nebula" nebula-protocol-interop:latest -config lighthouse1.yml

docker run -d --name nebula-protocol-interop-host2 --rm \
    --network host \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$HERE/build:/nebula" nebula-protocol-interop:latest -config host2.yml

sleep 2
echo " *** sanity check: lighthouse1 <-> host2 over real Go nebula ***"
docker exec nebula-protocol-interop-host2 ping -c1 -W3 10.100.0.1
