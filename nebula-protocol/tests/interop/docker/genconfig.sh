#!/bin/sh
set -e

cat <<EOF
pki:
  ca: ca.crt
  cert: ${HOST}.crt
  key: ${HOST}.key

lighthouse:
  am_lighthouse: ${AM_LIGHTHOUSE:-false}
  hosts: ${LIGHTHOUSE_HOSTS:-[]}

static_host_map:
  '10.100.0.1': ['127.0.0.1:4242']

listen:
  host: 0.0.0.0
  port: ${LISTEN_PORT:-4242}

cipher: ${CIPHER:-aes}

tun:
  disabled: ${TUN_DISABLED:-false}
  dev: ${TUN_DEV:-nebula1}

firewall:
  inbound_action: reject
  outbound_action: reject
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
EOF
