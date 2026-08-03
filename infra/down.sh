#!/bin/sh
set -e
podman rm -f radius iperf3 >/dev/null 2>&1 || true
podman network rm labsvc >/dev/null 2>&1 || true
echo "services stopped"
