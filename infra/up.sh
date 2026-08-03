#!/bin/sh
# Bring up the self-contained lab services on the station host.
#
# RADIUS uses HOST networking, deliberately. Its client is the AP, not the
# station, so there is no loopback-shortcut problem to solve and no isolation
# requirement — the AP reaches it at the Pi's own address over the wire.
#
# An earlier revision put it on a macvlan child of eth0 to isolate a local
# iperf3 peer from the station. That peer is gone: connectivity is now measured
# with librespeed-cli against public servers, which crosses the air by
# definition. Since the only reason for macvlan was the local peer, and a
# macvlan child on the management NIC is a plausible cause of the station
# dropping off the network mid-sweep, it is not worth the risk.
set -e
INFRA=${INFRA:-/opt/regression-infra}
. "$INFRA/infra.env"

podman rm -f radius iperf3 >/dev/null 2>&1 || true
podman network rm labsvc >/dev/null 2>&1 || true

# No arm64 image is published upstream, so build the equivalent locally.
podman image exists localhost/bench-freeradius || \
  podman build -t localhost/bench-freeradius "$INFRA/freeradius"

sed "s/@SECRET@/$RADIUS_SECRET/g" "$INFRA/freeradius/clients.conf.tmpl" \
  > "$INFRA/freeradius/clients.conf"

podman run -d --name radius --network host --restart no \
  -v "$INFRA/freeradius/clients.conf":/etc/freeradius/3.0/clients.conf:ro,z \
  -v "$INFRA/freeradius/authorize":/etc/freeradius/3.0/mods-config/files/authorize:ro,z \
  localhost/bench-freeradius

sleep 3
podman ps --format '  {{.Names}}  {{.Status}}'
echo "RADIUS listening on this host's address, port 1812/1813"
