#!/bin/sh
# Install or update the Bench Console on the station host. Idempotent.
#
# Run from the repo root on the Pi:  sh benchd/deploy/install.sh
set -e
ROOT=${BENCH_ROOT:-/opt/bench}
REPO=${BENCH_REPO:-$ROOT/repo}

echo "==> venv"
[ -d "$ROOT/venv" ] || python3 -m venv "$ROOT/venv"
"$ROOT/venv/bin/pip" install -q --upgrade pip
"$ROOT/venv/bin/pip" install -q -e "$REPO[console]"

echo "==> directories"
mkdir -p "$ROOT/runs"

echo "==> service"
sudo cp "$REPO/benchd/deploy/benchd.service" /etc/systemd/system/benchd.service
sudo systemctl daemon-reload
sudo systemctl enable benchd
sudo systemctl restart benchd

# RADIUS must come back by itself after a reboot. It did not, once, and every
# enterprise case in the sweep that followed failed with the client associating
# and finding no authentication server — which reads as an AP fault.
sudo systemctl enable --now podman-restart 2>/dev/null || true

echo "==> done"
sleep 2
systemctl --no-pager --lines=3 status benchd || true
