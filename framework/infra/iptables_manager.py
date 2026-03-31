"""
iptables manager — manages forwarding and NAT rules on the external
infra Linux box.

Usage:
    from framework.infra.iptables_manager import IPTablesManager
    mgr = IPTablesManager(infra_client, wan_iface="eth1")
    mgr.enable_masquerade()                      # NAT all traffic via eth1
    mgr.allow_forward(src="192.168.10.0/24")     # permit VLAN10 → internet
    mgr.block_inter_vlan(src_vlan="vlan10", dst_vlan="vlan20")
    mgr.flush_test_rules()                        # remove rules tagged TEST_
"""
from __future__ import annotations
import logging
from framework.clients.infra_client import InfraClient

log = logging.getLogger(__name__)

# Comment tag added to every rule written by this manager so they can be
# identified and removed without touching rules that pre-exist on the box.
_TAG = "TEST_FRAMEWORK"


class IPTablesManager:
    """
    Thin wrapper around iptables commands executed over SSH on the infra box.

    * All rules written by this class are tagged with a comment so they can
      be cleaned up in bulk without affecting pre-existing infra rules.
    * Uses iptables (IPv4 only).  IPv6 is out of scope for the test suite.
    """

    def __init__(self, client: InfraClient, wan_iface: str = "eth0"):
        self._client   = client
        self._wan_iface = wan_iface

    # ── NAT / Masquerade ──────────────────────────────────────────────────────

    def enable_masquerade(self, *, chain: str = "POSTROUTING") -> None:
        """Add a MASQUERADE rule so test VLANs can reach the internet via wan_iface."""
        cmd = (
            f"iptables -t nat -A {chain} -o {self._wan_iface} "
            f"-m comment --comment {_TAG} -j MASQUERADE"
        )
        self._run(cmd)

    def disable_masquerade(self) -> None:
        """Remove all MASQUERADE rules tagged by this manager."""
        self._delete_tagged_nat("POSTROUTING", "MASQUERADE")

    # ── Forward rules ────────────────────────────────────────────────────────

    def allow_forward(
        self,
        src: str | None = None,
        dst: str | None = None,
        in_iface: str | None = None,
        out_iface: str | None = None,
    ) -> None:
        """
        Add a FORWARD ACCEPT rule.

        Parameters
        ----------
        src       : Source CIDR (e.g. "192.168.10.0/24").  Optional.
        dst       : Destination CIDR.  Optional.
        in_iface  : Ingress interface.  Optional.
        out_iface : Egress interface.  Optional.
        """
        parts = ["iptables -A FORWARD"]
        if in_iface:  parts.append(f"-i {in_iface}")
        if out_iface: parts.append(f"-o {out_iface}")
        if src:       parts.append(f"-s {src}")
        if dst:       parts.append(f"-d {dst}")
        parts.append(f"-m comment --comment {_TAG} -j ACCEPT")
        self._run(" ".join(parts))

    def block_inter_vlan(
        self,
        src_iface: str | None = None,
        dst_iface: str | None = None,
        src: str | None = None,
        dst: str | None = None,
    ) -> None:
        """
        Insert a DROP rule in FORWARD to block traffic between two VLANs.
        Rule is INSERTed at position 1 so it takes priority over ACCEPT rules.
        """
        parts = ["iptables -I FORWARD 1"]
        if src_iface: parts.append(f"-i {src_iface}")
        if dst_iface: parts.append(f"-o {dst_iface}")
        if src:       parts.append(f"-s {src}")
        if dst:       parts.append(f"-d {dst}")
        parts.append(f"-m comment --comment {_TAG} -j DROP")
        self._run(" ".join(parts))

    # ── Cleanup ──────────────────────────────────────────────────────────────

    def flush_test_rules(self) -> None:
        """
        Remove all iptables rules (filter + nat) that carry the test tag comment.
        Safe to call at test teardown even if no rules were added.
        """
        log.info("Flushing iptables rules tagged '%s'", _TAG)
        # For filter table (FORWARD, INPUT, OUTPUT)
        for chain in ("INPUT", "FORWARD", "OUTPUT"):
            self._delete_tagged_filter(chain)
        # For nat table (PREROUTING, POSTROUTING)
        for chain in ("PREROUTING", "POSTROUTING"):
            self._delete_tagged_nat(chain)

    def enable_ip_forward(self) -> None:
        """Enable kernel IP forwarding (required for routing between VLANs)."""
        self._run("sysctl -w net.ipv4.ip_forward=1")

    def get_forward_rules(self) -> list[str]:
        """Return the current FORWARD chain rules as a list of strings."""
        stdout, _, rc = self._client.exec("iptables -L FORWARD -n --line-numbers")
        if rc != 0:
            return []
        return stdout.splitlines()

    # ── Internal ─────────────────────────────────────────────────────────────

    def _run(self, cmd: str) -> None:
        log.debug("iptables: %s", cmd)
        stdout, stderr, rc = self._client.exec(cmd)
        if rc != 0:
            log.warning("iptables cmd failed (rc=%d): %s\ncmd: %s", rc, stderr, cmd)

    def _delete_tagged_filter(self, chain: str, action: str | None = None) -> None:
        """Delete all tagged rules from a filter table chain."""
        target_flag = f"-j {action}" if action else ""
        cmd = (
            f"iptables -L {chain} --line-numbers -n | "
            f"grep '{_TAG}' {('| grep ' + action) if action else ''} | "
            f"awk '{{print $1}}' | sort -rn | "
            f"xargs -r -I{{}} iptables -D {chain} {{}}"
        )
        stdout, stderr, rc = self._client.exec(cmd)
        if rc != 0 and "No chain" not in stderr:
            log.debug("_delete_tagged_filter %s: rc=%d %s", chain, rc, stderr)

    def _delete_tagged_nat(self, chain: str, action: str | None = None) -> None:
        """Delete all tagged rules from a nat table chain."""
        cmd = (
            f"iptables -t nat -L {chain} --line-numbers -n | "
            f"grep '{_TAG}' {('| grep ' + action) if action else ''} | "
            f"awk '{{print $1}}' | sort -rn | "
            f"xargs -r -I{{}} iptables -t nat -D {chain} {{}}"
        )
        stdout, stderr, rc = self._client.exec(cmd)
        if rc != 0 and "No chain" not in stderr:
            log.debug("_delete_tagged_nat %s: rc=%d %s", chain, rc, stderr)
