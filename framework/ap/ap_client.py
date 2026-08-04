"""
Direct-SSH AP client — drives an OpenWiFi AP with no uCentral cloud SDK.

The flow this framework uses:

1. Stop and disable the ``ucentral`` agent so nothing reverts our config.
2. Upload a uCentral JSON config to ``/tmp``.
3. Apply it with ``/usr/share/ucentral/ucentral.uc /tmp/<name>.json``.
4. Read back the resulting state to prove it took effect.

The most important detail: **when ucentral.uc is given a config path other than
``/etc/ucentral/ucentral.*`` it always exits 0**, success or failure. The exit
branch that would return non-zero is gated on the non-custom path. Failures are
therefore detected by parsing stdout/stderr, which is what
:func:`parse_apply_output` does.
"""
from __future__ import annotations

import json
import logging
import re
import shlex
import time
from dataclasses import dataclass, field

from framework.clients.ssh import SSHError, SSHSession

log = logging.getLogger(__name__)

UCENTRAL_UC = "/usr/share/ucentral/ucentral.uc"
GATEWAY_JSON = "/etc/ucentral/gateway.json"
GATEWAY_JSON_OFF = "/etc/ucentral/gateway.json.off"
REMOTE_CONFIG_DIR = "/tmp/regression"
UCI_BATCH_PATH = "/tmp/ucentral.uci"
APPLY_LOG = f"{REMOTE_CONFIG_DIR}/apply.log"
APPLY_RC = f"{REMOTE_CONFIG_DIR}/apply.rc"
ROLLBACK_CANCEL = f"{REMOTE_CONFIG_DIR}/rollback.cancel"

# Markers in ucentral.uc output. A successful render emits a UCI batch; a
# schema/renderer rejection emits only log messages carrying [E] lines.
_UCI_BATCH_MARKER = "UCI batch output:"
_LOG_MARKER = "Log messages:"
_FATAL_MARKER = "Fatal error while generating UCI"
_STRICT_REJECT = "Rejecting config due to strict-mode validation"
# ucentral.uc dies here when it cannot open the config it was handed: the open
# returns null and the very next call is `inputfile.read(...)`.
_UNREADABLE_INPUT = "left-hand side is not a function"
_ERROR_LINE = re.compile(r"^\s*\[E\]\s*(.+)$", re.MULTILINE)
_WARN_LINE = re.compile(r"^\s*\[W\]\s*(.+)$", re.MULTILINE)


@dataclass
class ApplyResult:
    """Outcome of one ``ucentral.uc`` invocation."""

    success: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    uci_batch: str = ""
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0

    @property
    def reason(self) -> str:
        if self.success:
            return "applied"
        # A renderer that hung is not a config the AP refused, and calling both
        # "rejected" sent several real hangs to the wrong triage bucket.
        if self.hung:
            return self.stderr.strip().splitlines()[0]
        if self.errors:
            return "; ".join(self.errors[:5])
        return "ucentral.uc produced no UCI batch and no error detail"

    @property
    def hung(self) -> bool:
        return "hung and was killed" in self.stderr


def parse_apply_output(stdout: str, stderr: str) -> ApplyResult:
    """
    Classify ucentral.uc output, since the exit code carries no information.

    Success is the presence of a rendered UCI batch. Anything else — schema
    rejection, renderer fatal, or empty output — is a failure.
    """
    errors = [m.strip() for m in _ERROR_LINE.findall(stdout)]
    errors += [m.strip() for m in _ERROR_LINE.findall(stderr)]
    warnings = [m.strip() for m in _WARN_LINE.findall(stdout)]

    if _FATAL_MARKER in stdout or _FATAL_MARKER in stderr:
        blob = stdout if _FATAL_MARKER in stdout else stderr
        for line in blob.splitlines():
            if _FATAL_MARKER in line:
                errors.append(line.strip())
        return ApplyResult(False, errors, warnings, stdout=stdout, stderr=stderr)

    if _UCI_BATCH_MARKER in stdout:
        batch = stdout.split(_UCI_BATCH_MARKER, 1)[1]
        if _LOG_MARKER in batch:
            batch = batch.split(_LOG_MARKER, 1)[0]
        return ApplyResult(
            success=not errors,
            errors=errors,
            warnings=warnings,
            uci_batch=batch.strip(),
            stdout=stdout,
            stderr=stderr,
        )

    if not errors:
        # Strict mode refuses on a *warning*, and says so on its own line
        # without an [E] prefix — so the renderer's actual explanation was
        # being thrown away and every one of these reported as the useless
        # "no UCI batch". Quote the reason, and the warnings that caused it.
        if _UNREADABLE_INPUT in stdout or _UNREADABLE_INPUT in stderr:
            errors.append(
                "ucentral.uc could not read the config file it was given "
                "(it died on inputfile.read) — the file was missing or "
                "unreadable, not refused"
            )
        elif _STRICT_REJECT in stdout or _STRICT_REJECT in stderr:
            detail = "; ".join(warnings) if warnings else "no warning was printed"
            errors.append(f"{_STRICT_REJECT} ({detail})")
        else:
            errors.append("no UCI batch in ucentral.uc output — config was rejected")
    return ApplyResult(False, errors, warnings, stdout=stdout, stderr=stderr)


@dataclass
class RadioCaps:
    """
    What one of the DUT's radios can actually do, from capabilities.json.

    The upstream examples are written against flagship Wi-Fi 6E/7 hardware, so
    on anything older they ask for modes and widths the radio does not have.
    The renderer only *warns* and silently falls back, so tests need these
    limits up front to normalize against.
    """

    band: str
    modes: frozenset[str] = frozenset()        # {"HT", "VHT", "HE", "EHT"}
    widths_by_mode: dict[str, frozenset[int]] = field(default_factory=dict)
    channels: frozenset[int] = frozenset()
    dfs_channels: frozenset[int] = frozenset()

    def widths_for(self, mode: str) -> frozenset[int]:
        return self.widths_by_mode.get(mode, frozenset())


# Ordered weakest to strongest; used to pick the best mode a radio supports.
MODE_ORDER = ("HT", "VHT", "HE", "EHT")
_HTMODE_RE = re.compile(r"^(EHT|VHT|HE|HT)(\d+)$")


def parse_radio_caps(capabilities: dict) -> dict[str, RadioCaps]:
    """Map band -> :class:`RadioCaps` from a parsed ``capabilities.json``."""
    out: dict[str, RadioCaps] = {}
    for _phy, data in (capabilities.get("wifi") or {}).items():
        data = data or {}
        bands = data.get("band") or []
        modes: set[str] = set()
        widths: dict[str, set[int]] = {}
        for htmode in data.get("htmode") or []:
            m = _HTMODE_RE.match(str(htmode).strip())
            if not m:
                continue
            mode, width = m.group(1), int(m.group(2))
            modes.add(mode)
            widths.setdefault(mode, set()).add(width)

        for band in bands:
            out[str(band)] = RadioCaps(
                band=str(band),
                modes=frozenset(modes),
                widths_by_mode={k: frozenset(v) for k, v in widths.items()},
                channels=frozenset(int(c) for c in (data.get("channels") or [])),
                dfs_channels=frozenset(int(c) for c in (data.get("dfs_channels") or [])),
            )
    return out


@dataclass
class DeviceInfo:
    """Identity of the DUT, for the report header."""

    model: str = "unknown"
    board_name: str = "unknown"
    platform: str = "unknown"
    firmware: str = "unknown"
    kernel: str = "unknown"
    serial: str = "unknown"
    radios: list[dict] = field(default_factory=list)

    def as_rows(self) -> list[tuple[str, str]]:
        return [
            ("Model", self.model),
            ("Board", self.board_name),
            ("Platform", self.platform),
            ("Firmware", self.firmware),
            ("Kernel", self.kernel),
            ("Serial", self.serial),
        ]


class APClient:
    """SSH control of a single OpenWiFi AP under test."""

    def __init__(
        self,
        host: str,
        user: str = "root",
        password: str = "openwifi",
        *,
        port: int = 22,
        key_path: str | None = None,
    ) -> None:
        self.host = host
        self.ssh = SSHSession(
            host, user, password, key_path=key_path, port=port, label=f"AP:{host}"
        )
        self._agent_disabled = False

    # ── Agent control ────────────────────────────────────────────────────────

    def disable_agent(self) -> None:
        """
        Stop the uCentral agent so the controller cannot push config mid-test.

        Deliberately *only* stop and disable the init script. An earlier version
        also moved ``/etc/ucentral/gateway.json`` aside, on the theory that
        ``start_service`` would then return early. On this firmware that is both
        useless and harmful: the agent takes its server from its own
        ``-s <host> -c <file>`` arguments rather than that file, so it starts
        anyway, and at the next boot ``/etc/rc.d/S98cloud_discover`` fails with
        "can't open /etc/ucentral/gateway.json" — leaving the AP unable to
        re-onboard.

        Stopping is not permanent by itself: every apply ends in
        ``reload_config``, which fires procd's reload trigger and restarts the
        agent. :meth:`_ensure_agent_down` re-stops it after each apply and
        throughout verification.
        """
        self.ssh.run("/etc/init.d/ucentral stop", timeout=30)
        self.ssh.run("/etc/init.d/ucentral disable", timeout=30)

        # Undo the damage if an older run left the file moved.
        if self.ssh.exists(GATEWAY_JSON_OFF) and not self.ssh.exists(GATEWAY_JSON):
            self.ssh.run(f"mv {GATEWAY_JSON_OFF} {GATEWAY_JSON}")
            log.info("Restored a gateway.json left aside by a previous run")

        self._agent_disabled = True
        log.info("uCentral agent stopped and disabled on %s", self.host)

    def restore_agent(self) -> None:
        """Undo :meth:`disable_agent` — best effort, never raises."""
        try:
            # Defensive: older runs may have left gateway.json moved, which
            # breaks cloud discovery at the next boot.
            if self.ssh.exists(GATEWAY_JSON_OFF) and not self.ssh.exists(GATEWAY_JSON):
                self.ssh.run(f"mv {GATEWAY_JSON_OFF} {GATEWAY_JSON}")
            self.ssh.run("/etc/init.d/ucentral enable", timeout=30)
            self.ssh.run("/etc/init.d/ucentral start", timeout=30)
            log.info("uCentral agent restored on %s", self.host)
        except SSHError as exc:
            log.warning("Could not restore uCentral agent: %s", exc)
        finally:
            self._agent_disabled = False

    # ── Commit-confirmed rollback ────────────────────────────────────────────

    def _spawn_detached(self, script: str, *, marker: str) -> bool:
        """
        Start *script* so it outlives this SSH session, portably.

        OpenWrt busybox images frequently ship **neither ``setsid`` nor
        ``nohup``** — this AP has neither. The obvious
        ``setsid nohup sh -c '...' &`` returns rc=0 because the shell forks
        successfully, and then nothing runs at all. That silently disabled both
        the detached apply and, far worse, the rollback safety net, which is why
        a bad config once stranded the AP with no recovery.

        ``start-stop-daemon -S -b`` is present on OpenWrt and is tried first.
        Launch is then *verified* rather than assumed.
        """
        quoted = shlex.quote(script)
        attempts = (
            f"start-stop-daemon -S -b -x /bin/sh -- -c {quoted}",
            f"setsid sh -c {quoted} >/dev/null 2>&1 &",
            f"sh -c {quoted} >/dev/null 2>&1 &",
        )
        for cmd in attempts:
            if not self.ssh.run(f"command -v {cmd.split()[0]} >/dev/null 2>&1").ok \
                    and cmd.split()[0] not in ("sh",):
                continue
            self.ssh.run(cmd, timeout=20)
            time.sleep(1)
            if self.ssh.run(f"ps w | grep -v grep | grep -q {shlex.quote(marker)}").ok:
                return True
        log.error(
            "Could not start a detached process on %s — tried start-stop-daemon, "
            "setsid and plain backgrounding", self.host
        )
        return False

    def arm_rollback(self, seconds: int = 300) -> None:
        """
        Schedule an unattended recovery that fires unless we cancel it.

        Applying an arbitrary config to a remote AP can cut the very path used
        to manage it — a config whose upstream interface selects ports this
        hardware does not have, or which renumbers the WAN, leaves the AP
        stranded with no way back but a physical power cycle. That happened on
        this bench.

        This is the network world's standard "commit confirmed": arm a timer
        before touching the config, and cancel it once management access is
        proven still to work. If we lose the AP, the timer factory-resets and
        reboots it, and it re-onboards to the controller by itself.

        The timer is detached with ``setsid``/``nohup`` so it survives both the
        SSH session ending and the service restarts an apply performs.
        """
        # Kill any timer still sleeping from an earlier apply first. Without
        # this, clearing the cancel file below re-arms every stale timer, and
        # one of them fires mid-run and factory-resets the AP underneath a
        # later test — which looks like a random config rejection.
        self.ssh.run(f"pkill -f {shlex.quote(ROLLBACK_CANCEL)} || true", timeout=20)
        self.ssh.run(f"mkdir -p {REMOTE_CONFIG_DIR}; rm -f {ROLLBACK_CANCEL}")
        script = (
            f"sleep {int(seconds)}; "
            f"[ -f {ROLLBACK_CANCEL} ] && exit 0; "
            f"logger -t regression 'rollback timer fired - factory resetting'; "
            f"/etc/init.d/ucentral enable; "
            f"jffs2reset -y; reboot"
        )
        if self._spawn_detached(script, marker=ROLLBACK_CANCEL):
            log.info("Rollback armed on %s: factory reset in %ss unless cancelled",
                     self.host, seconds)
        else:
            # Applying without a safety net is how the AP got stranded before.
            log.error(
                "Rollback could NOT be armed on %s. A config that costs management "
                "access will need a physical power cycle.", self.host
            )

    def cancel_rollback(self) -> bool:
        """
        Cancel a pending rollback. Returns False if the AP could not be reached,
        in which case the timer is deliberately left to fire.
        """
        try:
            # Touch the flag *and* kill the sleeping timer. The flag alone is
            # enough for a timer that is still asleep, but killing it means a
            # later arm cannot accidentally revive this one.
            self.ssh.run(f"mkdir -p {REMOTE_CONFIG_DIR}; touch {ROLLBACK_CANCEL}", timeout=20)
            self.ssh.run(f"pkill -f {shlex.quote(ROLLBACK_CANCEL)} || true", timeout=20)
            log.debug("Rollback cancelled on %s", self.host)
            return True
        except SSHError as exc:
            log.error(
                "Could not cancel rollback on %s (%s). Leaving the timer to fire — "
                "the AP will factory-reset and come back on its own.", self.host, exc
            )
            return False

    def factory_reset(self, wait_for_boot: bool = True, timeout: int = 300) -> bool:
        """
        Wipe the overlay and reboot — the cleanest way to hand the AP back.

        Preferred over :meth:`restore_agent` at the end of a run. Restoring the
        agent leaves whatever the tests applied committed in ``/etc/config``,
        and the AP then reconciles against the controller from that state. A
        factory reset returns it to a known baseline and lets it re-onboard
        cleanly, so the next run starts from the same place every time.

        Returns True if the AP came back (or if we were not asked to wait).
        """
        log.info("Factory-resetting %s (jffs2reset -y && reboot)", self.host)
        # The AP drops the connection as it reboots, so a lost session here is
        # success, not failure.
        try:
            self.ssh.run("jffs2reset -y && reboot", timeout=30)
        except SSHError as exc:
            log.debug("Connection dropped during factory reset, as expected: %s", exc)

        self._agent_disabled = False
        if not wait_for_boot:
            return True

        time.sleep(20)
        came_back = self.ssh.wait_until_reachable(timeout=timeout, interval=10)
        if came_back:
            log.info("%s is back after factory reset", self.host)
        else:
            log.warning(
                "%s did not answer within %ss after factory reset — it may still "
                "be booting or re-onboarding to the controller", self.host, timeout
            )
        return came_back

    def agent_running(self) -> bool:
        """
        True only if the uCentral agent itself is running.

        Getting this right needs care on busybox. A substring match on
        ``/usr/sbin/ucentral`` also hits the helper daemons ``ucentral-state``,
        ``ucentral-event`` and ``ucentral-wifiscan``, which the apply pipeline
        restarts every time — a false positive. But ``pgrep -x ucentral`` is a
        false *negative* here: it fails to match even when
        ``/usr/sbin/ucentral -S ... -s <gateway>`` is plainly in the process
        list. Matching the binary path followed by a space or end-of-line
        distinguishes the agent from its hyphenated helpers.
        """
        res = self.ssh.run(
            "ps w | grep -v grep | grep -cE '/usr/sbin/ucentral( |$)'"
        )
        return res.stdout.strip() not in ("", "0")

    # ── Config apply ─────────────────────────────────────────────────────────

    def _run_apply_detached(self, remote: str, timeout: int) -> tuple[str, str]:
        """
        Run ucentral.uc detached and poll for it to finish.

        The apply pipeline restarts services — dropbear among them — so the SSH
        channel running it can be killed part-way through, which looks like a
        180-second hang and then a transport error even though the apply
        succeeded. Detaching it and polling for the exit-code file makes the
        result readable across a dropped session.
        """
        self.ssh.run(f"rm -f {APPLY_LOG} {APPLY_RC}")
        script = f"{UCENTRAL_UC} {shlex.quote(remote)} > {APPLY_LOG} 2>&1; echo $? > {APPLY_RC}"
        if not self._spawn_detached(script, marker=remote):
            # Fall back to a foreground apply. It may die when the pipeline
            # restarts dropbear, but a possibly-truncated log beats no apply.
            log.warning("Falling back to a foreground apply on %s", self.host)
            res = self.ssh.run(f"{UCENTRAL_UC} {shlex.quote(remote)}", timeout=timeout)
            return res.stdout, res.stderr

        deadline = time.monotonic() + timeout
        finished = False
        rounds = 0
        while time.monotonic() < deadline:
            try:
                if self.ssh.exists(APPLY_RC):
                    finished = True
                    break
                # The apply's own `reload_config` fires procd's trigger and
                # brings the uCentral agent back up *while the render is still
                # running*. The agent then drives its own reload, and the two
                # wait on network.wireless settling that the other keeps
                # disturbing — the render never returns and the whole timeout
                # is spent. Holding the agent down for the apply window, not
                # just after it, is what stops that.
                rounds += 1
                if rounds % 5 == 0:
                    self._ensure_agent_down()
            except SSHError:
                # Session died with the service restart; reconnect and keep waiting.
                self.ssh.close()
            time.sleep(3)

        if not finished:
            # Distinguish a hang from a lost session: if ucentral.uc is still
            # running it is genuinely stuck, and leaving it there wedges every
            # later apply and lets the rollback timer factory-reset the AP
            # underneath the run. `dual-stack` does this reliably, stalling
            # mid-render in the DHCPv6 section.
            still = self.ssh.run(
                "ps w | grep -v grep | grep -c ucentral.uc"
            ).stdout.strip()
            hung = still not in ("", "0")
            if hung:
                self.ssh.run("pkill -9 -f ucentral.uc || true", timeout=20)
                log.error(
                    "ucentral.uc hung on %s after %ss and was killed; the config "
                    "was not applied", self.host, timeout
                )
            partial = ""
            try:
                partial = self.ssh.read_text(APPLY_LOG)
            except SSHError:
                pass
            return partial, (
                f"ucentral.uc {'hung and was killed' if hung else 'did not finish'} "
                f"after {timeout}s (no {APPLY_RC} written)"
            )

        # Reconnect if needed — the log is on disk, so a dropped session is
        # only a reason to retry the read, not to call the apply a failure.
        for attempt in range(3):
            try:
                return self.ssh.read_text(APPLY_LOG), ""
            except SSHError as exc:
                log.debug("Apply log read attempt %s failed: %s", attempt + 1, exc)
                self.ssh.close()
                time.sleep(2)
        return "", "apply finished but its log could not be read"

    def apply_config(
        self,
        config: dict,
        *,
        name: str = "config",
        timeout: int = 180,
        rollback_seconds: int = 300,
    ) -> ApplyResult:
        """
        Upload *config* and apply it with ucentral.uc.

        The apply pipeline is self-contained: it renders UCI into a shadow
        directory, waits for ``network.wireless`` to settle, commits, and
        restarts the affected services. No ``wifi reload`` is needed afterwards.
        """
        if not self._agent_disabled:
            log.warning(
                "Applying config while the uCentral agent is still enabled — "
                "it may revert this config"
            )

        remote = f"{REMOTE_CONFIG_DIR}/{name}.json"
        payload = json.dumps(config, indent=2)
        self.ssh.put_text(payload, remote)

        # Let the previous config finish coming up first. The apply pipeline
        # waits internally for network.wireless to settle, and starting it while
        # a radio is still `pending` from the last case is a way to wedge it
        # there for the whole timeout — `crypto-psk` and `eap_local` both hung
        # for 180s on 5G directly after their own 2G run, having applied
        # cleanly moments earlier.
        if not self.wait_for_wireless(timeout=60):
            log.warning(
                "Radios on %s still pending before applying %r — applying anyway",
                self.host, name,
            )

        # Safety net first: if this config costs us management access, the AP
        # recovers on its own instead of needing a physical power cycle.
        self.arm_rollback(seconds=rollback_seconds)

        started = time.monotonic()
        stdout, stderr = self._run_apply_detached(remote, timeout)

        # An empty log means we lost the transport or timed out, not that the
        # AP rejected anything — a real rejection always prints "[E]" lines or
        # "Rejecting config". Those two look identical downstream, so retry
        # once rather than reporting a config error that did not happen.
        #
        # A hang is retried too, once. Most are not the config's fault: they
        # cluster on the apply that follows a heavy multi-SSID case, where the
        # renderer wedges waiting on wireless state left over from the previous
        # one. `crypto-psk`, `eap_local` and `owe` each hung on an apply that
        # had succeeded minutes earlier with the same config. Giving the radios
        # time to settle and running it again clears that, at the cost of one
        # extra timeout on a config that genuinely wedges — `dual-stack` does.
        if not stdout.strip():
            hung = "hung" in stderr
            log.warning(
                "Apply of %r %s — settling the radios and retrying once", name,
                "hung" if hung else f"produced no output ({stderr or 'no detail'})",
            )
            self._ensure_agent_down()
            if hung:
                self.ssh.run("pkill -9 -f ucentral.uc || true", timeout=20)
                self.wait_for_wireless(timeout=90)
            # The config lives under /tmp, so anything that reboots the AP
            # between upload and apply takes it with it — the rollback timer
            # from an earlier case can do exactly that. ucentral.uc then dies
            # on `inputfile.read` because the open returned null, which reads
            # as a rejected config rather than a missing file.
            if not self.ssh.exists(remote):
                log.warning("%s vanished before the retry — re-uploading", remote)
                self.ssh.put_text(payload, remote)
            stdout, stderr = self._run_apply_detached(remote, timeout)

        elapsed = time.monotonic() - started

        result = parse_apply_output(stdout, stderr)
        result.duration_s = elapsed

        # Only stand the safety net down once the AP has answered us again.
        if self.ssh.is_reachable():
            self.cancel_rollback()
        else:
            log.error(
                "Lost contact with %s after applying %r — leaving the rollback "
                "timer to factory-reset it", self.host, name
            )
            result.success = False
            result.errors.append(
                "management access lost after apply; rollback timer left armed"
            )
            return result

        # The apply pipeline ends with reload_config, which fires procd's
        # reload trigger for the ucentral package and restarts the agent we
        # just stopped. Left alone it reconnects to the controller, which
        # pushes its own config straight over the one under test — the SSIDs
        # come up correctly and then silently revert seconds later.
        self._ensure_agent_down()

        if result.success:
            log.info("Applied %s in %.1fs (%d warnings)", name, elapsed, len(result.warnings))
        else:
            log.error("Apply of %s failed: %s", name, result.reason)
        return result

    def _ensure_agent_down(self) -> None:
        """
        Re-stop the agent if an apply brought it back. Cheap, so called often.

        Only meaningful once :meth:`disable_agent` has been called — otherwise
        the caller has deliberately left the AP under controller management.
        """
        if not self._agent_disabled:
            return
        if self.agent_running():
            log.warning(
                "uCentral agent restarted itself during apply (procd reload "
                "trigger) — stopping it again before verification"
            )
            self.ssh.run("/etc/init.d/ucentral stop", timeout=30)
            time.sleep(2)

    def wait_for_wireless(self, timeout: int = 90) -> bool:
        """
        Block until no radio reports ``pending``.

        ucentral.uc already waits internally, but a DFS channel or a slow radio
        bring-up can outlast that wait, and associating too early looks like an
        association failure.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.wireless_status()
            if status and not any(r.get("pending") for r in status.values()):
                return True
            time.sleep(3)
        log.warning("Radios still pending after %ss", timeout)
        return False

    # ── State readback ───────────────────────────────────────────────────────

    def wait_for_ssids(self, expected: set[str], timeout: int = 60) -> set[str]:
        """
        Poll until every SSID in *expected* is broadcasting; return any missing.

        ``wait_for_wireless`` only reports that the radios stopped saying
        "pending"; hostapd still needs a moment to bring each BSS up after
        that. Reading the SSID list immediately after an apply catches the AP
        mid-transition and reports SSIDs as missing when they are merely late.
        """
        deadline = time.monotonic() + timeout
        missing = set(expected)
        while time.monotonic() < deadline:
            # The agent can come back mid-wait and revert the config, so keep
            # it down for the whole verification window, not just after apply.
            self._ensure_agent_down()
            live = {s["ssid"] for s in self.ssids()}
            missing = set(expected) - live
            if not missing:
                return set()
            time.sleep(3)
        return missing

    def wireless_status(self) -> dict:
        """``ubus call network.wireless status`` — requested config per radio."""
        return self._ubus("network.wireless", "status")

    def iwinfo(self) -> str:
        """Ground truth: the channel/mode/txpower each VAP is actually using."""
        return self.ssh.run("iwinfo").stdout

    def uci_show(self, package: str = "wireless") -> str:
        return self.ssh.run(f"uci show {shlex.quote(package)}").stdout

    def rendered_uci(self) -> str:
        """The exact UCI batch the last render produced."""
        if self.ssh.exists(UCI_BATCH_PATH):
            return self.ssh.read_text(UCI_BATCH_PATH)
        return ""

    def hostapd_interfaces(self) -> list[str]:
        out = self.ssh.run("ubus list hostapd.*").stdout
        return [line.strip() for line in out.splitlines() if line.strip()]

    def hostapd_status(self, iface: str) -> dict:
        obj = iface if iface.startswith("hostapd.") else f"hostapd.{iface}"
        return self._ubus(obj, "get_status")

    def associated_clients(self) -> list[dict]:
        """Every station currently associated, across all BSSes."""
        clients: list[dict] = []
        for obj in self.hostapd_interfaces():
            data = self._ubus(obj, "get_clients")
            for mac, info in (data.get("clients") or {}).items():
                clients.append({"mac": mac.lower(), "bss": obj, **info})
        return clients

    def ssids(self) -> list[dict]:
        """SSID name plus interface for every configured BSS."""
        out = []
        for obj in self.hostapd_interfaces():
            status = self.hostapd_status(obj)
            if status.get("ssid"):
                out.append(
                    {
                        "ssid": status["ssid"],
                        "bss": obj,
                        "channel": status.get("channel"),
                        "freq": status.get("freq"),
                    }
                )
        return out

    # ── Identity ─────────────────────────────────────────────────────────────

    def device_info(self) -> DeviceInfo:
        info = DeviceInfo()

        board = self._ubus("system", "board")
        info.model = board.get("model", "unknown")
        info.board_name = board.get("board_name", "unknown")
        info.kernel = board.get("kernel", "unknown")
        release = board.get("release") or {}
        if isinstance(release, dict) and release.get("description"):
            info.firmware = release["description"]

        # The agent reports DISTRIB_REVISION, so match it for comparability.
        rev = self.ssh.run(
            "grep DISTRIB_REVISION /etc/openwrt_release | cut -d\"'\" -f2"
        ).stdout.strip()
        if rev:
            info.firmware = rev

        caps = self._json_file("/etc/ucentral/capabilities.json")
        if not caps:
            # capabilities.json is generated on demand; produce it if missing.
            self.ssh.run("/usr/share/ucentral/capabilities.uc > /etc/ucentral/capabilities.json")
            caps = self._json_file("/etc/ucentral/capabilities.json")
        if caps:
            info.platform = caps.get("platform", "unknown")
            info.model = caps.get("model", info.model)
            wifi = caps.get("wifi") or {}
            info.radios = [
                {"phy": phy, "bands": list((data or {}).get("band", []))}
                for phy, data in wifi.items()
            ]

        serial = self.ssh.run("uci get ucentral.config.serial").stdout.strip()
        if serial:
            info.serial = serial

        return info

    # ── Logs ─────────────────────────────────────────────────────────────────

    def radio_capabilities(self) -> dict[str, RadioCaps]:
        """
        Per-band capability of this DUT's radios, keyed by band ("2G"/"5G"/"6G").

        Returns an empty dict when capabilities.json is unavailable, which the
        normalizer treats as "leave the example's radio settings alone".
        """
        caps = self._json_file("/etc/ucentral/capabilities.json")
        if not caps:
            self.ssh.run(
                "/usr/share/ucentral/capabilities.uc > /etc/ucentral/capabilities.json"
            )
            caps = self._json_file("/etc/ucentral/capabilities.json")
        return parse_radio_caps(caps) if caps else {}

    def short_name(self) -> str:
        """
        A compact identifier for this AP, used to name test SSIDs.

        Prefers the board name ("edgecore,spw2ac1200" -> "spw2ac1200") because
        it is stable and short; falls back to the hostname.
        """
        board = self._ubus("system", "board")
        name = (board.get("board_name") or "").split(",")[-1].strip()
        if not name:
            name = self.ssh.run(
                "uci get system.@system[0].hostname 2>/dev/null"
            ).stdout.strip()
        cleaned = "".join(c for c in name if c.isalnum() or c in "-_")
        return (cleaned or "ap")[:20]

    def logread(self, lines: int = 300) -> str:
        return self.ssh.run(f"logread | tail -n {int(lines)}").stdout

    def clear_log_marker(self) -> str:
        """Return a marker string written into the log, to bound a later read."""
        marker = f"REGRESSION-MARK-{int(time.monotonic() * 1000)}"
        self.ssh.run(f"logger {shlex.quote(marker)}")
        return marker

    def logread_since(self, marker: str, lines: int = 500) -> str:
        blob = self.logread(lines)
        if marker in blob:
            return blob.split(marker, 1)[1]
        return blob

    # ── Internals ────────────────────────────────────────────────────────────

    def _ubus(self, obj: str, method: str, timeout: int = 30) -> dict:
        res = self.ssh.run(f"ubus call {shlex.quote(obj)} {shlex.quote(method)}", timeout=timeout)
        if not res.ok or not res.stdout.strip():
            return {}
        try:
            return json.loads(res.stdout)
        except json.JSONDecodeError:
            log.debug("Non-JSON from ubus call %s %s", obj, method)
            return {}

    def _json_file(self, path: str) -> dict:
        if not self.ssh.exists(path):
            return {}
        try:
            return json.loads(self.ssh.read_text(path))
        except json.JSONDecodeError:
            return {}

    def close(self) -> None:
        self.ssh.close()
