#!/usr/bin/env python3
"""
torkeep - Transparent Tor gateway for Linux with fail-closed kill switch.

Routes all TCP and DNS traffic through Tor at the kernel level using
nftables, blocks IPv6 and UDP, and continuously monitors for leaks.

License: GPL-3.0-or-later
"""

import argparse
import atexit
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

__version__ = "1.0.0"

TABLE_NAME = "torkeep"
DEFAULT_TRANS_PORT = 9040
DEFAULT_DNS_PORT = 5354
DEFAULT_TORRC = "/etc/tor/torrc"
TOR_USER_CANDIDATES = ("toranon", "debian-tor", "tor", "_tor")
LOCAL_NETWORKS_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
LOCAL_NETWORKS_V6 = ("fc00::/7", "fe80::/10")
MONITOR_INTERVAL = 3

log = logging.getLogger("torkeep")

BANNER = """
████████╗ ██████╗ ██████╗ ██╗  ██╗███████╗███████╗██████╗
╚══██╔══╝██╔═══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔══██╗
   ██║   ██║   ██║██████╔╝█████╔╝ █████╗  █████╗  ██████╔╝
   ██║   ██║   ██║██╔══██╗██╔═██╗ ██╔══╝  ██╔══╝  ██╔═══╝
   ██║   ╚██████╔╝██║  ██║██║  ██╗███████╗███████╗██║
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝
"""


def print_banner() -> None:
    """Print the torkeep banner with Tor-inspired colors."""
    PURPLE = "\033[38;5;98m"
    GREEN = "\033[38;5;70m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    if sys.stdout.isatty():
        print(f"{PURPLE}{BANNER}{RESET}", end="")
        print(f"{GREEN}{BOLD}   transparent Tor gateway - fail-closed{RESET}")
        print(f"{GREEN}   Developed by staatsrat  |  GPL-3.0-or-later{RESET}\n")
    else:
        print(BANNER, end="")
        print("   transparent Tor gateway - fail-closed")
        print("   Developed by staatsrat  |  GPL-3.0-or-later\n")


def run(cmd, check=True, capture=True):
    shell = isinstance(cmd, str)
    try:
        result = subprocess.run(cmd, shell=shell, check=check,
                                capture_output=capture, text=True)
        return result.stdout.strip() if capture else None
    except subprocess.CalledProcessError as exc:
        if exc.stderr:
            log.debug("cmd failed: %s -> %s", cmd, exc.stderr.strip())
        raise


def is_root() -> bool:
    return os.geteuid() == 0


def find_tor_uid() -> Optional[int]:
    for user in TOR_USER_CANDIDATES:
        try:
            out = run(["id", "-u", user], check=False, capture=True)
            if out and out.isdigit():
                return int(out)
        except Exception:
            continue
    try:
        pids = run("pgrep -x tor", check=False)
        if pids:
            for pid in pids.split():
                uid = run(["stat", "-c", "%u", f"/proc/{pid}"], check=False)
                if uid and uid.isdigit():
                    return int(uid)
    except Exception:
        pass
    return None


def read_torrc_ports(torrc: str = DEFAULT_TORRC):
    trans, dns = DEFAULT_TRANS_PORT, DEFAULT_DNS_PORT
    path = Path(torrc)
    if not path.exists():
        return trans, dns
    try:
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if line.startswith("#") or not line:
                continue
            if line.lower().startswith("transport"):
                m = re.search(r":(\d+)\s*$", line)
                if m:
                    trans = int(m.group(1))
            elif line.lower().startswith("dnsport"):
                m = re.search(r":(\d+)\s*$", line)
                if m:
                    dns = int(m.group(1))
    except OSError:
        pass
    return trans, dns


def tor_is_bootstrapped() -> bool:
    try:
        state = run("systemctl is-active tor", check=False)
        if state != "active":
            return False
        logs = run("journalctl -u tor --no-pager -n 50", check=False) or ""
        return "Bootstrapped 100%" in logs
    except Exception:
        return False


def firewalld_is_active() -> bool:
    try:
        return run("systemctl is-active firewalld", check=False) == "active"
    except Exception:
        return False


class Firewall:
    def __init__(self, tor_uid: int, trans_port: int, dns_port: int):
        self.tor_uid = tor_uid
        self.trans_port = trans_port
        self.dns_port = dns_port

    def _ruleset(self) -> str:
        v4 = ", ".join(LOCAL_NETWORKS_V4)
        v6 = ", ".join(LOCAL_NETWORKS_V6)
        return f"""
table inet {TABLE_NAME} {{
    chain output_nat {{
        type nat hook output priority dstnat; policy accept;

        oif "lo" return
        meta skuid {self.tor_uid} return
        ip daddr {{ {v4} }} return
        ip6 daddr {{ {v6} }} return

        udp dport 53 redirect to :{self.dns_port}
        tcp dport 53 redirect to :{self.dns_port}
        tcp dport != {self.dns_port} redirect to :{self.trans_port}
    }}

    chain output_filter {{
        type filter hook output priority filter; policy drop;

        ip6 daddr != {{ {v6} }} reject with icmpv6 type admin-prohibited

        oif "lo" accept
        meta skuid {self.tor_uid} accept
        ip daddr {{ {v4} }} accept
        ip6 daddr {{ {v6} }} accept
        ct state {{ established, related }} accept

        udp dport {self.dns_port} accept
        tcp dport {self.trans_port} accept

        reject with icmp type port-unreachable
    }}
}}
"""

    def apply(self) -> None:
        self.cleanup(quiet=True)
        payload = self._ruleset()
        proc = subprocess.run(["nft", "-f", "-"], input=payload,
                              text=True, capture_output=True)
        if proc.returncode != 0:
            raise RuntimeError(f"nft failed: {proc.stderr.strip()}")
        log.info("nftables rules applied (table inet %s).", TABLE_NAME)

    def cleanup(self, quiet: bool = False) -> None:
        subprocess.run(["nft", "delete", "table", "inet", TABLE_NAME],
                       capture_output=True, text=True)
        if not quiet:
            log.info("nftables table %s removed.", TABLE_NAME)

    def is_active(self) -> bool:
        out = run("nft list tables", check=False) or ""
        return f"table inet {TABLE_NAME}" in out


def get_reject_counter() -> Optional[int]:
    try:
        out = run(["nft", "-a", "list", "chain", "inet", TABLE_NAME,
                   "output_filter"], check=False) or ""
    except Exception:
        return None
    total = 0
    for line in out.splitlines():
        if "reject" not in line:
            continue
        m = re.search(r"packets\s+(\d+)", line)
        if m:
            total += int(m.group(1))
    return total


def find_real_leaks():
    count = get_reject_counter()
    if not count:
        return (0, [])
    return (count, [f"{count} packets rejected by torkeep filter"])


class LeakMonitor(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="torkeep-monitor")
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        log.info("Leak monitor started (interval %ds).", MONITOR_INTERVAL)
        while not self._stop.wait(MONITOR_INTERVAL):
            count, details = find_real_leaks()
            if count == 0:
                continue
            log.warning("Real leak detected: %d packet(s) rejected.", count)
            for line in details:
                log.warning("  %s", line)
        log.info("Leak monitor stopped.")


class TorKeep:
    def __init__(self, torrc: str = DEFAULT_TORRC, monitor: bool = True):
        self.torrc = torrc
        self.monitor_enabled = monitor
        self.firewall: Optional[Firewall] = None
        self.monitor: Optional[LeakMonitor] = None
        self.tor_uid: Optional[int] = None
        self._active = False

    def start(self) -> None:
        if not is_root():
            log.error("torkeep must run as root.")
            sys.exit(1)

        if self.firewall and self.firewall.is_active():
            log.info("torkeep is already active.")
            return

        self.tor_uid = find_tor_uid()
        if self.tor_uid is None:
            log.error("Could not find Tor user. Is Tor installed?")
            sys.exit(1)
        log.info("Using Tor user uid=%d", self.tor_uid)

        if firewalld_is_active():
            log.warning("firewalld is active and may conflict with torkeep. "
                        "Consider: sudo systemctl stop firewalld")

        if not tor_is_bootstrapped():
            log.warning("Tor does not appear to be bootstrapped. Starting tor...")
            run("systemctl start tor", check=False)
            for _ in range(30):
                if tor_is_bootstrapped():
                    break
                time.sleep(1)
            else:
                log.error("Tor failed to bootstrap within 30s.")
                sys.exit(1)

        trans_port, dns_port = read_torrc_ports(self.torrc)
        log.info("TransPort=%d DNSPort=%d", trans_port, dns_port)

        self.firewall = Firewall(self.tor_uid, trans_port, dns_port)
        self.firewall.apply()
        self._active = True

        atexit.register(self.stop)
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: self.stop())

        log.info("Flushing conntrack to invalidate old sockets...")
        subprocess.run(["conntrack", "-F"], capture_output=True, text=True)

        if self.monitor_enabled:
            self.monitor = LeakMonitor()
            self.monitor.start()

        log.info("torkeep is ACTIVE. Press Ctrl+C to stop.")

    def stop(self) -> None:
        if not self._active:
            return
        self._active = False
        if self.monitor:
            self.monitor.stop()
        if self.firewall:
            self.firewall.cleanup()
        log.info("torkeep stopped. System back to normal.")

    def status(self) -> dict:
        active = bool(self.firewall and self.firewall.is_active())
        return {
            "active": active,
            "tor_uid": find_tor_uid(),
            "tor_bootstrapped": tor_is_bootstrapped(),
            "firewalld": firewalld_is_active(),
            "rejected_packets": get_reject_counter() if active else 0,
        }


def setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    if quiet:
        level = logging.WARNING
    logging.basicConfig(level=level,
                        format="[torkeep] %(levelname)s: %(message)s")


def cmd_start(args) -> int:
    app = TorKeep(torrc=args.torrc, monitor=not args.no_monitor)
    app.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        app.stop()
    return 0


def cmd_stop(args) -> int:
    subprocess.run(["nft", "delete", "table", "inet", TABLE_NAME],
                   capture_output=True, text=True)
    log.info("Stop requested.")
    return 0


def cmd_status(args) -> int:
    app = TorKeep()
    info = app.status()
    print(f"Active:            {info['active']}")
    print(f"Tor UID:           {info['tor_uid']}")
    print(f"Tor bootstrapped:  {info['tor_bootstrapped']}")
    print(f"firewalld active:  {info['firewalld']}")
    print(f"Rejected packets:  {info['rejected_packets']}")
    return 0 if info["active"] else 1


def cmd_check(args) -> int:
    if not Firewall(0, 0, 0).is_active():
        print("torkeep is not active. Start it with: sudo torkeep start")
        return 1
    count, details = find_real_leaks()
    if count == 0:
        print("No leaks detected (reject counter = 0).")
        return 0
    print(f"Leak detected: {count} packet(s) rejected.")
    for line in details:
        print(f"  {line}")
    return 1


def cmd_monitor(args) -> int:
    if not is_root():
        log.error("monitor requires root.")
        return 1
    monitor = LeakMonitor()
    monitor.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        monitor.stop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="torkeep",
        description="Transparent Tor gateway with fail-closed kill switch.",
    )
    p.add_argument("--version", action="version",
                   version=f"torkeep {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--torrc", default=DEFAULT_TORRC)

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("start", help="Start transparent Tor routing.")
    sp.add_argument("--no-monitor", action="store_true",
                    help="Disable the background leak monitor.")
    sp.set_defaults(func=cmd_start)

    sp = sub.add_parser("stop", help="Stop and clean up.")
    sp.set_defaults(func=cmd_stop)

    sp = sub.add_parser("status", help="Show current status.")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("check", help="One-shot leak scan.")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("monitor", help="Foreground leak monitor.")
    sp.set_defaults(func=cmd_monitor)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose, args.quiet)
    if not args.quiet:
        print_banner()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
