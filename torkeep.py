#!/usr/bin/env python3

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

__version__ = "1.1.0"

TABLE_NAME = "torkeep"
LOG_PREFIX = "TOR_KEEP_LEAK"
DEFAULT_TRANS_PORT = 9040
DEFAULT_DNS_PORT = 5354
DEFAULT_TORRC = "/etc/tor/torrc"
TOR_USER_CANDIDATES = ("toranon", "debian-tor", "tor", "_tor")
LOCAL_NETWORKS_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
LOCAL_NETWORKS_V6 = ("fc00::/7", "fe80::/10")

log = logging.getLogger("torkeep")

BANNER = r"""
████████╗ ██████╗ ██████╗ ██╗  ██╗███████╗███████╗██████╗
╚══██╔══╝██╔═══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔══██╗
   ██║   ██║   ██║██████╔╝█████╔╝ █████╗  █████╗  ██████╔╝
   ██║   ██║   ██║██╔══██╗██╔═██╗ ██╔══╝  ██╔══╝  ██╔═══╝
   ██║   ╚██████╔╝██║  ██║██║  ██╗███████╗███████╗██║
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝
"""

RED = "\033[31;1m"
GREEN = "\033[38;5;70m"
PURPLE = "\033[38;5;98m"
YELLOW = "\033[33;1m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner() -> None:
    if sys.stdout.isatty():
        print(f"{PURPLE}{BANNER}{RESET}", end="")
        print(f"{GREEN}{BOLD}   TOR_KEEP - transparent Tor gateway{RESET}")
        print(f"{GREEN}   fail-closed | IPv6+UDP blocked | live leak detection{RESET}")
        print(f"{GREEN}   Developed by staatsrat | GPL-3.0-or-later{RESET}\n")
    else:
        print(BANNER, end="")
        print("   TOR_KEEP - transparent Tor gateway")
        print("   fail-closed | IPv6+UDP blocked | live leak detection")
        print("   Developed by staatsrat | GPL-3.0-or-later\n")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

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


class PortCache(threading.Thread):
    """Fast cache of (proto, port) -> process name.

    QUIC/UDP sockets live for milliseconds. We poll `ss` at 50ms and
    keep entries in a secondary "recently seen" store for 5 seconds so
    kernel log lines arriving slightly late can still be attributed.
    """

    INTERVAL = 0.05           # 20 Hz
    MEMORY_SECONDS = 5.0      # keep recently seen mappings

    def __init__(self):
        super().__init__(daemon=True, name="torkeep-portcache")
        self._stop = threading.Event()
        self._cache = {}
        self._memory = {}  # key -> (name, timestamp)
        self._lock = threading.Lock()

    def stop(self):
        self._stop.set()

    def lookup(self, proto, port):
        key = (proto.upper(), str(port))
        with self._lock:
            name = self._cache.get(key)
            if name:
                return name
            mem = self._memory.get(key)
            if mem:
                return mem[0]
        return None

    def run(self):
        while not self._stop.wait(self.INTERVAL):
            new_cache = {}
            for flags, proto in (("-tnpH", "TCP"), ("-unpH", "UDP")):
                try:
                    out = subprocess.run(["ss", flags],
                                         capture_output=True,
                                         text=True, timeout=1).stdout
                except Exception:
                    continue
                for line in out.splitlines():
                    m = re.search(r':(\d+)\s.*?users:\(\("([^"]+)"', line)
                    if not m:
                        continue
                    port = m.group(1)
                    name = m.group(2)
                    new_cache[(proto, port)] = name
            now = time.time()
            with self._lock:
                self._cache = new_cache
                # Add newly seen to memory
                for k, v in new_cache.items():
                    self._memory[k] = (v, now)
                # Prune old memory entries
                cutoff = now - self.MEMORY_SECONDS
                self._memory = {k: v for k, v in self._memory.items()
                                if v[1] > cutoff}


def guess_protocol_hint(proto, dpt, dst):
    """Return a human hint about what protocol this likely is."""
    dpt = str(dpt)
    if proto.upper().startswith("UDP"):
        if dpt == "443":
            return "QUIC / HTTP3 (browser)"
        if dpt in ("3478", "3479", "5349"):
            return "STUN / TURN (WebRTC)"
        if dpt == "53":
            return "DNS (UDP)"
        if dpt == "1900":
            return "SSDP / UPnP discovery"
        if dpt == "5353":
            return "mDNS / avahi"
        if dpt == "123":
            return "NTP"
        if dpt == "784":
            return "Tor pluggable transport"
        return "UDP"
    if proto.upper().startswith("TCP"):
        if dpt == "80":
            return "HTTP"
        if dpt == "443":
            return "HTTPS"
        return "TCP"
    if proto.upper().startswith("ICMP"):
        return "ICMP"
    return proto


def ip_version(addr):
    return "IPv6" if ":" in addr else "IPv4"



def lookup_udp_proc(local_port):
    """Fallback: read /proc/net/udp{,6} to map a local port to an inode,
    then walk /proc/*/fd to find the owning process. Only useful within
    a short window after the packet is sent."""
    import glob
    port_hex = f"{int(local_port):04X}"
    inode = None
    for fname in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(fname) as f:
                next(f)  # skip header
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    # local_address is column 1: "HEX:PORT"
                    la = parts[1]
                    if ":" not in la:
                        continue
                    _, p = la.rsplit(":", 1)
                    if p.upper() == port_hex:
                        inode = parts[9]
                        break
        except OSError:
            continue
        if inode:
            break
    if not inode:
        return None
    # Find which pid owns that inode
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if f"socket:[{inode}]" in target:
            try:
                pid = int(fd.split("/")[2])
                with open(f"/proc/{pid}/comm") as f:
                    return f.read().strip()
            except (OSError, ValueError, IndexError):
                continue
    return None


def find_app_by_port(port: str, proto: str) -> str:
    """Return the process name that owns the given local port.

    Uses ss to map port -> PID -> process name. Falls back to '?'.
    """
    try:
        flag = "-unapH" if proto.upper() == "UDP" else "-tnapH"
        out = subprocess.run(["ss", flag], capture_output=True, text=True,
                             timeout=2).stdout
        for line in out.splitlines():
            # Match local port
            if f":{port} " not in line and f":{port}\t" not in line:
                continue
            m = re.search(r'users:\(\("([^"]+)"', line)
            if m:
                return m.group(1)
            # No users field? try next line
        return "unknown"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------

class Firewall:
    def __init__(self, tor_uid: int, trans_port: int, dns_port: int):
        self.tor_uid = tor_uid
        self.trans_port = trans_port
        self.dns_port = dns_port

    def _ruleset(self) -> str:
        v4 = ", ".join(LOCAL_NETWORKS_V4)
        v6 = ", ".join(LOCAL_NETWORKS_V6)
        # Multicast and link-local traffic never leaves the LAN.
        mc4 = "224.0.0.0/4, 239.0.0.0/8"
        mc6 = "ff00::/8"
        return f"""
table inet {TABLE_NAME} {{
    chain output_nat {{
        type nat hook output priority dstnat; policy accept;

        oif "lo" return
        meta skuid {self.tor_uid} return
        ip daddr {{ {v4}, {mc4} }} return
        ip6 daddr {{ {v6}, {mc6} }} return

        udp dport 53 redirect to :{self.dns_port}
        tcp dport 53 redirect to :{self.dns_port}
        tcp dport != {self.dns_port} redirect to :{self.trans_port}
    }}

    chain output_filter {{
        type filter hook output priority filter; policy drop;

        # Loopback + Tor redirected traffic (address match needed because
        # nat REDIRECT changes daddr but oif still points to the original NIC).
        oif "lo" accept
        ip daddr 127.0.0.0/8 accept
        ip6 daddr ::1 accept
        meta skuid {self.tor_uid} accept

        # Multicast + link-local: LAN-only, never routed to internet.
        ip daddr {{ {mc4} }} accept
        ip6 daddr {{ {mc6}, fe80::/10 }} accept

        ip6 daddr != {{ {v6}, {mc6}, fe80::/10 }} log prefix "{LOG_PREFIX} " level warn reject with icmpv6 type admin-prohibited

        ip daddr {{ {v4} }} accept
        ip6 daddr {{ {v6} }} accept
        ct state {{ established, related }} accept

        udp dport {self.dns_port} accept
        tcp dport {self.trans_port} accept

        log prefix "{LOG_PREFIX} " level warn
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


# ---------------------------------------------------------------------------
# Leak Monitor
# ---------------------------------------------------------------------------

KERNEL_FIELD_RE = re.compile(r"([A-Z0-9_]+)=(\S+)")


def humanize(leak):
    """Turn a leak dict into a short human sentence.

    Returns something like 'chronyd is still trying to sync time' or
    'firefox is still trying to use QUIC' so the one-liner reads naturally.
    """
    app = (leak.get("app") or "unknown").lower()
    hint = (leak.get("hint") or "").lower()
    proto = (leak.get("proto") or "").upper()
    dpt = str(leak.get("dpt") or "")

    # Common app patterns
    if "chrony" in app or "ntp" in app or "timesyn" in app:
        return f"{app} is still trying to sync time"
    if "avahi" in app:
        return f"{app} is still trying to discover local services"
    if app.startswith("ping") or proto.startswith("ICMP"):
        return f"{app} is still trying to reach the internet"
    if app.startswith("traceroute") or app.startswith("tracepath"):
        return f"{app} is still trying to probe the network"
    if app in ("firefox", "firefox-bin", "brave", "brave-browser",
               "chromium", "chrome", "google-chrome"):
        if "quic" in hint or "http3" in hint:
            return f"{app} is still trying to use QUIC/HTTP3"
        if "stun" in hint or "webrtc" in hint or dpt in ("3478", "3479", "5349"):
            return f"{app} is still trying to use WebRTC"
        if proto.startswith("UDP"):
            return f"{app} is still trying to send UDP"
        return f"{app} is still trying to bypass the proxy"
    if app in ("curl", "wget"):
        return f"{app} is still trying to fetch directly"
    if app.startswith("tor") or app == "tor":
        return f"{app} is still opening a direct path (should not happen)"
    if app.startswith("nm-") or "networkmanager" in app:
        return f"{app} is still trying to check connectivity"

    # Fallback by protocol hint
    if "quic" in hint or "http3" in hint:
        return f"{app} is still trying to use QUIC/HTTP3"
    if "ntp" in hint:
        return f"{app} is still trying to sync time"
    if "mdns" in hint or "avahi" in hint:
        return f"{app} is still trying to discover local services"
    if "stun" in hint or "turn" in hint or "webrtc" in hint:
        return f"{app} is still trying to use WebRTC"
    if "dns" in hint:
        return f"{app} is still trying to resolve DNS directly"
    if proto.startswith("ICMP"):
        return f"{app} is still trying to reach the internet"
    if proto.startswith("UDP"):
        return f"{app} is still trying to send UDP"
    if proto.startswith("TCP"):
        return f"{app} is still trying to bypass the proxy"

    return f"{app} is still trying to send traffic outside Tor"


class LiveDisplay:
    """Compact single-line display that updates in place.

    Falls back to plain log lines when stdout is not a TTY.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.last_leak_time = None
        self.total = 0
        self.unique = 0
        self.current = None
        self._last_rendered_len = 0
        self._disabled = not sys.stdout.isatty()

    def update(self, leak, total, unique):
        if self._disabled:
            log.info("Blocked: %s -> %s:%s (%s)",
                     leak["app"], leak["dst"], leak["dpt"], leak["hint"])
            return
        with self.lock:
            self.current = leak
            self.total = total
            self.unique = unique
            self.last_leak_time = time.time()
            self._draw()

    def refresh(self):
        if self._disabled:
            return
        with self.lock:
            self._draw()

    def start(self):
        if self._disabled:
            return
        with self.lock:
            self._draw()

    def stop(self):
        if self._disabled:
            return
        with self.lock:
            if self._last_rendered_len:
                sys.stdout.write("\n")
                sys.stdout.flush()
                self._last_rendered_len = 0

    def _draw(self):
        now = time.time()
        elapsed = int(now - self.start_time)
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        if h:
            uptime = f"{h}h{m:02d}m{s:02d}s"
        elif m:
            uptime = f"{m:02d}m{s:02d}s"
        else:
            uptime = f"{s}s"

        if self.last_leak_time:
            since = int(now - self.last_leak_time)
            if since < 60:
                last = f"{since}s ago"
            else:
                mm, ss = divmod(since, 60)
                last = f"{mm}m{ss:02d}s ago"
        else:
            last = "never"

        if self.current:
            sentence = humanize(self.current)
            detail = f"{sentence} \u2014 blocked ({last})"
        else:
            detail = f"all traffic through Tor ({last})"

        prefix = f"[torkeep] {uptime}  |  {self.total} blocked"
        if self.unique != self.total:
            prefix += f" ({self.unique} unique)"
        full = f"{prefix}  |  {detail}"

        # Truncate safely by terminal width without breaking words too badly
        try:
            width = os.get_terminal_size().columns
        except OSError:
            width = 200
        width = max(width, 40)
        line = full
        if len(line) > width - 1:
            # Shorten the human sentence, keep prefix intact
            keep_prefix = prefix
            available = width - len(keep_prefix) - 6  # for "  |  …"
            if available > 20:
                detail_short = detail[:available - 1] + "\u2026"
                line = f"{keep_prefix}  |  {detail_short}"
            else:
                line = full[:width - 2] + "\u2026"

        out = []
        if self._last_rendered_len:
            out.append("\r")
        out.append("\033[K")
        out.append(line)
        sys.stdout.write("".join(out))
        sys.stdout.flush()
        self._last_rendered_len = len(line)



class LeakMonitor(threading.Thread):
    """Follows kernel logs for TOR_KEEP_LEAK entries and updates the display."""

    def __init__(self):
        super().__init__(daemon=True, name="torkeep-monitor")
        self._stop = threading.Event()
        self._proc = None
        self.leak_count = 0
        self.lock = threading.Lock()
        self.port_cache = None
        self.display = LiveDisplay()
        self._seen_keys = set()

    def stop(self):
        self._stop.set()
        if self.port_cache:
            self.port_cache.stop()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
        self.display.stop()

    def unique_count(self):
        with self.lock:
            return len(self._seen_keys)

    def _open_journal(self):
        try:
            proc = subprocess.Popen(
                ["journalctl", "-k", "-f", "-n", "0", "-o", "cat"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            return proc
        except FileNotFoundError:
            try:
                proc = subprocess.Popen(
                    ["dmesg", "--follow-new"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                )
                return proc
            except FileNotFoundError:
                return None

    def _refresher(self):
        while not self._stop.wait(1.0):
            self.display.refresh()

    def run(self):
        log.info("Leak monitor started (watching kernel log).")
        self.port_cache = PortCache()
        self.port_cache.start()
        self.display.start()
        threading.Thread(target=self._refresher, daemon=True).start()

        proc = self._open_journal()
        if proc is None:
            log.warning("Cannot follow kernel log - leak detection disabled.")
            return
        self._proc = proc

        try:
            for raw in proc.stdout:
                if self._stop.is_set():
                    break
                line = raw.strip()
                if LOG_PREFIX not in line:
                    continue
                self._handle_leak(line)
        except Exception as exc:
            log.debug("monitor loop error: %s", exc)
        finally:
            self.display.stop()
            log.info("Leak monitor stopped.")

    def _handle_leak(self, line):
        fields = dict(KERNEL_FIELD_RE.findall(line))
        proto = fields.get("PROTO", "?")
        src = fields.get("SRC", "?")
        dst = fields.get("DST", "?")
        spt = fields.get("SPT", "?")
        dpt = fields.get("DPT", "?")

        app = None
        if spt != "?":
            app = find_app_by_port(spt, proto)
            if (not app or app in ("unknown", "?")) and self.port_cache:
                app = self.port_cache.lookup(proto, spt)
            if (not app or app in ("unknown", "?")) and proto.upper() == "UDP":
                app = lookup_udp_proc(spt)
        if not app or app in ("unknown", "?"):
            app = "unidentified (ephemeral socket)"

        hint = guess_protocol_hint(proto, dpt, dst)
        ipver = ip_version(dst)

        with self.lock:
            self.leak_count += 1
            key = (app, dst, dpt)
            self._seen_keys.add(key)
            total = self.leak_count
            unique = len(self._seen_keys)

        leak = {
            "app": app,
            "hint": hint,
            "ipver": ipver,
            "dst": dst,
            "dpt": dpt,
            "src": src,
            "spt": spt,
            "proto": proto,
        }
        self.display.update(leak, total, unique)


class TorKeep:
    def __init__(self, torrc: str = DEFAULT_TORRC, monitor: bool = True):
        self.torrc = torrc
        self.monitor_enabled = monitor
        self.firewall: Optional[Firewall] = None
        self.monitor: Optional[LeakMonitor] = None
        self.tor_uid: Optional[int] = None
        self._active = False
        self._stopping = False

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
                        "Recommend: sudo systemctl stop firewalld")

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
        signal.signal(signal.SIGINT, lambda *_: self.stop())
        signal.signal(signal.SIGTERM, lambda *_: self.stop())

        log.info("Flushing conntrack to invalidate old sockets...")
        subprocess.run(["conntrack", "-F"], capture_output=True, text=True)

        if self.monitor_enabled:
            self.monitor = LeakMonitor()
            self.monitor.start()

        log.info("torkeep is ACTIVE. Press Ctrl+C to stop.")
        log.info("Watching for leak attempts...")
        # Give the display one blank line of separation from log output
        print()

    def stop(self) -> None:
        if self._stopping or not self._active:
            return
        self._stopping = True

        # Ignore further SIGINT during shutdown
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)

        self._active = False
        if self.monitor:
            self.monitor.stop()
        if self.firewall:
            self.firewall.cleanup()

        if self.monitor:
            n = self.monitor.leak_count
            u = self.monitor.unique_count()
            if n > 0:
                log.info("Summary: %d leak attempt(s) blocked (%d unique).", n, u)

        log.info("torkeep stopped. System back to normal.")
        sys.exit(0)

    def status(self) -> dict:
        active = bool(self.firewall and self.firewall.is_active())
        leaks = 0
        if self.monitor:
            with self.monitor.lock:
                leaks = self.monitor.leak_count
        return {
            "active": active,
            "tor_uid": find_tor_uid(),
            "tor_bootstrapped": tor_is_bootstrapped(),
            "firewalld": firewalld_is_active(),
            "leaks_blocked": leaks,
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

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
    print(f"Active:             {info['active']}")
    print(f"Tor UID:            {info['tor_uid']}")
    print(f"Tor bootstrapped:   {info['tor_bootstrapped']}")
    print(f"firewalld active:   {info['firewalld']}")
    print(f"Leaks blocked:      {info['leaks_blocked']}")
    return 0 if info["active"] else 1


def cmd_check(args) -> int:
    if not Firewall(0, 0, 0).is_active():
        print("torkeep is not active. Start it with: sudo torkeep start")
        return 1
    print("torkeep is active. Watch the running instance for live leak reports.")
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

    sp = sub.add_parser("check", help="One-shot status check.")
    sp.set_defaults(func=cmd_check)

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
