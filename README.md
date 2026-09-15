
```
████████╗ ██████╗ ██████╗ ██╗  ██╗███████╗███████╗██████╗
╚══██╔══╝██╔═══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔══██╗
   ██║   ██║   ██║██████╔╝█████╔╝ █████╗  █████╗  ██████╔╝
   ██║   ██║   ██║██╔══██╗██╔═██╗ ██╔══╝  ██╔══╝  ██╔═══╝
   ██║   ╚██████╔╝██║  ██║██║  ██╗███████╗███████╗██║
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝
```

**Lock down your Linux host. All TCP and DNS through Tor. IPv6 and UDP rejected. No cleartext, ever.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-7D4698.svg?style=for-the-badge)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-68B030.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tor](https://img.shields.io/badge/Tor-7D4698.svg?style=for-the-badge&logo=torproject&logoColor=white)](https://www.torproject.org/)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-68B030.svg?style=for-the-badge&logo=linux&logoColor=white)](https://www.kernel.org/)

</div>

---

## What is torkeep?

**torkeep** is a single-host transparent Tor gateway for Linux. It forces
all TCP and DNS traffic through Tor at the kernel level using nftables,
hard-blocks IPv6 and UDP to prevent leaks, and runs a fail-closed kill
switch that stops all network access the moment Tor dies.

No per-application configuration. No proxy settings. No VMs. One command
locks down the entire machine — every browser, every updater, every
background daemon — and guarantees that nothing leaves the host in
cleartext.

---

## Features

- **Transparent proxying** — no per-application configuration, no proxy
  settings, no browser flags
- **Fail-closed kill switch** — if Tor dies, all network access stops.
  No fallback, no cleartext, no exceptions.
- **IPv6 hard-block** — external IPv6 is rejected at the filter layer;
  Tor's IPv6 support is unreliable, so it is disabled
- **UDP reject** — WebRTC, QUIC, and every other UDP protocol cannot
  escape the tunnel
- **Conntrack flush on start** — old sockets are invalidated
  automatically, so stale connections cannot bypass the rules
- **Counter-based leak monitor** — inspects nftables reject counters,
  not the misleading `ss` output (which is blind to NAT redirects)
- **Clean rollback** — `Ctrl+C` removes everything, no leftover rules,
  no stale tables, no surprises
- **No telemetry, no logs, no data collection**

---

## Requirements

| Component | Version / Note |
|-----------|---------------|
| OS | Linux with `nftables` and `systemd` |
| Python | 3.9 or newer |
| Tor | `tor` daemon running as `toranon` (Fedora), `debian-tor` (Debian), or `tor` |
| nftables | `nft` binary available |
| Root | Required to modify kernel firewall rules |

Tested on **Fedora 40 / 41** with SELinux enforcing, firewalld active,
and an IPv6-only upstream (NAT64/DNS64).

---

## Installation

```bash
git clone https://github.com/staatsrat/torkeep.git
cd torkeep
sudo install -m 0755 torkeep.py /usr/local/bin/torkeep
```

That's it. No dependencies beyond the requirements above.

---

## Usage

```bash
# Activate transparent Tor routing
sudo torkeep start

# Show current state
torkeep status

# One-shot leak scan
torkeep check

# Foreground leak monitor
sudo torkeep monitor

# Deactivate and clean up
sudo torkeep stop
```

Press `Ctrl+C` while `torkeep start` is running to stop and roll back
cleanly.

---

## Verification

```bash
# 1. Confirm the exit node is Tor
curl -s https://check.torproject.org/api/ip
# -> {"IsTor":true,"IP":"..."}

# 2. Prove no cleartext leaves the host
sudo tcpdump -i <iface> -n 'tcp and not port 22'
# -> only Tor relay IPs

# 3. Kill-switch test
sudo systemctl stop tor
curl -m 5 https://example.com
# -> exit code 6 (DNS fail) or 28 (timeout), never 0
sudo systemctl start tor
```

The `tcpdump` test is the honest one. The `ss` command will still show
"connections" to remote servers, but that is a socket-level illusion —
the kernel rewrote the packets to `127.0.0.1:9040` before they left the
host. Only `tcpdump` reveals what actually goes on the wire.

---

## How it works

`torkeep` builds a single nftables table `inet torkeep` with two chains:

**`output_nat`** — a NAT chain that:

- returns traffic to loopback, the Tor user, and RFC1918 ranges
- redirects UDP and TCP port 53 to Tor's `DNSPort` (default `5354`)
- redirects all other TCP to Tor's `TransPort` (default `9040`)

**`output_filter`** — a filter chain with `policy drop` that:

- rejects all external IPv6 with `icmpv6 admin-prohibited`
- accepts loopback, the Tor user, and RFC1918
- accepts established/related connections
- accepts redirected DNS and Tor ports
- rejects everything else

Because the filter chain is fail-closed, if Tor stops listening the
redirected packets hit the reject rule and **no traffic leaves the host
in cleartext**.

The `LeakMonitor` thread polls the nftables reject counter every three
seconds. It does not use `ss` because socket state does not reflect NAT
redirects and would produce false positives on every browser tab.

---

## Limitations

- **UDP is blocked, not proxied.** Applications that require UDP — WebRTC,
  QUIC, some games, some VPNs — will not work. This is intentional.
- **External IPv6 is blocked.** Tor's IPv6 support is unreliable; blocking
  is the only way to guarantee no leaks.
- **Tor Browser is still recommended** for anonymity-grade browsing.
  `torkeep` prevents IP leaks; it does not touch browser fingerprinting.
- **Old sockets may briefly hang after start.** `torkeep` flushes the
  conntrack table on activation, but applications that hold a socket open
  in userspace may need a restart (or a page refresh in the browser).
- **firewalld on Fedora may conflict.** `torkeep` warns when it detects an
  active `firewalld`. For maximum stability, disable it while using
  `torkeep`:

  ```bash
  sudo systemctl stop firewalld
  sudo systemctl disable firewalld
  ```

---

## Troubleshooting

**`Tor does not appear to be bootstrapped`**

Check `journalctl -u tor --no-pager -n 50`. Ensure `TransPort` and
`DNSPort` are configured in `/etc/tor/torrc`:

```
TransPort 9040
DNSPort 5354
```

Restart Tor with `sudo systemctl restart tor`.

**`nft: Operation not permitted`**

Run as root. On SELinux systems, ensure `nftables` is permitted to load
rules for the `tor_t` domain.

**Everything is blocked, including Tor**

The `meta skuid <tor_uid>` rule relies on the correct Tor user. Check
`pgrep -x tor` and `stat -c %u /proc/<pid>`. If the user is different from
the defaults in `TOR_USER_CANDIDATES`, add it to that tuple in `torkeep.py`.

**Firefox / Brave still shows remote IPs in `ss`**

Expected. See the "Verification" section. Use `tcpdump` to see the truth.

---

## Roadmap

- systemd unit for boot-time activation
- `--refresh` command to rotate the Tor exit IP
- Tor bridge support (obfs4, snowflake) for censored networks
- Config file (`~/.config/torkeep/config.toml`) for persistent options
- Onion service helper (`.onion` binding without leaks)

---


<div align="center">

**Developed by [staatsrat](https://github.com/staatsrat)**

Stars are welcome — they help the project grow.

</div>
```
