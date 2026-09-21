# TunnelVisionVision

Endpoint detection and response for **TunnelVision (CVE-2024-3661)**: a rogue DHCP server pushes
option 121 classless static routes that are more specific than your VPN's routes. Traffic then leaves
unencrypted on the local network while the VPN still reports "connected" and kill switches never trip.

- Runs on **Linux, macOS, and Windows**, and in **containers** (Docker/Podman/Kubernetes, with host networking). Pure Python 3.9+ with no required dependencies.
- **Alerts the user** with a desktop dialog (osascript on macOS, zenity/kdialog/tkinter on Linux, tkinter or a MessageBox on Windows). On headless machines it falls back to a terminal prompt, `wall`, logs, or a hook command.
- Offers three choices:
  - **Mitigate:** remove the rogue routes, and keep removing them while the VPN stays up. Per-OS manual hardening steps are shown when something can't be fixed automatically.
  - **Disconnect:** take down the Wi-Fi/Ethernet link.
  - **Continue:** keep working on the vulnerable network. The tool reminds you later, or right away if the situation changes.
- **Runs as a service**: a privileged daemon (systemd, launchd, or a Windows scheduled task running as SYSTEM) plus a per-user agent that starts at login and shows the prompts.

## Why a new tool

As of September 2026 the public TunnelVision tooling is offensive: [Leviathan's PoC](https://github.com/leviathansecurity/TunnelVision) and
[CVE-2024-3661_Demo](https://github.com/YardenFadida/CVE-2024-3661_Demo). Defences exist only as VPN-vendor-specific fixes
or as network-side controls (DHCP snooping), which don't help a laptop on hostile Wi-Fi. I found no cross-platform endpoint detector
that alerts the user and offers a choice of response.

## How detection works

Each poll (default 5 s):

1. **Collect** interfaces, *all* routing tables (including Linux policy-routing tables such as wg-quick's `51820`), and the current
   DHCP lease's option 121 routes:
   - Linux: NetworkManager, systemd-networkd, dhclient, dhcpcd.
   - macOS: `ipconfig getpacket`.
   - Windows: the registry, best-effort (see limitations).
2. **Find VPN coverage**: routes on tunnel interfaces (WireGuard, tun/tap, utun, ppp, IPsec, plus known clients such as
   Tailscale, AnyConnect, GlobalProtect, Fortinet, OpenVPN/Wintun, and any interface you list in `vpn_interfaces`).
3. **Flag overriding routes**: any route on a physical interface that is at least as specific as a VPN route covering it.
   Normal LAN routes, link-local, multicast, and macOS interface-scoped routes are excluded.
4. **Confirm with the OS routing engine** (`ip route get`, `route -n get`, `Find-NetRoute`). If policy routing or scoping still
   sends the traffic into the VPN, the finding is downgraded to *not effective*. This avoids false positives with
   Tailscale, wg-quick, and similar setups.
5. **Canary probes**: a few public IPs plus samples from each VPN route are looked up. Any that exit via a physical interface
   raise an alert, even if the route that caused it couldn't be attributed.
6. **Optional passive sniffing** (`"sniff": true`): watches DHCP OFFER/ACKs as they arrive, so it can catch a rogue offer that carries
   VPN-bypassing routes and spot multiple competing DHCP servers.
   - Linux: raw socket with a kernel BPF filter, no dependencies.
   - Elsewhere: requires scapy.

| Severity | Meaning (alerts fire at `HIGH` and above by default) |
|---|---|
| CRITICAL | A route that overrides the VPN **and** came from DHCP (matches the lease's option 121, or the OS marks it `proto dhcp`), or a rogue DHCP offer was seen |
| HIGH | A non-host route that overrides the VPN, a host route that appeared after the VPN connected, or a canary IP leaking |
| MEDIUM | Host route to an unknown IP via the physical gateway (usually the VPN server, which you can list in `vpn_endpoints`), an oversized local subnet, or multiple DHCP servers |
| LOW / INFO | Option 121 present with no VPN running, an untrusted DHCP server, or an override that isn't effective |

## Install

```bash
pip install .                      # or run from the checkout: python3 -m tunnelvisionvision ...
```

```bash
tvv check                          # one-shot scan; exit code 1 means alert-worthy findings
```

```bash
tvv check --simulate               # fake attack to exercise the prompt; all actions are dry-run
```

```bash
sudo tvv install-service           # daemon at boot + agent at every user login
```

On **Windows**, run `tvv install-service` from an elevated prompt. It registers `\TunnelVisionVision\Daemon` (SYSTEM, at startup)
and `\TunnelVisionVision\Agent` (all users, at logon) in Task Scheduler. On macOS it installs LaunchDaemon and LaunchAgent plists.
On Linux it installs a systemd unit and an XDG autostart entry.

Other commands:

| Command | Purpose |
|---|---|
| `tvv monitor` | Continuous monitoring in the foreground with prompts (run elevated so the responses work) |
| `tvv status [--json]` | Show the daemon's state and current alert |
| `tvv action mitigate\|disconnect\|continue` | Answer the current alert from a shell (headless hosts, SSH, containers) |
| `tvv --dry-run ...` | Print response commands without running them |
| `tvv uninstall-service` | Remove the service and agent |

### Containers

A container with its own network namespace is actually *protected* from TunnelVision: that namespace isolation is Leviathan's
recommended fix. So what needs watching is the **host** network namespace.

```bash
docker build -t tunnelvisionvision .
```

```bash
docker run -d --name tvv --restart unless-stopped --network host --cap-add NET_ADMIN --cap-add NET_RAW -v /var/lib/NetworkManager:/var/lib/NetworkManager:ro -v /var/lib/dhcp:/var/lib/dhcp:ro -v /run/systemd/netif:/run/systemd/netif:ro tunnelvisionvision
```

```bash
docker exec tvv tvv action mitigate
```

For Kubernetes, see `deploy/kubernetes-daemonset.yaml`. On a Linux host without the desktop agent, the daemon uses `wall` for alerts
and `alert_command` for forwarding. **Docker Desktop (macOS/Windows)** runs containers inside a VM, so `--network host` there
means the VM's network, not the laptop's. Install natively on those machines instead.

## Configuration

JSON, at `/etc/tunnelvisionvision/config.json` (Linux), `/Library/Application Support/TunnelVisionVision/config.json` (macOS),
or `%ProgramData%\TunnelVisionVision\config.json` (Windows). Override the path with `$TVV_CONFIG` or `--config`.
See `config.example.json` for all keys.

| Key | Default | |
|---|---|---|
| `notify_min_severity` | `HIGH` | Minimum severity that raises a prompt |
| `auto_action` / `auto_action_delay` | `none` / 120 s | What to do if nobody answers: `mitigate` or `disconnect` (for unattended servers and containers) |
| `remind_after` | 3600 s | When to re-prompt after "Continue" |
| `vpn_endpoints` | `[]` | VPN server IPs, so their host routes are expected (auto-detected for WireGuard via `wg show`) |
| `trusted_routes` / `trusted_dhcp_servers` | `[]` | Legitimate option 121 routes and servers, to allowlist |
| `vpn_interfaces` / `ignore_interfaces` | `[]` | Override interface classification |
| `sniff` | `false` | Passive DHCP sniffing |
| `alert_command` | `""` | Command that receives the alert JSON on stdin, e.g. `curl -sd @- https://siem/...` |

## Response details

- **Mitigate** deletes each rogue route, so traffic falls back to the VPN's own route. It deliberately does *not* add
  replacement routes into the tunnel, because doing that can capture the VPN's own encrypted packets and create a routing loop.
  The rogue DHCP server re-pushes routes at every lease renewal, so the daemon keeps removing them while the VPN stays up.
  Findings that can't be fixed by deleting a route (an oversized subnet, or a canary leak with no attributable route) return
  OS-specific manual steps instead:
  - Linux: NetworkManager `ipv4.ignore-auto-routes`, networkd `UseRoutes=no`, the dhclient/dhcpcd equivalents, VPN in a
    network namespace, and nftables kill-switch rules.
  - macOS: the VPN client's include-all-networks or lockdown option, a manual IP configuration, and a pf anchor.
  - Windows: a firewall-based VPN lockdown, a static IP, and a Windows Firewall rule.
- **Disconnect** turns Wi-Fi off (`networksetup`/`netsh wlan disconnect`/`nmcli`) or takes the wired interface down.
- **Continue** acknowledges the alert. You're re-prompted after `remind_after`, or immediately if new findings appear.

The daemon's localhost API (`127.0.0.1:47121`) requires a token stored in the state directory. The token is readable by
local users so their agents can reach the daemon. This means any local user can trigger mitigate or disconnect.

## Testing

```bash
python3 -m unittest discover -s tests -t .
```

The unit tests cover RFC 3442 encoding and decoding, each OS's parsers (using real-format fixtures), detection scenarios
(full tunnel, split tunnel, policy routing, IPv6, host routes, canaries, sniffing), the daemon lifecycle
(alert, mitigate, re-enforce, resolve, continue, remind, auto-action) and the authenticated API.

**End-to-end lab** (needs a Linux kernel; Docker Desktop is fine). It runs a real dnsmasq rogue DHCP server pushing
`0.0.0.0/1` and `128.0.0.0/1` against a victim with a wg-quick-style full tunnel, then shows detection, mitigation, and
re-enforcement after a DHCP renewal:

```bash
docker build -t tvv-lab -f lab/Dockerfile . && docker run --rm --privileged tvv-lab
```

## Limitations

- **Verification status:**
  - macOS collection and detection have been run live (against a Tailscale exit-node VPN).
  - The Linux and Windows collectors are verified only against fixtures of their command output.
  - The service installers, Windows dialogs, and PowerShell response commands have not been run yet.
  - Do a pilot on each OS before a wide rollout.
- Windows has no public API for the DHCP option 121 contents. Reading the registry's `DhcpInterfaceOptions` value is best-effort,
  so Windows relies mainly on route analysis, OS confirmation, and canaries (enough to detect an attack, but it can't name the DHCP server).
- Before the daemon has seen the VPN come up, a single-IP (/32) targeted route that also isn't in a readable lease shows as MEDIUM
  (below the alert threshold). Add `vpn_endpoints`, or lower `notify_min_severity`, if that matters for you.
- IPv6 routes are analysed the same way, but IPv6 route injection via Router Advertisements is a different attack and isn't specifically detected.
- Detection can't stop the leak that happens in the seconds before an alert is answered. For zero exposure, use a
  firewall-based VPN lockdown or namespace isolation (see the manual steps), and set `auto_action` to `mitigate`.
