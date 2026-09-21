"""Install/uninstall the daemon as an OS service plus an auto-starting per-user agent."""

from __future__ import annotations

import json
import os
from html import escape
import sys
from pathlib import Path

from .config import Config, default_config_path
from .util import IS_LINUX, IS_MACOS, IS_WINDOWS, is_admin, run

PKG_PARENT = str(Path(__file__).resolve().parent.parent)

SYSTEMD_UNIT = "/etc/systemd/system/tunnelvisionvision.service"
XDG_AUTOSTART = "/etc/xdg/autostart/tunnelvisionvision-agent.desktop"
LAUNCHD_DAEMON = "/Library/LaunchDaemons/com.tunnelvisionvision.daemon.plist"
LAUNCHD_AGENT = "/Library/LaunchAgents/com.tunnelvisionvision.agent.plist"
MAC_LOG_DIR = "/Library/Logs/TunnelVisionVision"
WIN_TASK_PATH = "\\TunnelVisionVision\\"


def _write(path: str, content: str, mode: int = 0o644) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content, encoding="utf-8")
    if not IS_WINDOWS:
        os.chmod(path, mode)


def _ensure_config(cfg: Config) -> Path:
    path = default_config_path()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        example = Path(PKG_PARENT) / "config.example.json"
        data = example.read_text(encoding="utf-8") if example.exists() else json.dumps({"poll_interval": 5}, indent=2)
        path.write_text(data, encoding="utf-8")
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    return path


def install(cfg: Config, agent: bool = True) -> list[str]:
    if not is_admin():
        raise SystemExit("install-service must be run as root/Administrator")
    out = [f"config: {_ensure_config(cfg)}"]
    py = sys.executable
    if IS_LINUX:
        out += _install_linux(py, agent)
    elif IS_MACOS:
        out += _install_macos(py, agent)
    elif IS_WINDOWS:
        out += _install_windows(py, agent)
    return out


def uninstall() -> list[str]:
    if not is_admin():
        raise SystemExit("uninstall-service must be run as root/Administrator")
    out = []
    if IS_LINUX:
        run(["systemctl", "disable", "--now", "tunnelvisionvision.service"])
        for p in (SYSTEMD_UNIT, XDG_AUTOSTART):
            if os.path.exists(p):
                os.remove(p)
                out.append(f"removed {p}")
        run(["systemctl", "daemon-reload"])
    elif IS_MACOS:
        uid = _console_uid()
        run(["launchctl", "bootout", "system/com.tunnelvisionvision.daemon"])
        if uid:
            run(["launchctl", "bootout", f"gui/{uid}/com.tunnelvisionvision.agent"])
        for p in (LAUNCHD_DAEMON, LAUNCHD_AGENT):
            if os.path.exists(p):
                os.remove(p)
                out.append(f"removed {p}")
    elif IS_WINDOWS:
        from .platforms.windows import powershell

        run(powershell(f"Get-ScheduledTask -TaskPath '{WIN_TASK_PATH}' -ErrorAction SilentlyContinue | "
                       "ForEach-Object { Stop-ScheduledTask -InputObject $_; Unregister-ScheduledTask -InputObject $_ -Confirm:$false }"))
        out.append("removed scheduled tasks under " + WIN_TASK_PATH)
    return out


# ---------------------------------------------------------------------------------------------
def _install_linux(py: str, agent: bool) -> list[str]:
    _write(SYSTEMD_UNIT, f"""[Unit]
Description=TunnelVisionVision - TunnelVision (CVE-2024-3661) detector
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={py} -m tunnelvisionvision daemon
WorkingDirectory={PKG_PARENT}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""")
    out = [f"wrote {SYSTEMD_UNIT}"]
    if run(["systemctl", "daemon-reload"]).returncode == 0:
        proc = run(["systemctl", "enable", "--now", "tunnelvisionvision.service"])
        out.append("enabled and started tunnelvisionvision.service" if proc.returncode == 0 else f"systemctl failed: {proc.stderr.strip()}")
    else:
        out.append("systemd not available: start `python3 -m tunnelvisionvision daemon` with your init system")
    if agent:
        _write(XDG_AUTOSTART, f"""[Desktop Entry]
Type=Application
Name=TunnelVisionVision Agent
Comment=Shows TunnelVision alerts
Exec=sh -c 'cd "{PKG_PARENT}" && exec "{py}" -m tunnelvisionvision agent'
NoDisplay=true
X-GNOME-Autostart-enabled=true
""")
        out.append(f"wrote {XDG_AUTOSTART} (agent starts at next desktop login; run `tvv agent &` to start it now)")
    return out


def _plist(label: str, args: list[str], extra: str) -> str:
    argxml = "".join(f"<string>{escape(a)}</string>" for a in args)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key><array>{argxml}</array>
  <key>WorkingDirectory</key><string>{escape(PKG_PARENT)}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
{extra}</dict></plist>
"""


def _console_uid() -> str:
    uid = os.environ.get("SUDO_UID")
    if uid:
        return uid
    proc = run(["stat", "-f", "%u", "/dev/console"])
    return proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() != "0" else ""


def _install_macos(py: str, agent: bool) -> list[str]:
    os.makedirs(MAC_LOG_DIR, exist_ok=True)
    _write(LAUNCHD_DAEMON, _plist("com.tunnelvisionvision.daemon", [py, "-m", "tunnelvisionvision", "daemon"],
                                  f"  <key>StandardOutPath</key><string>{MAC_LOG_DIR}/daemon.log</string>\n"
                                  f"  <key>StandardErrorPath</key><string>{MAC_LOG_DIR}/daemon.log</string>\n"))
    run(["launchctl", "bootout", "system/com.tunnelvisionvision.daemon"])
    proc = run(["launchctl", "bootstrap", "system", LAUNCHD_DAEMON])
    out = [f"wrote {LAUNCHD_DAEMON}", "daemon loaded" if proc.returncode == 0 else f"launchctl: {proc.stderr.strip()}"]
    if agent:
        _write(LAUNCHD_AGENT, _plist("com.tunnelvisionvision.agent", [py, "-m", "tunnelvisionvision", "agent"],
                                     "  <key>LimitLoadToSessionType</key><string>Aqua</string>\n"
                                     "  <key>StandardErrorPath</key><string>/tmp/tunnelvisionvision-agent.log</string>\n"))
        out.append(f"wrote {LAUNCHD_AGENT}")
        uid = _console_uid()
        if uid:
            run(["launchctl", "bootout", f"gui/{uid}/com.tunnelvisionvision.agent"])
            proc = run(["launchctl", "bootstrap", f"gui/{uid}", LAUNCHD_AGENT])
            out.append(f"agent loaded for uid {uid}" if proc.returncode == 0 else f"launchctl agent: {proc.stderr.strip()}")
    return out


def _install_windows(py: str, agent: bool) -> list[str]:
    from .platforms.windows import powershell, ps_quote

    pyw = str(Path(py).with_name("pythonw.exe")) if Path(py).with_name("pythonw.exe").exists() else py
    settings = ("$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 "
                "-RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew")
    script = f"""$ErrorActionPreference = 'Stop'
{settings}
$a = New-ScheduledTaskAction -Execute {ps_quote(pyw)} -Argument '-m tunnelvisionvision daemon' -WorkingDirectory {ps_quote(PKG_PARENT)}
$t = New-ScheduledTaskTrigger -AtStartup
$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskPath '{WIN_TASK_PATH}' -TaskName 'Daemon' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
Start-ScheduledTask -TaskPath '{WIN_TASK_PATH}' -TaskName 'Daemon'
"""
    if agent:
        script += f"""$a2 = New-ScheduledTaskAction -Execute {ps_quote(pyw)} -Argument '-m tunnelvisionvision agent' -WorkingDirectory {ps_quote(PKG_PARENT)}
$t2 = New-ScheduledTaskTrigger -AtLogOn
$p2 = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\\Users' -RunLevel Limited
Register-ScheduledTask -TaskPath '{WIN_TASK_PATH}' -TaskName 'Agent' -Action $a2 -Trigger $t2 -Principal $p2 -Settings $s -Force | Out-Null
Start-ScheduledTask -TaskPath '{WIN_TASK_PATH}' -TaskName 'Agent'
"""
    proc = run(powershell(script), timeout=120)
    if proc.returncode != 0:
        raise SystemExit(f"failed to register scheduled tasks: {proc.stderr.strip() or proc.stdout.strip()}")
    return [f"registered scheduled task {WIN_TASK_PATH}Daemon (SYSTEM, at startup)"] + (
        [f"registered scheduled task {WIN_TASK_PATH}Agent (all users, at logon)"] if agent else [])
