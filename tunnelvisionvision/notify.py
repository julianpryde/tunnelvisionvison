"""User-facing notifications and the Mitigate / Disconnect / Continue prompt, per OS."""

from __future__ import annotations

import html
import sys
import threading
from typing import Optional

from .util import IS_LINUX, IS_MACOS, IS_WINDOWS, have, log, run

TITLE = "TunnelVision attack may be in progress"
BTN_MITIGATE = "Mitigate"
BTN_DISCONNECT = "Disconnect network"
BTN_CONTINUE = "Continue (stay vulnerable)"


def alert_text(alert: dict, max_findings: int = 6) -> str:
    fs = alert.get("findings", [])
    lines = [
        f"Severity: {alert.get('severity')}   VPN: {', '.join(alert.get('vpn_interfaces') or []) or 'none'}",
        "",
        "Your VPN appears connected, but this network has changed your routing so some traffic may leave OUTSIDE the "
        "encrypted tunnel (CVE-2024-3661, rogue DHCP option 121).",
        "",
    ]
    for f in fs[:max_findings]:
        lines.append(f"• [{f['severity']}] {f['title']}")
        for e in f.get("evidence", [])[:3]:
            lines.append(f"     - {e}")
    if len(fs) > max_findings:
        lines.append(f"• ... and {len(fs) - max_findings} more")
    lines += [
        "",
        f"{BTN_MITIGATE}: remove the rogue routes " + ("(automatic)" if alert.get("mitigable") else "(manual steps will be shown)"),
        f"{BTN_DISCONNECT}: shut down the Wi-Fi/Ethernet connection now",
        f"{BTN_CONTINUE}: keep working; the traffic above is not protected",
    ]
    return "\n".join(lines)


def result_text(result: dict) -> str:
    lines = [f"Action: {result.get('action')} — {'OK' if result.get('ok') else 'needs attention'}", ""]
    lines += [f"• {l}" for l in result.get("log", [])]
    steps = result.get("manual_steps") or []
    if steps:
        lines += ["", "Recommended next steps:"]
        lines += [f"{i}. {s}" for i, s in enumerate(steps, 1)]
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------
def notify(title: str, message: str) -> None:
    """Non-blocking desktop notification (best effort)."""
    try:
        if IS_MACOS:
            run(["osascript", "-e", f"display notification {_as(message)} with title {_as(title)} sound name \"Basso\""], timeout=10)
        elif IS_LINUX and have("notify-send"):
            run(["notify-send", "-u", "critical", "-a", "TunnelVisionVision", title, message], timeout=10)
    except Exception as e:
        log.debug("notify failed: %s", e)


def prompt(alert: dict, timeout: float = 0) -> Optional[str]:
    """Ask the user what to do. Returns 'mitigate' | 'disconnect' | 'continue' | None (no answer / no UI)."""
    text = alert_text(alert)
    for fn in _prompt_backends():
        try:
            choice = fn(text, timeout)
        except Exception as e:
            log.debug("prompt backend %s failed: %s", fn.__name__, e)
            continue
        if choice != "unavailable":
            return choice
    return None


def show_result(result: dict) -> None:
    text = result_text(result)
    try:
        if IS_MACOS:
            run(["osascript", "-e", f"display dialog {_as(text)} with title \"TunnelVisionVision\" buttons {{\"OK\"}} default button 1"], timeout=3600)
            return
        if IS_LINUX and have("zenity"):
            run(["zenity", "--info", "--title=TunnelVisionVision", "--width=640", f"--text={html.escape(text)}"], timeout=3600)
            return
        if IS_LINUX and have("kdialog"):
            run(["kdialog", "--title", "TunnelVisionVision", "--msgbox", text], timeout=3600)
            return
        if _tk_available():
            _tk_message(text)
            return
        if IS_WINDOWS:
            _win_msgbox(text, "OK")
            return
    except Exception as e:
        log.debug("show_result failed: %s", e)
    print(text, file=sys.stderr)


# ---------------------------------------------------------------------------------------------
def _prompt_backends():
    if IS_MACOS:
        return [_prompt_osascript, _prompt_tk, _prompt_terminal]
    if IS_WINDOWS:
        return [_prompt_tk, _prompt_win_msgbox, _prompt_terminal]
    return [_prompt_zenity, _prompt_kdialog, _prompt_tk, _prompt_terminal]


def _as(s: str) -> str:
    """AppleScript string literal."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _prompt_osascript(text: str, timeout: float) -> Optional[str]:
    script = (f"display dialog {_as(text)} with title {_as(TITLE)} with icon caution "
              f"buttons {{{_as(BTN_CONTINUE)}, {_as(BTN_DISCONNECT)}, {_as(BTN_MITIGATE)}}} default button {_as(BTN_MITIGATE)}")
    if timeout:
        script += f" giving up after {int(timeout)}"
    proc = run(["osascript", "-e", script], timeout=(timeout or 86400) + 30)
    if proc.returncode != 0:
        return "unavailable" if "execution error" in proc.stderr and "-128" not in proc.stderr else None
    return _map_button(proc.stdout)


def _prompt_zenity(text: str, timeout: float) -> Optional[str]:
    if not have("zenity"):
        return "unavailable"
    cmd = ["zenity", "--question", f"--title={TITLE}", "--width=640", f"--text={html.escape(text)}",
           f"--ok-label={BTN_MITIGATE}", f"--cancel-label={BTN_CONTINUE}", f"--extra-button={BTN_DISCONNECT}", "--icon-name=dialog-warning"]
    if timeout:
        cmd.append(f"--timeout={int(timeout)}")
    proc = run(cmd, timeout=(timeout or 86400) + 30)
    if proc.returncode == 0:
        return "mitigate"
    if proc.returncode == 1:
        return "disconnect" if BTN_DISCONNECT in proc.stdout else "continue"
    if proc.returncode == 5:
        return None
    return "unavailable"  # e.g. no display


def _prompt_kdialog(text: str, timeout: float) -> Optional[str]:
    if not have("kdialog"):
        return "unavailable"
    proc = run(["kdialog", "--title", TITLE, "--warningyesnocancel", text, "--yes-label", BTN_MITIGATE,
                "--no-label", BTN_DISCONNECT, "--cancel-label", BTN_CONTINUE], timeout=(timeout or 86400) + 30)
    return {0: "mitigate", 1: "disconnect", 2: "continue"}.get(proc.returncode, "unavailable")


def _tk_available() -> bool:
    try:
        import tkinter  # noqa: F401

        return True
    except Exception:
        return False


def _prompt_tk(text: str, timeout: float) -> Optional[str]:
    if not _tk_available():
        return "unavailable"
    import tkinter as tk

    try:
        root = tk.Tk()
    except tk.TclError:
        return "unavailable"
    choice: list[Optional[str]] = [None]
    root.title(TITLE)
    root.attributes("-topmost", True)
    tk.Label(root, text=text, justify="left", anchor="w", wraplength=640, padx=16, pady=12).pack(fill="both")
    frame = tk.Frame(root, pady=10)
    frame.pack()

    def pick(v):
        choice[0] = v
        root.destroy()

    tk.Button(frame, text=BTN_MITIGATE, command=lambda: pick("mitigate"), default="active").pack(side="left", padx=6)
    tk.Button(frame, text=BTN_DISCONNECT, command=lambda: pick("disconnect")).pack(side="left", padx=6)
    tk.Button(frame, text=BTN_CONTINUE, command=lambda: pick("continue")).pack(side="left", padx=6)
    root.protocol("WM_DELETE_WINDOW", lambda: pick(None))
    if timeout:
        root.after(int(timeout * 1000), lambda: pick(None))
    root.mainloop()
    return choice[0]


def _tk_message(text: str) -> None:
    import tkinter as tk

    root = tk.Tk()
    root.title("TunnelVisionVision")
    root.attributes("-topmost", True)
    tk.Label(root, text=text, justify="left", anchor="w", wraplength=700, padx=16, pady=12).pack(fill="both")
    tk.Button(root, text="OK", command=root.destroy).pack(pady=10)
    root.mainloop()


def _win_msgbox(text: str, buttons: str) -> str:
    from .platforms.windows import powershell, ps_quote

    script = ("Add-Type -AssemblyName System.Windows.Forms; "
              f"[System.Windows.Forms.MessageBox]::Show({ps_quote(text)}, {ps_quote(TITLE)}, '{buttons}', 'Warning')")
    return run(powershell(script), timeout=86400).stdout.strip()


def _prompt_win_msgbox(text: str, timeout: float) -> Optional[str]:
    if not IS_WINDOWS:
        return "unavailable"
    text += f"\n\nYes = {BTN_MITIGATE}    No = {BTN_DISCONNECT}    Cancel = {BTN_CONTINUE}"
    return {"Yes": "mitigate", "No": "disconnect", "Cancel": "continue"}.get(_win_msgbox(text, "YesNoCancel"), "unavailable")


def _prompt_terminal(text: str, timeout: float) -> Optional[str]:
    if not sys.stdin or not sys.stdin.isatty():
        return "unavailable"
    print("\a\n" + "=" * 72 + f"\n{TITLE}\n" + "=" * 72 + f"\n{text}\n", file=sys.stderr)
    answer: list[Optional[str]] = [None]

    def ask():
        try:
            answer[0] = input("[m]itigate / [d]isconnect / [c]ontinue > ").strip().lower()
        except EOFError:
            pass

    t = threading.Thread(target=ask, daemon=True)
    t.start()
    t.join(timeout or None)
    return {"m": "mitigate", "d": "disconnect", "c": "continue"}.get((answer[0] or "")[:1])


def _map_button(out: str) -> Optional[str]:
    if "gave up:true" in out:
        return None
    if BTN_MITIGATE in out:
        return "mitigate"
    if BTN_DISCONNECT in out:
        return "disconnect"
    if BTN_CONTINUE in out:
        return "continue"
    return None
