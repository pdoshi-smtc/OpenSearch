#!/usr/bin/env python3
"""
JSM Alerts watcher with GUI + notifications + sound + headless + systemd helper.

Features:
 - Polls a JSM/Alerts endpoint every N seconds (default 60)
 - Filters open alerts and optional priority filter (P1,P2,P3)
 - Converts ms epoch "*At" fields to ISO8601 UTC
 - Detects new/updated/closed open alerts vs previous poll
 - Saves snapshot to OUTPUT_FILE each poll
 - Desktop notifications (plyer / notify-send / osascript / powershell fallback)
 - Sound on new/updated alerts (winsound / paplay / aplay / play / bell)
 - Tkinter GUI (table) with improved styling: striping, priority coloring, tinyId column
 - Headless mode, systemd unit helper, manual refresh button in GUI

Usage examples:
  python alerts_watcher.py --poll 60 --priority P1,P2
  python alerts_watcher.py --headless
  python alerts_watcher.py --print-systemd
"""
from __future__ import annotations

import os
import sys
import json
import time
import threading
import queue
import subprocess
import platform
from datetime import datetime, timezone
import argparse
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# GUI imports guarded
try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    import tkinter.font as tkfont
    TK_AVAILABLE = True
except Exception:
    TK_AVAILABLE = False

# Optional extras
try:
    from plyer import notification as plyer_notification
    _HAS_PLYER = True
except Exception:
    _HAS_PLYER = False

try:
    import winsound
    _HAS_WINSOUND = True
except Exception:
    _HAS_WINSOUND = False

load_dotenv()

# ----- Config (env + defaults) -----
JIRA_EMAIL = os.getenv("JIRA_USER_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
JIRA_BASE_URL = os.getenv("JIRA_BASE_URL", "https://sierrawireless.atlassian.net")
ALERTS_ENDPOINT = os.getenv(
    "JIRA_ALERTS_ENDPOINT",
    "/gateway/api/jsm/ops/web/3a7467b6-6c2f-4bfc-a2d9-21020a74bee4/v1/alerts"
)
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "alert.json")
PAGE_LIMIT = int(os.getenv("PAGE_LIMIT", "50"))
MAX_ALERTS = int(os.getenv("MAX_ALERTS_TO_FETCH", "100"))
APPLY_VISIBILITY_FILTER = os.getenv("APPLY_VISIBILITY_FILTER", "false")
DEFAULT_POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))

ENV_PRIORITY_FILTER = os.getenv("PRIORITY_FILTER", "")  # e.g. "P1,P2"
ENABLE_SOUND_ENV = os.getenv("ENABLE_SOUND", "true").lower() in ("1", "true", "yes")
ENABLE_NOTIFY_ENV = os.getenv("ENABLE_NOTIFY", "true").lower() in ("1", "true", "yes")

JQL = os.getenv(
    "JQL_QUERY",
    'status:open AND details.key = "Environment" AND (details.value = "Production" OR details.value = "Operations") '
    'AND tag != "autoclose_maintenance" AND (priority = "P1" OR priority = "P2" OR priority = "P3") '
    'AND NOT (detailsPair("incident-alert-type":"owner") OR detailsPair("incident-alert-type":"responder") OR detailsPair("incident-alert-type":"associated"))'
)

if not JIRA_EMAIL or not JIRA_API_TOKEN:
    print("Please set JIRA_USER_EMAIL and JIRA_API_TOKEN in environment or .env", file=sys.stderr)
    sys.exit(1)

# Global toggles (overridden in main from CLI)
ENABLE_SOUND = ENABLE_SOUND_ENV
ENABLE_NOTIFY = ENABLE_NOTIFY_ENV

# ----- Networking / fetch logic -----
def fetch_batch(offset: int = 0, limit: int = 50):
    url = f"{JIRA_BASE_URL.rstrip('/')}{ALERTS_ENDPOINT}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    params = {
        "sort": "insertedAt",
        "limit": limit,
        "offset": offset,
        "applyVisibilityFilter": APPLY_VISIBILITY_FILTER,
        "jql": JQL
    }
    try:
        resp = requests.get(
            url,
            headers=headers,
            params=params,
            auth=HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN),
            timeout=30
        )
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}", file=sys.stderr)
        return None
    if resp.status_code != 200:
        print(f"HTTP {resp.status_code}: {resp.text[:1000]}", file=sys.stderr)
        return None
    try:
        return resp.json()
    except ValueError as e:
        print(f"Failed to parse JSON: {e}", file=sys.stderr)
        return None

def fetch_all():
    all_alerts = []
    offset = 0
    while len(all_alerts) < MAX_ALERTS:
        remaining = MAX_ALERTS - len(all_alerts)
        cur_limit = min(PAGE_LIMIT, remaining)
        data = fetch_batch(offset=offset, limit=cur_limit)
        if not data:
            break
        alerts = data.get("values") or data.get("alerts") or []
        if not alerts:
            break
        to_add = alerts[:remaining]
        all_alerts.extend(to_add)
        total_count = data.get("count") or data.get("total")
        if total_count is not None:
            try:
                if len(all_alerts) >= int(total_count):
                    break
            except Exception:
                pass
        if len(alerts) < cur_limit:
            break
        offset += cur_limit
        time.sleep(0.2)
    return all_alerts

def save_to_file(alerts):
    payload = {
        "alerts": alerts,
        "metadata": {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "source": f"{JIRA_BASE_URL.rstrip('/')}{ALERTS_ENDPOINT}",
            "total": len(alerts),
            "jql": JQL
        }
    }
    os.makedirs(os.path.dirname(os.path.abspath(OUTPUT_FILE)) or ".", exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

# ----- timestamp helpers -----
def convert_ms_to_utc(ms):
    if not isinstance(ms, (int, float)):
        return ms
    if ms < 0 or ms > 32503680000000:
        return ms
    try:
        return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
    except Exception:
        return ms

def normalize_alert_timestamps(obj):
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if k.endswith("At"):
                obj[k] = convert_ms_to_utc(v)
            else:
                if isinstance(v, (dict, list)):
                    normalize_alert_timestamps(v)
        return obj
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, (dict, list)):
                normalize_alert_timestamps(item)
        return obj
    else:
        return obj

# ----- identity + change detection helpers -----
def alert_identity_and_update_key(alert):
    if not isinstance(alert, dict):
        return None, None
    aid = alert.get("id") or alert.get("alertId") or alert.get("key") or alert.get("uuid")
    if not aid:
        try:
            aid = f"fh-{hash((alert.get('message'), alert.get('createdAt')))}"
        except Exception:
            aid = None
    updated = alert.get("updatedAt") or alert.get("lastUpdated") or alert.get("insertedAt") or alert.get("createdAt")
    return aid, str(updated)

# ----- filtering: open + priority -----
def is_status_open(a):
    if not isinstance(a, dict):
        return False
    st = a.get("alertStatus")
    if st:
        return str(st).lower() == "open"
    st2 = a.get("status")
    if st2:
        return str(st2).lower() == "open"
    return False

def is_priority_allowed(a, allowed_priorities):
    if not allowed_priorities:
        return True
    p = a.get("priority")
    if not p:
        # sometimes priority nested inside dict
        if isinstance(a.get("priority"), dict):
            p2 = a.get("priority").get("name")
            p = p2
    if not p:
        return False
    return str(p).upper() in allowed_priorities

# ----- notifications & sound -----
def notify_desktop(title, message):
    if not ENABLE_NOTIFY:
        return False
    # try plyer first
    if _HAS_PLYER:
        try:
            plyer_notification.notify(title=title, message=message, timeout=6)
            return True
        except Exception:
            pass
    # fallback to OS tools
    try:
        if platform.system() == "Linux":
            subprocess.run(["notify-send", title, message], check=False)
            return True
        if platform.system() == "Darwin":
            cmd = ['osascript', '-e', f'display notification "{message.replace("\"", "\\\"")}" with title "{title.replace("\"", "\\\"")}"']
            subprocess.run(cmd, check=False)
            return True
        if platform.system() == "Windows":
            ps = f'[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime];' \
                 f'$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);' \
                 f'$texts = $template.GetElementsByTagName("text"); $texts.Item(0).AppendChild($template.CreateTextNode("{title}")) | Out-Null; $texts.Item(1).AppendChild($template.CreateTextNode("{message}")) | Out-Null;' \
                 f'$toast = [Windows.UI.Notifications.ToastNotification]::new($template); [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("AlertsWatcher").Show($toast)'
            subprocess.run(["powershell", "-Command", ps], check=False)
            return True
    except Exception:
        pass
    return False

def play_sound():
    if not ENABLE_SOUND:
        return False
    try:
        if _HAS_WINSOUND and platform.system() == "Windows":
            winsound.Beep(750, 300)
            return True
        for cmd in (["paplay", "/usr/share/sounds/freedesktop/stereo/complete.oga"],
                    ["aplay", "/usr/share/sounds/alsa/Front_Center.wav"],
                    ["play", "-nq", "-t", "alsa", "synth", "0.2", "sin", "880"]):
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                return True
            except Exception:
                continue
        print("\a", end="", flush=True)
        return True
    except Exception:
        try:
            print("\a", end="", flush=True)
        except Exception:
            pass
        return False

# ----- Polling + change detection -----
class Poller:
    def __init__(self, out_queue, allowed_priorities=None):
        self.prev_map = {}  # id -> update_key
        self.q = out_queue
        self.lock = threading.Lock()
        self.allowed_priorities = set([p.upper() for p in allowed_priorities]) if allowed_priorities else set()

    def run_once(self):
        try:
            alerts = fetch_all()
            if not alerts:
                return
            open_alerts = [a for a in alerts if is_status_open(a) and is_priority_allowed(a, self.allowed_priorities)]
            for a in open_alerts:
                if isinstance(a, dict):
                    normalize_alert_timestamps(a)

            new_map = {}
            changed_alerts = []
            for a in open_alerts:
                aid, updated_key = alert_identity_and_update_key(a)
                if not aid:
                    changed_alerts.append(a)
                    continue
                new_map[aid] = updated_key
                prev_val = self.prev_map.get(aid)
                if prev_val is None or prev_val != updated_key:
                    changed_alerts.append(a)

            closed_ids = [pid for pid in self.prev_map.keys() if pid not in new_map]

            try:
                save_to_file(open_alerts)
            except Exception as e:
                print(f"Warning: failed to save file: {e}", file=sys.stderr)

            with self.lock:
                self.prev_map = new_map

            if changed_alerts or closed_ids:
                payload = {
                    "alerts": open_alerts,
                    "changed": changed_alerts,
                    "closed_ids": closed_ids,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                try:
                    self.q.put_nowait(payload)
                except queue.Full:
                    pass

                try:
                    play_sound()
                except Exception:
                    pass

                try:
                    title = f"Alerts: {len(changed_alerts)} new/updated • {len(closed_ids)} closed"
                    msg_lines = []
                    for a in (changed_alerts[:5] or []):
                        m = (a.get("message") or a.get("summary") or "").strip()
                        created = a.get("createdAt") or ""
                        msg_lines.append(f"{m[:120]} [{created}]")
                    message = "\n".join(msg_lines) if msg_lines else f"{len(open_alerts)} open alerts"
                    notify_desktop(title, message)
                except Exception:
                    pass
        except Exception as e:
            print(f"Poll error: {e}", file=sys.stderr)

    def start_periodic(self, interval_seconds):
        def worker():
            while True:
                self.run_once()
                time.sleep(interval_seconds)
        t = threading.Thread(target=worker, daemon=True)
        t.start()

# # ----- Styling helper for ttk -----
# def setup_ttk_style(root):
#     if not TK_AVAILABLE:
#         return
#     style = ttk.Style(root)
#     try:
#         # prefer current/native theme
#         style.theme_use(style.theme_use())
#     except Exception:
#         try:
#             style.theme_use("clam")
#         except Exception:
#             pass

#     header_font = tkfont.nametofont("TkHeadingFont") if "TkHeadingFont" in tkfont.names() else tkfont.Font(weight="bold", size=10)
#     body_font = tkfont.nametofont("TkTextFont") if "TkTextFont" in tkfont.names() else tkfont.Font(size=10)

#     header_font.configure(weight="bold", size=10)
#     body_font.configure(size=10)

#     style.configure("Treeview",
#                     font=body_font,
#                     rowheight=26,
#                     fieldbackground="#f6f8fa",
#                     background="#ffffff")
#     style.configure("Treeview.Heading",
#                     font=header_font,
#                     relief="flat",
#                     background="#f0f0f0")
#     style.map("Treeview.Heading",
#               relief=[("active", "raised")])

#     style.map("Treeview",
#               background=[("selected", "#cfefff")],
#               foreground=[("selected", "#000000")])

#     style.configure("Status.TLabel", background="#f0f0f0", padding=(6,4))

# # ----- Tkinter GUI (only used if not headless) -----
# class AlertGUI:
#     def __init__(self, root, q):
#         self.root = root
#         self.q = q
#         root.title("Open Alerts")
#         root.geometry("1000x520")
#         root.minsize(800, 320)

#         setup_ttk_style(root)

#         columns = ("tinyId", "message", "createdAt", "status", "priority")
#         self.tree = ttk.Treeview(root, columns=columns, show="headings", selectmode="browse")

#         headings = [
#             ("tinyId", "Tiny ID", 120),
#             ("message", "Message", 520),
#             ("createdAt", "CreatedAt (UTC)", 180),
#             ("status", "Status", 90),
#             ("priority", "Priority", 80),
#         ]
#         for col, label, width in headings:
#             self.tree.heading(col, text=label, anchor="w")
#             self.tree.column(col, width=width, anchor="w", stretch=(col != "tinyId"))

#         # Tags for striping and priority coloring
#         self.tree.tag_configure("oddrow", background="#ffffff")
#         self.tree.tag_configure("evenrow", background="#fbfbfb")
#         self.tree.tag_configure("prio-P1", background="#ffecec")
#         self.tree.tag_configure("prio-P2", background="#fff8e6")
#         self.tree.tag_configure("prio-P3", background="#eefaf0")

#         vsb = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
#         hsb = ttk.Scrollbar(root, orient="horizontal", command=self.tree.xview)
#         self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

#         frame = ttk.Frame(root, padding=(8,8,8,4))
#         frame.grid(row=0, column=0, sticky="nsew")
#         self.tree.grid(row=0, column=0, sticky="nsew", in_=frame)
#         vsb.grid(row=0, column=1, sticky="ns", in_=frame)
#         hsb.grid(row=1, column=0, columnspan=2, sticky="ew", in_=frame)

#         frame.grid_rowconfigure(0, weight=1)
#         frame.grid_columnconfigure(0, weight=1)
#         root.grid_rowconfigure(0, weight=1)
#         root.grid_columnconfigure(0, weight=1)

#         status_frame = ttk.Frame(root)
#         status_frame.grid(row=1, column=0, sticky="we", padx=8, pady=(0,8))
#         self.status_var = tk.StringVar(value="Starting...")
#         status_label = ttk.Label(status_frame, textvariable=self.status_var, style="Status.TLabel", anchor="w")
#         status_label.pack(fill="x", expand=True)

#         ctrl_frame = ttk.Frame(root)
#         ctrl_frame.grid(row=2, column=0, sticky="we", padx=8, pady=(0,8))
#         ctrl_frame.columnconfigure(0, weight=1)
#         ctrl_frame.columnconfigure(1, weight=0)
#         legend = ttk.Label(ctrl_frame, text="Legend: P1 (critical) • P2 (high) • P3 (normal)  — Double-click a row to open in browser", anchor="w")
#         legend.grid(row=0, column=0, sticky="w")
#         reload_btn = ttk.Button(ctrl_frame, text="Refresh Now", command=lambda: self.q.put({"manual_refresh": True}))
#         reload_btn.grid(row=0, column=1, sticky="e", padx=(8,0))

#         self.tree.bind("<Double-1>", self.on_row_double_click)

#         self.root.withdraw()
#         self.root.after(800, self.check_queue)

#     def on_row_double_click(self, event):
#         item = self.tree.focus()
#         if not item:
#             return
#         vals = self.tree.item(item, "values")
#         tiny = vals[0] if vals else None
#         try:
#             if hasattr(self, "_alert_lookup") and tiny in self._alert_lookup:
#                 a = self._alert_lookup[tiny]
#                 url = a.get("alertUrl") or a.get("url") or a.get("link") or a.get("jiraUrl")
#                 if url:
#                     import webbrowser
#                     webbrowser.open(url)
#         except Exception:
#             pass

#     def check_queue(self):
#         updated = False
#         try:
#             while True:
#                 payload = self.q.get_nowait()
#                 if isinstance(payload, dict) and payload.get("manual_refresh"):
#                     # manual refresh: nothing special here because poller runs periodically.
#                     # We could trigger an immediate poll by other mechanisms; for now just continue.
#                     continue
#                 alerts = payload.get("alerts", [])
#                 changed = payload.get("changed", [])
#                 closed = payload.get("closed_ids", [])
#                 ts = payload.get("timestamp")
#                 self.update_table(alerts)
#                 if changed:
#                     msg = f"{len(changed)} new/updated, {len(closed)} closed — last update {ts}"
#                 else:
#                     msg = f"No changes, {len(alerts)} open alerts — last update {ts}"
#                 self.status_var.set(msg)
#                 updated = True
#         except queue.Empty:
#             pass

#         if updated:
#             if len(self.tree.get_children()) > 0:
#                 try:
#                     self.root.deiconify()
#                     self.root.lift()
#                 except Exception:
#                     pass
#             else:
#                 self.root.withdraw()

#         self.root.after(800, self.check_queue)

#     def update_table(self, alerts):
#         self._alert_lookup = {}
#         for row in self.tree.get_children():
#             self.tree.delete(row)

#         def created_key(a):
#             v = a.get("createdAt") or a.get("insertedAt") or ""
#             return str(v)

#         alerts_sorted = sorted(alerts, key=created_key, reverse=True)
#         for idx, a in enumerate(alerts_sorted):
#             tiny = str(a.get("tinyId") or a.get("id") or a.get("alertId") or f"t-{idx}")
#             msg = (a.get("message") or a.get("summary") or a.get("description") or "").strip()
#             created = a.get("createdAt") or a.get("insertedAt") or ""
#             status = a.get("alertStatus") or a.get("status") or ""
#             priority = a.get("priority") or ""
#             if isinstance(priority, dict):
#                 prio_val = (priority.get("name") or "").upper()
#             else:
#                 prio_val = str(priority).upper()
#             prio_tag = None
#             if prio_val == "P1":
#                 prio_tag = "prio-P1"
#             elif prio_val == "P2":
#                 prio_tag = "prio-P2"
#             elif prio_val == "P3":
#                 prio_tag = "prio-P3"
#             row_tag = prio_tag or ("evenrow" if idx % 2 == 0 else "oddrow")
#             self.tree.insert("", "end", values=(tiny, msg, created, status, priority), tags=(row_tag,))
#             self._alert_lookup[tiny] = a

# --------------------------
# Replace existing style + AlertGUI with this
# --------------------------
import tkinter.font as tkfont  # ensure import at top if not already

def setup_ttk_style(root):
    if not TK_AVAILABLE:
        return
    style = ttk.Style(root)
    # try to keep native theme, fallback to clam
    try:
        style.theme_use(style.theme_use())
    except Exception:
        try:
            style.theme_use("clam")
        except Exception:
            pass

    # fonts
    try:
        header_font = tkfont.nametofont("TkHeadingFont")
    except Exception:
        header_font = tkfont.Font(weight="bold", size=10)
    try:
        body_font = tkfont.nametofont("TkTextFont")
    except Exception:
        body_font = tkfont.Font(size=10)

    header_font.configure(weight="bold", size=10)
    body_font.configure(size=10)

    style.configure("Treeview",
                    font=body_font,
                    rowheight=26,
                    background="#ffffff",
                    fieldbackground="#ffffff")
    style.configure("Treeview.Heading",
                    font=header_font,
                    background="#f0f0f0",
                    relief="flat")
    style.map("Treeview",
              background=[("selected", "#cfefff")],
              foreground=[("selected", "#000000")])

    style.configure("Status.TLabel", background="#f0f0f0", padding=(6,4))

class AlertGUI:
    def __init__(self, root, q):
        self.root = root
        self.q = q
        root.title("Open Alerts")
        root.geometry("1000x520")
        root.minsize(800, 320)

        # ensure style exists
        setup_ttk_style(root)

        # container frame (fills the window)
        self.frame = ttk.Frame(root, padding=(8,8))
        self.frame.grid(row=0, column=0, sticky="nsew")
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(0, weight=1)

        # Treeview + scrollbars
        columns = ("tinyId", "message", "createdAt", "status", "priority")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings", selectmode="browse")

        headings = [
            ("tinyId", "Tiny ID", 120),
            ("message", "Message", 520),
            ("createdAt", "CreatedAt (UTC)", 180),
            ("status", "Status", 90),
            ("priority", "Priority", 80),
        ]
        for col, label, width in headings:
            self.tree.heading(col, text=label, anchor="w")
            self.tree.column(col, width=width, anchor="w", minwidth=50, stretch=(col != "tinyId"))

        # tags for striping + priority colors
        self.tree.tag_configure("oddrow", background="#ffffff")
        self.tree.tag_configure("evenrow", background="#fbfbfb")
        self.tree.tag_configure("prio-P1", background="#ffecec")
        self.tree.tag_configure("prio-P2", background="#fff8e6")
        self.tree.tag_configure("prio-P3", background="#eefaf0")

        vsb = ttk.Scrollbar(self.frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self.frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        # grid them properly inside frame
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, columnspan=2, sticky="ew")

        # allow frame to expand
        self.frame.grid_rowconfigure(0, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)

        # status bar below
        self.status_var = tk.StringVar(value="Waiting for data...")
        status_label = ttk.Label(root, textvariable=self.status_var, style="Status.TLabel", anchor="w")
        status_label.grid(row=1, column=0, sticky="we", padx=8, pady=(0,8))

        # control row: legend + refresh
        ctrl_frame = ttk.Frame(root)
        ctrl_frame.grid(row=2, column=0, sticky="we", padx=8, pady=(0,8))
        ctrl_frame.columnconfigure(0, weight=1)
        legend = ttk.Label(ctrl_frame, text="Legend: P1 (critical) • P2 (high) • P3 (normal)  — Double-click a row to open in browser", anchor="w")
        legend.grid(row=0, column=0, sticky="w")
        reload_btn = ttk.Button(ctrl_frame, text="Refresh Now", command=lambda: self.q.put({"manual_refresh": True}))
        reload_btn.grid(row=0, column=1, sticky="e", padx=(8,0))

        # double-click handler
        self.tree.bind("<Double-1>", self.on_row_double_click)

        # lookup for opening urls
        self._alert_lookup = {}

        # schedule the queue checker
        self.root.after(500, self.check_queue)

    def on_row_double_click(self, event):
        item = self.tree.focus()
        if not item:
            return
        vals = self.tree.item(item, "values")
        tiny = vals[0] if vals else None
        try:
            if tiny and tiny in self._alert_lookup:
                a = self._alert_lookup[tiny]
                url = a.get("alertUrl") or a.get("url") or a.get("link") or a.get("jiraUrl")
                if url:
                    import webbrowser
                    webbrowser.open(url)
        except Exception:
            pass

    def check_queue(self):
        updated = False
        try:
            while True:
                payload = self.q.get_nowait()
                if isinstance(payload, dict) and payload.get("manual_refresh"):
                    # nothing to do here; poller already running
                    continue
                alerts = payload.get("alerts", [])
                changed = payload.get("changed", [])
                closed = payload.get("closed_ids", [])
                ts = payload.get("timestamp")
                self.update_table(alerts)
                if changed:
                    msg = f"{len(changed)} new/updated, {len(closed)} closed — last update {ts}"
                else:
                    msg = f"No changes, {len(alerts)} open alerts — last update {ts}"
                self.status_var.set(msg)
                updated = True
        except queue.Empty:
            pass

        # ensure visibility if updated
        if updated:
            if len(self.tree.get_children()) > 0:
                try:
                    self.root.deiconify()
                    self.root.lift()
                except Exception:
                    pass
            else:
                # show window but indicate empty table
                try:
                    self.root.deiconify()
                    self.root.lift()
                except Exception:
                    pass

        self.root.after(500, self.check_queue)

    def update_table(self, alerts):
        # rebuild lookup & rows
        self._alert_lookup = {}
        # clear existing
        for row in self.tree.get_children():
            self.tree.delete(row)

        def created_key(a):
            return str(a.get("createdAt") or a.get("insertedAt") or "")

        alerts_sorted = sorted(alerts, key=created_key, reverse=True)
        for idx, a in enumerate(alerts_sorted):
            tiny = str(a.get("tinyId") or a.get("id") or a.get("alertId") or f"t-{idx}")
            msg = (a.get("message") or a.get("summary") or a.get("description") or "").strip()
            created = a.get("createdAt") or a.get("insertedAt") or ""
            status = a.get("alertStatus") or a.get("status") or ""
            priority = a.get("priority") or ""
            if isinstance(priority, dict):
                prio_val = (priority.get("name") or "").upper()
            else:
                prio_val = str(priority).upper()
            if prio_val == "P1":
                prio_tag = "prio-P1"
            elif prio_val == "P2":
                prio_tag = "prio-P2"
            elif prio_val == "P3":
                prio_tag = "prio-P3"
            else:
                prio_tag = "evenrow" if idx % 2 == 0 else "oddrow"
            self.tree.insert("", "end", values=(tiny, msg, created, status, priority), tags=(prio_tag,))
            self._alert_lookup[tiny] = a

        # force the GUI to show & update immediately if there are rows
        if self.tree.get_children():
            try:
                self.root.deiconify()
                self.root.update_idletasks()
            except Exception:
                pass
        else:
            # update status to indicate empty
            self.status_var.set("No open alerts")


# ----- systemd unit helper -----
SYSTEMD_UNIT_TEMPLATE = """[Unit]
Description=JSM Alerts Watcher
After=network.target

[Service]
User={user}
WorkingDirectory={cwd}
ExecStart={python} {script} --headless --poll {poll}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

def print_systemd_unit(script_path, poll_interval):
    print(SYSTEMD_UNIT_TEMPLATE.format(
        user=os.getenv("USER") or os.getenv("USERNAME") or "root",
        cwd=os.path.abspath(os.path.dirname(script_path)),
        python=sys.executable,
        script=os.path.abspath(script_path),
        poll=poll_interval
    ))

# ----- CLI parsing and main -----
def main():
    global ENABLE_SOUND, ENABLE_NOTIFY
    parser = argparse.ArgumentParser(description="JSM Alerts watcher")
    parser.add_argument("--headless", action="store_true", help="Run without GUI")
    parser.add_argument("--poll", type=int, default=DEFAULT_POLL_INTERVAL, help="Poll interval seconds")
    parser.add_argument("--priority", type=str, default=ENV_PRIORITY_FILTER, help="Comma-separated priorities to include (e.g. P1,P2)")
    parser.add_argument("--no-sound", action="store_true", help="Disable sound")
    parser.add_argument("--no-notify", action="store_true", help="Disable desktop notifications")
    parser.add_argument("--print-systemd", action="store_true", help="Print a sample systemd service unit")
    args = parser.parse_args()

    ENABLE_SOUND = ENABLE_SOUND_ENV and not args.no_sound
    ENABLE_NOTIFY = ENABLE_NOTIFY_ENV and not args.no_notify

    if args.print_systemd:
        print_systemd_unit(__file__, args.poll)
        return

    allowed_priorities = [p.strip().upper() for p in (args.priority or "").split(",") if p.strip()] or None

    q = queue.Queue(maxsize=8)
    poller = Poller(q, allowed_priorities=allowed_priorities)
    poller.start_periodic(args.poll)

    threading.Thread(target=poller.run_once, daemon=True).start()

    if args.headless:
        print("Running in headless mode. Polling every", args.poll, "seconds.")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("Exiting (headless).")
            return

    if not TK_AVAILABLE:
        print("Tkinter not available on this system; use --headless to run without GUI.", file=sys.stderr)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return

    try:
        root = tk.Tk()
    except Exception as e:
        print(f"Failed to start Tkinter: {e}", file=sys.stderr)
        print("Use --headless to run without GUI.")
        return

    gui = AlertGUI(root, q)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("Exiting...")

if __name__ == "__main__":
    main()
