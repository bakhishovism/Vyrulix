"""
Vyrulix - Bare-Metal Desktop Malware Triage & Forensic Analyzer GUI (main.py)
Principal Security Architect Refactor:
  1. Non-Blocking Asynchronous UI/UX Synchronization:
     - Tracks real-time file availability on disk (`os.path.isfile`), active I/O worker states
       (`is_scanning`, `is_uploading_vt`, `is_detonating_sandbox`), and VirusTotal HTTP 404
       responses (`vt_uncataloged_404`) to dynamically toggle Upload and Sandbox Detonation states.
     - Executes all file scanning, cloud intelligence lookups, VirusTotal uploads, 15-second
       Windows Sandbox (`.wsb`) detonations, YARA ruleset syncs, and online community syncs
       on background worker threads communicating strictly via `self.ui_queue`.
  2. Bare-Metal Forensic Visualization (`DETAILS` & `BEHAVIOR / PE` Panes):
     - Renders Zero-Copy Native PE Header metadata (`MapViewOfFile` / `mmap`), IAT starvation,
       Export Table reflective loader indicators, and pre-entry-point TLS Callbacks (`T1055.005`).
     - Renders the first 100 disassembled instructions at `AddressOfEntryPoint` (Capstone Engine)
       alongside flagged compiler stubs, unpacker loops, and self-modifying code (SMC) anomalies.
     - Displays `MD5`, `SHA-1`, `SHA-256`, `ImpHash`, `ssdeep` (CTPH), `TLSH` (Locality Hash),
       99%-precision variant clusters, and 15-second Windows Sandbox TCP/UDP + child-drop telemetry.
  3. Previous Architecture & Upgrades:
  1. Rebranded to `Vyrulix` (`VyrulixApp`, `VYRULIX_NOTIFY_TITLE`).
  2. Enhanced Authentication UI:
     - Sign-Up: Username, Email Address, Password, Confirm Password, Role, and
       6-digit confirmation email dispatch notification.
     - Sign-In: "Username or Email" + Password.
     - Show/Hide Password Toggle ("👁" button) alongside every password entry field.
  3. High-DPI Scaling in `ScoreRingGauge` via `ctk.ScalingTracker.get_widget_scaling(self)`.
  4. Sequential Auto-Scan Queue (`self.pending_auto_files = collections.deque()`) &
     live filter-mode synchronization (`self.auto_watcher.mode = mode`).
"""

from __future__ import annotations

import collections
import ctypes
import multiprocessing
import os
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog
from typing import Any, Deque, Dict, List, Optional, Tuple

import customtkinter as ctk

try:
    from plyer import notification as plyer_notification  # type: ignore

    PLYER_AVAILABLE = True
except ImportError:
    plyer_notification = None
    PLYER_AVAILABLE = False

from community import CommunityManager, VALID_VERDICTS
from scanner import (
    VyrulixScanner,
    PACKED_ENTROPY_THRESHOLD,
    RealtimeDirectoryWatcher,
    ScanReport,
    ensure_default_yara_rules_file,
    load_vyrulix_config,
    save_vyrulix_config,
)

# Strict Cross-Platform Guard for Win32 GDI / DWM APIs
IS_WINDOWS_WIN32: bool = bool(sys.platform == "win32" and hasattr(ctypes, "windll"))

# Dark Slate Color Palette
VT_BG_MAIN = "#111521"       # Primary deep slate background
VT_BG_SURFACE = "#171C2B"    # Card / panel background
VT_BG_ELEVATED = "#1E2538"   # Header / navbar / row background
VT_BORDER = "#283149"        # Subtle 1px divider
VT_BLUE = "#3B82F6"          # Primary blue accent
VT_BLUE_HOVER = "#2563EB"
VT_TEXT_PRIMARY = "#F1F5F9"
VT_TEXT_MUTED = "#94A3B8"
VT_GREEN = "#10B981"         # Safe / Undetected
VT_AMBER = "#F59E0B"         # Suspicious
VT_RED = "#EF4444"           # Malicious / Stop
VT_GREY = "#64748B"          # Neutral Unknown / No Prior Intelligence

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Static constant PowerShell script reading strictly from environment variables (Zero string interpolation)
STATIC_POWERSHELL_BALLOON_SCRIPT = (
    "Add-Type -AssemblyName System.Windows.Forms; "
    "$n = New-Object System.Windows.Forms.NotifyIcon; "
    "$n.Icon = [System.Drawing.SystemIcons]::Information; "
    "$n.Visible = $true; "
    "$n.ShowBalloonTip(5000, $env:VYRULIX_NOTIFY_TITLE, $env:VYRULIX_NOTIFY_BODY, "
    "[System.Windows.Forms.ToolTipIcon]::Info); "
    "Start-Sleep -Seconds 5; $n.Dispose()"
)


def _is_live_tk_widget(widget: Any, require_mapped: bool = False) -> bool:
    """
    Safely verifies that a Tkinter/CustomTkinter widget reference has not been
    destroyed (`winfo_exists() == 1`) and optionally that it is currently mapped
    on screen (`winfo_ismapped() == 1`) before issuing any HWND or canvas operation.
    """
    if widget is None:
        return False
    try:
        if not int(widget.winfo_exists()):
            return False
        if require_mapped and not int(widget.winfo_ismapped()):
            return False
        return True
    except (tk.TclError, RuntimeError, AttributeError, Exception):
        return False


def apply_windows_dwm_dark_mode(window: tk.Misc) -> None:
    """Applies Windows 10/11 DWM dark titlebar attribute safely (no-op on macOS/Linux)."""
    if not IS_WINDOWS_WIN32 or not _is_live_tk_widget(window, require_mapped=False):
        return
    try:
        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return
        raw_id = int(window.winfo_id() or 0)
        if raw_id <= 0:
            return
        hwnd = windll.user32.GetParent(ctypes.c_void_p(raw_id)) or raw_id
        if not hwnd or not windll.user32.IsWindow(ctypes.c_void_p(hwnd)):
            return
        dark_mode = ctypes.c_int(1)
        windll.dwmapi.DwmSetWindowAttribute(
            ctypes.c_void_p(hwnd), 20, ctypes.byref(dark_mode), ctypes.sizeof(dark_mode)
        )
    except Exception:
        pass


def _resolve_ctk_color(color_val: Any, fallback: str = VT_BG_SURFACE) -> str:
    """Extracts the active dark-mode hex color string from a CustomTkinter color attribute."""
    if isinstance(color_val, (tuple, list)) and len(color_val) >= 2:
        c = str(color_val[1])
    elif isinstance(color_val, str):
        c = color_val
    else:
        return fallback
    if c in ("transparent", "", "system"):
        return fallback
    return c


def apply_rounded_hwnd_clip(widget: tk.Misc, force: bool = False) -> None:
    """
    Hardened, GDI-leak-free rounded corner clipping for Windhawk Translucent Windows:
      - Verifies `_is_live_tk_widget(t, require_mapped=True)` and Win32 `user32.IsWindow(hwnd)`
        so destroyed or unmapped canvas/frame widgets never trigger invalid HWND operations.
      - Caches `(hwnd, width, height, diameter)` on each target widget so `CreateRoundRectRgn`
        is only invoked when geometry or HWND state actually changes.
      - Wraps `CreateRoundRectRgn` + `SetWindowRgn` in an explicit `try ... finally` ownership
        guard (`rgn_owned_by_os`): per Microsoft Win32 specifications, the OS assumes ownership
        of `hrgn` ONLY when `SetWindowRgn` returns non-zero. If `SetWindowRgn` returns `0` or
        raises an exception, `gdi32.DeleteObject(hrgn)` is guaranteed to execute.
    """
    if not _is_live_tk_widget(widget, require_mapped=False):
        return
    # Never apply SetWindowRgn to CTkTextbox or CTkScrollableFrame (or their internal
    # text/canvas children) because clipping their parent/canvas HWND clips child
    # tk.Text / scrollable frame HWNDs and renders them blank in compiled PyInstaller builds.
    if isinstance(widget, (ctk.CTkTextbox, ctk.CTkScrollableFrame)):
        return
    try:
        radius = getattr(widget, "_corner_radius", 0)
        canvas = getattr(widget, "_canvas", None)
        if canvas is not None and _is_live_tk_widget(canvas, require_mapped=False):
            try:
                canvas.configure(highlightthickness=0, bd=0, relief="flat")
            except tk.TclError:
                return

        if not isinstance(radius, (int, float)) or radius <= 0:
            return

        fg_raw = getattr(widget, "_fg_color", VT_BG_SURFACE)
        border_w = getattr(widget, "_border_width", 0)
        border_raw = getattr(widget, "_border_color", fg_raw)
        fill_hex = _resolve_ctk_color(fg_raw, VT_BG_SURFACE)
        edge_hex = _resolve_ctk_color(border_raw, fill_hex) if border_w and border_w > 0 else fill_hex

        if canvas is not None and _is_live_tk_widget(canvas, require_mapped=False):
            try:
                if canvas.cget("bg") != edge_hex:
                    canvas.configure(bg=edge_hex)
                for tag in ("background_corner_parts", "bg_parts"):
                    canvas.itemconfig(tag, state="hidden")
            except Exception:
                pass

        if not IS_WINDOWS_WIN32:
            return

        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return

        scale_fn = getattr(widget, "_apply_widget_scaling", None)
        r_px = float(scale_fn(radius)) if callable(scale_fn) else float(radius)
        diameter = max(2, int(round(r_px * 2)))

        targets: List[tk.Misc] = [widget]
        if canvas is not None:
            targets.append(canvas)

        for t in targets:
            # Skip destroyed or unmapped widgets so invalid HWNDs are never touched
            if not _is_live_tk_widget(t, require_mapped=True):
                continue
            try:
                w = int(t.winfo_width())
                h = int(t.winfo_height())
                hwnd = int(t.winfo_id() or 0)
            except (tk.TclError, ValueError, Exception):
                continue

            if w <= 4 or h <= 4 or hwnd <= 0:
                continue

            if not windll.user32.IsWindow(ctypes.c_void_p(hwnd)):
                continue

            dims_key = (hwnd, w, h, diameter)
            if not force and getattr(t, "_last_rgn_dims", None) == dims_key:
                continue

            hrgn = None
            rgn_owned_by_os = False
            try:
                hrgn = windll.gdi32.CreateRoundRectRgn(
                    0, 0, w + 1, h + 1, diameter, diameter
                )
                if hrgn:
                    if windll.user32.IsWindow(ctypes.c_void_p(hwnd)):
                        res = windll.user32.SetWindowRgn(
                            ctypes.c_void_p(hwnd), ctypes.c_void_p(hrgn), True
                        )
                        if res != 0:
                            rgn_owned_by_os = True
                            setattr(t, "_last_rgn_dims", dims_key)
            finally:
                if hrgn and not rgn_owned_by_os:
                    try:
                        windll.gdi32.DeleteObject(ctypes.c_void_p(hrgn))
                    except Exception:
                        pass
    except Exception:
        pass


def attach_glass_rounded_hooks(root: tk.Misc) -> None:
    """
    Attaches a lightweight `<Configure>` listener to live rounded CustomTkinter widgets
    without monkey-patching `_draw`, explicitly skipping `CTkTextbox` and `CTkScrollableFrame`
    so their internal child HWNDs are never clipped by `SetWindowRgn`.
    """
    if not _is_live_tk_widget(root, require_mapped=False):
        return
    try:
        is_scrollable_or_textbox = isinstance(root, (ctk.CTkTextbox, ctk.CTkScrollableFrame))
        if (
            not is_scrollable_or_textbox
            and hasattr(root, "_corner_radius")
            and getattr(root, "_corner_radius", 0) > 0
        ):
            if not getattr(root, "_windhawk_hooked", False):
                setattr(root, "_windhawk_hooked", True)
                root.bind(
                    "<Configure>",
                    lambda _e, w=root: apply_rounded_hwnd_clip(w, force=False),
                    add="+",
                )
            apply_rounded_hwnd_clip(root, force=True)

        # Do not recurse into CTkTextbox internal tk.Text/scrollbar children
        if isinstance(root, ctk.CTkTextbox):
            return

        for child in root.winfo_children():
            attach_glass_rounded_hooks(child)
    except Exception:
        pass


def send_desktop_notification(title: str, message: str) -> None:
    """
    Fires a non-blocking, injection-safe native OS desktop notification when a scan
    taking >= 5 seconds completes.
    """
    safe_title = str(title or "Vyrulix")[:120]
    safe_message = str(message or "")[:240]

    def _worker() -> None:
        if PLYER_AVAILABLE and plyer_notification is not None:
            try:
                plyer_notification.notify(
                    title=safe_title,
                    message=safe_message,
                    app_name="Vyrulix",
                    timeout=5,
                )
                return
            except Exception:
                pass

        if IS_WINDOWS_WIN32:
            try:
                import winsound

                winsound.MessageBeep(winsound.MB_ICONASTERISK)
            except Exception:
                pass
            try:
                env = os.environ.copy()
                env["VYRULIX_NOTIFY_TITLE"] = safe_title
                env["VYRULIX_NOTIFY_BODY"] = safe_message
                subprocess.Popen(
                    [
                        "powershell",
                        "-NoProfile",
                        "-NonInteractive",
                        "-WindowStyle",
                        "Hidden",
                        "-Command",
                        STATIC_POWERSHELL_BALLOON_SCRIPT,
                    ],
                    env=env,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except Exception:
                pass
        elif sys.platform == "darwin":
            try:
                subprocess.Popen(
                    [
                        "osascript",
                        "-e",
                        "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run",
                        safe_title,
                        safe_message,
                    ]
                )
            except Exception:
                pass
        else:
            try:
                subprocess.Popen(["notify-send", "--", safe_title, safe_message])
            except Exception:
                pass

    threading.Thread(target=_worker, daemon=True).start()


class ScoreRingGauge(tk.Canvas):
    """
    High-DPI-aware circular detection score ring gauge supporting Safe (Green),
    Suspicious (Amber), Malicious (Red), and Unknown (Neutral Grey) states.
    """

    def __init__(self, master: Any, size: int = 104, bg_color: str = VT_BG_SURFACE) -> None:
        self.base_size = size
        scale = self._get_dpi_scale(master)
        scaled_size = int(round(self.base_size * scale))

        super().__init__(
            master,
            width=scaled_size,
            height=scaled_size,
            bg=bg_color,
            highlightthickness=0,
            bd=0,
            relief="flat",
        )
        self._anim_after_id: Optional[str] = None
        self.set_score(0, 6, "Safe", animate=False)

    def _get_dpi_scale(self, widget_ref: Any = None) -> float:
        try:
            target = widget_ref if widget_ref is not None else self
            scale = float(ctk.ScalingTracker.get_widget_scaling(target))
            return max(1.0, scale)
        except Exception:
            return 1.0

    def set_score(self, flagged: int, total: int, verdict: str = "Safe", animate: bool = True) -> None:
        if self._anim_after_id is not None:
            try:
                self.after_cancel(self._anim_after_id)
            except Exception:
                pass
            self._anim_after_id = None

        if verdict == "Unknown":
            ring_color = VT_GREY
            center_top = "?"
            center_sub = "Unknown"
            target_ratio = 1.0
        else:
            if verdict == "Malicious" or flagged >= 2:
                ring_color = VT_RED
            elif verdict == "Suspicious" or flagged == 1:
                ring_color = VT_AMBER
            else:
                ring_color = VT_GREEN
            center_top = str(flagged)
            center_sub = f"/ {total}"
            target_ratio = 1.0 if flagged == 0 else max(0.08, min(1.0, flagged / max(1, total)))

        if not animate:
            self._draw_frame(center_top, center_sub, ring_color, target_ratio)
            return

        steps = 14
        step_idx = 0

        def _step() -> None:
            nonlocal step_idx
            step_idx += 1
            progress = 1.0 - (1.0 - step_idx / steps) ** 2
            self._draw_frame(center_top, center_sub, ring_color, target_ratio * progress)
            if step_idx < steps:
                self._anim_after_id = self.after(18, _step)
            else:
                self._anim_after_id = None

        _step()

    def _draw_frame(self, center_top: str, center_sub: str, ring_color: str, current_ratio: float) -> None:
        scale = self._get_dpi_scale(self)
        canvas_px = int(round(self.base_size * scale))
        stroke_px = max(2, int(round(8 * scale)))
        pad = int(round(10 * scale))

        self.configure(width=canvas_px, height=canvas_px)
        self.delete("all")

        x0, y0, x1, y1 = pad, pad, canvas_px - pad, canvas_px - pad
        self.create_oval(x0, y0, x1, y1, outline="#2A334D", width=stroke_px)

        extent = -359.9 * max(0.01, min(1.0, current_ratio))
        self.create_arc(
            x0,
            y0,
            x1,
            y1,
            start=90,
            extent=extent,
            style=tk.ARC,
            outline=ring_color,
            width=stroke_px,
        )

        cx, cy = canvas_px // 2, canvas_px // 2
        top_font_size = int(round(20 * scale))
        sub_font_size = int(round(10 * scale))

        self.create_text(
            cx,
            cy - int(round(8 * scale)),
            text=center_top,
            fill=ring_color,
            font=("Segoe UI", top_font_size, "bold"),
        )
        self.create_text(
            cx,
            cy + int(round(18 * scale)),
            text=center_sub,
            fill=VT_TEXT_MUTED,
            font=("Segoe UI", sub_font_size),
        )


class VyrulixApp(ctk.CTk):
    """Vyrulix Desktop Malware & Threat Intelligence Analyzer."""

    def __init__(self) -> None:
        super().__init__(fg_color=VT_BG_MAIN)

        self.title("Vyrulix v1.1 // Malware & Threat Intelligence Analyzer")
        self.geometry("1280x850")
        self.minsize(1060, 720)

        self.yara_rules_path = ensure_default_yara_rules_file()
        self.scanner = VyrulixScanner(yara_rules_path=self.yara_rules_path)
        self.community_db = CommunityManager()

        # Scan, Filter & Sequential Auto-Scan Queue state
        self.selected_filepath: str = ""
        self.file_filter_mode: str = "ALL"
        self.current_report: Optional[ScanReport] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.is_scanning: bool = False
        self.is_uploading_vt: bool = False
        self.is_detonating_sandbox: bool = False
        self._last_synced_file_state: Optional[Tuple[str, bool, bool, bool, bool]] = None
        self._poll_tick_counter: int = 0
        self.is_closing: bool = False
        self.cancel_event = threading.Event()
        self.ui_queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self.pending_auto_files: Deque[str] = collections.deque()

        # Auto-Scan (Real-time directory watcher) state
        self.auto_watcher: Optional[RealtimeDirectoryWatcher] = None
        self.watched_folder: str = str(Path.home() / "Downloads")
        if not os.path.isdir(self.watched_folder):
            self.watched_folder = os.path.abspath(".")

        # UI View & Timer handles for clean shutdown
        self.current_view_name: str = "HOME"
        self.home_sub_mode: str = "FILE"
        self.active_tab_name: str = "DETECTION"
        self.help_visible: bool = False
        self.settings_modal: Optional[ctk.CTkToplevel] = None
        self._poll_after_id: Optional[str] = None
        self._anim_job: Optional[str] = None
        self._toast_job: Optional[str] = None

        self.protocol("WM_DELETE_WINDOW", self._on_close_window)

        self._build_ui()
        self.after(50, self._init_platform_styling)
        self._poll_after_id = self.after(40, self._poll_ui_queue)

    def _init_platform_styling(self) -> None:
        if not self.is_closing:
            apply_windows_dwm_dark_mode(self)
            attach_glass_rounded_hooks(self)

    def _on_close_window(self) -> None:
        """
        Cleanly terminates active scan threads, stops the directory watcher,
        cancels scheduled Tkinter timers, and closes the application window.
        """
        self.is_closing = True
        self.cancel_event.set()
        self.pending_auto_files.clear()

        if self.auto_watcher is not None:
            try:
                self.auto_watcher.stop()
            except Exception:
                pass
            self.auto_watcher = None

        for timer_id in (self._poll_after_id, self._anim_job, self._toast_job):
            if timer_id is not None:
                try:
                    self.after_cancel(timer_id)
                except Exception:
                    pass

        if self.scan_thread is not None and self.scan_thread.is_alive():
            try:
                self.scan_thread.join(timeout=0.25)
            except Exception:
                pass

        try:
            self.destroy()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Top Navigation Bar, Help Popover & Notification Toast
    # -------------------------------------------------------------------------
    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_navbar()
        self._build_progress_strip()

        self.view_deck = ctk.CTkFrame(self, fg_color=VT_BG_MAIN, corner_radius=0)
        self.view_deck.grid(row=2, column=0, sticky="nsew")
        self.view_deck.grid_columnconfigure(0, weight=1)
        self.view_deck.grid_rowconfigure(0, weight=1)

        self.home_view = ctk.CTkFrame(self.view_deck, fg_color=VT_BG_MAIN, corner_radius=0)
        self.report_view = ctk.CTkFrame(self.view_deck, fg_color=VT_BG_MAIN, corner_radius=0)
        self.auth_view = ctk.CTkFrame(self.view_deck, fg_color=VT_BG_MAIN, corner_radius=0)

        self._build_home_view()
        self._build_report_view()
        self._build_auth_view()

        self.help_banner = ctk.CTkFrame(
            self,
            fg_color=VT_BG_ELEVATED,
            corner_radius=8,
            border_width=1,
            border_color=VT_BLUE,
        )
        repo_issues_url = os.environ.get(
            "VYRULIX_REPO_URL", "https://github.com/vyrulix/vyrulix/issues"
        )
        self.help_banner_lbl = ctk.CTkLabel(
            self.help_banner,
            text=f"Documentation & Issue Tracker: {repo_issues_url}",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#60A5FA",
        )
        self.help_banner_lbl.pack(padx=12, pady=6)

        self.toast_frame = ctk.CTkFrame(
            self,
            fg_color=VT_BG_ELEVATED,
            corner_radius=10,
            border_width=1,
            border_color=VT_GREEN,
        )
        self.toast_lbl = ctk.CTkLabel(
            self.toast_frame,
            text="",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=VT_TEXT_PRIMARY,
        )
        self.toast_lbl.pack(padx=16, pady=10)

        self._show_view("HOME", animate=False)
        self._refresh_navbar_auth_state()

    def _build_navbar(self) -> None:
        nav = ctk.CTkFrame(
            self,
            fg_color=VT_BG_ELEVATED,
            corner_radius=0,
            border_width=1,
            border_color=VT_BORDER,
            height=60,
        )
        nav.grid(row=0, column=0, sticky="ew")
        nav.grid_columnconfigure(2, weight=1)

        self.logo_btn = ctk.CTkButton(
            nav,
            text="⛨  VYRULIX",
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_BG_SURFACE,
            text_color="#60A5FA",
            font=ctk.CTkFont(family="Segoe UI", size=19, weight="bold"),
            corner_radius=8,
            width=155,
            height=38,
            command=lambda: self._show_view("HOME"),
        )
        self.logo_btn.grid(row=0, column=0, padx=(12, 4), pady=10, sticky="w")

        # Hidden initially when self.current_report is None
        self.report_nav_btn = ctk.CTkButton(
            nav,
            text="Current Report",
            fg_color=VT_BG_SURFACE,
            hover_color=VT_BORDER,
            text_color="#60A5FA",
            font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=8,
            width=120,
            height=36,
            command=lambda: self._show_view("REPORT"),
        )

        search_container = ctk.CTkFrame(nav, fg_color="transparent", corner_radius=0)
        search_container.grid(row=0, column=2, padx=8, pady=10, sticky="ew")
        search_container.grid_columnconfigure(0, weight=1)

        self.file_entry = ctk.CTkEntry(
            search_container,
            placeholder_text="URL, IP address, domain, file hash (SHA-256), or local file path...",
            height=36,
            corner_radius=8,
            fg_color=VT_BG_MAIN,
            border_color=VT_BORDER,
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.file_entry.grid(row=0, column=0, padx=(0, 6), sticky="ew")
        self.file_entry.bind("<Return>", lambda _e: self._on_action_scan_or_stop())

        self.browse_btn = ctk.CTkButton(
            search_container,
            text="Choose File",
            width=105,
            height=36,
            corner_radius=8,
            fg_color=VT_BG_SURFACE,
            hover_color=VT_BORDER,
            border_width=1,
            border_color=VT_BLUE,
            text_color="#60A5FA",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_browse_file,
        )
        self.browse_btn.grid(row=0, column=1, padx=4)

        self.action_scan_btn = ctk.CTkButton(
            search_container,
            text="Analyze Now",
            width=122,
            height=36,
            corner_radius=8,
            fg_color=VT_BLUE,
            hover_color=VT_BLUE_HOVER,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._on_action_scan_or_stop,
        )
        self.action_scan_btn.grid(row=0, column=2, padx=4)

        self.autoscan_nav_btn = ctk.CTkButton(
            search_container,
            text="Auto-Scan: OFF",
            width=122,
            height=36,
            corner_radius=8,
            fg_color=VT_BG_SURFACE,
            hover_color=VT_BORDER,
            border_width=1,
            border_color=VT_BORDER,
            text_color=VT_TEXT_MUTED,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._toggle_auto_scan,
        )
        self.autoscan_nav_btn.grid(row=0, column=3, padx=(4, 0))

        right_nav = ctk.CTkFrame(nav, fg_color="transparent", corner_radius=0)
        right_nav.grid(row=0, column=3, padx=(6, 14), pady=10, sticky="e")

        self.settings_btn = ctk.CTkButton(
            right_nav,
            text="⚙",
            width=32,
            height=32,
            corner_radius=16,
            fg_color=VT_BG_SURFACE,
            hover_color=VT_BLUE,
            border_width=1,
            border_color="#60A5FA",
            text_color="#60A5FA",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            command=self._open_api_settings_modal,
        )
        self.settings_btn.pack(side="left", padx=(2, 6))

        self.help_circle_btn = ctk.CTkButton(
            right_nav,
            text="?",
            width=32,
            height=32,
            corner_radius=16,
            fg_color=VT_BG_SURFACE,
            hover_color=VT_BLUE,
            border_width=1,
            border_color="#60A5FA",
            text_color="#60A5FA",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            command=self._toggle_help_contact_text,
        )
        self.help_circle_btn.pack(side="left", padx=(0, 8))

        self.auth_nav_frame = ctk.CTkFrame(right_nav, fg_color="transparent", corner_radius=0)
        self.auth_nav_frame.pack(side="left")

    def _update_current_report_button_visibility(self) -> None:
        if self.current_report is not None:
            self.report_nav_btn.grid(row=0, column=1, padx=4, pady=10, sticky="w")
            apply_rounded_hwnd_clip(self.report_nav_btn, force=True)
        else:
            self.report_nav_btn.grid_forget()

    def _toggle_help_contact_text(self) -> None:
        self.help_visible = not self.help_visible
        if self.help_visible:
            self.help_banner.place(relx=0.985, y=62, anchor="ne")
            self.help_banner.lift()
            apply_rounded_hwnd_clip(self.help_banner, force=True)
        else:
            self.help_banner.place_forget()

    def _open_api_settings_modal(self) -> None:
        """
        Opens a dark-themed CustomTkinter modal window allowing the analyst to configure:
          - VirusTotal v3 API Key (with show/hide toggle)
          - VirusTotal Rate-Limit Tier (Free 4 RPM vs. Enterprise 500+ RPM)
          - Optional abuse.ch Auth-Key (MalwareBazaar / ThreatFox first-line feeds)
        """
        if self.settings_modal is not None:
            try:
                if self.settings_modal.winfo_exists():
                    self.settings_modal.lift()
                    self.settings_modal.focus_force()
                    return
            except Exception:
                pass
            self.settings_modal = None

        cfg = load_vyrulix_config()
        current_vt_key = str(cfg.get("vt_api_key", "") or "")
        current_tier = str(cfg.get("vt_tier", "free") or "free").lower()
        current_abuse_key = str(cfg.get("abusech_api_key", "") or "")

        modal = ctk.CTkToplevel(self, fg_color=VT_BG_MAIN)
        modal.title("Vyrulix // Cloud Intelligence & Rate-Limit Settings")
        modal.geometry("560x470")
        modal.resizable(False, False)
        modal.transient(self)
        self.settings_modal = modal

        def _on_modal_close() -> None:
            try:
                modal.grab_release()
            except Exception:
                pass
            try:
                modal.destroy()
            except Exception:
                pass
            self.settings_modal = None

        modal.protocol("WM_DELETE_WINDOW", _on_modal_close)

        card = ctk.CTkFrame(
            modal,
            fg_color=VT_BG_SURFACE,
            corner_radius=12,
            border_width=1,
            border_color=VT_BORDER,
        )
        card.pack(fill="both", expand=True, padx=18, pady=18)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text="⚙  Threat Intelligence & Rate-Limit Configuration",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#60A5FA",
            anchor="w",
        ).pack(fill="x", padx=22, pady=(18, 4))

        ctk.CTkLabel(
            card,
            text=(
                "MalwareBazaar & ThreatFox (abuse.ch) are queried first (30 RPM). "
                "VirusTotal v3 is only queried when open-source feeds return zero hits."
            ),
            font=ctk.CTkFont(size=12),
            text_color=VT_TEXT_MUTED,
            justify="left",
            wraplength=500,
            anchor="w",
        ).pack(fill="x", padx=22, pady=(0, 12))

        form = ctk.CTkFrame(card, fg_color="transparent", corner_radius=0)
        form.pack(fill="both", expand=True, padx=22, pady=4)
        form.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            form,
            text="VirusTotal v3 API Key:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=VT_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill="x", pady=(4, 2))

        vt_key_entry = self._create_password_row(
            form, placeholder="Paste your 64-character VirusTotal v3 API key"
        )
        if current_vt_key:
            vt_key_entry.insert(0, current_vt_key)

        ctk.CTkLabel(
            form,
            text="VirusTotal Rate-Limit Tier:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=VT_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill="x", pady=(6, 4))

        tier_labels = ["Free (4 req/min)", "Enterprise (500+ req/min)"]
        tier_seg = ctk.CTkSegmentedButton(
            form,
            values=tier_labels,
            height=34,
            corner_radius=8,
            fg_color=VT_BG_MAIN,
            selected_color=VT_BLUE,
            selected_hover_color=VT_BLUE_HOVER,
            unselected_color=VT_BG_ELEVATED,
            unselected_hover_color=VT_BORDER,
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        tier_seg.set(
            "Enterprise (500+ req/min)" if current_tier == "enterprise" else "Free (4 req/min)"
        )
        tier_seg.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            form,
            text="Optional abuse.ch Auth-Key (MalwareBazaar / ThreatFox):",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=VT_TEXT_PRIMARY,
            anchor="w",
        ).pack(fill="x", pady=(4, 2))

        abuse_key_entry = self._create_password_row(
            form, placeholder="Optional Auth-Key from auth.abuse.ch (blank = public access)"
        )
        if current_abuse_key:
            abuse_key_entry.insert(0, current_abuse_key)

        btn_row = ctk.CTkFrame(card, fg_color="transparent", corner_radius=0)
        btn_row.pack(fill="x", padx=22, pady=(8, 18))
        btn_row.grid_columnconfigure(0, weight=1)
        btn_row.grid_columnconfigure(1, weight=1)

        def _on_save() -> None:
            new_vt_key = vt_key_entry.get().strip()
            sel_tier_label = tier_seg.get()
            new_tier = "enterprise" if "Enterprise" in sel_tier_label else "free"
            new_abuse_key = abuse_key_entry.get().strip()

            saved = save_vyrulix_config(
                vt_api_key=new_vt_key,
                vt_tier=new_tier,
                abusech_api_key=new_abuse_key,
            )
            self.scanner.vt_api_key = saved["vt_api_key"]
            rpm_val = saved["vt_rpm"]
            tier_display = "Enterprise (500 RPM)" if new_tier == "enterprise" else "Free (4 RPM)"

            self.status_label.configure(
                text=f"✔ Cloud Settings Saved  •  VirusTotal Tier: {tier_display}",
                text_color=VT_GREEN,
            )
            try:
                modal.grab_release()
            except Exception:
                pass
            modal.destroy()
            self.settings_modal = None
            self._show_completion_toast(
                f"Settings saved — VirusTotal {tier_display} ({rpm_val} req/min) active",
                border_color=VT_GREEN,
            )

        cancel_btn = ctk.CTkButton(
            btn_row,
            text="Cancel",
            height=38,
            corner_radius=8,
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_BORDER,
            text_color=VT_TEXT_MUTED,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=_on_modal_close,
        )
        cancel_btn.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        save_btn = ctk.CTkButton(
            btn_row,
            text="Save Settings",
            height=38,
            corner_radius=8,
            fg_color=VT_BLUE,
            hover_color=VT_BLUE_HOVER,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=_on_save,
        )
        save_btn.grid(row=0, column=1, padx=(6, 0), sticky="ew")

        modal.after(30, lambda: (apply_windows_dwm_dark_mode(modal), attach_glass_rounded_hooks(modal)))
        modal.after(50, modal.grab_set)

    def _show_completion_toast(self, message: str, border_color: str = VT_GREEN) -> None:
        if self._toast_job is not None:
            try:
                self.after_cancel(self._toast_job)
            except Exception:
                pass
            self._toast_job = None

        self.toast_frame.configure(border_color=border_color)
        self.toast_lbl.configure(text=f"🔔  {message}")

        steps = 8
        idx = 0

        def _slide_in() -> None:
            if self.is_closing:
                return
            nonlocal idx
            idx += 1
            cur_y = int(42 + (26 * (idx / steps)))
            self.toast_frame.place(relx=0.985, y=cur_y, anchor="ne")
            self.toast_frame.lift()
            apply_rounded_hwnd_clip(self.toast_frame, force=(idx == 1))
            if idx < steps:
                self.after(16, _slide_in)

        _slide_in()
        self._toast_job = self.after(6500, lambda: self.toast_frame.place_forget())

    def _build_progress_strip(self) -> None:
        strip = ctk.CTkFrame(
            self,
            fg_color=VT_BG_SURFACE,
            corner_radius=0,
            height=28,
        )
        strip.grid(row=1, column=0, sticky="ew")
        strip.grid_columnconfigure(0, weight=1)

        self.progress_bar = ctk.CTkProgressBar(
            strip,
            height=6,
            corner_radius=3,
            fg_color=VT_BG_MAIN,
            progress_color=VT_BLUE,
        )
        self.progress_bar.set(0.0)
        self.progress_bar.grid(row=0, column=0, padx=(16, 12), pady=8, sticky="ew")

        rule_name = os.path.basename(self.scanner.yara_rules_path) or "vyrulix_default.yar"
        self.status_label = ctk.CTkLabel(
            strip,
            text=f"Ready  •  Vyrulix Streaming Engine & YARA ({rule_name}) Active",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=VT_TEXT_MUTED,
        )
        self.status_label.grid(row=0, column=1, padx=(0, 16), pady=4, sticky="e")

    # -------------------------------------------------------------------------
    # Soft Animated View Transitions
    # -------------------------------------------------------------------------
    def _show_view(self, view_name: str, animate: bool = True) -> None:
        if self._anim_job is not None:
            try:
                self.after_cancel(self._anim_job)
            except Exception:
                pass
            self._anim_job = None

        self.current_view_name = view_name
        for v in (self.home_view, self.report_view, self.auth_view):
            v.grid_forget()
            v.place_forget()

        target = (
            self.home_view
            if view_name == "HOME"
            else self.report_view
            if view_name == "REPORT"
            else self.auth_view
        )

        if not animate:
            target.grid(row=0, column=0, sticky="nsew")
            self.after(20, lambda: attach_glass_rounded_hooks(target))
            return

        total_steps = 8
        step = 0

        def _animate_step() -> None:
            if self.is_closing:
                return
            nonlocal step
            step += 1
            if step < total_steps:
                offset_y = int(18 * (1.0 - step / total_steps) ** 2)
                target.grid(row=0, column=0, sticky="nsew", pady=(offset_y, 0))
                self._anim_job = self.after(15, _animate_step)
            else:
                target.grid(row=0, column=0, sticky="nsew", pady=(0, 0))
                self._anim_job = None
                attach_glass_rounded_hooks(target)

        _animate_step()

    # -------------------------------------------------------------------------
    # 1. VirusTotal Home View (FILE | URL | SEARCH + Automated Scan + YARA Pack)
    # -------------------------------------------------------------------------
    def _build_home_view(self) -> None:
        self.home_view.grid_columnconfigure(0, weight=1)
        self.home_view.grid_rowconfigure(0, weight=1)

        center_card = ctk.CTkFrame(
            self.home_view,
            fg_color=VT_BG_SURFACE,
            corner_radius=12,
            border_width=1,
            border_color=VT_BORDER,
        )
        center_card.grid(row=0, column=0, padx=130, pady=36, sticky="nsew")
        center_card.grid_columnconfigure(0, weight=1)

        hero_logo = ctk.CTkLabel(
            center_card,
            text="⛨  VYRULIX",
            font=ctk.CTkFont(family="Segoe UI", size=36, weight="bold"),
            text_color="#60A5FA",
        )
        hero_logo.pack(pady=(28, 6))

        hero_sub = ctk.CTkLabel(
            center_card,
            text=(
                "Analyze suspicious files, domains, IPs and URLs to detect malware and other\n"
                "breaches, automatically share them with the security community."
            ),
            font=ctk.CTkFont(family="Segoe UI", size=14),
            text_color=VT_TEXT_MUTED,
            justify="center",
        )
        hero_sub.pack(pady=(0, 18))

        mode_tab_bar = ctk.CTkFrame(center_card, fg_color="transparent", corner_radius=0)
        mode_tab_bar.pack(pady=(0, 14))

        self.home_tab_btns: Dict[str, ctk.CTkButton] = {}
        for idx, (m_key, m_label) in enumerate(
            [("FILE", "FILE"), ("URL", "URL"), ("SEARCH", "SEARCH")]
        ):
            b = ctk.CTkButton(
                mode_tab_bar,
                text=m_label,
                width=160,
                height=38,
                corner_radius=8,
                fg_color=VT_BLUE if m_key == "FILE" else VT_BG_ELEVATED,
                hover_color=VT_BLUE_HOVER,
                text_color="#FFFFFF" if m_key == "FILE" else VT_TEXT_MUTED,
                font=ctk.CTkFont(size=13, weight="bold"),
                command=lambda k=m_key: self._switch_home_sub_mode(k),
            )
            b.grid(row=0, column=idx, padx=6)
            self.home_tab_btns[m_key] = b

        self.home_mode_container = ctk.CTkFrame(
            center_card, fg_color="transparent", corner_radius=0
        )
        self.home_mode_container.pack(fill="both", expand=True, padx=48, pady=6)

        auto_bar = ctk.CTkFrame(
            center_card,
            fg_color=VT_BG_MAIN,
            corner_radius=10,
            border_width=1,
            border_color=VT_BORDER,
        )
        auto_bar.pack(fill="x", padx=48, pady=(8, 22))
        auto_bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            auto_bar,
            text="⚡ Real-Time Folder Guard:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=VT_TEXT_PRIMARY,
        ).grid(row=0, column=0, padx=(14, 8), pady=10, sticky="w")

        self.auto_folder_lbl = ctk.CTkLabel(
            auto_bar,
            text=f"Folder: {self.watched_folder}",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=VT_TEXT_MUTED,
            anchor="w",
        )
        self.auto_folder_lbl.grid(row=0, column=1, padx=6, pady=10, sticky="ew")

        load_yara_btn = ctk.CTkButton(
            auto_bar,
            text="Load Custom .yar",
            width=122,
            height=32,
            corner_radius=8,
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_BORDER,
            font=ctk.CTkFont(size=12),
            command=self._choose_custom_yara_file,
        )
        load_yara_btn.grid(row=0, column=2, padx=4, pady=10)

        self.sync_yara_btn = ctk.CTkButton(
            auto_bar,
            text="↻ Sync Threat Rules",
            width=142,
            height=32,
            corner_radius=8,
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_BLUE,
            border_width=1,
            border_color="#60A5FA",
            text_color="#60A5FA",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_sync_threat_rules,
        )
        self.sync_yara_btn.grid(row=0, column=3, padx=4, pady=10)

        choose_dir_btn = ctk.CTkButton(
            auto_bar,
            text="Change Folder",
            width=112,
            height=32,
            corner_radius=8,
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_BORDER,
            font=ctk.CTkFont(size=12),
            command=self._choose_watch_folder,
        )
        choose_dir_btn.grid(row=0, column=4, padx=4, pady=10)

        self.home_autoscan_btn = ctk.CTkButton(
            auto_bar,
            text="Enable Auto-Scan",
            width=136,
            height=32,
            corner_radius=8,
            fg_color=VT_GREEN,
            hover_color="#059669",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._toggle_auto_scan,
        )
        self.home_autoscan_btn.grid(row=0, column=5, padx=(6, 14), pady=10)

        self._switch_home_sub_mode("FILE")

    def _choose_custom_yara_file(self) -> None:
        yar_file = filedialog.askopenfilename(
            title="Select YARA Rule File (.yar / .yara)",
            filetypes=[("YARA Rules", "*.yar *.yara"), ("All Files", "*.*")],
        )
        if yar_file:
            ok, msg = self.scanner.reload_yara_rules(yar_file)
            self.yara_rules_path = self.scanner.yara_rules_path
            self.status_label.configure(
                text=f"✔ {msg}" if ok else f"✖ {msg}",
                text_color=VT_GREEN if ok else VT_RED,
            )

    def _on_sync_threat_rules(self) -> None:
        """
        Triggers a non-blocking manual synchronization of open-source YARA rules
        (Neo23x0/signature-base & ReversingLabs) and routes completion via `self.ui_queue`.
        """
        if hasattr(self, "sync_yara_btn"):
            self.sync_yara_btn.configure(state="disabled", text="↻ Syncing Rules...")
            apply_rounded_hwnd_clip(self.sync_yara_btn, force=True)

        self.status_label.configure(
            text="↻ Synchronizing open-source YARA threat rules in background (Neo23x0 / ReversingLabs)...",
            text_color="#60A5FA",
        )

        def _on_sync_done(ok: bool, message: str) -> None:
            if not self.is_closing:
                self.ui_queue.put(("YARA_SYNC_DONE", (ok, message)))

        self.scanner.trigger_manual_yara_update(on_complete=_on_sync_done, blocking=False)

    def _set_file_filter_mode(self, mode: str) -> None:
        """Updates the file filter mode and synchronizes any active Auto-Scan watcher."""
        self.file_filter_mode = mode
        if self.auto_watcher is not None:
            self.auto_watcher.mode = mode

        if hasattr(self, "filter_all_btn") and hasattr(self, "filter_exec_btn"):
            if mode == "ALL":
                self.filter_all_btn.configure(fg_color=VT_BLUE, text_color="#FFFFFF")
                self.filter_exec_btn.configure(fg_color=VT_BG_ELEVATED, text_color=VT_TEXT_MUTED)
            else:
                self.filter_all_btn.configure(fg_color=VT_BG_ELEVATED, text_color=VT_TEXT_MUTED)
                self.filter_exec_btn.configure(fg_color=VT_BLUE, text_color="#FFFFFF")
            apply_rounded_hwnd_clip(self.filter_all_btn, force=True)
            apply_rounded_hwnd_clip(self.filter_exec_btn, force=True)

    def _switch_home_sub_mode(self, mode_key: str) -> None:
        self.home_sub_mode = mode_key
        for k, btn in self.home_tab_btns.items():
            if k == mode_key:
                btn.configure(fg_color=VT_BLUE, text_color="#FFFFFF")
            else:
                btn.configure(fg_color=VT_BG_ELEVATED, text_color=VT_TEXT_MUTED)
            apply_rounded_hwnd_clip(btn, force=True)

        for child in self.home_mode_container.winfo_children():
            child.destroy()

        if mode_key == "FILE":
            icon_box = ctk.CTkFrame(
                self.home_mode_container,
                fg_color=VT_BG_MAIN,
                corner_radius=12,
                border_width=1,
                border_color=VT_BLUE,
                width=320,
                height=165,
            )
            icon_box.pack(pady=(10, 14))
            icon_box.pack_propagate(False)

            ctk.CTkLabel(
                icon_box,
                text="📄  🔍",
                font=ctk.CTkFont(size=38),
                text_color="#60A5FA",
            ).pack(pady=(22, 8))

            ctk.CTkButton(
                icon_box,
                text="Choose File",
                width=190,
                height=40,
                corner_radius=8,
                fg_color=VT_BLUE,
                hover_color=VT_BLUE_HOVER,
                font=ctk.CTkFont(size=14, weight="bold"),
                command=self._on_hero_choose_and_scan,
            ).pack(pady=(4, 14))

            mode_row = ctk.CTkFrame(
                self.home_mode_container, fg_color="transparent", corner_radius=0
            )
            mode_row.pack(pady=4)

            ctk.CTkLabel(
                mode_row,
                text="Filter Mode:",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=VT_TEXT_PRIMARY,
            ).pack(side="left", padx=(0, 10))

            self.filter_all_btn = ctk.CTkButton(
                mode_row,
                text="Scan All Files",
                width=130,
                height=34,
                corner_radius=8,
                fg_color=VT_BLUE if self.file_filter_mode == "ALL" else VT_BG_ELEVATED,
                hover_color=VT_BLUE_HOVER,
                text_color="#FFFFFF" if self.file_filter_mode == "ALL" else VT_TEXT_MUTED,
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda: self._set_file_filter_mode("ALL"),
            )
            self.filter_all_btn.pack(side="left", padx=4)

            self.filter_exec_btn = ctk.CTkButton(
                mode_row,
                text="Executables & Disk Images Only",
                width=220,
                height=34,
                corner_radius=8,
                fg_color=VT_BLUE if self.file_filter_mode == "SPECIFIC" else VT_BG_ELEVATED,
                hover_color=VT_BLUE_HOVER,
                text_color="#FFFFFF" if self.file_filter_mode == "SPECIFIC" else VT_TEXT_MUTED,
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda: self._set_file_filter_mode("SPECIFIC"),
            )
            self.filter_exec_btn.pack(side="left", padx=4)

        elif mode_key == "URL":
            ctk.CTkLabel(
                self.home_mode_container,
                text="🌐  Scan a Website or Suspicious URL",
                font=ctk.CTkFont(size=20, weight="bold"),
                text_color=VT_TEXT_PRIMARY,
            ).pack(pady=(22, 6))

            ctk.CTkLabel(
                self.home_mode_container,
                text="Inspect URLs for phishing patterns, direct IP C2 hosts, high-risk TLDs, and payload droppers.",
                font=ctk.CTkFont(size=13),
                text_color=VT_TEXT_MUTED,
            ).pack(pady=(0, 16))

            self.home_url_entry = ctk.CTkEntry(
                self.home_mode_container,
                placeholder_text="https://example.com/download/setup.exe",
                height=42,
                width=540,
                corner_radius=8,
                fg_color=VT_BG_MAIN,
                border_color=VT_BLUE,
                font=ctk.CTkFont(family="Consolas", size=13),
            )
            self.home_url_entry.pack(pady=6)
            self.home_url_entry.bind("<Return>", lambda _e: self._on_submit_home_url())

            ctk.CTkButton(
                self.home_mode_container,
                text="Analyze URL",
                width=200,
                height=40,
                corner_radius=8,
                fg_color=VT_BLUE,
                hover_color=VT_BLUE_HOVER,
                font=ctk.CTkFont(size=14, weight="bold"),
                command=self._on_submit_home_url,
            ).pack(pady=14)

        elif mode_key == "SEARCH":
            ctk.CTkLabel(
                self.home_mode_container,
                text="🔎  Search for a File Hash, IP Address, Domain, or URL",
                font=ctk.CTkFont(size=20, weight="bold"),
                text_color=VT_TEXT_PRIMARY,
            ).pack(pady=(22, 6))

            ctk.CTkLabel(
                self.home_mode_container,
                text="Enter a SHA-256, SHA-1, or MD5 hash, IPv4 address (e.g. 1.1.1.1, 8.8.8.8), or domain name.",
                font=ctk.CTkFont(size=13),
                text_color=VT_TEXT_MUTED,
            ).pack(pady=(0, 16))

            self.home_search_entry = ctk.CTkEntry(
                self.home_mode_container,
                placeholder_text="URL, IP address, domain, or file hash (SHA-256 / SHA-1 / MD5)",
                height=42,
                width=540,
                corner_radius=8,
                fg_color=VT_BG_MAIN,
                border_color=VT_BLUE,
                font=ctk.CTkFont(family="Consolas", size=13),
            )
            self.home_search_entry.pack(pady=6)
            self.home_search_entry.bind("<Return>", lambda _e: self._on_submit_home_search())

            ctk.CTkButton(
                self.home_mode_container,
                text="Search Indicator",
                width=200,
                height=40,
                corner_radius=8,
                fg_color=VT_BLUE,
                hover_color=VT_BLUE_HOVER,
                font=ctk.CTkFont(size=14, weight="bold"),
                command=self._on_submit_home_search,
            ).pack(pady=14)

        self.after(20, lambda: attach_glass_rounded_hooks(self.home_mode_container))

    def _on_hero_choose_and_scan(self) -> None:
        filepath = filedialog.askopenfilename(
            title="Choose File to Analyze with Vyrulix"
        )
        if filepath:
            self.selected_filepath = filepath
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, filepath)
            self._start_scan_from_input(filepath)

    def _on_submit_home_url(self) -> None:
        url = self.home_url_entry.get().strip()
        if url:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, url)
            self._start_scan_from_input(url, force_kind="URL")

    def _on_submit_home_search(self) -> None:
        query = self.home_search_entry.get().strip()
        if query:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, query)
            self._start_scan_from_input(query, force_kind="SEARCH")

    # -------------------------------------------------------------------------
    # Non-Blocking Automated Real-Time Folder Watcher ("Auto-Scan")
    # -------------------------------------------------------------------------
    def _choose_watch_folder(self) -> None:
        folder = filedialog.askdirectory(
            title="Select Folder for Automated Real-Time Malware Monitoring",
            initialdir=self.watched_folder,
        )
        if folder:
            self.watched_folder = os.path.abspath(folder)
            self.auto_folder_lbl.configure(text=f"Folder: {self.watched_folder}")
            if self.auto_watcher is not None:
                self._toggle_auto_scan()
                self._toggle_auto_scan()

    def _toggle_auto_scan(self) -> None:
        if self.auto_watcher is not None:
            self.auto_watcher.stop()
            self.auto_watcher = None
            self.autoscan_nav_btn.configure(
                text="Auto-Scan: OFF",
                fg_color=VT_BG_SURFACE,
                border_color=VT_BORDER,
                text_color=VT_TEXT_MUTED,
            )
            self.home_autoscan_btn.configure(
                text="Enable Auto-Scan",
                fg_color=VT_GREEN,
                hover_color="#059669",
            )
            self.status_label.configure(
                text="Automated folder monitoring stopped.", text_color=VT_TEXT_MUTED
            )
        else:
            watcher = RealtimeDirectoryWatcher(
                watch_directory=self.watched_folder,
                on_new_file_callback=lambda path: self.ui_queue.put(("AUTO_FILE", path)),
                mode=self.file_filter_mode,
            )
            ok, msg = watcher.start()
            if ok:
                self.auto_watcher = watcher
                self.autoscan_nav_btn.configure(
                    text="⚡ Auto-Scan: ON",
                    fg_color=VT_GREEN,
                    border_color=VT_GREEN,
                    text_color="#FFFFFF",
                )
                self.home_autoscan_btn.configure(
                    text="Disable Auto-Scan",
                    fg_color=VT_RED,
                    hover_color="#B91C1C",
                )
                self.status_label.configure(
                    text=f"⚡ Auto-Scan active: watching {self.watched_folder} for new files...",
                    text_color=VT_GREEN,
                )
            else:
                self.auto_watcher = None
                self.status_label.configure(
                    text=msg,
                    text_color=VT_RED,
                )
        apply_rounded_hwnd_clip(self.autoscan_nav_btn, force=True)
        apply_rounded_hwnd_clip(self.home_autoscan_btn, force=True)

    # -------------------------------------------------------------------------
    # 2. VirusTotal Analysis Report View
    # -------------------------------------------------------------------------
    def _build_report_view(self) -> None:
        self.report_view.grid_columnconfigure(0, weight=1)
        self.report_view.grid_rowconfigure(2, weight=1)

        self.summary_card = ctk.CTkFrame(
            self.report_view,
            fg_color=VT_BG_SURFACE,
            corner_radius=10,
            border_width=1,
            border_color=VT_BORDER,
        )
        self.summary_card.grid(row=0, column=0, padx=18, pady=(14, 8), sticky="ew")
        self.summary_card.grid_columnconfigure(1, weight=1)

        gauge_col = ctk.CTkFrame(self.summary_card, fg_color="transparent", corner_radius=0)
        gauge_col.grid(row=0, column=0, padx=(18, 14), pady=12)

        self.score_gauge = ScoreRingGauge(gauge_col, size=104, bg_color=VT_BG_SURFACE)
        self.score_gauge.pack()

        self.community_mini_badge = ctk.CTkLabel(
            gauge_col,
            text="Community: 0 votes",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=VT_TEXT_MUTED,
        )
        self.community_mini_badge.pack(pady=(4, 0))

        mid_col = ctk.CTkFrame(self.summary_card, fg_color="transparent", corner_radius=0)
        mid_col.grid(row=0, column=1, padx=8, pady=12, sticky="nsew")
        mid_col.grid_columnconfigure(0, weight=1)

        self.verdict_banner_frame = ctk.CTkFrame(
            mid_col,
            fg_color=VT_BG_ELEVATED,
            corner_radius=8,
            border_width=1,
            border_color=VT_GREEN,
        )
        self.verdict_banner_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self.verdict_banner_lbl = ctk.CTkLabel(
            self.verdict_banner_frame,
            text="✔  No security vendors flagged this file as malicious",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=VT_GREEN,
            anchor="w",
        )
        self.verdict_banner_lbl.pack(fill="x", padx=12, pady=6)

        hash_row = ctk.CTkFrame(mid_col, fg_color="transparent", corner_radius=0)
        hash_row.grid(row=1, column=0, sticky="ew", pady=2)

        self.lbl_sha256_top = ctk.CTkLabel(
            hash_row,
            text="SHA-256: —",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=VT_TEXT_PRIMARY,
            anchor="w",
        )
        self.lbl_sha256_top.pack(side="left")

        self.copy_sha_btn = ctk.CTkButton(
            hash_row,
            text="Copy Hash",
            width=82,
            height=26,
            corner_radius=6,
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_BORDER,
            font=ctk.CTkFont(size=11),
            command=self._copy_current_sha256,
        )
        self.copy_sha_btn.pack(side="left", padx=(10, 4))

        self.sandbox_detonate_btn = ctk.CTkButton(
            hash_row,
            text="📦 Detonate in Sandbox (.wsb)",
            width=185,
            height=26,
            corner_radius=6,
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_BLUE,
            border_width=1,
            border_color="#60A5FA",
            text_color="#60A5FA",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_detonate_in_sandbox,
        )
        self.sandbox_detonate_btn.pack(side="left", padx=4)

        self.vt_upload_btn = ctk.CTkButton(
            hash_row,
            text="☁ Upload to VirusTotal",
            width=155,
            height=26,
            corner_radius=6,
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_AMBER,
            border_width=1,
            border_color=VT_AMBER,
            text_color=VT_AMBER,
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_confirm_and_upload_vt,
        )
        self.vt_upload_btn.pack(side="left", padx=4)

        self.lbl_filename_top = ctk.CTkLabel(
            mid_col,
            text="File: No sample loaded",
            font=ctk.CTkFont(size=13),
            text_color=VT_TEXT_MUTED,
            anchor="w",
        )
        self.lbl_filename_top.grid(row=2, column=0, sticky="ew", pady=2)

        self.tags_row_lbl = ctk.CTkLabel(
            mid_col,
            text="Tags: —",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#60A5FA",
            anchor="w",
        )
        self.tags_row_lbl.grid(row=3, column=0, sticky="ew", pady=(4, 0))

        right_col = ctk.CTkFrame(self.summary_card, fg_color="transparent", corner_radius=0)
        right_col.grid(row=0, column=2, padx=(12, 18), pady=12, sticky="ns")

        self.lbl_right_size = ctk.CTkLabel(
            right_col,
            text="Size\n—",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=VT_TEXT_PRIMARY,
            justify="center",
        )
        self.lbl_right_size.grid(row=0, column=0, padx=12, pady=18)

        self.lbl_right_speed = ctk.CTkLabel(
            right_col,
            text="Scan Speed\n—",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=VT_TEXT_PRIMARY,
            justify="center",
        )
        self.lbl_right_speed.grid(row=0, column=1, padx=12, pady=18)

        self.ext_badge = ctk.CTkLabel(
            right_col,
            text="FILE",
            width=64,
            height=64,
            corner_radius=10,
            fg_color=VT_BG_ELEVATED,
            text_color="#60A5FA",
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
        )
        self.ext_badge.grid(row=0, column=2, padx=(10, 0), pady=12)

        tab_bar = ctk.CTkFrame(
            self.report_view,
            fg_color=VT_BG_SURFACE,
            corner_radius=10,
            border_width=1,
            border_color=VT_BORDER,
            height=44,
        )
        tab_bar.grid(row=1, column=0, padx=18, pady=(0, 8), sticky="ew")

        self.tab_buttons: Dict[str, ctk.CTkButton] = {}
        tab_specs = [
            ("DETECTION", "DETECTION"),
            ("DETAILS", "DETAILS"),
            ("RELATIONS", "RELATIONS"),
            ("BEHAVIOR", "BEHAVIOR / PE"),
            ("COMMUNITY", "COMMUNITY"),
        ]
        for idx, (tab_key, tab_title) in enumerate(tab_specs):
            btn = ctk.CTkButton(
                tab_bar,
                text=tab_title,
                width=145,
                height=36,
                corner_radius=8,
                fg_color=VT_BLUE if tab_key == "DETECTION" else VT_BG_SURFACE,
                hover_color=VT_BG_ELEVATED,
                text_color="#FFFFFF" if tab_key == "DETECTION" else VT_TEXT_MUTED,
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda k=tab_key: self._select_report_tab(k),
            )
            btn.grid(row=0, column=idx, padx=4, pady=4)
            self.tab_buttons[tab_key] = btn

        self.tab_deck = ctk.CTkFrame(
            self.report_view,
            fg_color=VT_BG_MAIN,
            corner_radius=0,
        )
        self.tab_deck.grid(row=2, column=0, padx=18, pady=(0, 16), sticky="nsew")
        self.tab_deck.grid_columnconfigure(0, weight=1)
        self.tab_deck.grid_rowconfigure(0, weight=1)

        self.pane_detection = ctk.CTkFrame(self.tab_deck, fg_color=VT_BG_SURFACE, corner_radius=10, border_width=1, border_color=VT_BORDER)
        self.pane_details = ctk.CTkFrame(self.tab_deck, fg_color=VT_BG_SURFACE, corner_radius=10, border_width=1, border_color=VT_BORDER)
        self.pane_relations = ctk.CTkFrame(self.tab_deck, fg_color=VT_BG_SURFACE, corner_radius=10, border_width=1, border_color=VT_BORDER)
        self.pane_behavior = ctk.CTkFrame(self.tab_deck, fg_color=VT_BG_SURFACE, corner_radius=10, border_width=1, border_color=VT_BORDER)
        self.pane_community = ctk.CTkFrame(self.tab_deck, fg_color=VT_BG_SURFACE, corner_radius=10, border_width=1, border_color=VT_BORDER)

        self._build_detection_pane()
        self._build_details_pane()
        self._build_relations_pane()
        self._build_behavior_pane()
        self._build_community_pane()

        self._select_report_tab("DETECTION", animate=False)

    def _select_report_tab(self, tab_key: str, animate: bool = True) -> None:
        self.active_tab_name = tab_key
        for k, btn in self.tab_buttons.items():
            if k == tab_key:
                btn.configure(fg_color=VT_BLUE, text_color="#FFFFFF")
            else:
                btn.configure(fg_color=VT_BG_SURFACE, text_color=VT_TEXT_MUTED)
            apply_rounded_hwnd_clip(btn, force=True)

        for pane in (
            self.pane_detection,
            self.pane_details,
            self.pane_relations,
            self.pane_behavior,
            self.pane_community,
        ):
            pane.grid_forget()

        mapping = {
            "DETECTION": self.pane_detection,
            "DETAILS": self.pane_details,
            "RELATIONS": self.pane_relations,
            "BEHAVIOR": self.pane_behavior,
            "COMMUNITY": self.pane_community,
        }
        target_pane = mapping[tab_key]

        if not animate:
            target_pane.grid(row=0, column=0, sticky="nsew")
            self.after(20, lambda: attach_glass_rounded_hooks(target_pane))
            return

        steps = 6
        idx = 0

        def _tab_step() -> None:
            if self.is_closing:
                return
            nonlocal idx
            idx += 1
            pad_top = int(12 * (1.0 - idx / steps))
            target_pane.grid(row=0, column=0, sticky="nsew", pady=(pad_top, 0))
            if idx < steps:
                self.after(14, _tab_step)
            else:
                attach_glass_rounded_hooks(target_pane)

        _tab_step()

    # -------------------------------------------------------------------------
    # Report Panes Construction
    # -------------------------------------------------------------------------
    def _build_detection_pane(self) -> None:
        self.pane_detection.grid_columnconfigure(0, weight=1)
        self.pane_detection.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkLabel(
            self.pane_detection,
            text="Security Vendors' & Static Heuristics Analysis",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=VT_TEXT_PRIMARY,
            anchor="w",
        )
        hdr.grid(row=0, column=0, padx=16, pady=(12, 6), sticky="ew")

        self.detection_list_frame = ctk.CTkScrollableFrame(
            self.pane_detection,
            fg_color=VT_BG_MAIN,
            corner_radius=8,
        )
        self.detection_list_frame.grid(row=1, column=0, padx=16, pady=(0, 14), sticky="nsew")
        self.detection_list_frame.grid_columnconfigure(0, weight=1)
        self.detection_list_frame.grid_columnconfigure(1, weight=1)

    def _build_details_pane(self) -> None:
        self.pane_details.grid_columnconfigure(0, weight=1)
        self.pane_details.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkLabel(
            self.pane_details,
            text="Basic Properties, Cryptographic Hashes (MD5 / SHA-1 / SHA-256) & Signature Info",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=VT_TEXT_PRIMARY,
            anchor="w",
        )
        hdr.grid(row=0, column=0, padx=16, pady=(12, 6), sticky="ew")

        self.details_textbox = ctk.CTkTextbox(
            self.pane_details,
            fg_color=VT_BG_MAIN,
            text_color=VT_TEXT_PRIMARY,
            corner_radius=8,
            border_width=1,
            border_color=VT_BORDER,
            font=ctk.CTkFont(family="Consolas", size=13),
            wrap="none",
        )
        self.details_textbox.grid(row=1, column=0, padx=16, pady=(0, 14), sticky="nsew")

    def _build_relations_pane(self) -> None:
        self.pane_relations.grid_columnconfigure(0, weight=1)
        self.pane_relations.grid_columnconfigure(1, weight=1)
        self.pane_relations.grid_rowconfigure(1, weight=1)

        lbl_u = ctk.CTkLabel(
            self.pane_relations,
            text="Contacted / Embedded Domains & URLs",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        lbl_u.grid(row=0, column=0, padx=16, pady=(12, 6), sticky="ew")

        lbl_ip = ctk.CTkLabel(
            self.pane_relations,
            text="Embedded IPv4 Addresses (Public vs Private)",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        lbl_ip.grid(row=0, column=1, padx=16, pady=(12, 6), sticky="ew")

        self.urls_textbox = ctk.CTkTextbox(
            self.pane_relations,
            fg_color=VT_BG_MAIN,
            text_color=VT_TEXT_PRIMARY,
            corner_radius=8,
            border_width=1,
            border_color=VT_BORDER,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="none",
        )
        self.urls_textbox.grid(row=1, column=0, padx=(16, 8), pady=(0, 14), sticky="nsew")

        self.ips_textbox = ctk.CTkTextbox(
            self.pane_relations,
            fg_color=VT_BG_MAIN,
            text_color=VT_TEXT_PRIMARY,
            corner_radius=8,
            border_width=1,
            border_color=VT_BORDER,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="none",
        )
        self.ips_textbox.grid(row=1, column=1, padx=(8, 16), pady=(0, 14), sticky="nsew")

    def _build_behavior_pane(self) -> None:
        self.pane_behavior.grid_columnconfigure(0, weight=3)
        self.pane_behavior.grid_columnconfigure(1, weight=2)
        self.pane_behavior.grid_rowconfigure(2, weight=1)

        self.pe_summary_label = ctk.CTkLabel(
            self.pane_behavior,
            text="Capabilities, Section Entropy & PE Imports",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=VT_TEXT_PRIMARY,
            anchor="w",
        )
        self.pe_summary_label.grid(
            row=0, column=0, columnspan=2, padx=16, pady=(12, 4), sticky="ew"
        )

        # Highlighted MITRE ATT&CK Techniques banner (shown when pe_report.mitre_techniques is non-empty)
        self.mitre_banner_frame = ctk.CTkFrame(
            self.pane_behavior,
            fg_color=VT_BG_ELEVATED,
            corner_radius=8,
            border_width=1,
            border_color=VT_AMBER,
        )
        self.mitre_banner_frame.grid_columnconfigure(0, weight=1)

        self.mitre_banner_title = ctk.CTkLabel(
            self.mitre_banner_frame,
            text="⚔  MITRE ATT&CK® Techniques Identified",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=VT_AMBER,
            anchor="w",
        )
        self.mitre_banner_title.grid(row=0, column=0, padx=12, pady=(8, 2), sticky="ew")

        self.mitre_badges_flow = ctk.CTkFrame(
            self.mitre_banner_frame, fg_color="transparent", corner_radius=0
        )
        self.mitre_badges_flow.grid(row=1, column=0, padx=10, pady=(2, 8), sticky="ew")

        self.sections_textbox = ctk.CTkTextbox(
            self.pane_behavior,
            fg_color=VT_BG_MAIN,
            text_color=VT_TEXT_PRIMARY,
            corner_radius=8,
            border_width=1,
            border_color=VT_BORDER,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="none",
        )
        self.sections_textbox.grid(row=2, column=0, padx=(16, 8), pady=(4, 14), sticky="nsew")

        self.imports_textbox = ctk.CTkTextbox(
            self.pane_behavior,
            fg_color=VT_BG_MAIN,
            text_color=VT_TEXT_PRIMARY,
            corner_radius=8,
            border_width=1,
            border_color=VT_BORDER,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="none",
        )
        self.imports_textbox.grid(row=2, column=1, padx=(8, 16), pady=(4, 14), sticky="nsew")

    def _build_community_pane(self) -> None:
        self.pane_community.grid_columnconfigure(0, weight=3)
        self.pane_community.grid_columnconfigure(1, weight=2)
        self.pane_community.grid_rowconfigure(1, weight=1)

        top_bar = ctk.CTkFrame(self.pane_community, fg_color="transparent", corner_radius=0)
        top_bar.grid(row=0, column=0, columnspan=2, padx=16, pady=(12, 6), sticky="ew")
        top_bar.grid_columnconfigure(0, weight=1)

        self.community_banner = ctk.CTkLabel(
            top_bar,
            text="Community Intelligence (Stored locally in ~/.vyrulix/community.json unless a cloud proxy is configured)  •  Scan an item to view or share verdicts",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#60A5FA",
            anchor="w",
        )
        self.community_banner.grid(row=0, column=0, sticky="w")

        self.sync_btn = ctk.CTkButton(
            top_bar,
            text="↻ Refresh Feed",
            width=125,
            height=30,
            corner_radius=8,
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_BORDER,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_manual_sync_community,
        )
        self.sync_btn.grid(row=0, column=1, padx=6, sticky="e")

        self.community_feed_scroll = ctk.CTkScrollableFrame(
            self.pane_community,
            fg_color=VT_BG_MAIN,
            corner_radius=8,
        )
        self.community_feed_scroll.grid(
            row=1, column=0, padx=(16, 8), pady=(0, 14), sticky="nsew"
        )
        self.community_feed_scroll.grid_columnconfigure(0, weight=1)

        self.composer_card = ctk.CTkFrame(
            self.pane_community,
            fg_color=VT_BG_MAIN,
            corner_radius=8,
            border_width=1,
            border_color=VT_BORDER,
        )
        self.composer_card.grid(row=1, column=1, padx=(8, 16), pady=(0, 14), sticky="nsew")
        self.composer_card.grid_columnconfigure(0, weight=1)
        self.composer_card.grid_rowconfigure(4, weight=1)

        self.composer_title_lbl = ctk.CTkLabel(
            self.composer_card,
            text="Share Your Verdict & Thoughts",
            font=ctk.CTkFont(size=15, weight="bold"),
            anchor="w",
        )
        self.composer_title_lbl.grid(row=0, column=0, padx=14, pady=(14, 4), sticky="ew")

        self.composer_auth_status_lbl = ctk.CTkLabel(
            self.composer_card,
            text="You must be signed in to post a comment.",
            font=ctk.CTkFont(size=12),
            text_color=VT_AMBER,
            anchor="w",
        )
        self.composer_auth_status_lbl.grid(row=1, column=0, padx=14, pady=(0, 8), sticky="ew")

        verdict_bar = ctk.CTkFrame(self.composer_card, fg_color="transparent", corner_radius=0)
        verdict_bar.grid(row=2, column=0, padx=14, pady=6, sticky="ew")
        for col_i in range(3):
            verdict_bar.grid_columnconfigure(col_i, weight=1)

        self.selected_verdict = "Safe"
        self.verdict_btns: Dict[str, ctk.CTkButton] = {}
        for idx, v_name in enumerate(VALID_VERDICTS):
            vb = ctk.CTkButton(
                verdict_bar,
                text=v_name,
                height=32,
                corner_radius=8,
                fg_color=VT_BLUE if v_name == "Safe" else VT_BG_ELEVATED,
                hover_color=VT_BLUE_HOVER,
                text_color="#FFFFFF" if v_name == "Safe" else VT_TEXT_MUTED,
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda vn=v_name: self._select_verdict_pill(vn),
            )
            vb.grid(row=0, column=idx, padx=3, sticky="ew")
            self.verdict_btns[v_name] = vb

        self.comment_input = ctk.CTkTextbox(
            self.composer_card,
            fg_color=VT_BG_SURFACE,
            corner_radius=8,
            border_width=1,
            border_color=VT_BORDER,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            wrap="word",
        )
        self.comment_input.grid(row=4, column=0, padx=14, pady=8, sticky="nsew")

        self.submit_comment_btn = ctk.CTkButton(
            self.composer_card,
            text="Post Comment",
            height=38,
            corner_radius=8,
            fg_color=VT_BLUE,
            hover_color=VT_BLUE_HOVER,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._on_submit_community_comment,
        )
        self.submit_comment_btn.grid(row=5, column=0, padx=14, pady=(4, 14), sticky="ew")

    def _select_verdict_pill(self, verdict_name: str) -> None:
        self.selected_verdict = verdict_name
        for k, btn in self.verdict_btns.items():
            if k == verdict_name:
                btn.configure(fg_color=VT_BLUE, text_color="#FFFFFF")
            else:
                btn.configure(fg_color=VT_BG_ELEVATED, text_color=VT_TEXT_MUTED)
            apply_rounded_hwnd_clip(btn, force=True)

    # -------------------------------------------------------------------------
    # 3. Upgraded Sign In / Sign Up Page (Email, Confirm Password, Show Password 👁)
    # -------------------------------------------------------------------------
    def _build_auth_view(self) -> None:
        self.auth_view.grid_columnconfigure(0, weight=1)
        self.auth_view.grid_rowconfigure(0, weight=1)

        auth_card = ctk.CTkFrame(
            self.auth_view,
            fg_color=VT_BG_SURFACE,
            corner_radius=12,
            border_width=1,
            border_color=VT_BORDER,
            width=540,
        )
        auth_card.grid(row=0, column=0, padx=240, pady=24, sticky="nsew")
        auth_card.grid_columnconfigure(0, weight=1)

        hdr_lbl = ctk.CTkLabel(
            auth_card,
            text="⛨  Vyrulix Community Account",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#60A5FA",
        )
        hdr_lbl.pack(pady=(20, 4))

        sub_lbl = ctk.CTkLabel(
            auth_card,
            text="Sign in with your username or email, or create a local-first analyst account.",
            font=ctk.CTkFont(size=13),
            text_color=VT_TEXT_MUTED,
        )
        sub_lbl.pack(pady=(0, 12))

        switch_row = ctk.CTkFrame(auth_card, fg_color="transparent", corner_radius=0)
        switch_row.pack(padx=40, pady=6, fill="x")
        switch_row.grid_columnconfigure(0, weight=1)
        switch_row.grid_columnconfigure(1, weight=1)

        self.auth_tab_signin_btn = ctk.CTkButton(
            switch_row,
            text="Sign In",
            height=36,
            corner_radius=8,
            fg_color=VT_BLUE,
            hover_color=VT_BLUE_HOVER,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=lambda: self._on_auth_mode_changed("Sign In"),
        )
        self.auth_tab_signin_btn.grid(row=0, column=0, padx=4, sticky="ew")

        self.auth_tab_signup_btn = ctk.CTkButton(
            switch_row,
            text="Sign Up",
            height=36,
            corner_radius=8,
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_BLUE_HOVER,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=lambda: self._on_auth_mode_changed("Sign Up"),
        )
        self.auth_tab_signup_btn.grid(row=0, column=1, padx=4, sticky="ew")

        self.auth_form_frame = ctk.CTkFrame(auth_card, fg_color="transparent", corner_radius=0)
        self.auth_form_frame.pack(padx=40, pady=6, fill="both", expand=True)
        self.auth_form_frame.grid_columnconfigure(0, weight=1)

        self.auth_feedback_lbl = ctk.CTkLabel(
            auth_card,
            text="",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=VT_GREEN,
            wraplength=460,
        )
        self.auth_feedback_lbl.pack(pady=(2, 6))

        back_btn = ctk.CTkButton(
            auth_card,
            text="← Back to Analyzer",
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_BORDER,
            text_color=VT_TEXT_MUTED,
            corner_radius=8,
            height=34,
            command=lambda: self._show_view("REPORT" if self.current_report else "HOME"),
        )
        back_btn.pack(pady=(0, 16))

        self._on_auth_mode_changed("Sign In")

    def _open_auth_page(self, initial_tab: str = "SIGN_IN") -> None:
        self._show_view("AUTH")
        if initial_tab == "SIGN_UP":
            self._on_auth_mode_changed("Sign Up")
        else:
            self._on_auth_mode_changed("Sign In")

    @staticmethod
    def _toggle_password_visibility(entry_widget: ctk.CTkEntry, toggle_btn: ctk.CTkButton) -> None:
        """Toggles a password entry's `show` attribute between `'*'` and `''`."""
        current_show = str(entry_widget.cget("show") or "")
        if current_show == "*":
            entry_widget.configure(show="")
            toggle_btn.configure(fg_color=VT_BLUE, text_color="#FFFFFF")
        else:
            entry_widget.configure(show="*")
            toggle_btn.configure(fg_color=VT_BG_ELEVATED, text_color=VT_TEXT_PRIMARY)
        apply_rounded_hwnd_clip(toggle_btn, force=True)

    def _create_password_row(
        self, parent: ctk.CTkFrame, placeholder: str = "Enter your password"
    ) -> ctk.CTkEntry:
        """Creates a password entry field paired with an inline '👁' show-password toggle button."""
        row = ctk.CTkFrame(parent, fg_color="transparent", corner_radius=0)
        row.pack(fill="x", pady=(0, 10))
        row.grid_columnconfigure(0, weight=1)

        entry = ctk.CTkEntry(
            row,
            placeholder_text=placeholder,
            show="*",
            height=36,
            corner_radius=8,
            fg_color=VT_BG_MAIN,
            border_color=VT_BORDER,
        )
        entry.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        eye_btn = ctk.CTkButton(
            row,
            text="👁",
            width=40,
            height=36,
            corner_radius=8,
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_BORDER,
            text_color=VT_TEXT_PRIMARY,
            font=ctk.CTkFont(size=14),
        )
        eye_btn.configure(
            command=lambda e=entry, b=eye_btn: self._toggle_password_visibility(e, b)
        )
        eye_btn.grid(row=0, column=1)
        return entry

    def _on_auth_mode_changed(self, selected: str) -> None:
        if hasattr(self, "auth_tab_signin_btn") and hasattr(self, "auth_tab_signup_btn"):
            if selected == "Sign In":
                self.auth_tab_signin_btn.configure(fg_color=VT_BLUE, text_color="#FFFFFF")
                self.auth_tab_signup_btn.configure(fg_color=VT_BG_ELEVATED, text_color=VT_TEXT_MUTED)
            else:
                self.auth_tab_signin_btn.configure(fg_color=VT_BG_ELEVATED, text_color=VT_TEXT_MUTED)
                self.auth_tab_signup_btn.configure(fg_color=VT_BLUE, text_color="#FFFFFF")
            apply_rounded_hwnd_clip(self.auth_tab_signin_btn, force=True)
            apply_rounded_hwnd_clip(self.auth_tab_signup_btn, force=True)

        for child in self.auth_form_frame.winfo_children():
            child.destroy()
        self.auth_feedback_lbl.configure(text="")

        if selected == "Sign In":
            ctk.CTkLabel(
                self.auth_form_frame,
                text="Username or Email:",
                anchor="w",
                font=ctk.CTkFont(size=13, weight="bold"),
            ).pack(fill="x", pady=(6, 2))
            self.auth_user_entry = ctk.CTkEntry(
                self.auth_form_frame,
                placeholder_text="Enter your username or email address",
                height=36,
                corner_radius=8,
                fg_color=VT_BG_MAIN,
                border_color=VT_BORDER,
            )
            self.auth_user_entry.pack(fill="x", pady=(0, 10))

            ctk.CTkLabel(
                self.auth_form_frame,
                text="Password:",
                anchor="w",
                font=ctk.CTkFont(size=13, weight="bold"),
            ).pack(fill="x", pady=(2, 2))
            self.auth_pass_entry = self._create_password_row(
                self.auth_form_frame, placeholder="Enter your password"
            )

        else:
            # Sign Up Flow: Username, Email Address, Password, Confirm Password, Role
            ctk.CTkLabel(
                self.auth_form_frame,
                text="Username:",
                anchor="w",
                font=ctk.CTkFont(size=13, weight="bold"),
            ).pack(fill="x", pady=(4, 2))
            self.auth_user_entry = ctk.CTkEntry(
                self.auth_form_frame,
                placeholder_text="Choose a username",
                height=36,
                corner_radius=8,
                fg_color=VT_BG_MAIN,
                border_color=VT_BORDER,
            )
            self.auth_user_entry.pack(fill="x", pady=(0, 8))

            ctk.CTkLabel(
                self.auth_form_frame,
                text="Email Address:",
                anchor="w",
                font=ctk.CTkFont(size=13, weight="bold"),
            ).pack(fill="x", pady=(2, 2))
            self.auth_email_entry = ctk.CTkEntry(
                self.auth_form_frame,
                placeholder_text="analyst@example.com",
                height=36,
                corner_radius=8,
                fg_color=VT_BG_MAIN,
                border_color=VT_BORDER,
            )
            self.auth_email_entry.pack(fill="x", pady=(0, 8))

            ctk.CTkLabel(
                self.auth_form_frame,
                text="Password (min 6 chars):",
                anchor="w",
                font=ctk.CTkFont(size=13, weight="bold"),
            ).pack(fill="x", pady=(2, 2))
            self.auth_pass_entry = self._create_password_row(
                self.auth_form_frame, placeholder="Create a password"
            )

            ctk.CTkLabel(
                self.auth_form_frame,
                text="Confirm Password:",
                anchor="w",
                font=ctk.CTkFont(size=13, weight="bold"),
            ).pack(fill="x", pady=(2, 2))
            self.auth_confirm_pass_entry = self._create_password_row(
                self.auth_form_frame, placeholder="Re-enter your password"
            )

            ctk.CTkLabel(
                self.auth_form_frame,
                text="Role / Badge Title:",
                anchor="w",
                font=ctk.CTkFont(size=13, weight="bold"),
            ).pack(fill="x", pady=(2, 2))
            self.auth_role_entry = ctk.CTkEntry(
                self.auth_form_frame,
                placeholder_text="e.g. Security Researcher / Malware Analyst",
                height=36,
                corner_radius=8,
                fg_color=VT_BG_MAIN,
                border_color=VT_BORDER,
            )
            self.auth_role_entry.insert(0, "Security Researcher")
            self.auth_role_entry.pack(fill="x", pady=(0, 8))

        action_text = "Sign In" if selected == "Sign In" else "Create Account"
        submit_btn = ctk.CTkButton(
            self.auth_form_frame,
            text=action_text,
            height=40,
            corner_radius=8,
            fg_color=VT_BLUE,
            hover_color=VT_BLUE_HOVER,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=lambda m=selected: self._submit_auth_form(m),
        )
        submit_btn.pack(fill="x", pady=10)
        self.after(20, lambda: attach_glass_rounded_hooks(self.auth_form_frame))

    def _submit_auth_form(self, mode: str) -> None:
        identifier_or_user = self.auth_user_entry.get().strip()
        password = self.auth_pass_entry.get().strip()

        try:
            if mode == "Sign Up":
                email = self.auth_email_entry.get().strip()
                confirm_pw = self.auth_confirm_pass_entry.get().strip()
                role = self.auth_role_entry.get().strip() or "Security Researcher"
                session = self.community_db.register_user(
                    username=identifier_or_user,
                    password=password,
                    email=email,
                    confirm_password=confirm_pw,
                    role=role,
                )
                self.status_label.configure(
                    text=f"✔ Account created for {session['handle']} ({session['role']})",
                    text_color=VT_GREEN,
                )
            else:
                session = self.community_db.login_user(
                    identifier=identifier_or_user,
                    password=password,
                )
                self.status_label.configure(
                    text=f"✔ Signed in as {session['handle']} ({session['role']})",
                    text_color=VT_GREEN,
                )

            self.auth_feedback_lbl.configure(
                text=f"✔ Signed in as {session['handle']} ({session['role']})",
                text_color=VT_GREEN,
            )
            self._refresh_navbar_auth_state()
            if self.current_report:
                self._refresh_community_tab(self.current_report.sha256)
                self._show_view("REPORT")
                self._select_report_tab("COMMUNITY")
            else:
                self._show_view("HOME")
        except Exception as exc:
            self.auth_feedback_lbl.configure(text=f"✖ {exc}", text_color=VT_RED)

    def _refresh_navbar_auth_state(self) -> None:
        for child in self.auth_nav_frame.winfo_children():
            child.destroy()

        user = self.community_db.get_current_user()
        if user:
            badge = ctk.CTkButton(
                self.auth_nav_frame,
                text=f"👤 {user['handle']}",
                height=34,
                corner_radius=8,
                fg_color=VT_BG_SURFACE,
                hover_color=VT_BORDER,
                text_color="#60A5FA",
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda: self._open_auth_page("SIGN_IN"),
            )
            badge.pack(side="left", padx=4)

            out_btn = ctk.CTkButton(
                self.auth_nav_frame,
                text="Sign Out",
                width=80,
                height=34,
                corner_radius=8,
                fg_color=VT_BG_SURFACE,
                hover_color=VT_BORDER,
                border_width=1,
                border_color=VT_BORDER,
                text_color=VT_TEXT_MUTED,
                font=ctk.CTkFont(size=12),
                command=self._on_logout,
            )
            out_btn.pack(side="left", padx=4)

            self.composer_auth_status_lbl.configure(
                text=f"Posting as {user['handle']} ({user.get('role', 'Analyst')})",
                text_color=VT_GREEN,
            )
            self.submit_comment_btn.configure(text="Post Verdict & Comment")
        else:
            signin_btn = ctk.CTkButton(
                self.auth_nav_frame,
                text="Sign In",
                width=80,
                height=34,
                corner_radius=8,
                fg_color=VT_BG_SURFACE,
                hover_color=VT_BORDER,
                border_width=1,
                border_color=VT_BORDER,
                text_color=VT_TEXT_PRIMARY,
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda: self._open_auth_page("SIGN_IN"),
            )
            signin_btn.pack(side="left", padx=4)

            signup_btn = ctk.CTkButton(
                self.auth_nav_frame,
                text="Sign Up",
                width=84,
                height=34,
                corner_radius=8,
                fg_color=VT_BLUE,
                hover_color=VT_BLUE_HOVER,
                text_color="#FFFFFF",
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda: self._open_auth_page("SIGN_UP"),
            )
            signup_btn.pack(side="left", padx=4)

            self.composer_auth_status_lbl.configure(
                text="⚠ You must be signed in to post a comment (Click 'Sign In' in top right).",
                text_color=VT_AMBER,
            )
            self.submit_comment_btn.configure(text="Sign In to Post Comment")

        self.after(20, lambda: attach_glass_rounded_hooks(self.auth_nav_frame))

    def _on_logout(self) -> None:
        self.community_db.logout_user()
        self._refresh_navbar_auth_state()
        if self.current_report:
            self._refresh_community_tab(self.current_report.sha256)

    # -------------------------------------------------------------------------
    # Unified "Analyze Now" <-> "Stop" Button & Background Scanning
    # -------------------------------------------------------------------------
    def _set_action_button_scanning_state(self, scanning: bool) -> None:
        self.is_scanning = scanning
        if scanning:
            self.action_scan_btn.configure(
                text="Stop",
                fg_color=VT_RED,
                hover_color="#B91C1C",
            )
            self.browse_btn.configure(state="disabled")
        else:
            self.action_scan_btn.configure(
                text="Analyze Now",
                fg_color=VT_BLUE,
                hover_color=VT_BLUE_HOVER,
            )
            self.browse_btn.configure(state="normal")
        apply_rounded_hwnd_clip(self.action_scan_btn, force=True)

    def _on_browse_file(self) -> None:
        filepath = filedialog.askopenfilename(
            title="Select Target File for Vyrulix"
        )
        if filepath:
            self.selected_filepath = filepath
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, filepath)

    def _on_action_scan_or_stop(self) -> None:
        if self.is_scanning and self.scan_thread is not None and self.scan_thread.is_alive():
            self.cancel_event.set()
            self.pending_auto_files.clear()
            self.status_label.configure(text="Stopping scan...", text_color=VT_AMBER)
            return

        target_input = self.file_entry.get().strip()
        if not target_input:
            self.status_label.configure(
                text="⚠ Choose a file or enter a URL, IP, domain, or SHA-256 hash first.",
                text_color=VT_AMBER,
            )
            return

        self._start_scan_from_input(target_input)

    def _start_scan_from_input(self, target_input: str, force_kind: Optional[str] = None) -> None:
        if self.is_scanning and self.scan_thread is not None and self.scan_thread.is_alive():
            return

        self.cancel_event.clear()
        self._set_action_button_scanning_state(True)
        self._sync_report_action_buttons(None)
        self._show_view("REPORT")
        self.progress_bar.set(0.0)
        self.status_label.configure(
            text=f"Analyzing {os.path.basename(target_input) or target_input}...",
            text_color="#60A5FA",
        )

        self.scan_thread = threading.Thread(
            target=self._background_scan_worker,
            args=(target_input, self.file_filter_mode, force_kind),
            daemon=True,
        )
        self.scan_thread.start()

    def _background_scan_worker(
        self, target_input: str, mode: str, force_kind: Optional[str]
    ) -> None:
        def _progress_cb(percent: float, mb_done: float, total_mb: float) -> None:
            if not self.is_closing:
                self.ui_queue.put(("PROGRESS", (percent, mb_done, total_mb)))

        def _status_cb(status_msg: str) -> None:
            if not self.is_closing:
                self.ui_queue.put(("STATUS", status_msg))

        if force_kind == "URL":
            report = self.scanner.scan_url(target_input)
        elif force_kind == "SEARCH":
            report = self.scanner.scan_search_query(
                target_input,
                status_callback=_status_cb,
                cancel_event=self.cancel_event,
            )
        elif os.path.isfile(target_input):
            report = self.scanner.scan_file(
                filepath=target_input,
                mode=mode,
                progress_callback=_progress_cb,
                cancel_event=self.cancel_event,
                status_callback=_status_cb,
            )
        else:
            report = self.scanner.scan_search_query(
                target_input,
                status_callback=_status_cb,
                cancel_event=self.cancel_event,
            )

        if not self.is_closing:
            self.ui_queue.put(("COMPLETE", report))

    def _poll_ui_queue(self) -> None:
        if self.is_closing:
            return
        try:
            while True:
                event_type, payload = self.ui_queue.get_nowait()
                if event_type == "PROGRESS":
                    percent, mb_done, total_mb = payload
                    self.progress_bar.set(max(0.0, min(1.0, percent / 100.0)))
                    self.status_label.configure(
                        text=f"Scanning: {percent:5.1f}%  •  {mb_done:,.1f} / {total_mb:,.1f} MB",
                        text_color="#60A5FA",
                    )
                elif event_type == "STATUS":
                    status_text = str(payload)
                    is_throttled = "Throttled - Retrying" in status_text
                    self.status_label.configure(
                        text=f"⏳ {status_text}" if is_throttled else f"🔎 {status_text}",
                        text_color=VT_AMBER if is_throttled else "#60A5FA",
                    )
                elif event_type == "YARA_SYNC_DONE":
                    ok, sync_msg = payload
                    if hasattr(self, "sync_yara_btn"):
                        self.sync_yara_btn.configure(state="normal", text="↻ Sync Threat Rules")
                        apply_rounded_hwnd_clip(self.sync_yara_btn, force=True)
                    self.yara_rules_path = self.scanner.yara_rules_path
                    active_yar = os.path.basename(self.yara_rules_path) or "vyrulix_master.yar"
                    self.status_label.configure(
                        text=f"{'✔' if ok else '⚠'} {sync_msg}  •  Active: {active_yar}",
                        text_color=VT_GREEN if ok else VT_AMBER,
                    )
                    self._show_completion_toast(
                        sync_msg, border_color=VT_GREEN if ok else VT_AMBER
                    )
                    send_desktop_notification("Vyrulix Threat Rules Sync", sync_msg)
                elif event_type == "COMPLETE":
                    self.is_uploading_vt = False
                    self.is_detonating_sandbox = False
                    self._handle_scan_complete(payload)
                elif event_type == "VT_UPLOAD_DONE":
                    self.is_uploading_vt = False
                    self._handle_scan_complete(payload)
                elif event_type == "SANDBOX_DONE":
                    self.is_detonating_sandbox = False
                    self._handle_scan_complete(payload)
                elif event_type == "COMMUNITY_SYNC_DONE":
                    synced_sha = str(payload or "")
                    if self.current_report and self.current_report.sha256 == synced_sha:
                        self._refresh_community_tab(synced_sha, sync_online=False)
                elif event_type == "AUTO_FILE":
                    new_filepath = str(payload)
                    if os.path.isfile(new_filepath):
                        if self.is_scanning:
                            # Queue auto-scanned files instead of dropping them
                            if new_filepath not in self.pending_auto_files:
                                self.pending_auto_files.append(new_filepath)
                        else:
                            self.file_entry.delete(0, "end")
                            self.file_entry.insert(0, new_filepath)
                            self._start_scan_from_input(new_filepath)
        except queue.Empty:
            pass
        finally:
            if not self.is_closing:
                self._poll_tick_counter = (self._poll_tick_counter + 1) % 15
                if self._poll_tick_counter == 0 and self.current_report is not None:
                    self._sync_report_action_buttons(self.current_report, quiet=True)
                self._poll_after_id = self.after(40, self._poll_ui_queue)

    # -------------------------------------------------------------------------
    # Rendering VirusTotal-Style Report, Sequential Auto-Scan Queue & >5s Toast
    # -------------------------------------------------------------------------
    def _sync_report_action_buttons(
        self, report: Optional[ScanReport], quiet: bool = False
    ) -> None:
        """
        Dynamically synchronizes the enabled/disabled state and visual styling of
        `📦 Detonate in Sandbox (.wsb)` and `☁ Upload to VirusTotal` based on:
          1. Real-time local file availability on disk (`os.path.isfile(report.filepath)`).
          2. VirusTotal HTTP 404 uncataloged response status (`report.vt_uncataloged_404`).
          3. Active non-blocking background I/O tasks (`is_scanning`, `is_uploading_vt`, `is_detonating_sandbox`).
        """
        filepath_str = getattr(report, "filepath", "") if report is not None else ""
        is_local_file = bool(
            report is not None
            and not report.skipped
            and not report.error
            and filepath_str
            and os.path.isfile(filepath_str)
        )
        is_404 = bool(is_local_file and getattr(report, "vt_uncataloged_404", False))
        busy_io = bool(self.is_scanning or self.is_uploading_vt or self.is_detonating_sandbox)

        state_key = (
            filepath_str,
            is_local_file,
            is_404,
            self.is_uploading_vt,
            self.is_detonating_sandbox,
        )
        if quiet and state_key == self._last_synced_file_state:
            return
        self._last_synced_file_state = state_key

        if hasattr(self, "sandbox_detonate_btn"):
            if self.is_detonating_sandbox:
                self.sandbox_detonate_btn.configure(
                    state="disabled",
                    text="📦 Detonating (15s .wsb)...",
                    fg_color=VT_BG_ELEVATED,
                    text_color=VT_AMBER,
                )
            elif is_local_file and not busy_io:
                self.sandbox_detonate_btn.configure(
                    state="normal",
                    text="📦 Detonate in Sandbox (15s .wsb)",
                    fg_color=VT_BG_ELEVATED,
                    text_color="#60A5FA",
                )
            else:
                self.sandbox_detonate_btn.configure(
                    state="disabled",
                    text="📦 Detonate in Sandbox (.wsb)" if not filepath_str else "📦 Sandbox (File Unavailable)",
                    fg_color=VT_BG_ELEVATED,
                    text_color=VT_TEXT_MUTED,
                )
            apply_rounded_hwnd_clip(self.sandbox_detonate_btn, force=True)

        if hasattr(self, "vt_upload_btn"):
            if self.is_uploading_vt:
                self.vt_upload_btn.configure(
                    state="disabled",
                    text="☁ Uploading to VT...",
                    fg_color=VT_BG_ELEVATED,
                    text_color=VT_AMBER,
                )
            elif is_local_file and is_404 and not busy_io:
                self.vt_upload_btn.configure(
                    state="normal",
                    text="☁ Upload 404 Sample to VT",
                    fg_color=VT_AMBER,
                    text_color="#111521",
                )
            elif is_local_file and not busy_io:
                self.vt_upload_btn.configure(
                    state="normal",
                    text="☁ Upload to VirusTotal",
                    fg_color=VT_BG_ELEVATED,
                    text_color=VT_AMBER,
                )
            else:
                self.vt_upload_btn.configure(
                    state="disabled",
                    text="☁ Upload to VirusTotal" if not filepath_str else "☁ Upload (File Unavailable)",
                    fg_color=VT_BG_ELEVATED,
                    text_color=VT_TEXT_MUTED,
                )
            apply_rounded_hwnd_clip(self.vt_upload_btn, force=True)

    def _handle_scan_complete(self, report: ScanReport) -> None:
        self.current_report = report
        self._update_current_report_button_visibility()
        self._set_action_button_scanning_state(False)
        self._sync_report_action_buttons(report)

        if report.cancelled:
            self.status_label.configure(text="Scan stopped by user.", text_color=VT_AMBER)
            return

        if report.skipped:
            self.progress_bar.set(0.0)
            self.status_label.configure(text=report.skip_reason, text_color=VT_AMBER)
            self.verdict_banner_frame.configure(border_color=VT_AMBER)
            self.verdict_banner_lbl.configure(
                text=f"⚠  {report.skip_reason}",
                text_color=VT_AMBER,
            )
            self._drain_next_auto_file()
            return

        if report.error:
            self.status_label.configure(text=f"Error: {report.error}", text_color=VT_RED)
            self._drain_next_auto_file()
            return

        self.progress_bar.set(1.0)
        self.status_label.configure(
            text=f"Complete  •  {report.human_size} analyzed in {report.scan_duration_sec:.2f}s",
            text_color=VT_TEXT_MUTED if report.verdict_label == "Unknown" else VT_GREEN,
        )

        self.score_gauge.set_score(
            report.flagged_count, report.total_engines, report.verdict_label, animate=True
        )

        if report.verdict_label == "Malicious":
            color = VT_RED
            prefix = "✖  "
        elif report.verdict_label == "Suspicious":
            color = VT_AMBER
            prefix = "⚠  "
        elif report.verdict_label == "Unknown":
            color = VT_GREY
            prefix = "●  "
        else:
            color = VT_GREEN
            prefix = "✔  "

        self.verdict_banner_frame.configure(border_color=color)
        self.verdict_banner_lbl.configure(
            text=f"{prefix}{report.verdict_summary}",
            text_color=color,
        )
        apply_rounded_hwnd_clip(self.verdict_banner_frame, force=True)

        self.lbl_sha256_top.configure(text=report.sha256)
        self.lbl_filename_top.configure(
            text=f"{report.filename}   •   {report.file_type_label}"
        )
        self.tags_row_lbl.configure(
            text="Tags:  " + "   ".join(f"[{t}]" for t in report.tags)
        )
        self.lbl_right_size.configure(
            text=f"Size\n{report.human_size}"
        )
        self.lbl_right_speed.configure(
            text=f"Speed\n{report.throughput_mb_s:,.1f} MB/s\n({report.scan_duration_sec:.2f}s)"
        )
        self.ext_badge.configure(text=report.file_extension[:5])

        self._populate_detection_pane(report)
        self._populate_details_pane(report)
        self._populate_relations_pane(report)
        self._populate_behavior_pane(report)
        self._refresh_community_tab(report.sha256)

        if report.scan_duration_sec >= 5.0:
            notif_msg = (
                f"Scan finished in {report.scan_duration_sec:.1f}s: "
                f"{report.filename} — {report.verdict_label.upper()}"
            )
            self._show_completion_toast(notif_msg, border_color=color)
            send_desktop_notification("Vyrulix Analysis Ready", notif_msg)

        # Pop and scan next queued Auto-Scan file sequentially if any are waiting
        self._drain_next_auto_file()

    def _drain_next_auto_file(self) -> None:
        while self.pending_auto_files and not self.is_scanning and not self.is_closing:
            next_filepath = self.pending_auto_files.popleft()
            if os.path.isfile(next_filepath):
                self.file_entry.delete(0, "end")
                self.file_entry.insert(0, next_filepath)
                self._start_scan_from_input(next_filepath)
                break

    def _populate_detection_pane(self, report: ScanReport) -> None:
        for child in self.detection_list_frame.winfo_children():
            child.destroy()

        mitre_regex = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")

        for idx, det in enumerate(report.detections):
            row_idx = idx // 2
            col_idx = idx % 2

            combined_text = f"{det.engine_name} {det.category} {det.detail}"
            mitre_ids = list(dict.fromkeys(mitre_regex.findall(combined_text)))
            has_mitre_tag = bool(mitre_ids) or (
                "MITRE ATT&CK" in combined_text and det.status in ("Malicious", "Suspicious")
            )

            if det.status == "Malicious":
                badge_text = "✖ Malicious"
                badge_color = VT_RED
                card_border = VT_RED if has_mitre_tag else VT_BORDER
            elif det.status == "Suspicious":
                badge_text = "⚠ Suspicious"
                badge_color = VT_AMBER
                card_border = VT_AMBER if has_mitre_tag else VT_BORDER
            elif det.status == "Unknown":
                badge_text = "● Unknown / No Prior Intel"
                badge_color = VT_GREY
                card_border = VT_BORDER
            else:
                badge_text = "✔ Undetected"
                badge_color = VT_GREEN
                card_border = VT_BORDER

            card = ctk.CTkFrame(
                self.detection_list_frame,
                fg_color=VT_BG_ELEVATED if has_mitre_tag else VT_BG_SURFACE,
                corner_radius=8,
                border_width=1,
                border_color=card_border,
            )
            card.grid(row=row_idx, column=col_idx, padx=6, pady=6, sticky="ew")
            card.grid_columnconfigure(0, weight=1)

            top_line = ctk.CTkFrame(card, fg_color="transparent", corner_radius=0)
            top_line.grid(row=0, column=0, padx=12, pady=(10, 2), sticky="ew")
            top_line.grid_columnconfigure(0, weight=1)

            eng_lbl = ctk.CTkLabel(
                top_line,
                text=f"{det.engine_name}  ({det.category})",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=VT_TEXT_PRIMARY,
                anchor="w",
            )
            eng_lbl.grid(row=0, column=0, sticky="w")

            if has_mitre_tag:
                mitre_pill_text = (
                    f"⚔ MITRE {', '.join(mitre_ids[:2])}"
                    if mitre_ids
                    else "⚔ MITRE ATT&CK"
                )
                mitre_pill = ctk.CTkLabel(
                    top_line,
                    text=mitre_pill_text,
                    fg_color=VT_BG_MAIN,
                    text_color="#C084FC" if det.status != "Malicious" else "#FCA5A5",
                    corner_radius=6,
                    font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                    padx=8,
                    pady=2,
                )
                mitre_pill.grid(row=0, column=1, padx=(6, 8), sticky="e")

            status_lbl = ctk.CTkLabel(
                top_line,
                text=badge_text,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=badge_color,
                anchor="e",
            )
            status_lbl.grid(row=0, column=2, sticky="e")

            desc_lbl = ctk.CTkLabel(
                card,
                text=det.detail,
                font=ctk.CTkFont(size=12),
                text_color=VT_TEXT_PRIMARY if has_mitre_tag else VT_TEXT_MUTED,
                anchor="w",
                justify="left",
                wraplength=480,
            )
            desc_lbl.grid(row=1, column=0, padx=12, pady=(0, 10), sticky="ew")

        self.after(20, lambda: attach_glass_rounded_hooks(self.detection_list_frame))

    def _populate_details_pane(self, report: ScanReport) -> None:
        pe = report.pe_report
        if pe.is_pe:
            sig_status = (
                f"{getattr(pe, 'signature_status', 'Signed')} — Publisher: {getattr(pe, 'signer_subject', '') or 'N/A'} "
                f"(Offset: 0x{pe.signature_offset:X}, Size: {pe.signature_size:,} bytes)"
                if pe.is_signed
                else "Unsigned PE Binary (WinVerifyTrust: No embedded Authenticode certificate)"
            )
            map_backend = getattr(pe, "mapping_backend", "ZeroCopy::MapViewOfFile")
            dos_nt_info = (
                f"e_lfanew={getattr(pe, 'dos_lfanew', '0x0')} | ImageBase={pe.image_base} | "
                f"EP={pe.entry_point} ({pe.entry_point_section}) | IAT={getattr(pe, 'iat_rva', '0x0')} ({getattr(pe, 'iat_size', 0):,} B)"
            )
        else:
            sig_status = "Not applicable (Non-PE Target)"
            map_backend = "ZeroCopy::MemoryMap"
            dos_nt_info = "Not applicable (Non-PE Target)"

        overlay_status = (
            f"Present ({pe.overlay_size:,} bytes beyond aligned sections/certificate)"
            if pe.has_overlay
            else "None"
        )
        imphash_val = getattr(report, "imphash", "") or getattr(pe, "imphash", "") or "N/A (Non-PE or no imports)"
        ssdeep_val = getattr(report, "ssdeep", "") or "N/A"
        tlsh_val = getattr(report, "tlsh", "") or "N/A"
        variants = list(getattr(report, "variant_matches", []) or [])

        lines = [
            "BASIC PROPERTIES, ZERO-COPY MEMORY MAP & AUTHENTICODE TRUST",
            "=" * 86,
            f"Target Name          : {report.filename}",
            f"Full Path / Target   : {report.filepath}",
            f"Local File Available : {'Yes (Ready for Cloud Upload / 15s Sandbox Detonation)' if (report.filepath and os.path.isfile(report.filepath)) else 'No (Remote / Hash / Deleted)'}",
            f"Item Type            : {report.file_type_label}",
            f"Zero-Copy Engine     : {map_backend}",
            f"DOS / NT / IAT Layout: {dos_nt_info}",
            f"Size (Human)         : {report.human_size} ({report.file_size_bytes:,} bytes)",
            f"Overall Entropy      : {report.overall_entropy:.3f} / 8.000 bits/byte (64KB Peak: {report.peak_window_entropy:.3f})",
            f"Authenticode Trust   : {sig_status}",
            f"PE Appended Overlay  : {overlay_status}",
            f"Active YARA Rules    : {self.scanner.yara_rules_path}",
            "",
            "CRYPTOGRAPHIC, IMPORT & FUZZY CLUSTERING HASHES (99% PRECISION HOMOLOGY)",
            "=" * 86,
            f"MD5                  : {report.md5}",
            f"SHA-1                : {report.sha1}",
            f"SHA-256              : {report.sha256}",
            f"PE ImpHash (Mandiant): {imphash_val}",
            f"ssdeep (CTPH Fuzzy)  : {ssdeep_val}",
            f"TLSH (Locality Hash) : {tlsh_val}",
        ]

        if variants:
            lines.extend(["", "VARIANT / HOMOLOGY CLUSTERS IDENTIFIED (99% PRECISION)", "=" * 86])
            for v_match in variants:
                lines.append(f"  [!] {v_match}")

        sbx = getattr(report, "sandbox_report", None)
        if isinstance(sbx, dict):
            lines.extend(
                [
                    "",
                    "DISPOSABLE WINDOWS SANDBOX (.WSB) 15-SECOND DYNAMIC TELEMETRY",
                    "=" * 86,
                    f"Sandbox Status       : {sbx.get('sandbox_status', 'N/A')}",
                    f"Observation Window   : {sbx.get('polling_window_sec', 15.0):.1f} seconds (High-Frequency 250ms Stopwatch Polling)",
                    f"Early Parent Exit    : {'Yes — Intercepted at ' + str(sbx.get('parent_exit_ms', 0)) + 'ms' if sbx.get('parent_terminated_early') else 'No (Standard lifecycle)'}",
                    f"WSB Profile Path     : {sbx.get('wsb_profile_path', 'N/A')}",
                    f"Dynamic Verdict      : {sbx.get('dynamic_verdict', 'Unknown')}",
                    f"Telemetry Summary    : {sbx.get('summary', '')}",
                ]
            )
            for c_line in sbx.get("child_process_drops") or []:
                lines.append(f"  [Child Drop!] {c_line}")
            for p_line in sbx.get("spawned_processes") or []:
                lines.append(f"  [Process]     {p_line}")
            for t_line in sbx.get("tcp_beacons") or []:
                lines.append(f"  [TCP Beacon]  {t_line}")
            for u_line in sbx.get("udp_beacons") or []:
                lines.append(f"  [UDP Beacon]  {u_line}")
            for f_line in sbx.get("filesystem_events") or []:
                lines.append(f"  [File Drop]   {f_line}")

        lines.extend(
            [
                "",
                "VERDICT SUMMARY",
                "=" * 86,
                f"Overall Assessment   : {report.verdict_label.upper()} ({report.verdict_summary})",
                f"Scan Duration        : {report.scan_duration_sec:.3f} seconds ({report.throughput_mb_s:,.2f} MB/s)",
            ]
        )
        self._set_textbox_content(self.details_textbox, "\n".join(lines))

    def _populate_relations_pane(self, report: ScanReport) -> None:
        url_lines = [
            f"CONTACTED / EMBEDDED DOMAINS ({len(report.domains)})",
            "=" * 64,
        ]
        if report.domains:
            url_lines.extend(f"  • {d}" for d in report.domains)
        else:
            url_lines.append("  No external domains detected.")

        url_lines.extend(["", f"FULL EXTRACTED URLs ({len(report.urls)})", "=" * 64])
        if report.urls:
            url_lines.extend(f"[{i + 1:04d}] {u}" for i, u in enumerate(report.urls))
        else:
            url_lines.append("  No hardcoded ASCII or UTF-16LE URLs found.")

        self._set_textbox_content(self.urls_textbox, "\n".join(url_lines))

        ip_lines = [
            f"EMBEDDED IPv4 ADDRESSES ({len(report.ipv4_addresses)})",
            "=" * 64,
        ]
        if report.ipv4_addresses:
            ip_lines.extend(f"[{i + 1:04d}] {ip}" for i, ip in enumerate(report.ipv4_addresses))
        else:
            ip_lines.append("  No hardcoded IPv4 addresses detected.")

        self._set_textbox_content(self.ips_textbox, "\n".join(ip_lines))

    def _populate_behavior_pane(self, report: ScanReport) -> None:
        pe = report.pe_report
        for child in self.mitre_badges_flow.winfo_children():
            child.destroy()

        if not pe.is_pe:
            self.mitre_banner_frame.grid_forget()
            self.pe_summary_label.configure(
                text=f"Item Type: {report.file_type_label} (Non-PE Target)"
            )
            self._set_textbox_content(
                self.sections_textbox,
                f"PLAIN-ENGLISH FORMAT EXPLANATION\n{'=' * 72}\n"
                f"Target '{report.filename}' is a {report.file_type_label}.\n"
                "Portable Executable (PE) section headers only apply to Windows binaries (.exe, .dll, .sys).",
            )
            self._set_textbox_content(
                self.imports_textbox,
                "No Windows DLL imports (non-PE target).",
            )
            return

        sig_badge = "Trusted Signed ✔" if pe.is_signature_trusted else ("Signed (Untrusted)" if pe.is_signed else "Unsigned")
        tls_count = len(getattr(pe, "tls_callbacks", []) or [])
        ep_insn_count = len(getattr(pe, "ep_disassembly", []) or [])
        self.pe_summary_label.configure(
            text=(
                f"PE Arch: {pe.machine} ({getattr(pe, 'mapping_backend', 'MapViewOfFile')})  •  "
                f"Subsystem: {pe.subsystem}  •  Signature: {sig_badge}  •  "
                f"EP: {pe.entry_point} ({pe.entry_point_section}, {ep_insn_count} insns)  •  TLS Callbacks: {tls_count}"
            )
        )

        mitre_list = list(getattr(pe, "mitre_techniques", []) or [])
        if mitre_list:
            self.mitre_banner_frame.grid(
                row=1, column=0, columnspan=2, padx=16, pady=(2, 6), sticky="ew"
            )
            self.mitre_banner_title.configure(
                text=f"⚔  MITRE ATT&CK® Techniques Identified ({len(mitre_list)})"
            )
            for idx, tech_str in enumerate(mitre_list[:6]):
                badge = ctk.CTkLabel(
                    self.mitre_badges_flow,
                    text=f" 🎯 {tech_str} ",
                    fg_color=VT_BG_MAIN,
                    text_color="#FBBF24",
                    corner_radius=6,
                    font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                    padx=10,
                    pady=4,
                )
                badge.grid(row=idx // 3, column=idx % 3, padx=4, pady=3, sticky="w")
            apply_rounded_hwnd_clip(self.mitre_banner_frame, force=True)
        else:
            self.mitre_banner_frame.grid_forget()

        sec_lines: List[str] = []
        if mitre_list:
            sec_lines.extend(
                [
                    "MITRE ATT&CK® TECHNIQUES IDENTIFIED (CAPA & DISASSEMBLY CORRELATION):",
                    "=" * 78,
                ]
            )
            for tech_str in mitre_list:
                sec_lines.append(f"  [⚔] {tech_str}")
            sec_lines.append("")

        sec_lines.extend(
            [
                "STRUCTURAL, IAT STARVATION, TLS CALLBACK & ENTRY-POINT ANOMALIES:",
                "=" * 78,
            ]
        )
        if pe.structural_anomalies:
            for anom in pe.structural_anomalies:
                sec_lines.append(f"  [!] {anom}")
        else:
            sec_lines.append("  [✔] No RWX sections, IAT starvation, anomalous TLS hooks, or EntryPoint unpacker loops.")

        tls_list = list(getattr(pe, "tls_callbacks", []) or [])
        sec_lines.extend(
            [
                "",
                f"PRE-ENTRY-POINT TLS CALLBACKS (IMAGE_DIRECTORY_ENTRY_TLS: {len(tls_list)}):",
                "=" * 78,
            ]
        )
        if tls_list:
            for cb_str in tls_list:
                sec_lines.append(f"  [TLS Hook] {cb_str}")
        else:
            sec_lines.append("  [✔] No pre-entry-point TLS Callback hooks registered.")

        sec_lines.extend(
            [
                "",
                "DETECTED CAPABILITIES & RUNTIME IMPORTS:",
                "=" * 78,
            ]
        )
        if pe.capabilities:
            for cap_name, api_ref, cap_desc in pe.capabilities:
                sec_lines.append(f"  • {cap_name:<26} | {api_ref}")
                sec_lines.append(f"      -> {cap_desc}")
        else:
            sec_lines.append("  [✔] No notable injection, hooking, or shell capabilities detected.")

        sec_lines.extend(
            [
                "",
                f"ZERO-COPY PE SECTIONS & SHANNON ENTROPY (Threshold > {PACKED_ENTROPY_THRESHOLD} = Packed):",
                "=" * 78,
                f"{'SECTION':<12} {'VIRT ADDR':<12} {'VIRT SIZE':>12} {'RAW SIZE':>12} {'ENTROPY':>9}  {'PERMS / STATUS'}",
                "-" * 78,
            ]
        )
        for sec in pe.sections:
            flags = []
            if sec.is_rwx:
                flags.append("RWX!")
            if sec.is_packed:
                flags.append("HighEntropy(>7.2)")
            status_flag = ", ".join(flags) if flags else "✔ Normal"
            sec_lines.append(
                f"{sec.name:<12} {sec.virtual_address:<12} {sec.virtual_size:>12,} "
                f"{sec.raw_size:>12,} {sec.entropy:>9.4f}  {status_flag}"
            )

        ep_insns = list(getattr(pe, "ep_disassembly", []) or [])
        ep_eng = getattr(pe, "ep_disassembly_engine", "Capstone Engine")
        ep_anoms = list(getattr(pe, "ep_anomalies", []) or [])
        sec_lines.extend(
            [
                "",
                f"ENTRY-POINT DISASSEMBLY ({ep_eng} — First {len(ep_insns)} Instructions at {pe.entry_point}):",
                "=" * 78,
            ]
        )
        if ep_anoms:
            for ea in ep_anoms:
                sec_lines.append(f"  [EP ALERT] {ea}")
            sec_lines.append("-" * 78)
        if ep_insns:
            sec_lines.extend(ep_insns[:100])
        else:
            sec_lines.append("  No instructions decoded at AddressOfEntryPoint.")

        self._set_textbox_content(self.sections_textbox, "\n".join(sec_lines))

        exp_list = list(getattr(pe, "exported_functions", []) or [])
        refl_list = list(getattr(pe, "reflective_indicators", []) or [])
        imp_lines = [
            f"IMPORT ADDRESS TABLE (IAT) & DLL IMPORTS ({len(pe.imports)} DLLs, {pe.total_imported_functions} functions):",
            "=" * 64,
            f"IAT Starvation Check : {'[!] FLAGGED (<= 4 imports or dynamic-resolver only)' if pe.has_import_starvation else '[✔] Normal IAT population'}",
            f"Exported Symbols     : {len(exp_list)} export(s)" + (f" (Reflective Alerts: {', '.join(refl_list)})" if refl_list else ""),
        ]
        if exp_list:
            imp_lines.append("\n[EXPORT TABLE SYMBOLS]")
            for ex_fn in exp_list[:40]:
                imp_lines.append(f"   * {ex_fn}")
        for dll_name, functions in pe.imports.items():
            imp_lines.append(f"\n[{dll_name}] ({len(functions)} functions)")
            for fn in functions[:120]:
                imp_lines.append(f"   |- {fn}")
        self._set_textbox_content(self.imports_textbox, "\n".join(imp_lines))

    def _on_manual_sync_community(self) -> None:
        if self.current_report and self.current_report.sha256:
            target_sha = self.current_report.sha256
            self.status_label.configure(
                text="↻ Synchronizing community intelligence in background...",
                text_color="#60A5FA",
            )

            def _sync_worker() -> None:
                try:
                    self.community_db.get_reputation_summary(target_sha, sync_online=True)
                except Exception:
                    pass
                if not self.is_closing:
                    self.ui_queue.put(("COMMUNITY_SYNC_DONE", target_sha))

            threading.Thread(target=_sync_worker, daemon=True).start()

    def _refresh_community_tab(self, sha256: str, sync_online: bool = False) -> None:
        if not sha256:
            return

        summary = self.community_db.get_reputation_summary(sha256, sync_online=sync_online)
        comments = self.community_db.fetch_comments(sha256, sync_online=False)

        self.community_mini_badge.configure(
            text=f"Community: {summary['total_comments']} vote(s)"
        )
        storage_mode = (
            "Cloud Proxy Active"
            if os.environ.get("VYRULIX_API_PROXY_URL", "").strip()
            else "Local: ~/.vyrulix/community.json (unless cloud proxy configured)"
        )
        self.community_banner.configure(
            text=(
                f"Comments ({summary['total_comments']})  •  {summary['consensus']}  "
                f"[ Safe: {summary['safe_count']} | Suspicious: {summary['suspicious_count']} | "
                f"Malicious: {summary['malicious_count']} ]  •  {storage_mode}"
            )
        )

        for child in self.community_feed_scroll.winfo_children():
            child.destroy()

        if not comments:
            empty_card = ctk.CTkFrame(
                self.community_feed_scroll,
                fg_color=VT_BG_SURFACE,
                corner_radius=8,
                border_width=1,
                border_color=VT_BORDER,
            )
            empty_card.grid(row=0, column=0, padx=8, pady=18, sticky="ew")
            ctk.CTkLabel(
                empty_card,
                text="💬  No comments found for this item yet",
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color=VT_TEXT_PRIMARY,
            ).pack(pady=(22, 4))
            ctk.CTkLabel(
                empty_card,
                text="Sign in and be the first to share your thoughts on this SHA-256 hash.",
                font=ctk.CTkFont(size=13),
                text_color=VT_TEXT_MUTED,
            ).pack(pady=(0, 22))
            self.after(20, lambda: attach_glass_rounded_hooks(self.community_feed_scroll))
            return

        for idx, item in enumerate(comments):
            verdict = item.get("verdict", "Suspicious")
            v_color = (
                VT_RED
                if verdict == "Malicious"
                else VT_AMBER
                if verdict == "Suspicious"
                else VT_GREEN
            )
            c_card = ctk.CTkFrame(
                self.community_feed_scroll,
                fg_color=VT_BG_SURFACE,
                corner_radius=8,
                border_width=1,
                border_color=VT_BORDER,
            )
            c_card.grid(row=idx, column=0, padx=6, pady=6, sticky="ew")
            c_card.grid_columnconfigure(0, weight=1)

            header_line = ctk.CTkFrame(c_card, fg_color="transparent", corner_radius=0)
            header_line.grid(row=0, column=0, padx=14, pady=(10, 4), sticky="ew")
            header_line.grid_columnconfigure(0, weight=1)

            author_lbl = ctk.CTkLabel(
                header_line,
                text=f"👤 {item.get('handle', '@analyst')}  ({item.get('role', 'Community')})   •   {item.get('timestamp', '')}",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#60A5FA",
                anchor="w",
            )
            author_lbl.grid(row=0, column=0, sticky="w")

            verdict_pill = ctk.CTkLabel(
                header_line,
                text=f"● {verdict.upper()}",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=v_color,
                anchor="e",
            )
            verdict_pill.grid(row=0, column=1, sticky="e")

            body_lbl = ctk.CTkLabel(
                c_card,
                text=item.get("comment", ""),
                font=ctk.CTkFont(size=13),
                text_color=VT_TEXT_PRIMARY,
                anchor="w",
                justify="left",
                wraplength=560,
            )
            body_lbl.grid(row=1, column=0, padx=14, pady=(2, 12), sticky="ew")

        self.after(20, lambda: attach_glass_rounded_hooks(self.community_feed_scroll))

    def _on_submit_community_comment(self) -> None:
        user = self.community_db.get_current_user()
        if user is None:
            self._open_auth_page("SIGN_IN")
            return

        if self.current_report is None or not self.current_report.sha256:
            self.status_label.configure(
                text="⚠ Scan a file, URL, or hash first before posting a community comment.",
                text_color=VT_AMBER,
            )
            return

        verdict = self.selected_verdict
        comment_text = self.comment_input.get("1.0", "end").strip()
        if not comment_text:
            self.status_label.configure(
                text="⚠ Please write a comment before posting.",
                text_color=VT_AMBER,
            )
            return

        try:
            self.community_db.append_comment(
                sha256=self.current_report.sha256,
                handle=user["handle"],
                verdict=verdict,
                comment=comment_text,
                filename=self.current_report.filename,
                role=user.get("role", "Community Analyst"),
            )
            self.comment_input.delete("1.0", "end")
            self._refresh_community_tab(self.current_report.sha256, sync_online=False)
            self.status_label.configure(
                text=f"✔ Verdict ({verdict}) posted by {user['handle']}!",
                text_color=VT_GREEN,
            )
        except Exception as exc:
            self.status_label.configure(text=f"Error: {exc}", text_color=VT_RED)

    def _copy_current_sha256(self) -> None:
        if self.current_report and self.current_report.sha256:
            self.clipboard_clear()
            self.clipboard_append(self.current_report.sha256)
            self.status_label.configure(
                text="✔ SHA-256 copied to clipboard!", text_color=VT_GREEN
            )

    def _on_detonate_in_sandbox(self) -> None:
        """
        Triggers dynamic validation in a disposable Windows Sandbox (`.wsb`)
        on a background thread and updates the current report when complete.
        """
        if self.current_report is None or not os.path.isfile(self.current_report.filepath):
            self.status_label.configure(
                text="⚠ Scan a local binary file first to stage a Windows Sandbox (.wsb) detonation.",
                text_color=VT_AMBER,
            )
            return

        if self.is_detonating_sandbox or self.is_scanning:
            return
        target_report = self.current_report
        self.is_detonating_sandbox = True
        self._sync_report_action_buttons(target_report)
        self.status_label.configure(
            text="📦 Launching 15-second Windows Sandbox (.wsb) monitor (capturing rapid parent exit, TCP/UDP beacons & child drops)...",
            text_color="#60A5FA",
        )

        def _status_cb(msg: str) -> None:
            if not self.is_closing:
                self.ui_queue.put(("STATUS", msg))

        def _worker() -> None:
            updated = self.scanner.detonate_in_windows_sandbox(
                target_report, timeout_sec=70, status_callback=_status_cb
            )
            if not self.is_closing:
                self.ui_queue.put(("SANDBOX_DONE", updated))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_confirm_and_upload_vt(self) -> None:
        """
        Opens a user-confirmation modal to upload an uncataloged (HTTP 404) sample
        to VirusTotal v3 (`POST /api/v3/files`) for 70+ vendor cloud analysis.
        """
        if self.current_report is None or not os.path.isfile(self.current_report.filepath):
            self.status_label.configure(
                text="⚠ Select and scan a local file before uploading to VirusTotal v3.",
                text_color=VT_AMBER,
            )
            return

        target_report = self.current_report
        confirm_win = ctk.CTkToplevel(self, fg_color=VT_BG_MAIN)
        confirm_win.title("Vyrulix // Confirm VirusTotal v3 Sample Upload")
        confirm_win.geometry("520x290")
        confirm_win.resizable(False, False)
        confirm_win.transient(self)

        def _close_confirm() -> None:
            try:
                confirm_win.grab_release()
            except Exception:
                pass
            try:
                confirm_win.destroy()
            except Exception:
                pass

        confirm_win.protocol("WM_DELETE_WINDOW", _close_confirm)

        card = ctk.CTkFrame(
            confirm_win,
            fg_color=VT_BG_SURFACE,
            corner_radius=12,
            border_width=1,
            border_color=VT_AMBER,
        )
        card.pack(fill="both", expand=True, padx=16, pady=16)

        ctk.CTkLabel(
            card,
            text="☁  Upload Uncataloged Binary to VirusTotal v3?",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=VT_AMBER,
            anchor="w",
        ).pack(fill="x", padx=20, pady=(16, 6))

        ctk.CTkLabel(
            card,
            text=(
                f"File: {target_report.filename} ({target_report.human_size})\n"
                f"SHA-256: {target_report.sha256[:32]}...\n\n"
                "Submitting this file via POST /api/v3/files shares the binary with "
                "VirusTotal's 70+ security vendors and cloud sandboxes. Proceed?"
            ),
            font=ctk.CTkFont(size=12),
            text_color=VT_TEXT_PRIMARY,
            justify="left",
            wraplength=460,
            anchor="w",
        ).pack(fill="x", padx=20, pady=(0, 14))

        btn_row = ctk.CTkFrame(card, fg_color="transparent", corner_radius=0)
        btn_row.pack(fill="x", padx=20, pady=(4, 14))
        btn_row.grid_columnconfigure(0, weight=1)
        btn_row.grid_columnconfigure(1, weight=1)

        def _proceed_upload() -> None:
            _close_confirm()
            if self.is_uploading_vt:
                return
            self.is_uploading_vt = True
            self._sync_report_action_buttons(target_report)
            self.status_label.configure(
                text=f"☁ Uploading {target_report.filename} to VirusTotal v3 (POST /api/v3/files)...",
                text_color=VT_AMBER,
            )

            def _status_cb(msg: str) -> None:
                if not self.is_closing:
                    self.ui_queue.put(("STATUS", msg))

            def _upload_worker() -> None:
                updated = self.scanner.upload_uncataloged_file_to_vt(
                    target_report,
                    status_callback=_status_cb,
                    cancel_event=self.cancel_event,
                )
                if not self.is_closing:
                    self.ui_queue.put(("VT_UPLOAD_DONE", updated))

            threading.Thread(target=_upload_worker, daemon=True).start()

        ctk.CTkButton(
            btn_row,
            text="Cancel",
            height=36,
            corner_radius=8,
            fg_color=VT_BG_ELEVATED,
            hover_color=VT_BORDER,
            text_color=VT_TEXT_MUTED,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=_close_confirm,
        ).grid(row=0, column=0, padx=(0, 6), sticky="ew")

        ctk.CTkButton(
            btn_row,
            text="Confirm & Upload to VT v3",
            height=36,
            corner_radius=8,
            fg_color=VT_AMBER,
            hover_color="#D97706",
            text_color="#111521",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=_proceed_upload,
        ).grid(row=0, column=1, padx=(6, 0), sticky="ew")

        confirm_win.after(
            30,
            lambda: (apply_windows_dwm_dark_mode(confirm_win), attach_glass_rounded_hooks(confirm_win)),
        )
        confirm_win.after(50, confirm_win.grab_set)

    @staticmethod
    def _set_textbox_content(textbox: ctk.CTkTextbox, text: str) -> None:
        textbox.configure(state="normal", text_color=VT_TEXT_PRIMARY)
        textbox.delete("1.0", "end")
        textbox.insert("1.0", text)
        textbox.configure(state="disabled")


VyrulixApp = VyrulixApp


if __name__ == "__main__":
    multiprocessing.freeze_support()
    app = VyrulixApp()
    app.mainloop()