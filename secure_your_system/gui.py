"""Desktop window for Secure Your System (built with tkinter, included with Python)."""
from __future__ import annotations

import os
import queue
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, ttk

from . import APP_NAME, __version__, report
from .models import Severity, fmt_time
from .platform_utils import (HAS_PSUTIL, IS_MAC, IS_WINDOWS, host_info, open_location,
                             relaunch_as_admin)
from .scanner import run_scan

# ---- Theme: dark violet with magenta highlights and a lime call-to-action ----
BG = "#0d0a14"            # window background
SURFACE = "#15111f"       # panels / tab pages
SURFACE_2 = "#1e1830"     # raised tiles, inputs, headings
BORDER = "#2e2645"
TEXT = "#f1eef8"
MUTED = "#9b93b0"
VIOLET = "#8b5cf6"
VIOLET_LIGHT = "#b8a1ff"
MAGENTA = "#d65cf0"
LIME = "#b8f23e"          # primary action button
LIME_HOVER = "#a3dd2a"
INK = "#120e1a"           # text on lime
CARD = SURFACE
SEV_COLORS = {"Critical": "#ff4d6d", "High": "#ff8c5a", "Medium": "#f6c945", "Low": "#6fb2ff", "Info": "#9b93b0"}
# Verdict banner: (background, accent) per risk level
RISK_COLORS = {0: ("#0f2e22", "#4ade80"), 1: ("#141f3d", "#6fb2ff"), 2: ("#33290f", "#f6c945"),
               3: ("#3a1b10", "#ff8c5a"), 4: ("#3d0f1c", "#ff4d6d")}
PRIORITY_COLORS = {"Now": "#ff4d6d", "Today": "#ff8c5a", "This week": "#f6c945", "Soon": "#6fb2ff",
                   "Ongoing": "#9b93b0"}


def _lerp(c1: str, c2: str, t: float) -> str:
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(round(x + (y - x) * t) for x, y in zip(a, b))
WINDOWS = [("Last 24 hours", 1), ("Last 7 days", 7), ("Last 30 days", 30), ("Last 90 days", 90)]


class RichText(tk.Text):
    """Read-only text area with simple formatting helpers."""

    def __init__(self, master, fonts, **kw):
        frame = ttk.Frame(master)
        super().__init__(frame, wrap="word", relief="flat", bd=0, padx=18, pady=14, bg=SURFACE, fg=TEXT,
                         font=fonts["body"], cursor="arrow", highlightthickness=0,
                         selectbackground=VIOLET, selectforeground="white", insertbackground=TEXT, **kw)
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.yview)
        self.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        super().pack(side="left", fill="both", expand=True)
        self.frame = frame
        self.tag_configure("h1", font=fonts["h1"], spacing1=4, spacing3=8, foreground=TEXT)
        self.tag_configure("h2", font=fonts["h2"], spacing1=16, spacing3=6, foreground=VIOLET_LIGHT)
        self.tag_configure("h3", font=fonts["bold"], spacing1=10, spacing3=2, foreground=MAGENTA)
        self.tag_configure("bold", font=fonts["bold"])
        self.tag_configure("muted", foreground=MUTED)
        self.tag_configure("mono", font=fonts["mono"], foreground="#d9ccff", background="#1b1529",
                           lmargin1=24, lmargin2=24)
        self.tag_configure("indent", lmargin1=24, lmargin2=24)
        self.tag_configure("bullet", lmargin1=10, lmargin2=26, spacing1=3)
        for name, col in {**SEV_COLORS, **PRIORITY_COLORS}.items():
            self.tag_configure(f"c_{name}", foreground=col, font=fonts["bold"])
        self.configure(state="disabled")

    def pack(self, **kw):
        self.frame.pack(**kw)

    def grid(self, **kw):
        self.frame.grid(**kw)

    def clear(self):
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")

    def add(self, text, *tags):
        self.configure(state="normal")
        self.insert("end", text, tags)
        self.configure(state="disabled")
        return self


class App:
    def __init__(self, root, args=None):
        self.root = root
        self.args = args
        self.result = None
        self.q = queue.Queue()
        self.cancel = threading.Event()
        self.scanning = False
        self.host = host_info()
        self._finding_map = {}
        self._fonts()
        self._style()
        self._build()
        self._welcome()

    # ---------------------------------------------------------------- setup --
    def _fonts(self):
        fam = tkfont.nametofont("TkDefaultFont").actual("family")
        if IS_WINDOWS:
            fam = "Segoe UI"
        mono = "Consolas" if IS_WINDOWS else ("Menlo" if IS_MAC else "DejaVu Sans Mono")
        base = 11 if IS_MAC else 10
        self.f = {
            "body": (fam, base), "bold": (fam, base, "bold"), "small": (fam, base - 1),
            "h1": (fam, base + 9, "bold"), "h2": (fam, base + 3, "bold"), "title": (fam, base + 6, "bold"),
            "mono": (mono, base - 1), "verdict": (fam, base + 10, "bold"), "big": (fam, base + 8, "bold"),
        }

    def _style(self):
        r = self.root
        s = ttk.Style(r)
        s.theme_use("clam")  # the only built-in theme that honours custom colours on every OS
        r.configure(bg=BG)
        s.configure(".", background=BG, foreground=TEXT, font=self.f["body"], bordercolor=BORDER,
                    lightcolor=BORDER, darkcolor=BORDER, troughcolor=SURFACE, fieldbackground=SURFACE_2,
                    selectbackground=VIOLET, selectforeground="white", insertcolor=TEXT, focuscolor=VIOLET)
        s.configure("TFrame", background=BG)
        s.configure("Card.TFrame", background=SURFACE)
        s.configure("TLabel", background=BG, foreground=TEXT)
        s.configure("Card.TLabel", background=SURFACE, foreground=TEXT)
        s.configure("Muted.TLabel", background=BG, foreground=MUTED)
        s.configure("Section.TLabel", background=BG, foreground=VIOLET_LIGHT, font=self.f["bold"])

        # Buttons: lime primary, violet secondary, dark ghost
        s.configure("Accent.TButton", font=self.f["bold"], padding=(20, 9), foreground=INK, background=LIME,
                    bordercolor=LIME, lightcolor=LIME, darkcolor=LIME, focuscolor=LIME)
        s.map("Accent.TButton", background=[("disabled", "#3c4a22"), ("active", LIME_HOVER)],
              foreground=[("disabled", "#7d8a5f")], bordercolor=[("active", LIME_HOVER)])
        s.configure("Violet.TButton", font=self.f["bold"], padding=(14, 8), foreground="white",
                    background=VIOLET, bordercolor=VIOLET, lightcolor=VIOLET, darkcolor=VIOLET)
        s.map("Violet.TButton", background=[("active", "#7a48ec")])
        for name in ("TButton", "TMenubutton"):
            s.configure(name, padding=(14, 8), foreground=TEXT, background=SURFACE_2, bordercolor=BORDER,
                        lightcolor=SURFACE_2, darkcolor=SURFACE_2, arrowcolor=VIOLET_LIGHT)
            s.map(name, background=[("disabled", SURFACE), ("active", "#2a2140")],
                  foreground=[("disabled", "#5d566e")], bordercolor=[("active", VIOLET)])

        # Inputs
        s.configure("TRadiobutton", background=BG, foreground=TEXT, indicatorbackground=SURFACE_2,
                    indicatorcolor=SURFACE_2, indicatorrelief="flat", indicatormargin=(0, 0, 6, 0))
        s.map("TRadiobutton", background=[("active", BG)], indicatorcolor=[("selected", MAGENTA)])
        s.configure("TCombobox", foreground=TEXT, background=SURFACE_2, fieldbackground=SURFACE_2,
                    arrowcolor=VIOLET_LIGHT, bordercolor=BORDER, padding=4)
        s.map("TCombobox", fieldbackground=[("readonly", SURFACE_2)], foreground=[("readonly", TEXT)],
              selectbackground=[("readonly", SURFACE_2)], selectforeground=[("readonly", TEXT)],
              bordercolor=[("focus", VIOLET), ("hover", VIOLET)])
        r.option_add("*TCombobox*Listbox.background", SURFACE_2)
        r.option_add("*TCombobox*Listbox.foreground", TEXT)
        r.option_add("*TCombobox*Listbox.selectBackground", VIOLET)
        r.option_add("*TCombobox*Listbox.selectForeground", "white")
        r.option_add("*TCombobox*Listbox.font", self.f["body"])
        r.option_add("*Menu.background", SURFACE_2)
        r.option_add("*Menu.foreground", TEXT)
        r.option_add("*Menu.activeBackground", VIOLET)
        r.option_add("*Menu.activeForeground", "white")
        r.option_add("*Menu.relief", "flat")

        # Tabs
        s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 6, 0, 0))
        s.configure("TNotebook.Tab", padding=(18, 9), font=self.f["bold"], background=BG, foreground=MUTED,
                    bordercolor=BG, lightcolor=BG)
        s.map("TNotebook.Tab", background=[("selected", SURFACE), ("active", "#18132a")],
              foreground=[("selected", TEXT), ("active", VIOLET_LIGHT)],
              lightcolor=[("selected", MAGENTA)], bordercolor=[("selected", BORDER)])

        # Tables
        s.configure("Treeview", rowheight=30, font=self.f["body"], background=SURFACE, fieldbackground=SURFACE,
                    foreground=TEXT, bordercolor=BORDER, lightcolor=SURFACE, darkcolor=SURFACE)
        s.map("Treeview", background=[("selected", "#2d2250")], foreground=[("selected", "white")])
        s.configure("Treeview.Heading", font=self.f["bold"], background=SURFACE_2, foreground=VIOLET_LIGHT,
                    bordercolor=BORDER, lightcolor=SURFACE_2, darkcolor=SURFACE_2, relief="flat", padding=(8, 6))
        s.map("Treeview.Heading", background=[("active", "#2a2140")])

        # Scrollbars, progress, panes
        for orient in ("Vertical", "Horizontal"):
            s.configure(f"{orient}.TScrollbar", background=SURFACE_2, troughcolor=SURFACE, bordercolor=SURFACE,
                        lightcolor=SURFACE_2, darkcolor=SURFACE_2, arrowcolor=MUTED, gripcount=0)
            s.map(f"{orient}.TScrollbar", background=[("active", "#3a2f5c")])
        s.configure("Violet.Horizontal.TProgressbar", background=VIOLET, troughcolor=SURFACE_2,
                    bordercolor=SURFACE_2, lightcolor=MAGENTA, darkcolor=VIOLET, thickness=8)
        s.configure("TPanedwindow", background=BG)
        s.configure("Sash", sashthickness=6, background=BG, bordercolor=BG, lightcolor=BG, darkcolor=BG)

    def _build(self):
        r = self.root
        r.title(f"{APP_NAME} v{__version__}")
        r.geometry("1180x800")
        r.minsize(940, 620)

        # Header: gradient bar drawn on a canvas
        admin = self.host.get("admin")
        self.hdr = tk.Canvas(r, height=76, highlightthickness=0, bd=0, bg=BG)
        self.hdr.pack(fill="x")
        self.hdr.bind("<Configure>", self._draw_header)

        # Controls
        ctl = ttk.Frame(r, padding=(24, 16, 24, 6))
        ctl.pack(fill="x")
        self.deep = tk.BooleanVar(value=bool(self.args and self.args.deep))
        box = ttk.Frame(ctl)
        box.pack(side="left")
        ttk.Label(box, text="SCAN TYPE", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(box, text="Quick  (key folders, ~1–3 min)", variable=self.deep, value=False).grid(row=1, column=0, sticky="w")
        ttk.Radiobutton(box, text="Deep  (entire home folder, slower)", variable=self.deep, value=True).grid(row=2, column=0, sticky="w")

        box2 = ttk.Frame(ctl, padding=(28, 0))
        box2.pack(side="left")
        ttk.Label(box2, text="WHEN MIGHT IT HAVE HAPPENED?", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.window = tk.StringVar(value="Last 7 days")
        cb = ttk.Combobox(box2, textvariable=self.window, values=[w[0] for w in WINDOWS], state="readonly", width=16)
        cb.grid(row=1, column=0, sticky="w", pady=(2, 0))
        ttk.Label(box2, text="Activity in this period is treated as suspect", style="Muted.TLabel",
                  font=self.f["small"]).grid(row=2, column=0, sticky="w")

        right = ttk.Frame(ctl)
        right.pack(side="right")
        self.btn_scan = ttk.Button(right, text="▶  Start Scan", style="Accent.TButton", command=self.start)
        self.btn_scan.pack(side="left", padx=4)
        self.btn_stop = ttk.Button(right, text="Stop", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=4)
        self.btn_export = ttk.Menubutton(right, text="Save Report ▾", state="disabled")
        m = tk.Menu(self.btn_export, tearoff=0)
        m.add_command(label="Report for reading (HTML)…", command=lambda: self.export("html"))
        m.add_command(label="Plain text…", command=lambda: self.export("txt"))
        m.add_command(label="Data for analysts (JSON)…", command=lambda: self.export("json"))
        self.btn_export["menu"] = m
        self.btn_export.pack(side="left", padx=4)
        if not admin:
            ttk.Button(right, text="Run as Administrator", style="Violet.TButton", command=self.elevate).pack(side="left", padx=4)

        # Progress
        pf = ttk.Frame(r, padding=(24, 6, 24, 10))
        pf.pack(fill="x")
        self.pbar = ttk.Progressbar(pf, mode="determinate", maximum=100, style="Violet.Horizontal.TProgressbar")
        self.pbar.pack(fill="x")
        self.status = ttk.Label(pf, text="Ready. Choose your options and press Start Scan.", style="Muted.TLabel")
        self.status.pack(anchor="w", pady=(4, 0))

        # Tabs
        self.nb = ttk.Notebook(r)
        self.nb.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        self.tab_overview = ttk.Frame(self.nb, style="Card.TFrame")
        self.tab_findings = ttk.Frame(self.nb, style="Card.TFrame")
        self.tab_exposure = ttk.Frame(self.nb, style="Card.TFrame")
        self.tab_actions = ttk.Frame(self.nb, style="Card.TFrame")
        self.tab_further = ttk.Frame(self.nb, style="Card.TFrame")
        self.tab_details = ttk.Frame(self.nb, style="Card.TFrame")
        for t, name in ((self.tab_overview, "  Overview  "), (self.tab_findings, "  Findings  "),
                        (self.tab_exposure, "  Origin & Exposure  "), (self.tab_actions, "  Do This Now  "),
                        (self.tab_further, "  Further Checks  "), (self.tab_details, "  Scan Details  ")):
            self.nb.add(t, text=name)
        self._build_overview()
        self._build_findings()
        self._build_exposure()
        self.actions_txt = RichText(self.tab_actions, self.f)
        self.actions_txt.pack(fill="both", expand=True)
        self.further_txt = RichText(self.tab_further, self.f)
        self.further_txt.pack(fill="both", expand=True)
        self._build_details()
        r.protocol("WM_DELETE_WINDOW", self.on_close)

    def _draw_header(self, e=None):
        c = self.hdr
        c.delete("all")
        w, h = c.winfo_width(), int(c.cget("height"))
        stops = [(0.0, "#0d0a14"), (0.55, "#1a1033"), (1.0, "#3a1660")]
        step = 4
        for x in range(0, max(w, 1), step):
            t = x / max(w - 1, 1)
            for (t0, c0), (t1, c1) in zip(stops, stops[1:]):
                if t0 <= t <= t1:
                    col = _lerp(c0, c1, (t - t0) / (t1 - t0))
                    break
            c.create_rectangle(x, 0, x + step, h, fill=col, outline=col)
        for x in range(0, max(w, 1), step):  # violet → magenta underline
            col = _lerp(VIOLET, MAGENTA, x / max(w - 1, 1))
            c.create_rectangle(x, h - 3, x + step, h, fill=col, outline=col)
        # shield mark
        cx, cy = 40, h // 2 - 1
        c.create_polygon(cx - 13, cy - 15, cx + 13, cy - 15, cx + 13, cy + 2, cx, cy + 16, cx - 13, cy + 2,
                         fill=VIOLET, outline=MAGENTA, width=2, smooth=False)
        c.create_line(cx - 6, cy, cx - 1, cy + 5, cx + 7, cy - 6, fill="white", width=3, capstyle="round")
        title = c.create_text(64, cy - 9, text="Evan's Secure Your System", anchor="w", fill=TEXT, font=self.f["title"])
        x2 = c.bbox(title)[2] + 10
        c.create_text(x2, cy - 8, text="Compromise Scanner", anchor="w", fill=MAGENTA, font=self.f["bold"])
        c.create_text(64, cy + 13, text="Detect malware & sniffing · trace the source · know what to do next",
                      anchor="w", fill=MUTED, font=self.f["small"])
        # right side: badge + host
        admin = self.host.get("admin")
        label = "ADMINISTRATOR" if admin else "STANDARD USER · LIMITED VIEW"
        bt = c.create_text(w - 34, cy - 8, text=label, anchor="e", font=self.f["bold"],
                           fill=INK if admin else "#f6c945")
        x0, y0, x1, y1 = c.bbox(bt)
        c.create_rectangle(x0 - 12, y0 - 5, x1 + 12, y1 + 5, fill=LIME if admin else "#2b2412",
                           outline=LIME if admin else "#f6c945", width=1)
        c.tag_raise(bt)
        c.create_text(w - 22, cy + 15, anchor="e", fill=MUTED, font=self.f["small"],
                      text=f"{self.host.get('os')}  ·  {self.host.get('hostname')}  ·  {self.host.get('user')}")

    def _build_overview(self):
        t = self.tab_overview
        # Verdict banner: coloured accent stripe + tinted panel
        self.banner = tk.Frame(t, bg=SURFACE_2, highlightthickness=1, highlightbackground=BORDER)
        self.banner.pack(fill="x", padx=18, pady=(18, 8))
        self.banner_stripe = tk.Frame(self.banner, bg=VIOLET, width=6)
        self.banner_stripe.pack(side="left", fill="y")
        self.banner_body = tk.Frame(self.banner, bg=SURFACE_2, padx=22, pady=16)
        self.banner_body.pack(side="left", fill="both", expand=True)
        self.banner_kicker = tk.Label(self.banner_body, text="STATUS", bg=SURFACE_2, fg=MUTED,
                                      font=self.f["small"], anchor="w")
        self.banner_kicker.pack(fill="x")
        self.banner_title = tk.Label(self.banner_body, text="", bg=SURFACE_2, fg=TEXT, font=self.f["verdict"],
                                     anchor="w")
        self.banner_title.pack(fill="x")
        self.banner_text = tk.Label(self.banner_body, text="", bg=SURFACE_2, fg=TEXT, font=self.f["body"],
                                    anchor="w", justify="left", wraplength=1000)
        self.banner_text.pack(fill="x", pady=(6, 0))
        self.banner.bind("<Configure>", lambda e: self.banner_text.configure(wraplength=max(400, e.width - 70)))
        self.stats_row = ttk.Frame(t, style="Card.TFrame", padding=(14, 4))
        self.stats_row.pack(fill="x")
        self.overview_txt = RichText(t, self.f)
        self.overview_txt.pack(fill="both", expand=True)

    def _build_findings(self):
        t = self.tab_findings
        top = ttk.Frame(t, style="Card.TFrame", padding=(12, 10, 12, 4))
        top.pack(fill="x")
        ttk.Label(top, text="Show:", style="Card.TLabel").pack(side="left")
        self.filter = tk.StringVar(value="All findings")
        fc = ttk.Combobox(top, textvariable=self.filter, state="readonly", width=24,
                          values=["All findings", "Critical & High", "Medium and above", "Low & Info"])
        fc.pack(side="left", padx=6)
        fc.bind("<<ComboboxSelected>>", lambda e: self._fill_findings())
        ttk.Label(top, text="Click a finding to see the details and evidence.", style="Card.TLabel",
                  foreground=MUTED).pack(side="left", padx=12)

        pw = ttk.PanedWindow(t, orient="vertical")
        pw.pack(fill="both", expand=True, padx=12, pady=8)
        tf = ttk.Frame(pw)
        cols = ("sev", "area", "title")
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
        for c, label, w, st in (("sev", "Severity", 100, False), ("area", "Area", 210, False),
                                ("title", "Finding", 700, True)):
            self.tree.heading(c, text=label)
            self.tree.column(c, width=w, stretch=st, anchor="w")
        for name, col in SEV_COLORS.items():
            self.tree.tag_configure(name, foreground=col)
        sb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._show_finding)
        pw.add(tf, weight=2)

        bf = ttk.Frame(pw)
        bar = ttk.Frame(bf, style="Card.TFrame")
        bar.pack(fill="x")
        self.btn_open = ttk.Button(bar, text="Open file location", command=self._open_selected, state="disabled")
        self.btn_open.pack(side="left", padx=4, pady=4)
        ttk.Button(bar, text="Copy details", command=self._copy_detail).pack(side="left", padx=4, pady=4)
        self.detail_txt = RichText(bf, self.f, height=12)
        self.detail_txt.pack(fill="both", expand=True)
        pw.add(bf, weight=3)

    def _build_exposure(self):
        t = self.tab_exposure
        pw = ttk.PanedWindow(t, orient="vertical")
        pw.pack(fill="both", expand=True)
        top = ttk.Frame(pw)
        self.exposure_txt = RichText(top, self.f)
        self.exposure_txt.pack(fill="both", expand=True)
        pw.add(top, weight=3)
        bot = ttk.Frame(pw, style="Card.TFrame", padding=(12, 6))
        hdr = ttk.Frame(bot, style="Card.TFrame")
        hdr.pack(fill="x")
        ttk.Label(hdr, text="Possibly affected file locations", style="Card.TLabel", font=self.f["h2"], foreground=VIOLET_LIGHT).pack(side="left")
        ttk.Button(hdr, text="Open location", command=self._open_loc).pack(side="right")
        lf = ttk.Frame(bot)
        lf.pack(fill="both", expand=True, pady=(6, 0))
        self.loc_tree = ttk.Treeview(lf, columns=("sev", "path", "why"), show="headings", selectmode="browse")
        for c, label, w, st in (("sev", "Risk", 80, False), ("path", "Location", 520, True),
                                ("why", "Why it's listed", 380, True)):
            self.loc_tree.heading(c, text=label)
            self.loc_tree.column(c, width=w, stretch=st, anchor="w")
        for name, col in SEV_COLORS.items():
            self.loc_tree.tag_configure(name, foreground=col)
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.loc_tree.yview)
        self.loc_tree.configure(yscrollcommand=sb.set)
        self.loc_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.loc_tree.bind("<Double-1>", lambda e: self._open_loc())
        pw.add(bot, weight=2)

    def _build_details(self):
        t = self.tab_details
        f = ttk.Frame(t, padding=12, style="Card.TFrame")
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="What was checked", style="Card.TLabel", font=self.f["h2"], foreground=VIOLET_LIGHT).pack(anchor="w")
        self.check_tree = ttk.Treeview(f, columns=("check", "status", "found", "time", "limits"),
                                       show="headings", height=8)
        for c, label, w, st in (("check", "Check", 220, False), ("status", "Status", 90, False),
                                ("found", "Findings", 80, False), ("time", "Time", 70, False),
                                ("limits", "Limited by", 600, True)):
            self.check_tree.heading(c, text=label)
            self.check_tree.column(c, width=w, stretch=st, anchor="w")
        self.check_tree.pack(fill="x", pady=(6, 10))
        self.details_txt = RichText(f, self.f)
        self.details_txt.pack(fill="both", expand=True)

    # -------------------------------------------------------------- welcome --
    def _welcome(self):
        self._set_banner(None, "Ready to scan",
                         "Secure Your System looks for malware, network sniffing and signs that data was stolen, "
                         "then tells you where it came from, what may be exposed and exactly what to do.")
        t = self.overview_txt
        t.clear()
        t.add("How to use\n", "h2")
        for n, s in enumerate([
            "Pick Quick scan (recommended first) or Deep scan.",
            "Choose when you think something may have happened. If unsure, keep 'Last 7 days'.",
            "Press Start Scan. You can keep using the computer; it only reads, never changes anything.",
            "Read the result here, then go to the 'Do This Now' tab.",
            "Save the report (HTML) to keep a record or share it with IT / a technician.",
        ], 1):
            t.add(f"  {n}.  ", "bold").add(s + "\n", "bullet")
        t.add("\nWhat it checks\n", "h2")
        for head, body in [
            ("Running programs", "fake system processes, hacking tools, crypto-miners, programs running from temp "
                                 "folders, malicious command lines, documents launching scripts."),
            ("Network", "suspicious connections, possible data exfiltration, unencrypted traffic."),
            ("Packet sniffing", "capture mode on network cards, sniffing tools, ARP spoofing (man-in-the-middle), "
                                "proxies and rogue certificates that intercept traffic."),
            ("Auto-start", "registry Run keys, scheduled tasks, services, cron, LaunchAgents, shell start-up files."),
            ("Files", "known-bad file hashes, disguised files, droppers, ransomware traces, recent downloads."),
            ("Sensitive data", "where your passwords, sessions, keys and wallets are and whether anything "
                               "unexpected is reading them."),
            ("Settings & protection", "hosts file, DNS, antivirus and firewall status, Defender history."),
        ]:
            t.add("  •  " + head + ": ", "bold").add(body + "\n", "bullet")
        if not self.host.get("admin"):
            t.add("\nYou are not running as administrator. ", "bold", "c_Medium")
            t.add("The scan still works, but some areas will be partly hidden. The report lists exactly which, "
                  "and how to check them.\n", "muted")
        if not HAS_PSUTIL:
            t.add("\nThe 'psutil' package is missing, so program and network checks are disabled. "
                  "See the README install guide (pip install psutil).\n", "c_High")
        for txt in (self.actions_txt, self.further_txt, self.exposure_txt, self.details_txt, self.detail_txt):
            txt.clear()
            txt.add("Run a scan to see results here.\n", "muted")

    # ---------------------------------------------------------------- scan ---
    def start(self):
        if self.scanning:
            return
        self.scanning = True
        self.cancel.clear()
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_export.configure(state="disabled")
        self.pbar["value"] = 0
        days = dict(WINDOWS).get(self.window.get(), 7)
        deep = self.deep.get()
        self._set_banner(None, "Scanning…", "Checking programs, network, auto-start items, files and settings. "
                                             "This only reads your system and changes nothing.")
        self.t0 = time.time()

        def worker():
            try:
                res = run_scan(window_days=days, deep=deep,
                               progress=lambda m, f: self.q.put(("progress", m, f)), cancel=self.cancel)
                self.q.put(("done", res, None))
            except Exception as e:  # never leave the UI stuck
                self.q.put(("error", str(e), None))

        threading.Thread(target=worker, daemon=True).start()
        self.root.after(100, self._poll)

    def stop(self):
        self.cancel.set()
        self.status.configure(text="Stopping after the current check…")

    def _poll(self):
        try:
            while True:
                kind, a, b = self.q.get_nowait()
                if kind == "progress":
                    self.pbar["value"] = b * 100
                    self.status.configure(text=f"{a}   ({int(time.time() - self.t0)}s)")
                elif kind == "done":
                    self._finish(a)
                    return
                elif kind == "error":
                    self.scanning = False
                    self.btn_scan.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    messagebox.showerror(APP_NAME, f"The scan stopped because of an error:\n\n{a}")
                    return
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _finish(self, res):
        self.result = res
        self.scanning = False
        self.btn_scan.configure(state="normal", text="▶  Scan Again")
        self.btn_stop.configure(state="disabled")
        self.btn_export.configure(state="normal")
        self.pbar["value"] = 100
        took = res.finished - res.started
        self.status.configure(text=f"{'Scan stopped early' if res.cancelled else 'Scan complete'} in "
                                   f"{took:.0f}s · {len(res.findings)} finding(s) · {fmt_time(res.finished)}")
        self._fill_overview()
        self._fill_findings()
        self._fill_exposure()
        self._fill_actions()
        self._fill_further()
        self._fill_details()
        if res.analysis["risk_level"] >= 3:
            self.nb.select(self.tab_overview)
            self.root.bell()

    # ------------------------------------------------------------- populate --
    def _set_banner(self, level, title, text):
        bg, accent = RISK_COLORS.get(level, (SURFACE_2, VIOLET_LIGHT)) if level is not None \
            else (SURFACE_2, VIOLET_LIGHT)
        for w in (self.banner_body, self.banner_kicker, self.banner_title, self.banner_text):
            w.configure(bg=bg)
        self.banner.configure(bg=bg, highlightbackground=accent if level is not None else BORDER)
        self.banner_stripe.configure(bg=accent if level is not None else MAGENTA)
        self.banner_title.configure(fg=accent if level is not None else TEXT)
        self.banner_kicker.configure(text="SCAN RESULT" if level is not None else "EVAN'S SECURE YOUR SYSTEM",
                                     fg=accent if level is not None else MAGENTA)
        self.banner_title.configure(text=title)
        self.banner_text.configure(text=text)

    def _fill_overview(self):
        r, a = self.result, self.result.analysis
        self._set_banner(a["risk_level"], a["headline"], a["narrative"])
        for w in self.stats_row.winfo_children():
            w.destroy()
        stat = {c.name: c.stats for c in r.checks}
        tiles = [
            ("Findings", sum(1 for f in r.findings if f.severity >= Severity.LOW)),
            ("Programs checked", stat.get("Running programs", {}).get("processes", "—")),
            ("Internet connections", stat.get("Network connections", {}).get("active_external", "—")),
            ("Auto-start items", stat.get("Auto-start & persistence", {}).get("autostart_entries_reviewed", "—")),
            ("Files checked", f"{stat.get('Files & downloads', {}).get('files_checked', 0):,}"),
            ("Sensitive stores", stat.get("Sensitive data exposure", {}).get("sensitive_items", "—")),
        ]
        for i, (label, val) in enumerate(tiles):
            accent = (MAGENTA if i == 0 and val else VIOLET_LIGHT)
            f = tk.Frame(self.stats_row, bg=SURFACE_2, padx=16, pady=10,
                         highlightthickness=1, highlightbackground=BORDER)
            f.grid(row=0, column=i, padx=4, pady=6, sticky="nsew")
            self.stats_row.columnconfigure(i, weight=1)
            tk.Frame(f, bg=accent, height=2, width=28).pack(anchor="w", pady=(0, 6))
            tk.Label(f, text=str(val), bg=SURFACE_2, fg=accent, font=self.f["big"]).pack(anchor="w")
            tk.Label(f, text=label.upper(), bg=SURFACE_2, fg=MUTED, font=self.f["small"]).pack(anchor="w")

        t = self.overview_txt
        t.clear()
        t.add("Findings by severity:  ", "bold")
        for k, v in a["counts"].items():
            if v:
                t.add(f"{k} {v}    ", f"c_{k}")
        if not any(a["counts"].values()):
            t.add("none", "muted")
        t.add("\n")
        if a["first_activity"]:
            t.add("Earliest suspicious activity: ", "bold").add(a["first_activity"] + "\n")
        if a["attack_types"]:
            t.add("\nWhat kind of problem\n", "h2")
            for at in a["attack_types"]:
                t.add(f"  •  {at['type']}", "bullet").add(f"  ({at['count']})\n", "muted")
        top = [f for f in r.findings if f.severity >= Severity.MEDIUM][:8]
        if top:
            t.add("\nMost important findings\n", "h2")
            for f in top:
                t.add(f"  {f.severity.label.upper():<9}", f"c_{f.severity.label}").add(f.title + "\n", "bullet")
            t.add("\nSee the Findings tab for evidence, and Do This Now for the steps to take.\n", "muted")
        if a["origin"] and not a["nothing_found"]:
            t.add("\nMost likely entry point\n", "h2")
            o = a["origin"][0]
            t.add(f"  {o['source']}", "bold").add(f"  ({o['confidence']} confidence)\n", "muted")
        if a["nothing_found"]:
            t.add("\nNothing significant found\n", "h2")
            t.add("No strong signs of malware or sniffing were found with the access this program has. "
                  "Open the ", "bullet").add("Further Checks", "bold").add(
                " tab for deeper checks you (or an administrator) can do to be sure.\n", "bullet")
        lims = [l for c in r.checks for l in c.limited]
        if lims:
            t.add("\nThis scan had limited visibility in some areas\n", "h2")
            for l in list(dict.fromkeys(lims))[:6]:
                t.add("  •  " + l + "\n", "bullet", "muted")

    def _fill_findings(self):
        if not self.result:
            return
        self.tree.delete(*self.tree.get_children())
        self._finding_map.clear()
        flt = self.filter.get()
        for i, f in enumerate(self.result.findings):
            if flt == "Critical & High" and f.severity < Severity.HIGH:
                continue
            if flt == "Medium and above" and f.severity < Severity.MEDIUM:
                continue
            if flt == "Low & Info" and f.severity > Severity.LOW:
                continue
            iid = self.tree.insert("", "end", values=(f.severity.label, f.check, f.title), tags=(f.severity.label,))
            self._finding_map[iid] = f
        kids = self.tree.get_children()
        if kids:
            self.tree.selection_set(kids[0])
            self.tree.focus(kids[0])
        else:
            self.detail_txt.clear()
            self.detail_txt.add("No findings in this view.\n", "muted")

    def _selected_finding(self):
        sel = self.tree.selection()
        return self._finding_map.get(sel[0]) if sel else None

    def _show_finding(self, _e=None):
        f = self._selected_finding()
        t = self.detail_txt
        t.clear()
        if not f:
            return
        t.add(f.severity.label.upper() + "   ", f"c_{f.severity.label}").add(f.title + "\n", "h2")
        t.add(f.description + "\n")
        if f.evidence:
            t.add("\nEvidence\n", "h3")
            for k, v in f.evidence.items():
                v = ", ".join(map(str, v)) if isinstance(v, (list, tuple)) else (
                    ", ".join(f"{a}={b}" for a, b in v.items()) if isinstance(v, dict) else v)
                t.add(f"  {k}: ", "bold", "indent").add(f"{v}\n", "indent")
        if f.paths:
            t.add("\nFile locations\n", "h3")
            for p in f.paths:
                t.add(p + "\n", "mono")
        if f.remotes:
            t.add("\nConnected to\n", "h3")
            t.add(", ".join(f.remotes[:20]) + "\n", "mono")
        if f.first_seen:
            t.add("\nFirst seen: ", "bold").add(fmt_time(f.first_seen) + "\n")
        self.btn_open.configure(state="normal" if any(os.path.exists(p) for p in f.paths) else "disabled")

    def _open_selected(self):
        f = self._selected_finding()
        if f:
            for p in f.paths:
                if os.path.exists(p):
                    open_location(p)
                    return

    def _copy_detail(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.detail_txt.get("1.0", "end"))
        self.status.configure(text="Details copied to clipboard.")

    def _fill_exposure(self):
        a = self.result.analysis
        t = self.exposure_txt
        t.clear()
        t.add("Where it likely came from\n", "h2")
        if a["origin"]:
            for o in a["origin"]:
                t.add("  •  " + o["source"], "bullet", "bold").add(f"   {o['confidence']} confidence\n", "muted")
                for ev in o["evidence"][:4]:
                    t.add("       " + ev + "\n", "muted")
        else:
            t.add("  No entry point identified — nothing suspicious enough to trace.\n", "muted")
        if a["first_activity"]:
            t.add("\nEarliest suspicious activity: ", "bold").add(a["first_activity"] + "\n")

        t.add("\nWhat may have been taken\n", "h2")
        if a["possibly_taken"]:
            for i in a["possibly_taken"]:
                risk = i["risk"] if i["risk"] in SEV_COLORS else "Medium"
                t.add(f"  {i['risk'].upper():<7}", f"c_{risk}").add(i["what"] + "\n", "bold")
                t.add("         " + i["why"] + "\n", "muted")
                for p in i["paths"][:6]:
                    t.add(p + "\n", "mono")
        else:
            t.add("  Nothing indicates data was taken.\n", "muted")

        t.add("\nWhat may have been sniffed (intercepted on the network)\n", "h2")
        if a["sniffed"]:
            for i in a["sniffed"]:
                t.add("  •  " + i["what"] + ": ", "bullet", "bold").add(i["why"] + "\n", "bullet")
        else:
            t.add("  No signs of packet sniffing or interception were found.\n", "muted")

        t.add("\nWhere data may have gone\n", "h2")
        if a["destinations"]:
            for d in a["destinations"]:
                t.add(f"{d['endpoint']:<28} {d['process']}\n", "mono")
            t.add("  Look these addresses up on virustotal.com or abuseipdb.com from another device.\n", "muted")
        else:
            t.add("  No suspicious outbound destinations were seen at scan time.\n", "muted")

        self.loc_tree.delete(*self.loc_tree.get_children())
        for l in a["affected_locations"]:
            self.loc_tree.insert("", "end", values=(l["severity"], l["path"], l["reason"]), tags=(l["severity"],))

    def _open_loc(self):
        sel = self.loc_tree.selection()
        if sel:
            p = self.loc_tree.item(sel[0], "values")[1]
            if os.path.exists(p):
                open_location(p)

    def _fill_actions(self):
        a = self.result.analysis
        t = self.actions_txt
        t.clear()
        t.add("Do this now\n", "h1")
        t.add("Steps are in order. Start at the top.\n\n", "muted")
        for n, s in enumerate(a["actions_now"], 1):
            t.add(f"{n}.  ", "bold").add(f"[{s['priority']}]  ", f"c_{s['priority']}").add(s["step"] + "\n", "bold")
            t.add(s["detail"] + "\n\n", "indent")

    def _fill_further(self):
        a = self.result.analysis
        t = self.further_txt
        t.clear()
        t.add("Further checks\n", "h1")
        t.add(("Nothing significant was found. These checks go beyond what this program can do with its "
               "current permissions, and can catch well-hidden threats.\n" if a["nothing_found"] else
               "These checks confirm the findings and look in places this program cannot reach.\n"), "muted")
        for g in a["further_checks"]:
            t.add(g["group"] + "\n", "h2")
            t.add(g["why"] + "\n", "muted")
            for i in g["items"]:
                t.add("  •  " + i["check"] + "\n", "bullet", "bold")
                t.add(i["how"] + "\n", "indent")

    def _fill_details(self):
        r = self.result
        self.check_tree.delete(*self.check_tree.get_children())
        for c in r.checks:
            self.check_tree.insert("", "end", values=(
                c.name, "Ran" if c.ran else "Skipped", len(c.findings), f"{c.duration:.1f}s",
                "; ".join(c.limited) or c.error or "—"))
        t = self.details_txt
        t.clear()
        t.add("Scan information\n", "h2")
        for k, v in [("Computer", r.host.get("hostname")), ("System", r.host.get("os")),
                     ("User", r.host.get("user")), ("Administrator", "Yes" if r.host.get("admin") else "No"),
                     ("Scan type", r.options.get("scan_type")),
                     ("Look-back window", f"{r.options.get('window_days')} day(s)"),
                     ("Started", fmt_time(r.started)), ("Finished", fmt_time(r.finished))]:
            t.add(f"  {k}: ", "bold").add(f"{v}\n")
        t.add("\nLimitations\n", "h2")
        for l in r.analysis["limitations"]:
            t.add("  •  " + l + "\n", "bullet")

    # -------------------------------------------------------------- actions --
    def export(self, kind):
        if not self.result:
            return
        stamp = time.strftime("%Y%m%d-%H%M")
        ext = {"html": ".html", "json": ".json", "txt": ".txt"}[kind]
        path = filedialog.asksaveasfilename(
            defaultextension=ext, initialfile=f"Secure-Your-System-report-{self.host.get('hostname')}-{stamp}{ext}",
            filetypes=[(kind.upper(), "*" + ext), ("All files", "*.*")])
        if not path:
            return
        try:
            if kind == "html":
                report.to_html(self.result, path)
            elif kind == "json":
                report.to_json(self.result, path)
            else:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(report.to_text(self.result))
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Could not save the report:\n{e}")
            return
        self.status.configure(text=f"Report saved: {path}")
        if kind == "html" and messagebox.askyesno(APP_NAME, "Report saved. Open it now?"):
            import webbrowser
            webbrowser.open("file://" + os.path.abspath(path))

    def elevate(self):
        if IS_WINDOWS:
            if relaunch_as_admin():
                self.root.destroy()
            else:
                messagebox.showinfo(APP_NAME, "Administrator access was not granted. You can keep scanning "
                                              "with the limited view.")
        else:
            messagebox.showinfo(APP_NAME, "To scan with full access, close this window and start the program "
                                          "from Terminal with:\n\n    sudo ./run_mac_linux.sh\n\n"
                                          "You will be asked for your password.")

    def on_close(self):
        if self.scanning and not messagebox.askyesno(APP_NAME, "A scan is running. Stop it and quit?"):
            return
        self.cancel.set()
        self.root.destroy()


def launch(args=None):
    if IS_WINDOWS:
        try:  # crisp text on high-DPI screens
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    App(root, args)
    root.mainloop()
