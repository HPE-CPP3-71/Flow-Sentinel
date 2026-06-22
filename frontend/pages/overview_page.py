"""
OverviewPage — the dashboard frame (Figma image 3).

Top bar + collapsible sidebar (Overview active), then a KPI row of four
StatCards and a "Live Capture Stats" panel wrapping a FlowTable with an
Export button and pagination. All figures are placeholders until the page
is bound to AppState.snapshot_counters() / flow_log.
"""

import customtkinter as ctk

from frontend import theme
from frontend.components.flow_table import FlowTable
from frontend.components.footer import Footer
from frontend.components.sidebar import Sidebar
from frontend.components.stat_card import StatCard
from frontend.components.topbar import TopBar

_COLUMNS = [
    {"key": "src", "title": "SOURCE IP", "weight": 3, "align": "w"},
    {"key": "dst", "title": "DESTINATION IP", "weight": 3, "align": "w"},
    {"key": "pkts", "title": "PACKETS", "weight": 2, "align": "e"},
    {"key": "proto", "title": "PROTOCOL", "weight": 2, "align": "w"},
    {"key": "status", "title": "STATUS / PREDICTION", "weight": 3, "align": "w"},
]


def _placeholder_rows():
    link = theme.COLORS["link"]
    ok = theme.COLORS["success"]
    bad = theme.COLORS["danger"]
    return [
        {"src": {"text": "192.168.1.105", "color": link}, "dst": "10.0.0.52",
         "pkts": {"text": "4,521", "align": "e"}, "proto": {"text": "TCP", "badge": True},
         "status": {"text": "Normal Traffic", "dot": ok, "color": theme.COLORS["text_body"]}},
        {"src": {"text": "192.168.1.112", "color": link}, "dst": "172.16.254.1",
         "pkts": {"text": "12,894"}, "proto": {"text": "UDP", "badge": True},
         "status": {"text": "Normal Traffic", "dot": ok, "color": theme.COLORS["text_body"]}},
        {"src": {"text": "45.22.19.102", "color": bad, "bold": True}, "dst": "10.0.0.8",
         "pkts": {"text": "89,201"},
         "proto": {"text": "ICMP", "badge": True, "badge_fg": "#3a1a1f",
                   "badge_text": theme.COLORS["danger_text"]},
         "status": {"text": "Suspicious Volumetric", "dot": bad, "color": bad,
                    "trailing": "⛉", "trailing_color": bad},
         "_fill": theme.COLORS["danger_bg"]},
        {"src": {"text": "192.168.2.50", "color": link}, "dst": "8.8.8.8",
         "pkts": {"text": "342"}, "proto": {"text": "DNS", "badge": True},
         "status": {"text": "Normal Traffic", "dot": ok, "color": theme.COLORS["text_body"]}},
    ]


class OverviewPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.COLORS["bg_app"])
        self.app = app
        self.fonts = app.fonts

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        TopBar(self, app, variant="dashboard",
               on_stop=lambda: app.show_page("start")).grid(row=0, column=0, sticky="ew")

        mid = ctk.CTkFrame(self, fg_color="transparent")
        mid.grid(row=1, column=0, sticky="nsew")
        mid.grid_rowconfigure(0, weight=1)
        mid.grid_columnconfigure(1, weight=1)

        Sidebar(mid, app, active="overview").grid(row=0, column=0, sticky="ns")
        ctk.CTkFrame(mid, fg_color=theme.COLORS["border_subtle"], width=1
                     ).grid(row=0, column=0, sticky="nse")
        self._build_content(mid).grid(row=0, column=1, sticky="nsew", padx=32, pady=24)

        Footer(self, app).grid(row=2, column=0, sticky="ew")

    def _build_content(self, parent) -> ctk.CTkFrame:
        content = ctk.CTkFrame(parent, fg_color="transparent")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(2, weight=1)

        # ── Header row ───────────────────────────────────────────────────
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 22))
        header.grid_columnconfigure(0, weight=1)
        titles = ctk.CTkFrame(header, fg_color="transparent")
        titles.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(titles, text="Overview", font=self.fonts["title"],
                     text_color=theme.COLORS["text_headline"]).pack(anchor="w")
        ctk.CTkLabel(titles, text="Real-time network traffic analysis.",
                     font=self.fonts["body_md"], text_color=theme.COLORS["text_muted"]
                     ).pack(anchor="w", pady=(4, 0))

        live = ctk.CTkFrame(header, fg_color="transparent")
        live.grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(live, text="●", font=self.fonts["mono_xs"],
                     text_color=theme.COLORS["success"]).pack(side="left", padx=(0, 6))
        ctk.CTkLabel(live, text="LIVE CAPTURE ACTIVE", font=self.fonts["label_sm"],
                     text_color=theme.COLORS["success"]).pack(side="left")

        # ── KPI cards ────────────────────────────────────────────────────
        cards = ctk.CTkFrame(content, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", pady=(0, 24))
        for i in range(4):
            cards.grid_columnconfigure(i, weight=1, uniform="kpi")
        specs = [
            dict(label="TOTAL PACKETS", value="1.24B", icon="◷"),
            dict(label="ACTIVE FLOWS", value="45,912", icon="✳"),
            dict(label="ANOMALIES DETECTED", value="34", icon="⚠",
                 badge="Action Required", variant="danger"),
            dict(label="BANDWIDTH", value="8.4", unit="Gbps", icon="◑"),
        ]
        for i, spec in enumerate(specs):
            StatCard(cards, self.app, **spec).grid(
                row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 12, 0))

        # ── Live Capture Stats panel ─────────────────────────────────────
        self._build_table_panel(content).grid(row=2, column=0, sticky="nsew")
        return content

    def _build_table_panel(self, parent) -> ctk.CTkFrame:
        panel = ctk.CTkFrame(parent, fg_color=theme.COLORS["bg_card"],
                             corner_radius=theme.RADIUS["card"],
                             border_width=1, border_color=theme.COLORS["border_subtle"])
        panel.grid_columnconfigure(0, weight=1)

        head = ctk.CTkFrame(panel, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 14))
        head.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(head, text="Live Capture Stats", font=self.fonts["headline_md"],
                     text_color=theme.COLORS["text_headline"]).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(head, text="⭳ Export", width=92, height=32,
                      font=self.fonts["body_sm"], corner_radius=theme.RADIUS["button"],
                      **theme.BUTTON_VARIANTS["outlined"]).grid(row=0, column=1, sticky="e")

        FlowTable(panel, self.app, _COLUMNS, _placeholder_rows(), row_height=52,
                  separators=True).grid(row=1, column=0, sticky="ew", padx=24)

        # ── pagination ───────────────────────────────────────────────────
        foot = ctk.CTkFrame(panel, fg_color="transparent")
        foot.grid(row=2, column=0, sticky="ew", padx=24, pady=(10, 18))
        foot.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(foot, text="Showing 1-4 of 45,912 flows", font=self.fonts["mono_xs"],
                     text_color=theme.COLORS["text_muted"]).grid(row=0, column=0, sticky="w")
        pager = ctk.CTkFrame(foot, fg_color="transparent")
        pager.grid(row=0, column=1, sticky="e")
        for label, active in [("‹", False), ("1", True), ("2", False),
                              ("3", False), ("›", False)]:
            if active:
                colors = dict(fg_color=theme.COLORS["bg_card_alt"],
                              hover_color=theme.COLORS["border"],
                              text_color=theme.COLORS["text_headline"])
            else:
                colors = dict(fg_color="transparent", hover_color=theme.COLORS["bg_card_alt"],
                              text_color=theme.COLORS["text_muted"])
            ctk.CTkButton(pager, text=label, width=30, height=30,
                          font=self.fonts["mono_md"], corner_radius=8, **colors
                          ).pack(side="left", padx=2)
        return panel
