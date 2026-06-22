"""
OverviewPage — the dashboard frame (Figma image 3).

Top bar + collapsible sidebar (Overview active), then a KPI row of four
StatCards and a "Live Capture Stats" panel.

The table is height-aware: instead of a fixed 4 rows it measures the space
available inside the card and renders as many rows as will fit, recomputing
on window resize. The header band (title + Export) is pinned to the top and
the footer (range text + pagination) to the bottom; only the table body
grows or shrinks. Pagination page-size and the "Showing X–Y of Z" text are
derived from the current visible row count.

All figures are placeholders until the page is bound to
AppState.snapshot_counters() / flow_log.
"""

import math

import customtkinter as ctk
from customtkinter import ScalingTracker

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

_TOTAL_FLOWS = 45_912
_ROW_HEIGHT = 50
_TABLE_HEADER_PX = 38   # column-title row + underline inside FlowTable

# Pools used to synthesise placeholder rows so a full page looks varied. The
# real rows will come from AppState.flow_log; this only fills the space.
_NORMAL = [
    ("192.168.1.105", "10.0.0.52", "TCP"),
    ("192.168.1.112", "172.16.254.1", "UDP"),
    ("192.168.2.50", "8.8.8.8", "DNS"),
    ("10.0.4.18", "10.0.0.52", "TCP"),
    ("172.16.9.40", "192.168.56.100", "UDP"),
]


def _row_for_index(i: int) -> dict:
    """Deterministic placeholder row for global flow index `i` (0-based)."""
    link = theme.COLORS["link"]
    ok = theme.COLORS["success"]
    bad = theme.COLORS["danger"]

    if i % 7 == 3:   # roughly one suspicious flow per screen
        return {
            "src": {"text": "45.22.19.102", "color": bad, "bold": True},
            "dst": "10.0.0.8", "pkts": {"text": f"{(i * 613 % 90000) + 1000:,}"},
            "proto": {"text": "ICMP", "badge": True, "badge_fg": "#3a1a1f",
                      "badge_text": theme.COLORS["danger_text"]},
            "status": {"text": "Suspicious Volumetric", "dot": bad, "color": bad,
                       "trailing": "⛉", "trailing_color": bad},
            "_fill": theme.COLORS["danger_bg"],
        }

    src, dst, proto = _NORMAL[i % len(_NORMAL)]
    return {
        "src": {"text": src, "color": link}, "dst": dst,
        "pkts": {"text": f"{(i * 617 % 90000) + 200:,}"},
        "proto": {"text": proto, "badge": True},
        "status": {"text": "Normal Traffic", "dot": ok, "color": theme.COLORS["text_body"]},
    }


class OverviewPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.COLORS["bg_app"])
        self.app = app
        self.fonts = app.fonts

        # pagination state — page_size is recomputed from the available height
        self.page = 1
        self.page_size = 1
        self.row_height = _ROW_HEIGHT
        self._table = None
        self._resize_job = None

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

        # first paint once geometry has settled (Configure refines it after)
        self.after(60, self._render_table)

    def _build_content(self, parent) -> ctk.CTkFrame:
        content = ctk.CTkFrame(parent, fg_color="transparent")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(2, weight=1)
        # Stop the table panel's height from bubbling up and overflowing the
        # window: content fills its (fixed) grid cell instead of growing to its
        # children, which keeps the table body's available height well-defined.
        content.grid_propagate(False)

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

    # ── Live Capture Stats panel ─────────────────────────────────────────
    def _build_table_panel(self, parent) -> ctk.CTkFrame:
        panel = ctk.CTkFrame(parent, fg_color=theme.COLORS["bg_card"],
                             corner_radius=theme.RADIUS["card"],
                             border_width=1, border_color=theme.COLORS["border_subtle"])
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)     # body row absorbs all spare height

        # Header band — distinct lighter fill whose rounded top corners share
        # the card's corners (flush, same radius, no inset) so the corners read
        # as one continuous rounded edge. Its rounded bottom corners blend into
        # the card body below, so no notch/separator artefact is left behind.
        band = ctk.CTkFrame(panel, fg_color=theme.COLORS["bg_panel_header"],
                            corner_radius=theme.RADIUS["card"])
        band.grid(row=0, column=0, sticky="ew")
        band.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(band, text="Live Capture Stats", font=self.fonts["headline_md"],
                     text_color=theme.COLORS["text_headline"]
                     ).grid(row=0, column=0, sticky="w", padx=24, pady=18)
        ctk.CTkButton(band, text="⭳ Export", width=92, height=32,
                      font=self.fonts["body_sm"], corner_radius=theme.RADIUS["button"],
                      **theme.BUTTON_VARIANTS["outlined"]
                      ).grid(row=0, column=1, sticky="e", padx=(0, 24))

        # Body — the height-aware table lives here. grid_propagate(False) is
        # essential: it makes the holder take the height its grid cell gives
        # it (the spare space in the card) rather than growing to fit the
        # table, so the measured height reflects the *available* space and the
        # row count can never overflow past the footer.
        self.body_holder = ctk.CTkFrame(panel, fg_color="transparent")
        self.body_holder.grid(row=1, column=0, sticky="nsew", padx=24, pady=(6, 0))
        self.body_holder.grid_propagate(False)
        self.body_holder.grid_columnconfigure(0, weight=1)
        self.body_holder.grid_rowconfigure(0, weight=1)
        self.body_holder.bind("<Configure>", self._on_body_configure)

        # Footer — pinned to the bottom of the card.
        foot = ctk.CTkFrame(panel, fg_color="transparent")
        foot.grid(row=2, column=0, sticky="ew", padx=24, pady=(8, 16))
        foot.grid_columnconfigure(0, weight=1)
        self.range_label = ctk.CTkLabel(foot, text="", font=self.fonts["mono_xs"],
                                        text_color=theme.COLORS["text_muted"])
        self.range_label.grid(row=0, column=0, sticky="w")
        self.pager = ctk.CTkFrame(foot, fg_color="transparent")
        self.pager.grid(row=0, column=1, sticky="e")
        return panel

    # ── height-aware rendering ───────────────────────────────────────────
    def _on_body_configure(self, event) -> None:
        # event.height is in physical pixels; row_height / header are in CTk
        # logical units, so divide by the widget scaling before comparing.
        scaling = ScalingTracker.get_widget_scaling(self)
        avail = event.height / scaling - _TABLE_HEADER_PX
        # +2 accounts for the 1px vertical gap (pady) around each row
        new_size = max(1, int(avail // (self.row_height + 2)))
        if new_size != self.page_size:
            self.page_size = new_size
            total_pages = max(1, math.ceil(_TOTAL_FLOWS / self.page_size))
            self.page = min(self.page, total_pages)
            if self._resize_job is not None:
                self.after_cancel(self._resize_job)
            self._resize_job = self.after(60, self._render_table)

    def _render_table(self) -> None:
        self._resize_job = None
        if self._table is not None:
            self._table.destroy()

        start = (self.page - 1) * self.page_size
        count = min(self.page_size, _TOTAL_FLOWS - start)
        rows = [_row_for_index(start + k) for k in range(count)]

        self._table = FlowTable(self.body_holder, self.app, _COLUMNS, rows,
                                row_height=self.row_height, separators=True)
        self._table.grid(row=0, column=0, sticky="new")
        self._update_footer(start, count)

    def _update_footer(self, start: int, count: int) -> None:
        first = start + 1 if count else 0
        last = start + count
        self.range_label.configure(
            text=f"Showing {first:,}-{last:,} of {_TOTAL_FLOWS:,} flows")

        for child in self.pager.winfo_children():
            child.destroy()
        total_pages = max(1, math.ceil(_TOTAL_FLOWS / self.page_size))

        # up-to-three page numbers, windowed around the current page
        win_start = max(1, self.page - 1)
        win_end = min(total_pages, win_start + 2)
        win_start = max(1, win_end - 2)
        items = ["‹"] + [str(p) for p in range(win_start, win_end + 1)] + ["›"]

        for label in items:
            active = label == str(self.page)
            if active:
                colors = dict(fg_color=theme.COLORS["bg_card_alt"],
                              hover_color=theme.COLORS["border"],
                              text_color=theme.COLORS["text_headline"])
            else:
                colors = dict(fg_color="transparent", hover_color=theme.COLORS["bg_card_alt"],
                              text_color=theme.COLORS["text_muted"])
            ctk.CTkButton(self.pager, text=label, width=30, height=30,
                          font=self.fonts["mono_md"], corner_radius=8,
                          command=lambda lb=label: self._on_page(lb), **colors
                          ).pack(side="left", padx=2)

    def _on_page(self, label: str) -> None:
        total_pages = max(1, math.ceil(_TOTAL_FLOWS / self.page_size))
        if label == "‹":
            target = self.page - 1
        elif label == "›":
            target = self.page + 1
        else:
            target = int(label)
        target = max(1, min(total_pages, target))
        if target != self.page:
            self.page = target
            self._render_table()
