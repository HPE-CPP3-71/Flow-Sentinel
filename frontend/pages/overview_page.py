"""
OverviewPage — the dashboard frame (Figma image 3).

Top bar + collapsible sidebar (Overview active), then a KPI row of four
StatCards and a "Live Capture Stats" panel — both bound to the live backend
state (core.state.AppState), not placeholder data.

  - The four cards (Total Packets / Total Flows / Anomalies / Bandwidth) are
    refreshed in place by a 1 s poll loop via StatCard.update_value().
  - The table reads AppState.get_flow_log_snapshot() each poll, newest-first,
    and paginates it. Page size is height-aware (as many rows as fit); the
    header band (title + Export) is pinned to the top and the footer
    (range text + pagination) to the bottom.
  - The capture-status pill reflects AppState.running.
  - Export writes every retained flow record to a CSV.

The shared header's Start/Stop call the same pause/resume capture mechanism
the Traffic page uses (Overview itself stays display-only).
"""

import math

import customtkinter as ctk
from customtkinter import ScalingTracker

from core.events import FlowEvent
from frontend import theme
from frontend.components.flow_table import FlowTable
from frontend.components.footer import Footer
from frontend.components.sidebar import Sidebar
from frontend.components.stat_card import StatCard
from frontend.components.topbar import TopBar

_COLUMNS = [
    {"key": "src", "title": "SOURCE IP", "weight": 3, "align": "w"},
    {"key": "dst", "title": "DESTINATION IP", "weight": 3, "align": "w"},
    {"key": "pkts", "title": "PACKETS", "weight": 2, "align": "w"},
    {"key": "proto", "title": "PROTOCOL", "weight": 2, "align": "w"},
    {"key": "status", "title": "STATUS / PREDICTION", "weight": 3, "align": "w"},
]

_ROW_HEIGHT = 50
_TABLE_HEADER_PX = 38   # column-title row + underline inside FlowTable
_POLL_MS = 1000         # card + table refresh cadence


# ── formatting helpers ───────────────────────────────────────────────────
def _fmt_packets(n: int) -> str:
    """1_240_000_000 → '1.24B', 45_912 → '45,912'."""
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.2f}B"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def _fmt_bandwidth(bps: float) -> tuple[str, str]:
    """Bytes/sec → (value, unit) in bits/sec, e.g. (1_050_000_000.0) → ('8.4', 'Gbps')."""
    bits = bps * 8
    if bits >= 1_000_000_000:
        return f"{bits / 1_000_000_000:.1f}", "Gbps"
    if bits >= 1_000_000:
        return f"{bits / 1_000_000:.1f}", "Mbps"
    if bits >= 1_000:
        return f"{bits / 1_000:.1f}", "Kbps"
    return f"{bits:.0f}", "bps"


def _event_to_overview_row(event: FlowEvent) -> dict:
    """
    Translate a FlowEvent into the row-dict the Live Capture Stats grid wants.
    Mirrors the keys in _COLUMNS exactly; reuses the existing benign / anomaly
    cell styling (green dot + 'Normal Traffic' vs red dot + 'Suspicious …').
    """
    link = theme.COLORS["link"]
    ok = theme.COLORS["success"]
    bad = theme.COLORS["danger"]

    if event.is_anomaly:
        return {
            "src": {"text": str(event.src_ip), "color": bad, "bold": True},
            "dst": str(event.dst_ip),
            "pkts": {"text": f"{event.packets:,}"},
            "proto": {"text": event.protocol, "badge": True, "badge_fg": "#3a1a1f",
                      "badge_text": theme.COLORS["danger_text"]},
            "status": {"text": f"Suspicious {event.anomaly_type}", "dot": bad, "color": bad},
            "_fill": theme.COLORS["danger_bg"],
        }

    return {
        "src": {"text": str(event.src_ip), "color": link},
        "dst": str(event.dst_ip),
        "pkts": {"text": f"{event.packets:,}"},
        "proto": {"text": event.protocol, "badge": True},
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
        self._total = 0
        self._table = None
        self._resize_job = None
        self._poll_job = None
        self._last_running = None   # gates header/status sync to actual changes

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Shared header: Start/Stop reuse the same pause/resume capture toggle
        # as the Traffic page (no second controller, no Overview-only state).
        self.topbar = TopBar(self, app, variant="dashboard", on_toggle=self._toggle_capture)
        self.topbar.grid(row=0, column=0, sticky="ew")

        mid = ctk.CTkFrame(self, fg_color="transparent")
        mid.grid(row=1, column=0, sticky="nsew")
        mid.grid_rowconfigure(0, weight=1)
        mid.grid_columnconfigure(1, weight=1)

        Sidebar(mid, app, active="overview").grid(row=0, column=0, sticky="ns")
        ctk.CTkFrame(mid, fg_color=theme.COLORS["border_subtle"], width=1
                     ).grid(row=0, column=0, sticky="nse")
        self._build_content(mid).grid(row=0, column=1, sticky="nsew", padx=32, pady=24)

        Footer(self, app).grid(row=2, column=0, sticky="ew")

        # first paint once geometry has settled (Configure refines it after),
        # then the steady 1 s poll loop.
        self.after(60, self._render_table)
        self._poll_job = self.after(_POLL_MS, self._poll)

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
        self._status_dot = ctk.CTkLabel(live, text="●", font=self.fonts["mono_xs"],
                                        text_color=theme.COLORS["success"])
        self._status_dot.pack(side="left", padx=(0, 6))
        self._status_text = ctk.CTkLabel(live, text="LIVE CAPTURE ACTIVE",
                                         font=self.fonts["label_sm"],
                                         text_color=theme.COLORS["success"])
        self._status_text.pack(side="left")

        # ── KPI cards (live values, refreshed in place by _poll) ─────────
        counters = self.app.app_state.snapshot_counters()
        cards = ctk.CTkFrame(content, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", pady=(0, 24))
        for i in range(4):
            cards.grid_columnconfigure(i, weight=1, uniform="kpi")

        self._card_packets = StatCard(cards, self.app, label="TOTAL PACKETS",
                                      value=_fmt_packets(counters["total_packets"]), icon="◷")
        self._card_flows = StatCard(cards, self.app, label="TOTAL FLOWS",
                                    value=f"{counters['total_flows']:,}", icon="✳")
        self._card_anomalies = StatCard(cards, self.app, label="ANOMALIES DETECTED",
                                        value=str(counters["anomalies"]), icon="⚠",
                                        badge="Action Required", variant="danger")
        self._card_bandwidth = StatCard(cards, self.app, label="BANDWIDTH",
                                        value="0.0", unit="Gbps", icon="◑")
        for i, card in enumerate((self._card_packets, self._card_flows,
                                  self._card_anomalies, self._card_bandwidth)):
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 12, 0))

        self._apply_capture_state(counters["running"])

        # ── Live Capture Stats panel ─────────────────────────────────────
        self._build_table_panel(content).grid(row=2, column=0, sticky="nsew")
        return content

    # ── Live Capture Stats panel ─────────────────────────────────────────
    def _build_table_panel(self, parent) -> ctk.CTkFrame:
        # No border on the card: the header band is flush and shares the card's
        # corner radius, so a 1px border would peek out behind the band's
        # rounded corners (mismatched-radius artefact). Fill contrast alone
        # gives a clean single rounded shape.
        panel = ctk.CTkFrame(parent, fg_color=theme.COLORS["bg_card"],
                             corner_radius=theme.RADIUS["card"], border_width=0)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)     # body row absorbs all spare height

        # Header band — distinct lighter fill, flush, same corner radius as the
        # card so the top corners read as one continuous rounded edge.
        band = ctk.CTkFrame(panel, fg_color=theme.COLORS["bg_panel_header"],
                            corner_radius=theme.RADIUS["card"])
        band.grid(row=0, column=0, sticky="ew")
        band.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(band, text="Live Capture Stats", font=self.fonts["headline_md"],
                     text_color=theme.COLORS["text_headline"]
                     ).grid(row=0, column=0, sticky="w", padx=24, pady=18)
        ctk.CTkButton(band, text="⭳ Export", width=92, height=32,
                      font=self.fonts["body_sm"], corner_radius=theme.RADIUS["button"],
                      command=self._on_export, **theme.BUTTON_VARIANTS["outlined"]
                      ).grid(row=0, column=1, sticky="e", padx=(0, 24))

        # Body — the height-aware table lives here. grid_propagate(False) keeps
        # the holder at the height its grid cell gives it (the spare space in
        # the card) so the measured height reflects the *available* space and
        # the row count can never overflow past the footer.
        self.body_holder = ctk.CTkFrame(panel, fg_color="transparent")
        self.body_holder.grid(row=1, column=0, sticky="nsew", padx=24, pady=(6, 0))
        self.body_holder.grid_propagate(False)
        self.body_holder.grid_columnconfigure(0, weight=1)
        self.body_holder.grid_rowconfigure(0, weight=1)
        self.body_holder.bind("<Configure>", self._on_body_configure)

        # Built once and then refreshed in place via update_data() — never
        # destroyed/recreated, so periodic refreshes don't blink.
        self._table = FlowTable(self.body_holder, self.app, _COLUMNS, [],
                                row_height=self.row_height, separators=True)
        self._table.grid(row=0, column=0, sticky="new")

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

    # ── capture status indicator ─────────────────────────────────────────
    def _update_status(self, running: bool) -> None:
        if running:
            color, text = theme.COLORS["success"], "LIVE CAPTURE ACTIVE"
        else:
            color, text = theme.COLORS["warning"], "LIVE CAPTURE STOPPED"
        self._status_dot.configure(text_color=color)
        self._status_text.configure(text=text, text_color=color)

    def _apply_capture_state(self, running: bool) -> None:
        """Sync the status pill + header Start/Stop enabled-state to the shared
        capture state — only when it actually changes, to avoid per-poll
        reconfigure flicker on the buttons."""
        if running == self._last_running:
            return
        self._last_running = running
        self._update_status(running)
        if running:
            self.topbar.set_running()
        else:
            self.topbar.set_paused()

    # ── shared capture toggle (the ONE controller, on the Traffic page) ──
    def _toggle_capture(self) -> None:
        """Start/Stop on this page delegate to the single capture controller
        that lives on the Traffic page. Overview owns no capture logic/state of
        its own and never creates a second controller."""
        traffic = self.app.pages.get("traffic")
        if traffic is not None and hasattr(traffic, "_toggle_capture"):
            traffic._toggle_capture()
        self._apply_capture_state(self.app.app_state.running)

    # ── periodic refresh ─────────────────────────────────────────────────
    def _poll(self) -> None:
        state = self.app.app_state
        counters = state.snapshot_counters()

        self._card_packets.update_value(_fmt_packets(counters["total_packets"]))
        self._card_flows.update_value(f"{counters['total_flows']:,}")
        self._card_anomalies.update_value(f"{counters['anomalies']:,}")
        val, unit = _fmt_bandwidth(state.bandwidth_bps())
        self._card_bandwidth.update_value(val, unit)

        self._apply_capture_state(counters["running"])
        self._render_table()

        self._poll_job = self.after(_POLL_MS, self._poll)

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
            total_pages = max(1, math.ceil(self._total / self.page_size))
            self.page = min(self.page, total_pages)
            if self._resize_job is not None:
                self.after_cancel(self._resize_job)
            self._resize_job = self.after(60, self._render_table)

    def _render_table(self) -> None:
        self._resize_job = None
        if self._table is None:
            return

        # Newest-first snapshot of the real flow history, then paginate.
        snapshot = self.app.app_state.get_flow_log_snapshot()
        self._total = len(snapshot)
        total_pages = max(1, math.ceil(self._total / self.page_size)) if self.page_size else 1
        self.page = min(self.page, total_pages)

        start = (self.page - 1) * self.page_size
        page_events = snapshot[::-1][start:start + self.page_size]
        rows = [_event_to_overview_row(e) for e in page_events]

        # In-place reconcile — reconfigures existing widgets, only adds/removes
        # rows when the count changes. No destroy/recreate, so no flicker.
        self._table.update_data(rows)
        self._update_footer(start, len(rows))

    def _update_footer(self, start: int, count: int) -> None:
        first = start + 1 if count else 0
        last = start + count
        self.range_label.configure(
            text=f"Showing {first:,}-{last:,} of {self._total:,} flows")

        for child in self.pager.winfo_children():
            child.destroy()
        total_pages = max(1, math.ceil(self._total / self.page_size))

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
        total_pages = max(1, math.ceil(self._total / self.page_size))
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

    # ── export ───────────────────────────────────────────────────────────
    def _on_export(self) -> None:
        """Write every retained flow record to a CSV the user picks."""
        import csv
        from tkinter import filedialog, messagebox

        snapshot = self.app.app_state.get_flow_log_snapshot()
        if not snapshot:
            messagebox.showinfo("Export", "No flow records to export yet.")
            return

        path = filedialog.asksaveasfilename(
            title="Export flow records",
            defaultextension=".csv",
            initialfile="flowsentinel_export.csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return

        columns = ["Source IP", "Destination IP", "Packet Count",
                   "Protocol", "Prediction", "Confidence"]
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(columns)
                for e in snapshot:
                    writer.writerow([e.src_ip, e.dst_ip, e.packets,
                                     e.protocol, e.prediction, f"{e.confidence:.4f}"])
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))
            return

        messagebox.showinfo(
            "Export complete",
            f"Exported {len(snapshot):,} flow records to:\n{path}")
