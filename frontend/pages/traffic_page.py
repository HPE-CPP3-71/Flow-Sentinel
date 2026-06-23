from collections import deque
import customtkinter as ctk

from core.events import FlowEvent
from frontend import theme
from frontend.components.feature_panel import FeaturePanel
from frontend.components.flow_table import FlowTable
from frontend.components.footer import Footer
from frontend.components.sidebar import Sidebar
from frontend.components.topbar import TopBar

_COLUMNS = [
    {"key": "time",  "title": "Time",       "weight": 3, "align": "w"},
    {"key": "model", "title": "Model",      "weight": 3, "align": "w"},
    {"key": "src",   "title": "Src IP",     "weight": 4, "align": "w"},
    {"key": "dst",   "title": "Dst IP",     "weight": 4, "align": "w"},
    {"key": "pkts",  "title": "Pkts",       "weight": 2, "align": "e"},
    {"key": "bytes", "title": "Bytes",      "weight": 2, "align": "e"},
    {"key": "pred",  "title": "Prediction", "weight": 4, "align": "w"},
    {"key": "conf",  "title": "Conf",       "weight": 2, "align": "e"},
]

# How many rows the table and the live-events deque both hold.
# They must match so on_select(index) maps correctly into _live_events[index].
_MAX_LIVE_ROWS = 500
_POLL_MS       = 150    # queue drain interval (ms)
_UPTIME_MS     = 1000   # uptime label refresh interval (ms)


def _event_to_row(event: FlowEvent) -> dict:
    """
    Translate a FlowEvent from the backend into the row-dict format
    that FlowTable._build_row() / push_row() understands.
    Mirrors the column keys in _COLUMNS exactly.
    """
    if event.prediction.startswith("ERR:"):
        pred_cell = {
            "text": "ERR",
            "bold": True,
            "color": theme.COLORS["warning"],
        }
        dim = False
    elif event.is_anomaly:
        pred_cell = {
            "text": f"⚠ {event.anomaly_type}",
            "bold": True,
            "color": theme.COLORS["danger_text"],
            "dim_color": theme.COLORS["danger_text"],
        }
        dim = True
    else:
        pred_cell = {
            "text": "BENIGN",
            "bold": True,
            "color": theme.COLORS["success_text"],
        }
        dim = False

    return {
        "time":  event.ts,
        "model": event.model_tag,
        "src":   event.src_ip,
        "dst":   event.dst_ip,
        "pkts":  str(event.packets),
        "bytes": str(event.bytes),
        "pred":  pred_cell,
        "conf":  {"text": f"{event.confidence:.4f}",
                  "color": theme.COLORS["text_muted"]},
        "_dim":  dim,
    }


class TrafficPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.COLORS["bg_app"])
        self.app = app
        self.fonts = app.fonts

        # Live event store — maxlen matches _MAX_LIVE_ROWS so that
        # on_select(index) always maps into _live_events[index] correctly
        # even after old rows have been dropped from the table.
        self._live_events = deque(maxlen=_MAX_LIVE_ROWS)

        # Label refs populated by _build_header; used by poll / uptime tick
        self._interface_lbl = None
        self._uptime_lbl    = None

        # .after() job handles so we can cancel cleanly on destroy
        self._poll_job   = None
        self._uptime_job = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.topbar = TopBar(self, app, variant="dashboard", on_toggle=self._toggle_capture)
        self.topbar.grid(row=0, column=0, sticky="ew")

        mid = ctk.CTkFrame(self, fg_color="transparent")
        mid.grid(row=1, column=0, sticky="nsew")
        mid.grid_rowconfigure(0, weight=1)
        mid.grid_columnconfigure(1, weight=1)

        Sidebar(mid, app, active="traffic").grid(row=0, column=0, sticky="ns")
        ctk.CTkFrame(mid, fg_color=theme.COLORS["border_subtle"], width=1
                     ).grid(row=0, column=0, sticky="nse")
        self._build_content(mid).grid(row=0, column=1, sticky="nsew", padx=32, pady=22)

        Footer(self, app).grid(row=2, column=0, sticky="ew")

        # Start the poll loops. They self-throttle when capture is not running
        # so no explicit start/stop wiring is needed.
        self._schedule_poll()
        self._schedule_uptime()

# ── content ──────────────────────────────────────────────────────────
    def _build_content(self, parent) -> ctk.CTkFrame:
        content = ctk.CTkFrame(parent, fg_color="transparent")

        # 1. THE HEADER (Packed at the top)
        header = self._build_header(content)
        header.pack(side="top", fill="x", pady=(0, 18))

        # 2. THE DIVIDER LINE (Packed right under the header)
        divider = ctk.CTkFrame(content, fg_color=theme.COLORS["text_muted"], height=2, corner_radius=0)
        divider.pack(side="top", fill="x", pady=(0, 22))

        # 3. THE STOP CAPTURE BUTTON (Pinned firmly to the absolute bottom)
        stop_row = ctk.CTkFrame(content, fg_color="transparent")
        stop_row.pack(side="bottom", pady=(22, 2))
        self.stop_btn = ctk.CTkButton(
            stop_row, text="◉  STOP CAPTURE", width=220, height=48,
            font=self.fonts["body_md"], corner_radius=theme.RADIUS["button"],
            fg_color="#a51d1d", hover_color="#8a1818", text_color=theme.SLATE[50],
            command=self._toggle_capture, # Point to the new toggle logic
        )
        self.stop_btn.pack()

        # 4. THE PANELS (Fills all remaining space in the middle)
        panels = ctk.CTkFrame(content, fg_color="transparent")
        panels.pack(side="top", fill="both", expand=True)
        
        panels.grid_rowconfigure(0, weight=1)
        panels.grid_columnconfigure(0, weight=1, uniform="tp")   # feature  (1/3)
        panels.grid_columnconfigure(1, weight=2, uniform="tp")   # predictions (2/3)

        self.feature_panel = FeaturePanel(panels, self.app)
        self.feature_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 16))
        self._build_predictions(panels).grid(row=0, column=1, sticky="nsew")

        return content

    def _build_header(self, parent) -> ctk.CTkFrame:
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.grid_columnconfigure(0, weight=1)

        titles = ctk.CTkFrame(header, fg_color="transparent")
        titles.grid(row=0, column=0, sticky="w")
        live = ctk.CTkFrame(titles, fg_color="transparent")
        live.pack(anchor="w")
        ctk.CTkLabel(live, text="●", font=self.fonts["mono_xs"],
                     text_color=theme.COLORS["success"]).pack(side="left", padx=(0, 6))
        self._interface_lbl = ctk.CTkLabel(
            live, text="Pipeline live on [...]",
            font=self.fonts["mono_md"], text_color=theme.COLORS["success_text"])
        self._interface_lbl.pack(side="left")
        ctk.CTkLabel(titles, text="Live Traffic Detection", font=self.fonts["title"],
                     text_color=theme.COLORS["text_headline"]).pack(anchor="w", pady=(6, 0))

        pill = ctk.CTkFrame(header, fg_color=theme.COLORS["bg_card"], corner_radius=8,
                            border_width=1, border_color=theme.COLORS["border_subtle"])
        pill.grid(row=0, column=1, sticky="e")
        self._uptime_lbl = ctk.CTkLabel(
            pill, text="Uptime: 00:00:00",
            font=self.fonts["mono_xs"], text_color=theme.COLORS["text_muted"])
        self._uptime_lbl.pack(padx=14, pady=8)
        return header

    def _build_predictions(self, parent) -> ctk.CTkFrame:
        panel = ctk.CTkFrame(parent, fg_color=theme.COLORS["bg_card"],
                             corner_radius=theme.RADIUS["card"],
                             border_width=1, border_color=theme.COLORS["border_subtle"])
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)

        head = ctk.CTkFrame(panel, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 6))
        head.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(head, text="Flow Predictions", font=self.fonts["headline_md"],
                     text_color=theme.COLORS["text_headline"]).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(head, text="•  •  •", font=self.fonts["mono_xs"],
                     text_color=theme.COLORS["text_muted"]).grid(row=0, column=1, sticky="e")

        self.pred_table = FlowTable(
            panel, self.app, _COLUMNS, [],   # starts empty — poll() pushes rows live
            row_height=42, font_key="mono_md", cell_pad=8,
            scrollable=True, selectable=True, separators=True,
            max_rows=_MAX_LIVE_ROWS,
            on_select=self._on_row_select,
        )
        self.pred_table.grid(row=1, column=0, sticky="nsew", padx=(20, 8), pady=(4, 0))

        foot = ctk.CTkFrame(panel, fg_color="transparent")
        foot.grid(row=2, column=0, pady=(6, 14))
        ctk.CTkLabel(foot, text="•  •  •    Awaiting stream...", font=self.fonts["mono_xs"],
                     text_color=theme.COLORS["text_muted"]).pack()
        return panel

    # ── stop function( previously used not not used)─────────────────────────────────────────────────────────────
    def _on_stop(self) -> None:
        """Stop the backend capture and return to the Start page."""
        self.app.app_state.stop()
        self.app.show_page("start")
# ── stop and resume ────────────────────────────────────────────────────────
    def _toggle_capture(self) -> None:
        """Acts as a Pause/Resume toggle for the backend capture stream."""
        state = self.app.app_state
        
        if state.running:
            # PAUSE MODE
            state.stop()
            self.stop_btn.configure(
                text="▶ RESUME CAPTURE", 
                fg_color=theme.COLORS["primary"], # Turns it Teal!
                hover_color=theme.TEAL[700]
            )
            # Sync the top bar
            if hasattr(self.topbar, "set_paused"):
                self.topbar.set_paused()
        else:
            # RESUME MODE (Spawns a fresh worker thread)
            self.app.on_start(state, state.interface)
            self.stop_btn.configure(
                text="◉  STOP CAPTURE", 
                fg_color="#a51d1d", # Turns it back to Red!
                hover_color="#8a1818"
            )
            # Sync the top bar
            if hasattr(self.topbar, "set_running"):
                self.topbar.set_running()
    # ── row selection ─────────────────────────────────────────────────────
    def _on_row_select(self, index: int) -> None:
        """Push the selected flow's feature dict into the FeaturePanel."""
        if 0 <= index < len(self._live_events):
            features = self._live_events[index].key_features
            if features:
                self.feature_panel.update_features(features)
            else:
                # ICMP flows or error events have an empty key_features dict
                self.feature_panel.reset()

    # ── poll loop — drains state.queue every _POLL_MS ────────────────────
    def _schedule_poll(self) -> None:
        self._poll_job = self.after(_POLL_MS, self._poll)

    def _poll(self) -> None:
        state = self.app.app_state
        if state.running:
            # Update interface label (cheap; interface is fixed per capture)
            if state.interface and self._interface_lbl:
                self._interface_lbl.configure(
                    text=f"Pipeline live on [{state.interface}]")
            # Drain the shared queue and push each event into the table
            for event in state.drain_queue():
                self._live_events.append(event)
                self.pred_table.push_row(_event_to_row(event))
        self._schedule_poll()

    # ── uptime tick — updates the pill label every _UPTIME_MS ────────────
    def _schedule_uptime(self) -> None:
        self._uptime_job = self.after(_UPTIME_MS, self._tick_uptime)

    def _tick_uptime(self) -> None:
        state = self.app.app_state
        if self._uptime_lbl:
            if state.running:
                self._uptime_lbl.configure(
                    text=f"Uptime: {state.uptime_str()}")
            else:
                self._uptime_lbl.configure(text="Uptime: --:--:--")
        self._schedule_uptime()