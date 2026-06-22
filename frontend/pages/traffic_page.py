"""
TrafficPage — the live-detection frame (Figma image 2).

Top bar + collapsible sidebar (Traffic active), then a header with the
"Pipeline live" status and uptime pill, two side-by-side panels — the
FeaturePanel (left, ~1/3) and a "Flow Predictions" panel wrapping a
scrollable, selectable FlowTable (right, ~2/3) — and a red STOP CAPTURE
button.

Interaction: selecting a row in the predictions table highlights it and
pushes that flow's feature read-out into the FeaturePanel; with nothing
selected the panel shows its placeholder values. All rows/features are
placeholders until the page is bound to AppState.
"""

import customtkinter as ctk

from frontend import theme
from frontend.components.feature_panel import PLACEHOLDER, FeaturePanel
from frontend.components.flow_table import FlowTable
from frontend.components.footer import Footer
from frontend.components.sidebar import Sidebar
from frontend.components.topbar import TopBar

_COLUMNS = [
    {"key": "time", "title": "Time", "weight": 3, "align": "w"},
    {"key": "model", "title": "Model", "weight": 3, "align": "w"},
    {"key": "src", "title": "Src IP", "weight": 4, "align": "w"},
    {"key": "dst", "title": "Dst IP", "weight": 4, "align": "w"},
    {"key": "pkts", "title": "Pkts", "weight": 2, "align": "e"},
    {"key": "bytes", "title": "Bytes", "weight": 2, "align": "e"},
    {"key": "pred", "title": "Prediction", "weight": 4, "align": "w"},
    {"key": "conf", "title": "Conf", "weight": 2, "align": "e"},
]

# (time, model, src, dst, pkts, bytes, kind, conf)
_RAW = [
    ("20:52:38", "TCP/UDP", "192.168.56.108", "192.168.56.100", "2", "830", "benign", "0.9363"),
    ("20:52:37", "TCP/UDP", "192.168.56.108", "192.168.56.102", "14", "12040", "benign", "0.9912"),
    ("20:52:37", "ICMP", "10.0.0.5", "192.168.56.100", "4", "256", "benign", "0.8841"),
    ("20:52:35", "TCP/UDP", "185.15.22.1", "192.168.56.100", "120", "45092", "anomaly", "0.9998"),
    ("20:52:38", "TCP/UDP", "192.168.56.108", "192.168.56.100", "2", "830", "benign", "0.9363"),
    ("20:52:37", "TCP/UDP", "192.168.56.108", "192.168.56.102", "14", "12040", "benign", "0.9912"),
    ("20:52:37", "ICMP", "10.0.0.5", "192.168.56.100", "4", "256", "benign", "0.8841"),
    ("20:52:35", "TCP/UDP", "185.15.22.1", "192.168.56.100", "120", "45092", "anomaly", "0.9998"),
]


def _features_for(pkts: str, byts: str, kind: str) -> dict:
    """A per-flow feature read-out so the inspector visibly changes on select."""
    feats = dict(PLACEHOLDER)
    feats["bidirectional_max_ps"] = byts
    feats["src2dst_min_ps"] = pkts
    if kind == "anomaly":
        feats["RST Flag Cnt"] = "7"
        feats["PSH Flag Cnt"] = "5"
        feats["dst2src_rst_packets"] = "3"
        feats["bidirectional_mean_ps"] = "1204.0"
    return feats


class TrafficPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.COLORS["bg_app"])
        self.app = app
        self.fonts = app.fonts
        self._features = [_features_for(p, b, k) for _, _, _, _, p, b, k, _ in _RAW]

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        TopBar(self, app, variant="dashboard",
               on_stop=lambda: app.show_page("start")).grid(row=0, column=0, sticky="ew")

        mid = ctk.CTkFrame(self, fg_color="transparent")
        mid.grid(row=1, column=0, sticky="nsew")
        mid.grid_rowconfigure(0, weight=1)
        mid.grid_columnconfigure(1, weight=1)

        Sidebar(mid, app, active="traffic").grid(row=0, column=0, sticky="ns")
        ctk.CTkFrame(mid, fg_color=theme.COLORS["border_subtle"], width=1
                     ).grid(row=0, column=0, sticky="nse")
        self._build_content(mid).grid(row=0, column=1, sticky="nsew", padx=32, pady=22)

        Footer(self, app).grid(row=2, column=0, sticky="ew")

    # ── content ──────────────────────────────────────────────────────────
    def _build_content(self, parent) -> ctk.CTkFrame:
        content = ctk.CTkFrame(parent, fg_color="transparent")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(1, weight=1)

        self._build_header(content).grid(row=0, column=0, sticky="ew", pady=(0, 18))

        panels = ctk.CTkFrame(content, fg_color="transparent")
        panels.grid(row=1, column=0, sticky="nsew")
        panels.grid_rowconfigure(0, weight=1)
        panels.grid_columnconfigure(0, weight=1, uniform="tp")   # feature  (1/3)
        panels.grid_columnconfigure(1, weight=2, uniform="tp")   # predictions (2/3)

        self.feature_panel = FeaturePanel(panels, self.app)
        self.feature_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 16))
        self._build_predictions(panels).grid(row=0, column=1, sticky="nsew")

        stop_row = ctk.CTkFrame(content, fg_color="transparent")
        stop_row.grid(row=2, column=0, pady=(22, 2))
        ctk.CTkButton(
            stop_row, text="◉  STOP CAPTURE", width=220, height=48,
            font=self.fonts["body_md"], corner_radius=theme.RADIUS["button"],
            fg_color="#a51d1d", hover_color="#8a1818", text_color=theme.SLATE[50],
            command=lambda: self.app.show_page("start"),
        ).pack()
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
        ctk.CTkLabel(live, text="Pipeline live on [enp0s8]", font=self.fonts["mono_md"],
                     text_color=theme.COLORS["success_text"]).pack(side="left")
        ctk.CTkLabel(titles, text="Live Traffic Detection", font=self.fonts["title"],
                     text_color=theme.COLORS["text_headline"]).pack(anchor="w", pady=(6, 0))

        pill = ctk.CTkFrame(header, fg_color=theme.COLORS["bg_card"], corner_radius=8,
                            border_width=1, border_color=theme.COLORS["border_subtle"])
        pill.grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(pill, text="Uptime: 14h 22m 10s", font=self.fonts["mono_xs"],
                     text_color=theme.COLORS["text_muted"]).pack(padx=14, pady=8)
        return header

    def _build_predictions(self, parent) -> ctk.CTkFrame:
        panel = ctk.CTkFrame(parent, fg_color=theme.COLORS["bg_card"],
                             corner_radius=theme.RADIUS["card"],
                             border_width=1, border_color=theme.COLORS["border_subtle"])
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)

        # Header band — same treatment as the Overview "Live Capture Stats"
        # card: distinct lighter fill, flush rounded top corners sharing the
        # card's corners, title sitting inside the band.
        head = ctk.CTkFrame(panel, fg_color=theme.COLORS["bg_panel_header"],
                            corner_radius=theme.RADIUS["card"])
        head.grid(row=0, column=0, sticky="ew")
        head.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(head, text="Flow Predictions", font=self.fonts["headline_md"],
                     text_color=theme.COLORS["text_headline"]
                     ).grid(row=0, column=0, sticky="w", padx=20, pady=18)
        ctk.CTkLabel(head, text="•  •  •", font=self.fonts["mono_xs"],
                     text_color=theme.COLORS["text_muted"]
                     ).grid(row=0, column=1, sticky="e", padx=(0, 20))

        self.pred_table = FlowTable(
            panel, self.app, _COLUMNS, self._build_rows(), row_height=42,
            font_key="mono_md", cell_pad=8, scrollable=True, selectable=True,
            on_select=self._on_row_select,
        )
        self.pred_table.grid(row=1, column=0, sticky="nsew", padx=(20, 8), pady=(4, 0))

        foot = ctk.CTkFrame(panel, fg_color="transparent")
        foot.grid(row=2, column=0, pady=(6, 14))
        ctk.CTkLabel(foot, text="•  •  •    Awaiting stream...", font=self.fonts["mono_xs"],
                     text_color=theme.COLORS["text_muted"]).pack()
        return panel

    # ── rows / interaction ───────────────────────────────────────────────
    def _build_rows(self) -> list[dict]:
        benign = {"text": "BENIGN", "color": theme.COLORS["success_text"], "bold": True}
        rows = []
        for t, m, s, d, p, b, kind, c in _RAW:
            anomaly = kind == "anomaly"
            rows.append({
                "time": t, "model": m, "src": s, "dst": d, "pkts": p, "bytes": b,
                "conf": {"text": c, "color": theme.COLORS["text_muted"]},
                "pred": ({"text": "⚠ ANOMALY", "bold": True,
                          "color": theme.COLORS["danger_text"],
                          "dim_color": theme.COLORS["danger_text"]}
                         if anomaly else benign),
                "_dim": anomaly,
            })
        return rows

    def _on_row_select(self, index: int) -> None:
        self.feature_panel.update_features(self._features[index])
