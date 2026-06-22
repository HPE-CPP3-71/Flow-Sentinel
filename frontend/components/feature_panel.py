"""
FeaturePanel — the "--- TCP Model Features ---" inspector on the Traffic frame.

A bordered card with a monospace header (dashed title + a small terminal
glyph) and a structured list of "feature_name = value" rows, mirroring the
TCP_KEY_FEATURES read-out from the backend. Values are right-aligned in a
mono column; long feature/value pairs wrap onto a second right-aligned line
instead of clipping (matching the Figma).

The panel is live: TrafficPage calls `update(features)` when a row in the
Flow Predictions table is selected, and `reset()` (placeholder values) when
nothing is selected.
"""

import customtkinter as ctk

from frontend import theme

# Placeholder rows — the TCP_KEY_FEATURES order from backend/pipeline.py,
# shown until a flow is selected.
PLACEHOLDER = {
    "src2dst_psh_packets": "0",
    "dst2src_rst_packets": "0",
    "dst2src_psh_packets": "0",
    "RST Flag Cnt": "0",
    "PSH Flag Cnt": "0",
    "dst2src_stddev_ps": "0.0",
    "bidirectional_stddev_ps": "188.09040379562165",
    "Pkt Len Var": "35378.00000000001",
    "src2dst_min_ps": "282",
    "bidirectional_mean_ps": "415.0",
    "bidirectional_max_ps": "548",
    "udps.fwd_seg_size_min": "28",
    "udps.init_fwd_win": "-1",
}

_WRAP_THRESHOLD = 30   # name+value chars above which the value wraps to line 2


class FeaturePanel(ctk.CTkFrame):
    def __init__(self, parent, app, features: dict | None = None,
                 title: str = "--- TCP Model Features ---"):
        super().__init__(parent, fg_color=theme.COLORS["bg_card"],
                         corner_radius=theme.RADIUS["card"],
                         border_width=1, border_color=theme.COLORS["border_subtle"])
        self.fonts = app.fonts
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # ── Header ───────────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 8))
        header.grid_columnconfigure(0, weight=1)
        self.title_label = ctk.CTkLabel(header, text=title, font=self.fonts["label_md"],
                                        text_color=theme.COLORS["text_body"])
        self.title_label.grid(row=0, column=0, sticky="w")

        icon = ctk.CTkFrame(header, fg_color="transparent", corner_radius=6,
                            border_width=1, border_color=theme.COLORS["border"],
                            width=30, height=30)
        icon.grid(row=0, column=1, sticky="e")
        icon.grid_propagate(False)
        ctk.CTkLabel(icon, text=">_", font=self.fonts["mono_md"],
                     text_color=theme.COLORS["text_muted"]).place(relx=0.5, rely=0.5,
                                                                  anchor="center")

        # divider under the header
        ctk.CTkFrame(self, fg_color=theme.COLORS["border_subtle"], height=1
                     ).grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 6))

        # ── Body (rebuilt by update / reset) ─────────────────────────────
        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.grid(row=2, column=0, sticky="nsew", padx=20, pady=(2, 14))
        self.body.grid_columnconfigure(0, weight=1)

        self._render(features or PLACEHOLDER)

    # ── public API ───────────────────────────────────────────────────────
    def update_features(self, features: dict) -> None:
        self._render(features)

    def reset(self) -> None:
        self._render(PLACEHOLDER)

    # ── rendering ────────────────────────────────────────────────────────
    def _render(self, features: dict) -> None:
        for child in self.body.winfo_children():
            child.destroy()
        for name, value in features.items():
            self._add_row(name, str(value))

    def _add_row(self, name: str, value: str) -> None:
        row = ctk.CTkFrame(self.body, fg_color="transparent")
        row.pack(fill="x", pady=5)
        row.grid_columnconfigure(0, weight=1)

        if len(name) + len(value) > _WRAP_THRESHOLD:
            # Long pair → "name =" then the value right-aligned underneath.
            ctk.CTkLabel(row, text=f"{name} =", font=self.fonts["mono_md"],
                         text_color=theme.COLORS["text_body"], anchor="w"
                         ).grid(row=0, column=0, sticky="w")
            ctk.CTkLabel(row, text=value, font=self.fonts["mono_md"],
                         text_color=theme.COLORS["text_muted"], anchor="e"
                         ).grid(row=1, column=0, sticky="e", pady=(2, 0))
        else:
            ctk.CTkLabel(row, text=name, font=self.fonts["mono_md"],
                         text_color=theme.COLORS["text_body"], anchor="w"
                         ).grid(row=0, column=0, sticky="w")
            ctk.CTkLabel(row, text=f"= {value}", font=self.fonts["mono_md"],
                         text_color=theme.COLORS["text_muted"], anchor="e"
                         ).grid(row=0, column=1, sticky="e", padx=(20, 0))
