"""
TopBar — the application header shown at the top of every frame.

Two variants, both present in the Figma:
  - "start"     : logo + wordmark on the left, help (?) and settings (gear)
                  icons on the right (Start frame).
  - "dashboard" : logo + wordmark on the left, Start / Stop buttons and a
                  settings gear on the right (Overview + Traffic frames).

All button callbacks are optional so the UI stands alone with placeholder
behaviour until it's wired to the backend.
"""

import customtkinter as ctk

from frontend import theme
from frontend.components.logo import FlowLogo


class TopBar(ctk.CTkFrame):
    def __init__(self, parent, app, variant: str = "dashboard",
                 on_start=None, on_stop=None):
        super().__init__(parent, fg_color=theme.COLORS["bg_app"],
                         corner_radius=0, height=64,
                         border_width=0)
        self.app = app
        self.fonts = app.fonts
        self.on_start = on_start
        self.on_stop = on_stop

        self.grid_propagate(False)
        self.grid_columnconfigure(0, weight=1)   # brand block — pushes actions right

        # subtle hairline along the bottom edge
        self.configure(border_width=0)

        self._build_brand()
        if variant == "start":
            self._build_start_actions()
        else:
            self._build_dashboard_actions()

    # ── Left: logo + wordmark ────────────────────────────────────────────
    def _build_brand(self) -> None:
        brand = ctk.CTkFrame(self, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="w", padx=(24, 0), pady=14)
        FlowLogo(brand, size=26, bg=theme.COLORS["bg_app"]).pack(side="left")
        ctk.CTkLabel(brand, text="FlowSentinel", font=self.fonts["headline_md"],
                     text_color=theme.TEAL[300]).pack(side="left", padx=(10, 0))

    # ── Right (start frame): help + settings ─────────────────────────────
    def _build_start_actions(self) -> None:
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=0, column=1, sticky="e", padx=(0, 24), pady=14)
        self._icon_button(actions, "?").pack(side="left", padx=(0, 8))
        self._icon_button(actions, "⚙").pack(side="left")

    # ── Right (dashboard frames): Start / Stop + settings ────────────────
    def _build_dashboard_actions(self) -> None:
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=0, column=1, sticky="e", padx=(0, 24), pady=12)

        ctk.CTkButton(
            actions, text="▶ Start", width=86, height=34,
            font=self.fonts["body_sm"], corner_radius=theme.RADIUS["button"],
            command=self.on_start, **theme.BUTTON_VARIANTS["primary"],
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            actions, text="□ Stop", width=80, height=34,
            font=self.fonts["body_sm"], corner_radius=theme.RADIUS["button"],
            command=self.on_stop, **theme.BUTTON_VARIANTS["outlined"],
        ).pack(side="left", padx=(0, 12))

        self._icon_button(actions, "⚙").pack(side="left")

    # ── helpers ──────────────────────────────────────────────────────────
    def _icon_button(self, parent, glyph: str) -> ctk.CTkButton:
        return ctk.CTkButton(
            parent, text=glyph, width=34, height=34,
            font=self.fonts["body_lg"], corner_radius=theme.RADIUS["button"],
            fg_color="transparent", hover_color=theme.COLORS["bg_card"],
            text_color=theme.COLORS["text_muted"],
        )
