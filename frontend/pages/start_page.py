"""
StartPage — the landing frame (Figma image 1).

Left: the FlowSentinel hero (logo tile + wordmark + tagline). A vertical
teal accent line splits the frame. Right: a terminal-styled card with an
interface picker and a large circular Start button, plus a "System Ready"
status line.

Clicking Start hands the chosen interface to app.on_start (the backend
hook supplied by main.py) and routes to the Overview frame.
"""

import customtkinter as ctk

from frontend import theme
from frontend.components.footer import Footer
from frontend.components.logo import FlowLogo
from frontend.components.start_button import StartButton
from frontend.components.topbar import TopBar

# Placeholder interface list — the real list would come from the backend.
INTERFACES = [
    "eth0 (Primary - 10Gbps)",
    "enp0s8 (Secondary - 1Gbps)",
    "wlan0 (Wireless)",
    "lo (Loopback)",
]


class StartPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.COLORS["bg_app"])
        self.app = app
        self.fonts = app.fonts

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        TopBar(self, app, variant="start").grid(row=0, column=0, sticky="ew")
        self._build_body().grid(row=1, column=0, sticky="nsew")
        Footer(self, app).grid(row=2, column=0, sticky="ew")

    # ── body: hero | accent line | terminal card ────────────────────────
    def _build_body(self) -> ctk.CTkFrame:
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=5)   # hero
        body.grid_columnconfigure(1, weight=0)   # accent line
        body.grid_columnconfigure(2, weight=5)   # terminal card

        self._build_hero(body).grid(row=0, column=0, sticky="nsew", padx=(60, 30))

        line = ctk.CTkFrame(body, fg_color=theme.COLORS["accent_line"], width=2)
        line.grid(row=0, column=1, sticky="ns", pady=120)

        self._build_terminal(body).grid(row=0, column=2, sticky="", padx=(40, 60))
        return body

    def _build_hero(self, parent) -> ctk.CTkFrame:
        hero = ctk.CTkFrame(parent, fg_color="transparent")
        hero.grid_columnconfigure(0, weight=1)
        hero.grid_rowconfigure(0, weight=1)
        hero.grid_rowconfigure(3, weight=1)

        title_row = ctk.CTkFrame(hero, fg_color="transparent")
        title_row.grid(row=1, column=0, sticky="w")

        logo_tile = ctk.CTkFrame(title_row, fg_color=theme.COLORS["bg_card"],
                                 corner_radius=18, width=84, height=84,
                                 border_width=1, border_color=theme.COLORS["border"])
        logo_tile.pack(side="left")
        logo_tile.pack_propagate(False)
        FlowLogo(logo_tile, size=46, bg=theme.COLORS["bg_card"]).pack(expand=True)

        ctk.CTkLabel(title_row, text="FlowSentinel", font=self.fonts["display"],
                     text_color=theme.COLORS["text_headline"]).pack(side="left", padx=(20, 0))

        ctk.CTkLabel(hero, text="Intelligent Network Traffic Anomaly Detection",
                     font=self.fonts["body_lg"], text_color=theme.COLORS["text_muted"]
                     ).grid(row=2, column=0, sticky="w", pady=(22, 0))
        return hero

    def _build_terminal(self, parent) -> ctk.CTkFrame:
        card = ctk.CTkFrame(parent, fg_color=theme.COLORS["Start_Page"],
                            corner_radius=theme.RADIUS["card"], width=620, height=720,
                            border_width=1, border_color=theme.COLORS["border_subtle"])
        card.grid_propagate(False)
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(2, weight=1)

        # ── window chrome: traffic-light dots + path ─────────────────────
        chrome = ctk.CTkFrame(card, fg_color="transparent")
        chrome.grid(row=0, column=0, sticky="ew", padx=22, pady=(18, 6))
        for color in (theme.COLORS["term_red"], theme.COLORS["term_yellow"],
                      theme.COLORS["term_green"]):
            dot = ctk.CTkLabel(chrome, text="●", font=self.fonts["body_md"],
                               text_color=color)
            dot.pack(side="left", padx=(0, 4))
        ctk.CTkLabel(chrome, text="admin@flowsentinel:~/core", font=self.fonts["mono_md"],
                     text_color=theme.COLORS["text_muted"]).pack(side="left", padx=(12, 0))

        # ── interface picker panel ───────────────────────────────────────
        picker = ctk.CTkFrame(card, fg_color=theme.COLORS["bg_card_alt"],
                              corner_radius=12)
        picker.grid(row=1, column=0, sticky="ew", padx=22, pady=(10, 0))
        picker.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(picker, text="SELECT NETWORK INTERFACE", font=self.fonts["label_sm"],
                     text_color=theme.COLORS["text_muted"]
                     ).grid(row=0, column=0, sticky="w", padx=20, pady=(18, 8))
        self.interface_var = ctk.StringVar(value=INTERFACES[0])
        ctk.CTkOptionMenu(
            picker, variable=self.interface_var, values=INTERFACES,
            font=self.fonts["mono_md"], dropdown_font=self.fonts["mono_md"],
            height=46, corner_radius=10,
            fg_color=theme.COLORS["bg_card"], button_color=theme.COLORS["bg_card"],
            button_hover_color=theme.COLORS["border"], text_color=theme.COLORS["text_body"],
            dropdown_fg_color=theme.COLORS["bg_card"],
            dropdown_text_color=theme.COLORS["text_body"],
            dropdown_hover_color=theme.COLORS["bg_card_alt"],
        ).grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))

        # ── big circular Start button (canvas-drawn, with glow) ──────────
        center = ctk.CTkFrame(card, fg_color="transparent")
        center.grid(row=2, column=0, sticky="nsew")
        center.grid_rowconfigure((0, 2), weight=1)
        center.grid_columnconfigure(0, weight=1)

        StartButton(
            center, command=self._on_start, size=300,
            bg=theme.COLORS["Start_Page"], font=self.fonts["start_btn"],
        ).grid(row=1, column=0)

        # ── status line ──────────────────────────────────────────────────
        status = ctk.CTkFrame(card, fg_color="transparent")
        status.grid(row=3, column=0, pady=(0, 28))
        ctk.CTkLabel(status, text="●", font=self.fonts["mono_md"],
                     text_color=theme.COLORS["success"]).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(status, text="System Ready. Awaiting Input.",
                     font=self.fonts["mono_md"], text_color=theme.COLORS["text_muted"]
                     ).pack(side="left")
        return card

    # ── behaviour ────────────────────────────────────────────────────────
    def _on_start(self) -> None:
        interface = self.interface_var.get().split(" ")[0]
        if callable(self.app.on_start):
            try:
                self.app.on_start(self.app.app_state, interface)
            except Exception as exc:  # backend may be unavailable in UI-only runs
                print(f"[StartPage] pipeline start failed (UI placeholder): {exc}")
        self.app.show_page("overview")
