"""
The CustomTkinter root window and page router. This is what main.py
instantiates: App(state, on_start).

App itself doesn't know about pages yet — they're registered after the fact
via register_page(), once start_page.py / overview_page.py / traffic_page.py
exist. That keeps this file stable while pages get built incrementally on
top of it.

Run this file directly (`python3 -m frontend.app`, no sudo needed) to open a
standalone theme preview instead of the real app — it renders the color
scales, fonts, button variants, search bar, progress bars, and nav pill from
theme.py side by side, so you can check it against the Figma reference
before any real page is built on top of it.
"""

import customtkinter as ctk

from frontend import theme


class App(ctk.CTk):
    def __init__(self, state, on_start):
        super().__init__()
        # NOTE: stored as `app_state`, not `state` — ctk.CTk (Tk) already has a
        # built-in `.state()` method (window state), and CustomTkinter's DPI
        # scaling tracker calls it. Shadowing it with the AppState object
        # breaks that callback, so we keep the Tk method intact.
        self.app_state = state
        self.on_start = on_start

        ctk.set_appearance_mode("dark")

        # Centralized adaptive scaling — the single place UI scale is decided.
        # Must run before geometry()/minsize() so the window scales too, and
        # before building widgets/fonts so they pick up the factor. Derived
        # dynamically from DPI + screen resolution (see theme.compute_scaling);
        # no hardcoded scaling value anywhere else in the app.
        self.ui_scale = theme.init_scaling(self)

        self.configure(fg_color=theme.COLORS["bg_app"])
        self.title("FlowSentinel")
        self.geometry("1360x860")
        self.minsize(1180, 740)

        # Fonts need a live Tk root before they can be built — this is that
        # point. theme.get_fonts() also does the installed-font check.
        self.fonts = theme.get_fonts()

        # Shared UI state that needs to persist across page switches (e.g. the
        # sidebar collapse toggle), so it lives on the app rather than a page.
        self.sidebar_collapsed = False

        # All pages live in this container and raise themselves over each
        # other via .tkraise() — the classic Tkinter multi-page pattern.
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.pages: dict = {}
        self._register_pages()
        self.show_page("start")

    def _register_pages(self) -> None:
        """
        Imported here (not at module top) so the page modules — which pull in
        the component widgets — are only loaded once a Tk root and fonts
        exist, and to keep app.py importable for the standalone theme preview.
        """
        from frontend.pages.start_page import StartPage
        from frontend.pages.overview_page import OverviewPage
        from frontend.pages.traffic_page import TrafficPage
        from frontend.pages.settings_page import SettingsPage

        self.register_page("start", StartPage)
        self.register_page("overview", OverviewPage)
        self.register_page("traffic", TrafficPage)
        self.register_page("settings", SettingsPage)

    def register_page(self, name: str, frame_class) -> None:
        """
        Call once per page, after this App is constructed:
            app.register_page("start", StartPage)
            app.register_page("overview", OverviewPage)
            app.register_page("traffic", TrafficPage)
        Each page class must accept (parent, app) and be a CTkFrame subclass.
        """
        frame = frame_class(self.container, app=self)
        frame.grid(row=0, column=0, sticky="nsew")
        self.pages[name] = frame

    def show_page(self, name: str) -> None:
        self.pages[name].tkraise()


# ═══════════════════════════════════════════════════════════════════════════
# Standalone theme preview — not used by main.py, just a visual check
# ═══════════════════════════════════════════════════════════════════════════

def _swatch_card(parent, label: str, hex_value: str, scale: dict, fonts: dict) -> ctk.CTkFrame:
    card = ctk.CTkFrame(parent, fg_color=theme.COLORS["bg_card"], corner_radius=theme.RADIUS["card"])
    card.grid_columnconfigure(0, weight=1)

    header = ctk.CTkFrame(card, fg_color="transparent")
    header.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 6))
    header.grid_columnconfigure(0, weight=1)
    ctk.CTkLabel(header, text=label, font=fonts["label_md"], text_color=theme.COLORS["text_label"]
                 ).grid(row=0, column=0, sticky="w")
    ctk.CTkLabel(header, text=hex_value, font=fonts["label_sm"], text_color=theme.COLORS["text_muted"]
                 ).grid(row=0, column=1, sticky="e")

    strip = ctk.CTkFrame(card, fg_color="transparent")
    strip.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 14))
    for i, step in enumerate([950, 900, 800, 700, 600, 500, 400, 300, 200, 100, 50]):
        strip.grid_columnconfigure(i, weight=1)
        ctk.CTkFrame(strip, fg_color=scale[step], height=28, corner_radius=4, width=0
                     ).grid(row=0, column=i, sticky="ew", padx=1)
    return card


def _font_card(parent, label: str, family_hint: str, sample_font, fonts: dict) -> ctk.CTkFrame:
    card = ctk.CTkFrame(parent, fg_color=theme.COLORS["bg_card"], corner_radius=theme.RADIUS["card"])
    card.grid_columnconfigure(0, weight=1)

    header = ctk.CTkFrame(card, fg_color="transparent")
    header.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 0))
    header.grid_columnconfigure(0, weight=1)
    ctk.CTkLabel(header, text=label, font=fonts["label_md"], text_color=theme.COLORS["text_muted"]
                 ).grid(row=0, column=0, sticky="w")
    ctk.CTkLabel(header, text=family_hint, font=fonts["label_sm"], text_color=theme.COLORS["text_muted"]
                 ).grid(row=0, column=1, sticky="e")

    ctk.CTkLabel(card, text="Aa", font=sample_font, text_color=theme.COLORS["text_headline"]
                 ).grid(row=1, column=0, padx=14, pady=(0, 14), sticky="w")
    return card


def _button_row(parent, fonts: dict) -> ctk.CTkFrame:
    card = ctk.CTkFrame(parent, fg_color=theme.COLORS["bg_card"], corner_radius=theme.RADIUS["card"])
    card.grid_columnconfigure((0, 1), weight=1)
    variants = [("primary", "Primary"), ("secondary", "Secondary"),
                ("inverted", "Inverted"), ("outlined", "Outlined")]
    for i, (key, text) in enumerate(variants):
        r, c = divmod(i, 2)
        ctk.CTkButton(
            card, text=text, font=fonts["body_sm"], corner_radius=theme.RADIUS["button"],
            **theme.BUTTON_VARIANTS[key],
        ).grid(row=r, column=c, padx=10, pady=10, sticky="ew")
    return card


def _search_bar(parent, fonts: dict) -> ctk.CTkFrame:
    card = ctk.CTkFrame(parent, fg_color=theme.COLORS["bg_card"], corner_radius=theme.RADIUS["card"])
    card.grid_columnconfigure(0, weight=1)
    bar = ctk.CTkFrame(card, fg_color=theme.COLORS["bg_card_alt"], corner_radius=theme.RADIUS["search"])
    bar.grid(row=0, column=0, padx=16, pady=16, sticky="ew")
    ctk.CTkLabel(bar, text="\U0001F50D  Search", font=fonts["label_md"],
                 text_color=theme.COLORS["text_muted"]).pack(padx=14, pady=10, anchor="w")
    return card


def _progress_stack(parent, fonts: dict) -> ctk.CTkFrame:
    card = ctk.CTkFrame(parent, fg_color=theme.COLORS["bg_card"], corner_radius=theme.RADIUS["card"])
    card.grid_columnconfigure(0, weight=1)
    values = [("primary", 0.85), ("secondary", 0.55), ("tertiary", 0.25)]
    for i, (key, value) in enumerate(values):
        bar = ctk.CTkProgressBar(card, corner_radius=theme.RADIUS["pill"], height=8,
                                  **theme.PROGRESS_COLORS[key])
        bar.set(value)
        bar.grid(row=i, column=0, padx=16, pady=(16 if i == 0 else 6, 6), sticky="ew")
    return card


def _nav_pill(parent, fonts: dict) -> ctk.CTkFrame:
    card = ctk.CTkFrame(parent, fg_color=theme.COLORS["bg_card"], corner_radius=theme.RADIUS["card"])
    card.grid_columnconfigure(0, weight=1)
    pill = ctk.CTkFrame(card, fg_color=theme.COLORS["bg_card_alt"], corner_radius=theme.RADIUS["pill"])
    pill.grid(row=0, column=0, padx=16, pady=16)

    ctk.CTkButton(pill, text="\u2302", width=40, height=40, corner_radius=theme.RADIUS["button"],
                  fg_color=theme.TEAL[300], hover_color=theme.TEAL[400],
                  text_color=theme.SLATE[900], font=fonts["body_md"]
                  ).grid(row=0, column=0, padx=6, pady=6)
    ctk.CTkButton(pill, text="\U0001F50D", width=40, height=40, corner_radius=theme.RADIUS["button"],
                  fg_color="transparent", hover_color=theme.COLORS["bg_card"],
                  text_color=theme.COLORS["text_body"], font=fonts["body_md"]
                  ).grid(row=0, column=1, padx=6, pady=6)
    ctk.CTkButton(pill, text="\U0001F464", width=40, height=40, corner_radius=theme.RADIUS["button"],
                  fg_color="transparent", hover_color=theme.COLORS["bg_card"],
                  text_color=theme.COLORS["text_body"], font=fonts["body_md"]
                  ).grid(row=0, column=2, padx=6, pady=6)
    return card


def run_theme_preview() -> None:
    root = ctk.CTk()
    ctk.set_appearance_mode("dark")
    root.configure(fg_color=theme.COLORS["bg_app"])
    root.title("FlowSentinel — Theme Preview")
    root.geometry("1080x920")

    fonts = theme.get_fonts()

    outer = ctk.CTkFrame(root, fg_color="transparent")
    outer.pack(fill="both", expand=True, padx=24, pady=24)
    outer.grid_columnconfigure(0, weight=1)
    outer.grid_rowconfigure(0, weight=3)
    outer.grid_rowconfigure(1, weight=1)
    outer.grid_rowconfigure(2, weight=1)

    # Row 0: color swatches (left) + font samples (right), side by side
    top_panel = ctk.CTkFrame(outer, fg_color="transparent")
    top_panel.grid(row=0, column=0, sticky="nsew")
    top_panel.grid_columnconfigure((0, 1), weight=1)
    top_panel.grid_rowconfigure(0, weight=1)

    swatches = ctk.CTkFrame(top_panel, fg_color="transparent")
    swatches.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
    swatches.grid_columnconfigure(0, weight=1)
    for i, (label, hexval, scale) in enumerate([
        ("Primary", "#0D9488", theme.TEAL),
        ("Secondary", "#3B82F6", theme.BLUE),
        ("Tertiary", "#C36D4B", theme.TERTIARY),
        ("Neutral", "#0F172A", theme.SLATE),
    ]):
        swatches.grid_rowconfigure(i, weight=1)
        _swatch_card(swatches, label, hexval, scale, fonts).grid(row=i, column=0, sticky="nsew", pady=6)

    fontcol = ctk.CTkFrame(top_panel, fg_color="transparent")
    fontcol.grid(row=0, column=1, sticky="nsew", padx=(12, 0))
    fontcol.grid_columnconfigure(0, weight=1)
    for i, (label, hint, sample) in enumerate([
        ("Headline", "Geist", fonts["headline_xl"]),
        ("Body", "Geist", fonts["headline_lg"]),
        ("Label", "JetBrains Mono", fonts["headline_md"]),
    ]):
        fontcol.grid_rowconfigure(i, weight=1)
        _font_card(fontcol, label, hint, sample, fonts).grid(row=i, column=0, sticky="nsew", pady=6)

    # Row 1: components row (buttons + search)
    comp_top = ctk.CTkFrame(outer, fg_color="transparent")
    comp_top.grid(row=1, column=0, sticky="nsew", pady=(16, 0))
    comp_top.grid_columnconfigure((0, 1), weight=1)
    _button_row(comp_top, fonts).grid(row=0, column=0, sticky="nsew", padx=(0, 6))
    _search_bar(comp_top, fonts).grid(row=0, column=1, sticky="nsew", padx=(6, 0))

    # Row 2: progress bars + nav pill
    comp_bottom = ctk.CTkFrame(outer, fg_color="transparent")
    comp_bottom.grid(row=2, column=0, sticky="nsew", pady=(16, 0))
    comp_bottom.grid_columnconfigure((0, 1), weight=1)
    _progress_stack(comp_bottom, fonts).grid(row=0, column=0, sticky="nsew", padx=(0, 6))
    _nav_pill(comp_bottom, fonts).grid(row=0, column=1, sticky="nsew", padx=(6, 0))

    root.mainloop()


if __name__ == "__main__":
    run_theme_preview()