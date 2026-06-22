"""
Sidebar — the left navigation rail on the Overview and Traffic frames.

Collapsible with a smooth, animated width change: a chevron at the top
toggles between the expanded state (icon + label) and the collapsed state
(centred icon only). Nav buttons are built once and simply re-styled on
toggle, so the transition animates instead of snapping. The active item is
highlighted with the blue "nav_active" pill.

Navigation is driven through app.show_page(name); the page that hosts the
sidebar passes its own key as `active` so the right item is highlighted. The
collapse state is remembered on the app so it stays consistent across pages.
"""

import customtkinter as ctk

from frontend import theme

# (page key, glyph, label) — order matches the Figma top-to-bottom.
NAV_ITEMS = [
    ("overview", "▦", "Overview"),
    ("traffic", "◴", "Traffic"),
    ("settings", "⚙", "Settings"),
]

_EXPANDED_W = 210
_COLLAPSED_W = 66
_ANIM_STEP = 18      # px per frame
_ANIM_DELAY = 10     # ms per frame


class Sidebar(ctk.CTkFrame):
    def __init__(self, parent, app, active: str = "overview"):
        super().__init__(parent, fg_color=theme.COLORS["bg_app"],
                         corner_radius=0, border_width=0)
        self.app = app
        self.fonts = app.fonts
        self.active = active
        self.collapsed = getattr(app, "sidebar_collapsed", False)

        self._width = _COLLAPSED_W if self.collapsed else _EXPANDED_W
        self._anim_job = None
        self.configure(width=self._width)
        self.grid_propagate(False)
        self.grid_columnconfigure(0, weight=1)

        self._buttons: dict[str, ctk.CTkButton] = {}
        self._build()
        self._apply_mode()

    # ── build (once) ─────────────────────────────────────────────────────
    def _build(self) -> None:
        toggle_row = ctk.CTkFrame(self, fg_color="transparent")
        toggle_row.grid(row=0, column=0, sticky="ew", padx=14, pady=(16, 18))
        toggle_row.grid_columnconfigure(0, weight=1)
        self.chevron = ctk.CTkButton(
            toggle_row, text="‹", width=32, height=32, font=self.fonts["body_lg"],
            corner_radius=theme.RADIUS["button"], fg_color="transparent",
            hover_color=theme.COLORS["bg_card"], text_color=theme.COLORS["text_muted"],
            command=self._toggle,
        )
        self.chevron.grid(row=0, column=0, sticky="e")
        self.grid_rowconfigure(1, weight=1)
        
        for i, (key, glyph, label) in enumerate(NAV_ITEMS, start=2):
            is_active = key == self.active
            if is_active:
                colors = dict(fg_color=theme.COLORS["nav_active"],
                              hover_color=theme.COLORS["nav_active_hover"],
                              text_color=theme.SLATE[50])
            else:
                colors = dict(fg_color="transparent",
                              hover_color=theme.COLORS["bg_card"],
                              text_color=theme.COLORS["text_body"])
            btn = ctk.CTkButton(
                self, text="", font=self.fonts["body_md"], height=44,
                corner_radius=theme.RADIUS["button"],
                command=lambda k=key: self._navigate(k), **colors,
            )
            btn.grid(row=i, column=0, sticky="ew", padx=14, pady=6)
            self._buttons[key] = (btn, glyph, label)

        self.grid_rowconfigure(len(NAV_ITEMS) + 2, weight=1)
        
    # ── collapse / expand ────────────────────────────────────────────────
    def _apply_mode(self) -> None:
        self.chevron.configure(text="›" if self.collapsed else "‹")
        for key, (btn, glyph, label) in self._buttons.items():
            if self.collapsed:
                btn.configure(text=glyph, anchor="center")
            else:
                btn.configure(text=f"{glyph}    {label}", anchor="w")

    def _toggle(self) -> None:
        self.collapsed = not self.collapsed
        self.app.sidebar_collapsed = self.collapsed
        self._apply_mode()
        self._animate_to(_COLLAPSED_W if self.collapsed else _EXPANDED_W)

    def _animate_to(self, target: int) -> None:
        if self._anim_job is not None:
            self.after_cancel(self._anim_job)
        step = _ANIM_STEP if target > self._width else -_ANIM_STEP

        def tick():
            self._width += step
            if (step > 0 and self._width >= target) or (step < 0 and self._width <= target):
                self._width = target
                self.configure(width=self._width)
                self._anim_job = None
                return
            self.configure(width=self._width)
            self._anim_job = self.after(_ANIM_DELAY, tick)

        tick()

    # ── navigation ───────────────────────────────────────────────────────
    def _navigate(self, key: str) -> None:
        if key == self.active:
            return
        if key in self.app.pages:
            self.app.show_page(key)
