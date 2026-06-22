"""
StartButton — the big circular Start control on the Start frame.

CustomTkinter buttons can't render a true circle with a soft halo, so this
is drawn on a Canvas: a radial teal glow built from concentric rings blended
into the panel background, a solid teal disc, and the play-triangle + "Start"
label on top. The whole canvas is clickable and brightens on hover.
"""

import tkinter as tk

from frontend import theme


def _rgb(hex_color: str):
    hex_color = hex_color.lstrip("#")
    return tuple(int(hex_color[i:i + 2], 16) for i in (0, 2, 4))


def _blend(c_from: str, c_to: str, t: float) -> str:
    """t=0 → c_from, t=1 → c_to."""
    a, b = _rgb(c_from), _rgb(c_to)
    r, g, bl = (round(a[i] + (b[i] - a[i]) * t) for i in range(3))
    return f"#{r:02x}{g:02x}{bl:02x}"


class StartButton(tk.Canvas):
    def __init__(self, parent, command=None, size: int = 300,
                 bg: str | None = None, font=None):
        bg = bg or theme.COLORS["bg_card"]
        super().__init__(parent, width=size, height=size, bg=bg,
                         highlightthickness=0, bd=0)
        self._command = command
        self._size = size
        self._bg = bg
        self._font = font
        self._radius = int(size * 0.35)
        self._fill = theme.TEAL[300]
        self._circle = None

        self._draw()
        self.bind("<Button-1>", self._on_click)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _draw(self) -> None:
        self.delete("all")
        c = self._size / 2
        r = self._radius

        # Soft glow — concentric rings, faint outside, stronger toward the disc.
        glow_span = int(self._size * 0.13)
        steps = 26
        for i in range(steps):
            frac = i / (steps - 1)
            radius = (r + glow_span) - frac * glow_span
            intensity = 0.05 + 0.32 * frac
            color = _blend(self._bg, theme.TEAL[400], intensity)
            self.create_oval(c - radius, c - radius, c + radius, c + radius,
                             fill=color, outline="")

        # Solid disc
        self._circle = self.create_oval(c - r, c - r, c + r, c + r,
                                        fill=self._fill, outline="")

        # Play triangle + label, both dark on the teal disc.
        ink = theme.SLATE[900]
        tri = r * 0.30
        ty = c - r * 0.28
        self.create_polygon(
            c - tri * 0.55, ty - tri, c - tri * 0.55, ty + tri, c + tri * 0.9, ty,
            fill=ink, outline="",
        )
        self.create_text(c, c + r * 0.16, text="Start", fill=ink,
                         font=self._font or ("Segoe UI", 28, "bold"))

    # ── interaction ──────────────────────────────────────────────────────
    def _on_click(self, _event=None) -> None:
        if callable(self._command):
            self._command()

    def _on_enter(self, _event=None) -> None:
        self._fill = theme.TEAL[200]
        self.itemconfigure(self._circle, fill=self._fill)
        self.configure(cursor="hand2")

    def _on_leave(self, _event=None) -> None:
        self._fill = theme.TEAL[300]
        self.itemconfigure(self._circle, fill=self._fill)
