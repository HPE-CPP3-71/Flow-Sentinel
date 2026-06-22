"""
FlowLogo — the teal "network node" brand mark from the Figma.

It's a small central node with spokes radiating to five outer nodes (the
molecule/graph glyph next to the "FlowSentinel" wordmark). Tkinter has no
SVG support, so we draw it on a plain Canvas. The widget is purely
decorative — no state, no callbacks.
"""

import math
import tkinter as tk

from frontend import theme


class FlowLogo(tk.Canvas):
    def __init__(self, parent, size: int = 28, bg: str | None = None,
                 color: str | None = None, **kwargs):
        bg = bg or theme.COLORS["bg_app"]
        super().__init__(
            parent, width=size, height=size, bg=bg,
            highlightthickness=0, bd=0, **kwargs,
        )
        self._size = size
        self._color = color or theme.TEAL[300]
        self._draw()

    def _draw(self) -> None:
        s = self._size
        cx = cy = s / 2
        center_r = max(2.5, s * 0.13)      # central node radius
        outer_r = max(1.8, s * 0.10)       # outer node radius
        ring = s * 0.34                    # distance of outer nodes from center

        # Five outer nodes, evenly spaced, first one pointing up.
        points = []
        for i in range(5):
            ang = -math.pi / 2 + i * (2 * math.pi / 5)
            points.append((cx + ring * math.cos(ang), cy + ring * math.sin(ang)))

        # Spokes from center to each outer node.
        for (px, py) in points:
            self.create_line(cx, cy, px, py, fill=self._color,
                             width=max(1, s * 0.045))

        # Outer nodes.
        for (px, py) in points:
            self.create_oval(px - outer_r, py - outer_r, px + outer_r, py + outer_r,
                             fill=self._color, outline="")

        # Central node.
        self.create_oval(cx - center_r, cy - center_r, cx + center_r, cy + center_r,
                         fill=self._color, outline="")
