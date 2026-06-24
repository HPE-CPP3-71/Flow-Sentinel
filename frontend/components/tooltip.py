"""
Tooltip — a lightweight hover tooltip used across the Settings page.

Attach it to any widget; on hover (after a short delay) a small bordered card
appears just below the widget with wrapped explanatory text, styled from the
shared theme so it matches the rest of the UI. Hidden on leave or click.

    Tooltip(info_icon, "What this setting does…", app)
"""

import tkinter as tk

import customtkinter as ctk

from frontend import theme


class Tooltip:
    def __init__(self, widget, text: str, app, delay: int = 350,
                 wraplength: int = 300):
        self.widget = widget
        self.text = text
        self.fonts = app.fonts
        self.delay = delay
        self.wraplength = wraplength
        self._tip = None
        self._after = None

        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None) -> None:
        self._cancel()
        self._after = self.widget.after(self.delay, self._show)

    def _cancel(self) -> None:
        if self._after is not None:
            try:
                self.widget.after_cancel(self._after)
            except Exception:
                pass
            self._after = None

    def _show(self) -> None:
        if self._tip is not None:
            return
        x = self.widget.winfo_rootx() + 18
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6

        # Borderless top-level positioned manually; the 1px outer bg acts as the
        # border so the rounded inner card reads cleanly on the dark theme.
        self._tip = tk.Toplevel(self.widget)
        self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f"+{x}+{y}")
        self._tip.configure(bg=theme.COLORS["border"])
        try:
            self._tip.attributes("-topmost", True)
        except Exception:
            pass

        frame = ctk.CTkFrame(self._tip, fg_color=theme.COLORS["bg_card_alt"],
                             corner_radius=8, border_width=1,
                             border_color=theme.COLORS["border"])
        frame.pack(padx=1, pady=1)
        ctk.CTkLabel(frame, text=self.text, font=self.fonts["body_sm"],
                     text_color=theme.COLORS["text_body"], justify="left",
                     wraplength=self.wraplength
                     ).pack(padx=12, pady=8)

    def _hide(self, _event=None) -> None:
        self._cancel()
        if self._tip is not None:
            self._tip.destroy()
            self._tip = None
