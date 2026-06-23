"""
StatCard — one metric tile in the Overview frame's KPI row.

Four are shown in the Figma: Total Packets, Active Flows, Anomalies Detected
(danger variant — rose border, tinted fill, "Action Required" badge) and
Bandwidth (value + smaller unit). The component covers all four through its
constructor args; pages never style the card directly.
"""

import customtkinter as ctk

from frontend import theme


class StatCard(ctk.CTkFrame):
    def __init__(self, parent, app, label: str, value: str, icon: str = "",
                 unit: str = "", badge: str | None = None, variant: str = "normal"):
        danger = variant == "danger"
        super().__init__(
            parent,
            fg_color=theme.COLORS["danger_bg"] if danger else theme.COLORS["bg_card"],
            corner_radius=theme.RADIUS["card"],
            border_width=1,
            border_color=theme.COLORS["danger_border"] if danger else theme.COLORS["border_subtle"],
        )
        self.fonts = app.fonts
        self.grid_columnconfigure(0, weight=1)

        # ── Top row: label + icon ────────────────────────────────────────
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 10))
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            top, text=label, font=self.fonts["label_sm"],
            text_color=theme.COLORS["danger_text"] if danger else theme.COLORS["text_muted"],
        ).grid(row=0, column=0, sticky="w")
        if icon:
            ctk.CTkLabel(
                top, text=icon, font=self.fonts["body_lg"],
                text_color=theme.COLORS["danger"] if danger else theme.COLORS["text_muted"],
            ).grid(row=0, column=1, sticky="e")

        # ── Value row: big number (+ optional unit / badge) ──────────────
        value_row = ctk.CTkFrame(self, fg_color="transparent")
        value_row.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        # Stored so the Overview poll can update the figure in place rather
        # than rebuilding the card.
        self.value_lbl = ctk.CTkLabel(
            value_row, text=value, font=self.fonts["stat_value"],
            text_color=theme.COLORS["danger"] if danger else theme.COLORS["text_headline"],
        )
        self.value_lbl.pack(side="left")
        if unit:
            # Stored too — bandwidth flips its unit (Gbps ⇄ Mbps) at runtime.
            self.unit_lbl = ctk.CTkLabel(value_row, text=f" {unit}", font=self.fonts["body_md"],
                                         text_color=theme.COLORS["text_muted"])
            self.unit_lbl.pack(side="left", pady=(8, 0))
        if badge:
            ctk.CTkLabel(
                value_row, text=f" {badge} ", font=self.fonts["mono_xs"],
                text_color=theme.COLORS["danger_text"], fg_color="#3a1a1f",
                corner_radius=6, height=20,
            ).pack(side="left", padx=(10, 0))

    # ── live update ──────────────────────────────────────────────────────
    def update_value(self, value: str, unit: str = "") -> None:
        """
        Update the figure (and unit, if this card has one) in place.

        Named update_value, not update, on purpose: CTk/Tk widgets already have
        a built-in .update() that pumps the event loop, and shadowing it breaks
        internal redraw calls.
        """
        self.value_lbl.configure(text=value)
        if unit and hasattr(self, "unit_lbl"):
            self.unit_lbl.configure(text=f" {unit}")
