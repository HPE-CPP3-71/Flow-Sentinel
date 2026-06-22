"""
Footer — the thin status strip at the bottom of every frame:
"© 2026 FlowSentinel. Technical Operation Center."  on the left and
"Documentation" on the right, above a faint top hairline.
"""

import customtkinter as ctk

from frontend import theme


class Footer(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.COLORS["bg_app"],
                         corner_radius=0, height=44)
        self.fonts = app.fonts
        self.grid_propagate(False)
        self.grid_columnconfigure(0, weight=1)

        # top hairline
        ctk.CTkFrame(self, fg_color=theme.COLORS["border_subtle"], height=1
                     ).grid(row=0, column=0, columnspan=2, sticky="new")

        ctk.CTkLabel(self, text="© 2026 FlowSentinel. Technical Operation Center.",
                     font=self.fonts["mono_xs"], text_color=theme.COLORS["text_muted"]
                     ).grid(row=1, column=0, sticky="w", padx=24, pady=12)
        ctk.CTkLabel(self, text="Documentation", font=self.fonts["mono_xs"],
                     text_color=theme.COLORS["text_muted"]
                     ).grid(row=1, column=1, sticky="e", padx=24, pady=12)
