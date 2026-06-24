"""
SettingsPage — the configuration frame reached from the sidebar "Settings"
item.

Exposes the tunable rule-engine thresholds (IGMP / OSPF / PIM) plus the
Overview refresh cadence, all backed by core.config.CONFIG (persisted to a
JSON file). Each setting has an ⓘ info icon with a hover tooltip explaining
what it controls, its unit, and the effect of raising/lowering it.

Validation happens on Save via CONFIG.update(), which rejects empty,
non-numeric, or non-positive input without touching the stored values — so a
bad entry can never be half-applied. Detection-threshold changes take effect on
the NEXT capture (an active capture keeps the values it started with); the
Overview refresh interval applies on the next refresh tick.

Layout/chrome mirrors the other dashboard frames (top bar + sidebar + footer),
and Start/Stop in the shared header delegate to the single capture controller
on the Traffic page — Settings owns no capture logic of its own.
"""

import customtkinter as ctk
from tkinter import messagebox

from core.config import CONFIG, DEFAULTS
from frontend import theme
from frontend.components.footer import Footer
from frontend.components.sidebar import Sidebar
from frontend.components.tooltip import Tooltip
from frontend.components.topbar import TopBar

# (key, label, unit, is_int, tooltip) grouped into sections.
_SECTIONS = [
    ("IGMP Detection", [
        ("IGMP_GENERAL_QUERY_FLOOD_IAT", "General-Query Flood IAT", "seconds", False,
         "Minimum allowed interval between IGMP General Queries. Queries arriving "
         "faster than this threshold are treated as a flood. Lower = stricter "
         "(more sensitive to floods); higher = more tolerant. Unit: seconds."),
    ]),
    ("OSPF Detection", [
        ("OSPF_LSA_IAT_THRESHOLD", "LSA Flood IAT", "seconds", False,
         "Minimum allowed interval between refreshes of the same LSA. LSAs "
         "refreshing faster than this are flagged as an LSA flood (normal refresh "
         "is ~1800s). Lower = stricter; higher = more tolerant. Unit: seconds."),
        ("OSPF_MAX_AGE_THRESHOLD", "Max LSA Age", "seconds", False,
         "Maximum LSA age before it is considered a Max-Age attack. 3600 is the "
         "OSPF protocol maximum. Lower = more aggressive flagging. Unit: seconds."),
        ("OSPF_HELLO_IAT_THRESHOLD", "Hello Flood IAT", "seconds", False,
         "Minimum allowed interval between OSPF Hello packets from a router. "
         "Hellos faster than this are treated as a Hello flood (actual interval "
         "is ~10s). Lower = stricter; higher = more tolerant. Unit: seconds."),
    ]),
    ("PIM Detection", [
        ("PIM_HELLO_IAT_THRESHOLD", "Hello Flood IAT", "seconds", False,
         "Minimum allowed interval between PIM Hello packets from a router. "
         "Hellos faster than this are treated as a flood/anomaly. Lower = "
         "stricter; higher = more tolerant. Unit: seconds."),
    ]),
    ("Overview", [
        ("OVERVIEW_REFRESH_MS", "Refresh Interval", "milliseconds", True,
         "How often the Overview cards and table refresh. Lower = more frequent "
         "updates (more CPU); higher = less frequent. Applies on the next refresh "
         "tick. Unit: milliseconds."),
    ]),
]


class SettingsPage(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=theme.COLORS["bg_app"])
        self.app = app
        self.fonts = app.fonts

        self._entries: dict[str, ctk.CTkEntry] = {}
        self._field_meta: dict[str, tuple] = {}
        self._last_running = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Shared header: Start/Stop reuse the single capture controller on the
        # Traffic page (Settings owns no capture state).
        self.topbar = TopBar(self, app, variant="dashboard", on_toggle=self._toggle_capture)
        self.topbar.grid(row=0, column=0, sticky="ew")

        mid = ctk.CTkFrame(self, fg_color="transparent")
        mid.grid(row=1, column=0, sticky="nsew")
        mid.grid_rowconfigure(0, weight=1)
        mid.grid_columnconfigure(1, weight=1)

        Sidebar(mid, app, active="settings").grid(row=0, column=0, sticky="ns")
        ctk.CTkFrame(mid, fg_color=theme.COLORS["border_subtle"], width=1
                     ).grid(row=0, column=0, sticky="nse")
        self._build_content(mid).grid(row=0, column=1, sticky="nsew", padx=32, pady=24)

        Footer(self, app).grid(row=2, column=0, sticky="ew")

        self._apply_capture_state(self.app.app_state.running)

    # ── content ──────────────────────────────────────────────────────────
    def _build_content(self, parent) -> ctk.CTkFrame:
        content = ctk.CTkFrame(parent, fg_color="transparent")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 18))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Settings", font=self.fonts["title"],
                     text_color=theme.COLORS["text_headline"]).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Tune detection thresholds and refresh behaviour.",
                     font=self.fonts["body_md"], text_color=theme.COLORS["text_muted"]
                     ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Scrollable body so the form stays usable at any resolution.
        body = ctk.CTkScrollableFrame(content, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)

        values = CONFIG.all()
        for section_title, fields in _SECTIONS:
            self._build_section(body, section_title, fields, values).pack(
                fill="x", pady=(0, 16))

        # Footer actions: validation status + Save / Reset.
        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        actions.grid_columnconfigure(0, weight=1)
        self._status = ctk.CTkLabel(actions, text="", font=self.fonts["body_sm"],
                                    text_color=theme.COLORS["text_muted"], anchor="w")
        self._status.grid(row=0, column=0, sticky="w")
        ctk.CTkButton(actions, text="Reset to defaults", width=140, height=36,
                      font=self.fonts["body_sm"], corner_radius=theme.RADIUS["button"],
                      command=self._on_reset, **theme.BUTTON_VARIANTS["outlined"]
                      ).grid(row=0, column=1, padx=(0, 10))
        ctk.CTkButton(actions, text="Save changes", width=140, height=36,
                      font=self.fonts["body_sm"], corner_radius=theme.RADIUS["button"],
                      command=self._on_save, **theme.BUTTON_VARIANTS["primary"]
                      ).grid(row=0, column=2)
        return content

    def _build_section(self, parent, title: str, fields: list, values: dict) -> ctk.CTkFrame:
        card = ctk.CTkFrame(parent, fg_color=theme.COLORS["bg_card"],
                            corner_radius=theme.RADIUS["card"],
                            border_width=1, border_color=theme.COLORS["border_subtle"])
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card, text=title, font=self.fonts["headline_md"],
                     text_color=theme.COLORS["text_headline"]
                     ).grid(row=0, column=0, sticky="w", padx=22, pady=(16, 2))
        note = ("Applies on the next refresh." if title == "Overview"
                else "Changes take effect on the next capture.")
        ctk.CTkLabel(card, text=note, font=self.fonts["mono_xs"],
                     text_color=theme.COLORS["text_muted"]
                     ).grid(row=1, column=0, sticky="w", padx=22, pady=(0, 8))

        rows = ctk.CTkFrame(card, fg_color="transparent")
        rows.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 18))
        rows.grid_columnconfigure(0, weight=1)
        for r, (key, label, unit, is_int, tip) in enumerate(fields):
            self._field_meta[key] = (label, unit, is_int)
            self._build_field(rows, r, key, label, unit, tip, values.get(key, 0))
        return card

    def _build_field(self, parent, row: int, key: str, label: str, unit: str,
                     tip: str, value) -> None:
        line = ctk.CTkFrame(parent, fg_color="transparent")
        line.grid(row=row, column=0, sticky="ew", pady=6)
        line.grid_columnconfigure(0, weight=1)

        # Label + info icon
        left = ctk.CTkFrame(line, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(left, text=label, font=self.fonts["body_md"],
                     text_color=theme.COLORS["text_body"]).pack(side="left")
        info = ctk.CTkLabel(left, text="ⓘ", font=self.fonts["body_md"],
                            text_color=theme.COLORS["link"], cursor="hand2")
        info.pack(side="left", padx=(8, 0))
        Tooltip(info, tip, self.app)

        # Entry + unit
        right = ctk.CTkFrame(line, fg_color="transparent")
        right.grid(row=0, column=1, sticky="e")
        entry = ctk.CTkEntry(right, width=120, height=34, justify="right",
                             font=self.fonts["mono_md"],
                             fg_color=theme.COLORS["bg_card_alt"],
                             border_color=theme.COLORS["border"],
                             text_color=theme.COLORS["text_headline"])
        entry.insert(0, self._fmt_value(key, value))
        entry.pack(side="left")
        ctk.CTkLabel(right, text=unit, font=self.fonts["mono_xs"],
                     text_color=theme.COLORS["text_muted"]
                     ).pack(side="left", padx=(8, 0))
        self._entries[key] = entry

    # ── value formatting ──────────────────────────────────────────────────
    def _fmt_value(self, key: str, value) -> str:
        is_int = self._field_meta.get(key, (None, None, False))[2]
        try:
            return str(int(round(float(value)))) if is_int else self._trim(float(value))
        except (TypeError, ValueError):
            return str(value)

    @staticmethod
    def _trim(value: float) -> str:
        return str(int(value)) if float(value).is_integer() else str(value)

    # ── save / reset ────────────────────────────────────────────────────
    def _on_save(self) -> None:
        changes = {key: entry.get().strip() for key, entry in self._entries.items()}
        try:
            CONFIG.update(changes)
        except ValueError as exc:
            self._status.configure(text=f"✕ {exc}", text_color=theme.COLORS["danger_text"])
            return
        # Re-format entries from the now-canonical stored values.
        values = CONFIG.all()
        for key, entry in self._entries.items():
            entry.delete(0, "end")
            entry.insert(0, self._fmt_value(key, values.get(key)))
        self._status.configure(text="✓ Settings saved.", text_color=theme.COLORS["success_text"])
        messagebox.showinfo(
            "Settings saved",
            "Settings have been saved.\n\nDetection-threshold changes take effect "
            "on the next capture. The Overview refresh interval applies on the "
            "next refresh.")

    def _on_reset(self) -> None:
        for key, entry in self._entries.items():
            entry.delete(0, "end")
            entry.insert(0, self._fmt_value(key, DEFAULTS.get(key)))
        self._status.configure(text="Defaults restored — click Save to apply.",
                               text_color=theme.COLORS["text_muted"])

    # ── shared capture toggle (delegates to the Traffic controller) ──────
    def _toggle_capture(self) -> None:
        traffic = self.app.pages.get("traffic")
        if traffic is not None and hasattr(traffic, "_toggle_capture"):
            traffic._toggle_capture()
        self._apply_capture_state(self.app.app_state.running)

    def _apply_capture_state(self, running: bool) -> None:
        if running == self._last_running:
            return
        self._last_running = running
        if running:
            self.topbar.set_running()
        else:
            self.topbar.set_paused()
