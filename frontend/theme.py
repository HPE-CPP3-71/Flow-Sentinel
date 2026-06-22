"""
Design tokens pulled from the Figma references:
  - Primary   #0D9488  -> exactly Tailwind teal-600
  - Secondary #3B82F6  -> exactly Tailwind blue-500
  - Neutral   #0F172A  -> exactly Tailwind slate-900
  - Tertiary  #C36D4B  -> not a Tailwind stop, ramp generated algorithmically below

  - Headline / Body -> "Geist"
  - Label           -> "JetBrains Mono"

Two kinds of tokens live here:
  1. RAW SCALES (TEAL, BLUE, SLATE, TERTIARY) — the full 50..950 ramps, for
     when a component needs a specific step (e.g. a hover state one shade
     darker).
  2. SEMANTIC TOKENS (COLORS, BUTTON_VARIANTS, PROGRESS_COLORS, ...) — named
     by *role*, not by color, so pages and components never hardcode a hex
     value. If the brand palette changes later, it changes here once.

FONTS
-----
CTkFont objects can't be created until a Tk root exists, so fonts are NOT
defined at module import time. Call get_fonts() from App.__init__, after
super().__init__() has run. It also checks whether "Geist" / "JetBrains
Mono" are actually installed on the machine and falls back to a safe system
font (with a logged warning) if not — Tkinter won't error on a missing font
family, it'll just silently substitute something, which makes a real
mismatch easy to miss without this check.

To get a pixel-exact match, install on the target VM:
  - Geist:         https://github.com/vercel/geist-font (no apt package)
  - JetBrains Mono: `sudo apt install fonts-jetbrains-mono`
"""

import logging
import platform
import tkinter.font as tkfont

import customtkinter as ctk

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Raw color scales
# ═══════════════════════════════════════════════════════════════════════════

TEAL = {
    50: "#f0fdfa", 100: "#ccfbf1", 200: "#99f6e4", 300: "#5eead4", 400: "#2dd4bf",
    500: "#14b8a6", 600: "#0d9488", 700: "#0f766e", 800: "#115e59", 900: "#134e4a",
    950: "#042f2e",
}

BLUE = {
    50: "#eff6ff", 100: "#dbeafe", 200: "#bfdbfe", 300: "#93c5fd", 400: "#60a5fa",
    500: "#3b82f6", 600: "#2563eb", 700: "#1d4ed8", 800: "#1e40af", 900: "#1e3a8a",
    950: "#172554",
}

SLATE = {
    50: "#f8fafc", 100: "#f1f5f9", 200: "#e2e8f0", 300: "#cbd5e1", 400: "#94a3b8",
    500: "#64748b", 600: "#475569", 700: "#334155", 800: "#1e293b", 900: "#0f172a",
    950: "#020617",
}


def _hex_to_rgb(hex_color: str):
    hex_color = hex_color.lstrip("#")
    return tuple(int(hex_color[i:i + 2], 16) for i in (0, 2, 4))


def _rgb_to_hex(r: int, g: int, b: int) -> str:
    r, g, b = (max(0, min(255, v)) for v in (r, g, b))
    return f"#{r:02x}{g:02x}{b:02x}"


def _lighten(hex_color: str, amount: float) -> str:
    """amount in [0, 1] — 0 leaves the color unchanged, 1 fully washes it to white."""
    r, g, b = _hex_to_rgb(hex_color)
    return _rgb_to_hex(
        round(r + (255 - r) * amount),
        round(g + (255 - g) * amount),
        round(b + (255 - b) * amount),
    )


def _darken(hex_color: str, amount: float) -> str:
    """amount in [0, 1] — 0 leaves the color unchanged, 1 fully crushes it to black."""
    r, g, b = _hex_to_rgb(hex_color)
    return _rgb_to_hex(round(r * (1 - amount)), round(g * (1 - amount)), round(b * (1 - amount)))


def _generate_scale(base_hex: str) -> dict:
    """
    Builds a Tailwind-shaped 50..950 ramp around a base color, with the base
    sitting at the 500 step. Used for TERTIARY since it has no Tailwind
    reference to copy exact stops from.
    """
    return {
        50: _lighten(base_hex, 0.92),
        100: _lighten(base_hex, 0.85),
        200: _lighten(base_hex, 0.70),
        300: _lighten(base_hex, 0.50),
        400: _lighten(base_hex, 0.25),
        500: base_hex,
        600: _darken(base_hex, 0.15),
        700: _darken(base_hex, 0.35),
        800: _darken(base_hex, 0.55),
        900: _darken(base_hex, 0.70),
        950: _darken(base_hex, 0.85),
    }


TERTIARY = _generate_scale("#C36D4B")


# ═══════════════════════════════════════════════════════════════════════════
# Semantic tokens — components reference these, never the raw scales above
# ═══════════════════════════════════════════════════════════════════════════

COLORS = {
    # Surfaces
    "bg_app": SLATE[950],         # outermost window background
    "bg_card": SLATE[900],        # cards, panels, search bar fill
    "bg_card_alt": SLATE[800],    # nested/secondary surfaces (secondary button, nav pill)
    "border": SLATE[700],
    "border_subtle": SLATE[800],

    # Text
    "text_headline": SLATE[100],
    "text_body": SLATE[300],
    "text_muted": SLATE[400],
    "text_label": TEAL[100],      # the sage-tinted "Aa" sample under Label/JetBrains Mono

    # Brand tokens, as given
    "primary": TEAL[600],
    "secondary": BLUE[500],
    "tertiary": TERTIARY[500],
    "neutral": SLATE[900],
}

# Ready to unpack straight into a CTkButton: CTkButton(**BUTTON_VARIANTS["primary"], text="...")
BUTTON_VARIANTS = {
    "primary": {
        "fg_color": TEAL[300],
        "hover_color": TEAL[400],
        "text_color": SLATE[900],
        "border_width": 0,
    },
    "secondary": {
        "fg_color": SLATE[800],
        "hover_color": SLATE[700],
        "text_color": SLATE[200],
        "border_width": 0,
    },
    "inverted": {
        "fg_color": "#e4e7ff",
        "hover_color": "#f1f2ff",
        "text_color": SLATE[900],
        "border_width": 0,
    },
    "outlined": {
        "fg_color": "transparent",
        "hover_color": SLATE[800],
        "text_color": SLATE[200],
        "border_width": 1,
        "border_color": SLATE[500],
    },
}

# Ready to unpack into a CTkProgressBar: CTkProgressBar(**PROGRESS_COLORS["primary"])
PROGRESS_COLORS = {
    "primary": {"fg_color": SLATE[700], "progress_color": TEAL[400]},
    "secondary": {"fg_color": SLATE[700], "progress_color": BLUE[200]},
    "tertiary": {"fg_color": SLATE[700], "progress_color": TERTIARY[300]},
}

RADIUS = {
    "card": 16,
    "button": 10,
    "search": 12,
    "pill": 999,   # CTk clamps this to half the widget height automatically
}

SPACING = {"xs": 4, "sm": 8, "md": 16, "lg": 24, "xl": 32}


# ═══════════════════════════════════════════════════════════════════════════
# Fonts — must be built after a Tk root exists, hence a function not a constant
# ═══════════════════════════════════════════════════════════════════════════

def _resolve_family(preferred: str, fallback: str) -> str:
    available = tkfont.families()
    if preferred in available:
        return preferred
    logger.warning(
        "Font '%s' not found on this system — falling back to '%s'. "
        "Install '%s' for a pixel-exact match to the Figma reference.",
        preferred, fallback, preferred,
    )
    return fallback


def get_fonts() -> dict:
    """Call once, from App.__init__, after super().__init__() has run."""
    is_windows = platform.system() == "Windows"

    sans_fallback = "Segoe UI" if is_windows else "DejaVu Sans"
    mono_fallback = "Consolas" if is_windows else "DejaVu Sans Mono"

    sans_family = _resolve_family("Geist", sans_fallback)
    mono_family = _resolve_family("JetBrains Mono", mono_fallback)

    return {
        "headline_xl": ctk.CTkFont(family=sans_family, size=40, weight="bold"),
        "headline_lg": ctk.CTkFont(family=sans_family, size=24, weight="bold"),
        "headline_md": ctk.CTkFont(family=sans_family, size=18, weight="bold"),
        "body_md": ctk.CTkFont(family=sans_family, size=14),
        "body_sm": ctk.CTkFont(family=sans_family, size=12),
        "label_md": ctk.CTkFont(family=mono_family, size=13),
        "label_sm": ctk.CTkFont(family=mono_family, size=11),
    }