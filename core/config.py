"""
core/config.py

A tiny persisted settings store, shared across the app. It holds the
user-tunable rule-engine thresholds (mirrors the defaults baked into
backend/rule_based.py) and the Overview refresh cadence.

WHY THIS EXISTS
----------------
The rule detectors in backend/rule_based.py read their thresholds from
module-level constants. The Settings page lets the user retune those without
editing code, and the values need to survive a restart — so they live here in
a small JSON file and are loaded once at import time.

HOW IT'S WIRED
---------------
  - Settings page  : reads via CONFIG.all(), writes via CONFIG.update({...}).
                     update() validates, stores, and persists to disk.
  - run_pipeline   : at the start of every capture, copies the current values
                     into the backend.rule_based module globals. That's the
                     "applies on the next capture" contract — an already-running
                     capture keeps the thresholds it started with.
  - Overview page  : reads OVERVIEW_REFRESH_MS each poll tick (GUI-only, so it
                     can take effect on the next tick).

Validation lives in update(): every value must be a real, positive number.
That keeps invalid input from ever reaching the file or the detectors.
"""

import json
import logging
import os
import threading
from typing import Dict

logger = logging.getLogger(__name__)

# One file per user, beside the other app data in the home directory.
_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".flowsentinel")
_CONFIG_PATH = os.path.join(_CONFIG_DIR, "settings.json")

# Keys + their defaults. These mirror backend/rule_based.py's module constants
# (and the current Overview poll cadence) so the app behaves identically on a
# fresh install with no settings file present.
DEFAULTS: Dict[str, float] = {
    # ── IGMP ─────────────────────────────────────────────────────────────
    "IGMP_GENERAL_QUERY_FLOOD_IAT": 120.0,
    # ── OSPF ─────────────────────────────────────────────────────────────
    "OSPF_LSA_IAT_THRESHOLD": 1690.0,
    "OSPF_MAX_AGE_THRESHOLD": 3600.0,
    "OSPF_HELLO_IAT_THRESHOLD": 9.0,
    # ── PIM ──────────────────────────────────────────────────────────────
    "PIM_HELLO_IAT_THRESHOLD": 25.0,
    # ── Overview ─────────────────────────────────────────────────────────
    # GUI refresh cadence in milliseconds.
    "OVERVIEW_REFRESH_MS": 1000.0,
}


class Config:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: Dict[str, float] = dict(DEFAULTS)
        self.load()

    # ── reads ─────────────────────────────────────────────────────────────
    def get(self, key: str) -> float:
        with self._lock:
            return self._values.get(key, DEFAULTS.get(key, 0.0))

    def all(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._values)

    # ── writes ──────────────────────────────────────────────────────────
    def update(self, changes: Dict[str, float]) -> None:
        """
        Validate and persist a batch of changes. Raises ValueError on the first
        invalid value (non-numeric or non-positive) without changing anything,
        so a bad input can never be half-applied.
        """
        cleaned: Dict[str, float] = {}
        for key, raw in changes.items():
            if key not in DEFAULTS:
                raise ValueError(f"Unknown setting: {key}")
            try:
                value = float(raw)
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be a number.")
            if value != value or value in (float("inf"), float("-inf")):  # NaN/inf
                raise ValueError(f"{key} must be a finite number.")
            if value <= 0:
                raise ValueError(f"{key} must be greater than zero.")
            cleaned[key] = value

        with self._lock:
            self._values.update(cleaned)
            self._save_locked()

    # ── persistence ─────────────────────────────────────────────────────
    def load(self) -> None:
        try:
            with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
                stored = json.load(f)
        except FileNotFoundError:
            return
        except Exception as exc:
            logger.warning("Could not read settings file (%s) — using defaults.", exc)
            return
        if not isinstance(stored, dict):
            return
        with self._lock:
            for key in DEFAULTS:
                if key in stored:
                    try:
                        value = float(stored[key])
                        if value > 0:
                            self._values[key] = value
                    except (TypeError, ValueError):
                        continue

    def _save_locked(self) -> None:
        """Write the current values to disk. Caller must hold the lock."""
        try:
            os.makedirs(_CONFIG_DIR, exist_ok=True)
            with open(_CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self._values, f, indent=2)
        except Exception as exc:
            logger.error("Could not save settings file: %s", exc)


# App-wide singleton. Import this, not the class.
CONFIG = Config()
