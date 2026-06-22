"""
Entry point for the FlowSentinel GUI. Wires together:
  - core.state.AppState      the shared thread-safe state
  - backend.pipeline          the NFStreamer worker thread (started on demand)
  - frontend.app.App          the CustomTkinter window + page router

The backend pipeline needs raw-socket access (NFStreamer), so on Linux it
should be launched with sudo. The pipeline is imported lazily — only when the
Start button is actually pressed — so the GUI itself can be opened for design
review on any platform without NFStreamer installed.

    python main.py            # opens the GUI
    sudo python3 main.py      # Linux: also able to start a live capture
"""

import logging
import os
import threading

from core.state import AppState

ABS_PATH = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(ABS_PATH, "backend", "models")

logger = logging.getLogger(__name__)


def start_pipeline_thread(state: AppState, interface: str) -> threading.Thread:
    """
    Called by the Start page when the user picks an interface and clicks
    Start. Spawns the NFStreamer loop on a daemon thread so it (a) never
    blocks the GUI's mainloop, and (b) dies automatically if the GUI
    process exits, instead of leaving an orphaned capture running.

    run_pipeline is imported here, not at module top, so the GUI can launch
    on machines without NFStreamer (the UI is fully usable with placeholder
    data; only a live capture needs the backend).
    """
    from backend.pipeline import run_pipeline

    thread = threading.Thread(
        target=run_pipeline,
        args=(state, interface, MODELS_DIR),
        daemon=True,
    )
    thread.start()
    return thread


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # geteuid() only exists on Unix; on Windows we just warn instead.
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        logger.warning(
            "Not running as root — the GUI will open, but starting a live "
            "capture needs raw-socket access (re-run with sudo for that)."
        )

    from frontend.app import App

    state = AppState()
    app = App(state=state, on_start=start_pipeline_thread)
    app.mainloop()
