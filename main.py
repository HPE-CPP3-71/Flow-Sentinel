"""
Entry point for the FlowSentinel GUI. Wires together:
  - core.state.AppState     the shared thread-safe state
  - backend.pipeline         the NFStreamer worker thread
  - frontend.app.App         the CustomTkinter window + page router (next file to build)

Run as root, since NFStreamer needs raw-socket access:
    sudo python3 main.py

NOTE: this imports frontend.app.App, which doesn't exist yet — that's the
next file. Running this script before then will fail on that import; it's
written now so the contract between main.py and App is settled before we
build it: App(state, on_start) — on_start is the callback the Start page
calls with the chosen interface name.
"""

import logging
import os
import threading

from backend.pipeline import run_pipeline
from core.state import AppState

ABS_PATH = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(ABS_PATH, "backend", "models")


def start_pipeline_thread(state: AppState, interface: str) -> threading.Thread:
    """
    Called by the Start page when the user picks an interface and clicks
    Start. Spawns the NFStreamer loop on a daemon thread so it (a) never
    blocks the GUI's mainloop, and (b) dies automatically if the GUI
    process exits, instead of leaving an orphaned capture running.
    """
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

    if os.geteuid() != 0:
        raise SystemExit("FlowSentinel needs raw-socket access for NFStreamer — run with sudo.")

    from frontend.app import App  
    state = AppState()
    app = App(state=state, on_start=start_pipeline_thread)
    app.mainloop()