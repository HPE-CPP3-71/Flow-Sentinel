"""
core/state.py

AppState is the single shared object bridging the backend worker thread
(the NFStreamer loop in backend/pipeline.py) and the GUI thread (CustomTkinter's
mainloop).

WHY THIS EXISTS
----------------
NFStreamer's `for flow in streamer:` loop blocks whatever thread it runs on,
so it has to run on its own background thread — it can never run on the GUI
thread, or the window freezes for the whole capture. But that worker thread
can never call a CTk widget's update method directly either, since Tkinter
widgets are only safe to touch from the thread running mainloop().

AppState is the mailbox in between, with a one-way rule:
  - The WORKER thread (backend/pipeline.py) only ever WRITES here. It calls
    `state.record(event)` once per classified flow. It never imports
    anything from frontend/.
  - The GUI thread only ever READS here, on a timer via `.after()`. It calls
    `state.drain_queue()` and `state.snapshot_counters()`. It never reaches
    into backend/ directly.

Neither side calls the other's functions. They both just talk to AppState,
at different times, from different threads.

TWO KINDS OF SHARED DATA, TWO DIFFERENT TOOLS
-----------------------------------------------
1. `queue.Queue` — for the live row-by-row stream. The Traffic page needs
   every single flow, in arrival order, exactly once, so it makes sense to
   drain it (pop items out as they're read).
2. Lock-protected running totals (`total_packets`, `anomalies`, ...) — for
   the Overview page's stat cards. These need a "total so far" number on
   every poll; recomputing that by summing thousands of historical
   FlowEvents every ~150ms would be wasteful, so the worker thread keeps a
   running tally as it goes and the GUI just reads the current value.

`flow_log` is a bounded history (not drained, just appended-to and capped)
so the Overview table and the CSV export have something to read from
without replaying every event that's already been popped off `queue`.
"""

import queue
import threading
from collections import deque
from datetime import datetime
from typing import Deque, Dict, List, Optional

from core.events import FlowEvent


class AppState:
    def __init__(self, max_log_size: int = 2000):
        # ── Thread-safety ────────────────────────────────────────────────
        self.lock = threading.Lock()

        # ── Streaming channel — Traffic page drains this every poll ─────
        self.queue: "queue.Queue[FlowEvent]" = queue.Queue()

        # ── Rolling history — Overview table + CSV export read this ─────
        # Bounded so memory doesn't grow unbounded on a long-running capture.
        self.flow_log: Deque[FlowEvent] = deque(maxlen=max_log_size)

        # ── Aggregate counters — Overview stat cards read these ─────────
        # Written under `lock` by the worker thread, read under `lock` by
        # the GUI thread. Kept as running totals so reads are O(1).
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.anomalies: int = 0

        # Cumulative count of every flow processed since the app started.
        # Monotonic — never reset or decremented, even when older flows fall
        # out of the bounded flow_log. Backs the Overview "Total Flows" card.
        self.total_flows: int = 0

        # NOTE: active_flows is intentionally left at 0 here. A true "flows
        # currently open" count needs NFStreamer's on_init/on_expire hooks
        # (a flow is "active" between those two callbacks), which means
        # wiring it from a plugin in pipeline.py, not from this file. This
        # field exists now so the Overview card has something to bind to;
        # we'll wire the real value when we build pipeline.py.
        self.active_flows: int = 0

        # ── Bandwidth bookkeeping ────────────────────────────────────────
        # Bandwidth is a rate, not a running total, so it needs a previous
        # sample to diff against. The GUI poll loop owns the actual
        # bytes-per-second math; these two fields are just its inputs,
        # updated each time snapshot_counters() is read.
        self._last_byte_sample: int = 0
        self._last_sample_time: Optional[datetime] = None

        # ── Run control ──────────────────────────────────────────────────
        self.running: bool = False
        self.start_time: Optional[datetime] = None
        self.interface: Optional[str] = None

        self.accumulated_uptime: float = 0.0

    # ════════════════════════════════════════════════════════════════════
    # Methods the WORKER thread calls (backend/pipeline.py)
    # ════════════════════════════════════════════════════════════════════
    def record(self, event: FlowEvent) -> None:
        """Called once per classified flow. Updates totals, history, and stream."""
        with self.lock:
            self.total_packets += event.packets
            self.total_bytes += event.bytes
            self.total_flows += 1
            if event.is_anomaly:
                self.anomalies += 1
            self.flow_log.append(event)
        # Queue is already thread-safe internally — no lock needed here.
        self.queue.put(event)

    def start(self, interface: str) -> None:
        with self.lock:
            self.running = True
            self.start_time = datetime.now()
            self.interface = interface

    def stop(self) -> None:
        with self.lock:
            if self.running and self.start_time:
                self.accumulated_uptime += (datetime.now() - self.start_time).total_seconds()
            self.running = False

    # ════════════════════════════════════════════════════════════════════
    # Methods the GUI thread calls (frontend/pages/*.py, via .after())
    # ════════════════════════════════════════════════════════════════════
    def drain_queue(self, max_items: int = 200) -> List[FlowEvent]:
        """
        Pulls everything currently waiting, non-blocking, up to max_items.
        Call this from a .after() callback — never from the worker thread.
        """
        events: List[FlowEvent] = []
        try:
            for _ in range(max_items):
                events.append(self.queue.get_nowait())
        except queue.Empty:
            pass
        return events

    def get_flow_log_snapshot(self) -> List[FlowEvent]:
        """
        Thread-safe full copy of the rolling flow history, for the Overview
        table and the CSV export. Copying under the lock avoids reading the
        deque mid-append; cheap enough to call once per GUI poll tick.
        """
        with self.lock:
            return list(self.flow_log)

    def snapshot_counters(self) -> Dict[str, object]:
        """Thread-safe read of the aggregate counters, for the stat cards."""
        with self.lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "total_flows": self.total_flows,
                "anomalies": self.anomalies,
                "active_flows": self.active_flows,
                "running": self.running,
                "start_time": self.start_time,
                "interface": self.interface,
            }

    def bandwidth_bps(self) -> float:
        """
        Bytes/sec since the last time this was called. Call it once per GUI
        poll tick (e.g. every 1s) — calling it more often just shrinks the
        time window and makes the number noisier.
        """
        now = datetime.now()
        with self.lock:
            current_bytes = self.total_bytes
        if self._last_sample_time is None:
            self._last_byte_sample = current_bytes
            self._last_sample_time = now
            return 0.0
        elapsed = (now - self._last_sample_time).total_seconds()
        delta_bytes = current_bytes - self._last_byte_sample
        self._last_byte_sample = current_bytes
        self._last_sample_time = now
        return delta_bytes / elapsed if elapsed > 0 else 0.0

    def uptime_str(self) -> str:
        with self.lock:
            # ADD THIS: Calculate total uptime (paused time + currently running time)
            total_seconds = self.accumulated_uptime
            if self.running and self.start_time:
                total_seconds += (datetime.now() - self.start_time).total_seconds()
                
        h, rem = divmod(int(total_seconds), 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"