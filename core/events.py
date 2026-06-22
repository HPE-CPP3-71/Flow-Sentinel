"""
FlowEvent is the single data shape the backend produces for every classified
flow, regardless of which model made the call (ICMP or TCP/UDP). It is the
ONLY thing that crosses the thread boundary from backend/pipeline.py into the
GUI — pages never read raw NFStream `flow` objects, model objects, or feature
dicts directly. They read FlowEvents off AppState.
"""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class FlowEvent:
    ts: str                 
    model_tag: str          # "ICMP" or "TCP/UDP" — which model produced this
    src_ip: str
    dst_ip: str
    protocol: str           # resolved name ("TCP" / "UDP" / "ICMP"), not the raw int
    packets: int           
    bytes: int              
    prediction: str         # raw label from le.inverse_transform, e.g. "BENIGN", "PORTSCAN"
    confidence: float

    # ── Anomaly classification ──────────────────────────────────────────
    # "" means benign. Otherwise holds the actual attack label, e.g.
    # "PORTSCAN", "ICMP_FLOOD", "SSH-BRUTEFORCE" — same string as `prediction`
    # for an anomalous flow, kept as a separate field so display/counting
    # code doesn't have to special-case the literal string "BENIGN"
    # everywhere; it can just check `if event.anomaly_type`.
    anomaly_type: str = ""

    # ── Feature panel data (Traffic page's "TCP Model Features" box) ───────
    # Small curated subset (e.g. TCP_KEY_FEATURES from main.py)
    key_features: Dict[str, object] = field(default_factory=dict)

    @property
    def is_anomaly(self) -> bool:
        """Convenience boolean for code that just needs yes/no (e.g. counters)."""
        return bool(self.anomaly_type)