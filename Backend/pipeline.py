"""
backend/pipeline.py

The refactored version of your original console main.py's capture loop.
Same model-loading, same per-protocol branches, same SSH-BRUTEFORCE override,
same gate logic — but instead of print()-ing rows to a terminal, every
classified flow becomes a FlowEvent and goes into AppState via state.record().

This module is the only thing that should ever be running on the worker
thread. It never imports anything from frontend/ — it only knows about
core.state.AppState and core.events.FlowEvent.

DNS BRANCH: kept in place as requested. The model isn't trained/loaded yet,
so models.dns is None and _process_dns() raises a clear, caught error
instead of the original code's bare NameError on undefined dns_model /
build_dns_row / dns_le / dns_fcols. Wiring the real model later is a two-step
change: load it in load_models() below, and write build_dns_row() in
feature_builders.py — _process_dns() will pick it up automatically.
"""

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

import joblib
from nfstream import NFStreamer

from backend.feature_builders import build_icmp_row, build_dns_row,build_tcp_row, dump_full_flow
from backend.plugins import (
    ActiveIdlePlugin,
    BulkPlugin,
    ExtraFeaturesPlugin,
    HeaderLenPlugin,
    InitWindowPlugin,
)
from backend.predictor import run_prediction
from core.events import FlowEvent
from core.state import AppState

logger = logging.getLogger(__name__)

# Set True to dump every anomalous flow's full feature row to CSV for later
# inspection — same behavior as the commented-out dump_full_flow() call in
# your original main.py, just toggled in one place instead of a comment.
DEBUG_DUMP_CSV = False
DEBUG_DUMP_PATH = "/tmp/live_flows_dump.csv"

_PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
_BENIGN_LABELS = {"BENIGN", "G_BENIGN"}

# Small curated feature subset shown in the Traffic page's "TCP Model
# Features" panel — same list you were printing in main.py. The full
# build_tcp_row() dict (~60 features) is too dense for a side panel.
TCP_KEY_FEATURES = [
    'src2dst_psh_packets', 'dst2src_rst_packets', 'dst2src_psh_packets',
    'RST Flag Cnt', 'PSH Flag Cnt',
    'dst2src_stddev_ps', 'bidirectional_stddev_ps', 'Pkt Len Var',
    'src2dst_min_ps', 'bidirectional_mean_ps', 'bidirectional_max_ps',
    'udps.fwd_seg_size_min', 'udps.init_fwd_win',
]


# ═══════════════════════════════════════════════════════════════════════════
# Model loading
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ModelBundle:
    model: object
    le: object
    fcols: List[str]


@dataclass
class Models:
    icmp: ModelBundle
    tcp: ModelBundle
    dns: Optional[ModelBundle] = None   # not trained yet — see module docstring


def load_models(models_dir: str) -> Models:
    # NOTE: carried over verbatim from your original main.py — both the ICMP
    # model and the TCP model load from the same "ICMP" subfolder. Confirm
    # that's intentional (e.g. you keep all current models in one folder for
    # now) rather than a leftover path bug, since it'll matter once you add
    # a real "DNS" or "TCP" folder alongside it.
    base = os.path.join(models_dir, "ICMP")

    icmp = ModelBundle(
        model=joblib.load(f"{base}/xgboost_model3.pkl"),
        le=joblib.load(f"{base}/label_encoder3.pkl"),
        fcols=joblib.load(f"{base}/feature_columns3.pkl"),
    )
    logger.info("[ICMP] %d features | classes: %s", len(icmp.fcols), list(icmp.le.classes_))

    tcp = ModelBundle(
        model=joblib.load(f"{base}/tcp_model2.pkl"),
        le=joblib.load(f"{base}/tcp_label_encoder2.pkl"),
        fcols=joblib.load(f"{base}/tcp_feature_columns2.pkl"),
    )
    logger.info("[TCP ] %d features | classes: %s", len(tcp.fcols), list(tcp.le.classes_))

    return Models(icmp=icmp, tcp=tcp, dns=None)


# ═══════════════════════════════════════════════════════════════════════════
# Per-flow processing — one function per branch, same logic as main.py
# ═══════════════════════════════════════════════════════════════════════════

def _resolve_protocol(proto_num: int) -> str:
    return _PROTOCOL_NAMES.get(proto_num, str(proto_num))


def _build_event(
    ts: str,
    model_tag: str,
    flow,
    prediction: str,
    confidence: float,
    key_features: Optional[Dict[str, object]] = None,
) -> FlowEvent:
    is_error = prediction.startswith("ERR:")
    anomaly_type = "" if (prediction in _BENIGN_LABELS or is_error) else prediction

    return FlowEvent(
        ts=ts,
        model_tag=model_tag,
        src_ip=str(flow.src_ip),
        dst_ip=str(flow.dst_ip),
        protocol=_resolve_protocol(flow.protocol),
        packets=flow.bidirectional_packets,
        bytes=flow.bidirectional_bytes,
        prediction=prediction,
        confidence=confidence,
        anomaly_type=anomaly_type,
        key_features=key_features or {},
    )


def _process_icmp(flow, ts: str, models: Models) -> FlowEvent:
    # Early-exit gate: tiny flows (VirtualBox internal chatter, etc.) are
    # benign by definition — skip the model call entirely, same as before.
    if flow.bidirectional_packets < 5 and flow.bidirectional_duration_ms < 10:
        return _build_event(ts, "ICMP", flow, "BENIGN", 1.0)

    try:
        row = build_icmp_row(flow)
        pred, conf = run_prediction(models.icmp.model, models.icmp.le, models.icmp.fcols, row)
    except Exception as e:
        pred, conf = f"ERR:{e}", 0.0

    return _build_event(ts, "ICMP", flow, pred, conf)


def _process_dns(flow, ts: str, models: Models) -> FlowEvent:
    """DNS Spoofing/Tunneling detector — placeholder until the model is trained."""
    try:
        if models.dns is None:
            raise RuntimeError("DNS model not loaded yet")
        row = build_dns_row(flow)  # noqa: F821 — intentionally undefined until DNS work lands
        pred, conf = run_prediction(models.dns.model, models.dns.le, models.dns.fcols, row)
    except Exception as e:
        pred, conf = f"ERR:{e}", 0.0

    return _build_event(ts, "DNS", flow, pred, conf)


def _process_tcp(flow, ts: str, models: Models) -> FlowEvent:
    key_features: Dict[str, object] = {}
    try:
        row = build_tcp_row(flow)
        key_features = {feat: row.get(feat, "MISSING") for feat in TCP_KEY_FEATURES}

        pred, conf = run_prediction(models.tcp.model, models.tcp.le, models.tcp.fcols, row)

        # SSH-BRUTEFORCE override: a flow with no captured initial window and
        # no RST from the destination is almost always a normal paramiko
        # session fragmented by the short active_timeout, not a real
        # brute-force attempt.
        init_win = row.get('udps.init_fwd_win', 0)
        if pred == 'SSH-BRUTEFORCE' and init_win == -1 and row.get('dst2src_rst_packets', 0) == 0:
            pred = 'G_BENIGN'

        if DEBUG_DUMP_CSV and pred not in _BENIGN_LABELS:
            dump_full_flow(flow, pred, conf, row, out_csv=DEBUG_DUMP_PATH)

    except Exception as e:
        pred, conf = f"ERR:{e}", 0.0

    return _build_event(ts, "TCP/UDP", flow, pred, conf, key_features)


def process_flow(flow, models: Models) -> Optional[FlowEvent]:
    """Routes a single NFStream flow to the right model branch."""
    ts = datetime.now().strftime("%H:%M:%S")

    if flow.protocol == 1:
        return _process_icmp(flow, ts, models)
    elif flow.protocol == 17 and (flow.dst_port == 53 or flow.src_port == 53):
        return _process_dns(flow, ts, models)
    elif flow.protocol in (6, 17):
        return _process_tcp(flow, ts, models)
    else:
        logger.debug("Skipped non TCP/UDP/ICMP flow: protocol=%s", flow.protocol)
        return None


# ═══════════════════════════════════════════════════════════════════════════
# The worker-thread entry point
# ═══════════════════════════════════════════════════════════════════════════

def run_pipeline(state: AppState, interface: str, models_dir: str) -> None:
    """
    Runs on a daemon thread, started by the Start button. Blocks for the
    life of the capture — never call this from the GUI thread.
    """
    models = load_models(models_dir)

    streamer = NFStreamer(
        source=interface,
        statistical_analysis=True,
        splt_analysis=0,
        accounting_mode=3,
        idle_timeout=2,
        active_timeout=5,
        udps=[
            BulkPlugin(),
            HeaderLenPlugin(),
            InitWindowPlugin(),
            ExtraFeaturesPlugin(),
            ActiveIdlePlugin(idle_threshold_ms=5000),
        ],
    )

    state.start(interface)
    logger.info("Pipeline live on [%s]", interface)

    for flow in streamer:
        if not state.running:
            # Checked once per yielded flow — with active_timeout=5 /
            # idle_timeout=2 already configured, flows expire often enough
            # that Stop takes effect within a few seconds.
            break
        event = process_flow(flow, models)
        if event is not None:
            state.record(event)

    state.stop()
    logger.info("Pipeline stopped.")