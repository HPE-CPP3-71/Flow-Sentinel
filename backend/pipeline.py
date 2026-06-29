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

from backend.feature_builders import build_icmp_row, build_dns_row, build_tcp_row, build_igmp_row, dump_full_flow
from backend.plugins import (
    ActiveIdlePlugin,
    BulkPlugin,
    ExtraFeaturesPlugin,
    HeaderLenPlugin,
    InitWindowPlugin,
    FlowEntropyPlugin,
    QueryLengthPlugin,
)
from backend import rule_based
from backend.rule_based import IGMPAlertPlugin, OSPFAlertPlugin, PIMAlertPlugin
from backend.predictor import run_prediction
from core.config import CONFIG
from core.events import FlowEvent
from core.state import AppState

logger = logging.getLogger(__name__)

# Set True to dump every anomalous flow's full feature row to CSV for later
# inspection — same behavior as the commented-out dump_full_flow() call in
# your original main.py, just toggled in one place instead of a comment.
DEBUG_DUMP_CSV = False
DEBUG_DUMP_PATH = "/tmp/live_flows_dump.csv"

_PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 89: "OSPF", 103: "PIM"}
# "Benign" (capitalised) is the IGMP model's benign class — distinct from the
# ICMP/TCP "BENIGN"/"G_BENIGN". All three must be treated as non-anomalous.
_BENIGN_LABELS = {"BENIGN", "G_BENIGN", "Benign"}

# Rule-based events use a single Model tag and a fixed confidence; multiple rule
# violations on one flow are joined into one prediction string with this delimiter.
RULE_MODEL_TAG = "RULE-BASED"
RULE_CONFIDENCE = 1.0
RULE_VERDICT_DELIM = " | "

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
ICMP_KEY_FEATURES_UDPS = [
    'fwd_byts_b_avg', 'fwd_pkts_b_avg', 'fwd_blk_rate_avg',
    'fwd_header_len', 'fwd_act_data_pkts',
    'active_mean', 'active_max', 'active_min',
    'idle_mean', 'idle_std', 'idle_max', 'idle_min'
]
ICMP_KEY_FEATURES_EX = ['src2dst_min_piat_ms', 'src2dst_packets']
DNS_KEY_FEATURES_UDPS = [
    'l7_query_length','_fwd_total_bytes',
    'active_max','bwd_header_len']
DNS_KEY_FEATURES_EX = ['dst2src_max_ps','src2dst_max_ps','bidirectional_bytes','Flow Byts/s','bidirectional_max_piat_ms',
                       'bidirectional_mean_piat_ms','Bwd Pkts/s','Down/Up Ratio']
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
    dns: ModelBundle
    igmp: Optional[ModelBundle] = None


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
    base = os.path.join(models_dir, "TCP")
    tcp = ModelBundle(
        model=joblib.load(f"{base}/tcp_final_model.pkl"),
        le=joblib.load(f"{base}/tcp_final_label_encoder.pkl"),
        fcols=joblib.load(f"{base}/tcp_final_features.pkl"),
    )
    logger.info("[TCP ] %d features | classes: %s", len(tcp.fcols), list(tcp.le.classes_))
    base = os.path.join(models_dir, "IGMP")
    igmp = ModelBundle(
        model=joblib.load(f"{base}/igmp_xgboost_model2.pkl"),
        le=joblib.load(f"{base}/igmp_label_encoder2.pkl"),
        fcols=joblib.load(f"{base}/igmp_feature_columns2.pkl"),
    )
    logger.info("[IGMP] %d features | classes: %s", len(igmp.fcols), list(igmp.le.classes_))

    base = os.path.join(models_dir, "DNS")
    dns = ModelBundle(
        model=joblib.load(f"{base}/DNS_model3.pkl"),
        le=joblib.load(f"{base}/DNS_label_encoder.pkl"),
        fcols=joblib.load(f"{base}/DNS_feature_columns_model3.pkl"),
    )
    logger.info("[DNS ] %d features | classes: %s", len(dns.fcols), list(dns.le.classes_))

    return Models(icmp=icmp, tcp=tcp, igmp=igmp, dns=dns)


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
    
    key_features: Dict[str, object] = {}
    
    # Safely get udps plugin features
    for field in ICMP_KEY_FEATURES_UDPS:
        key_features[f"udps.{field}"] = getattr(flow.udps, field, "MISSING")
        
    # Safely get core flow features
    for field in ICMP_KEY_FEATURES_EX:
        key_features[field] = getattr(flow, field, "MISSING")

    if flow.bidirectional_packets < 5 and flow.bidirectional_duration_ms < 10:
        return _build_event(ts, "ICMP", flow, "BENIGN", 1.0,key_features)

    try:
        row = build_icmp_row(flow)
        pred, conf = run_prediction(models.icmp.model, models.icmp.le, models.icmp.fcols, row)
    except Exception as e:
        pred, conf = f"ERR:{e}", 0.0

    return _build_event(ts, "ICMP", flow, pred, conf,key_features)

def _process_dns(flow, ts: str, models: Models) -> FlowEvent:
    row = build_dns_row(flow)

    key_features: Dict[str, object] = {}

    for field in DNS_KEY_FEATURES_UDPS:
        key_features[f"udps.{field}"] = row.get(f"udps.{field}", "MISSING")

    for field in DNS_KEY_FEATURES_EX:
        key_features[field] = row.get(field, "MISSING")

    try:
        if models.dns is None:
            raise RuntimeError("DNS model not loaded yet")

        pred, conf = run_prediction(
            models.dns.model,
            models.dns.le,
            models.dns.fcols,
            row,
        )

    except Exception as e:
        pred, conf = f"ERR:{e}", 0.0

    return _build_event(ts, "DNS", flow, pred, conf, key_features)

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


# ── Rule-based branches (IGMP rules / OSPF / PIM) ────────────────────────────

def _rule_key_features(verdicts: List[str], info: Dict[str, object]) -> Dict[str, object]:
    """
    Detection Details payload for a rule-based event: the individual triggered
    rules (numbered, readable) followed by whatever supporting values the plugin
    actually captured. Nothing is fabricated — `info` only holds measured data.
    """
    key_features: Dict[str, object] = {}
    if verdicts:
        for i, verdict in enumerate(verdicts, 1):
            key_features[f"Rule {i}"] = verdict
    else:
        key_features["Verdict"] = "BENIGN"
    key_features.update(info)
    return key_features


def _build_rule_event(ts: str, flow, verdicts: List[str],
                      info: Dict[str, object]) -> FlowEvent:
    """One FlowEvent for a rule-based flow. Multiple verdicts → one joined
    prediction string → one row. Benign (no verdict) → "BENIGN"."""
    prediction = RULE_VERDICT_DELIM.join(verdicts) if verdicts else "BENIGN"
    return _build_event(ts, RULE_MODEL_TAG, flow, prediction, RULE_CONFIDENCE,
                        _rule_key_features(verdicts, info))


def _process_igmp(flow, ts: str, models: Models) -> List[FlowEvent]:
    """
    Strict separation — NO IGMP packet is analysed by both systems:

      • Type 0x11 present (igmp_query_count > 0): router-side Membership Query
        traffic → RULE ENGINE ONLY. Never builds ML features or runs ML.
        Always emits exactly one RULE-BASED row (benign, or the aggregated
        verdicts when one or more query rules fired).

      • No Type 0x11 (only reports/leaves): host-side multicast membership
        traffic → IGMP ML MODEL ONLY. Emits one "IGMP" model event.

    IGMP queries and reports are sourced/destined differently, so they form
    separate NFStream flows — this flow-level split is exact in practice.
    """
    query_count = getattr(flow.udps, "igmp_query_count", 0)

    # ── Router-side query traffic (Type 0x11) → rule engine only ──────────
    if query_count > 0:
        verdicts = list(getattr(flow.udps, "igmp_rule_verdicts", []))
        info = dict(getattr(flow.udps, "igmp_info", {}))
        info["Query Count"] = query_count
        info["Flood IAT Threshold (s)"] = rule_based.IGMP_GENERAL_QUERY_FLOOD_IAT
        return [_build_rule_event(ts, flow, verdicts, info)]

    # ── Host-side report/leave traffic → IGMP ML model only ───────────────
    if models.igmp is not None:
        try:
            row = build_igmp_row(flow)
            pred, conf = run_prediction(models.igmp.model, models.igmp.le,
                                        models.igmp.fcols, row)
            key_features = dict(row)
        except Exception as e:
            pred, conf, key_features = f"ERR:{e}", 0.0, {}
        return [_build_event(ts, "IGMP", flow, pred, conf, key_features)]

    return []


def _process_ospf(flow, ts: str, models: Models) -> List[FlowEvent]:
    """OSPF is rule-only — always emit one event (benign or with verdicts)."""
    verdicts = list(getattr(flow.udps, "ospf_verdicts", []))
    info = dict(getattr(flow.udps, "ospf_info", {}))
    return [_build_rule_event(ts, flow, verdicts, info)]


def _process_pim(flow, ts: str, models: Models) -> List[FlowEvent]:
    """PIM is rule-only — always emit one event (benign or with verdicts)."""
    verdicts = list(getattr(flow.udps, "pim_verdicts", []))
    info = dict(getattr(flow.udps, "pim_info", {}))
    return [_build_rule_event(ts, flow, verdicts, info)]


def process_flow(flow, models: Models) -> List[FlowEvent]:
    """
    Routes a single NFStream flow to the right branch(es). Returns a list so a
    single flow can yield more than one event (e.g. an IGMP flow that both feeds
    the ML model and trips a query rule). Empty list = nothing to record.
    """
    ts = datetime.now().strftime("%H:%M:%S")

    if flow.protocol == 1:
        return [_process_icmp(flow, ts, models)]
    elif flow.protocol == 2:
        return _process_igmp(flow, ts, models)
    elif flow.protocol == 89:
        return _process_ospf(flow, ts, models)
    elif flow.protocol == 103:
        return _process_pim(flow, ts, models)
    elif flow.protocol == 17 and (flow.dst_port == 53 or flow.src_port == 53):
        return [_process_dns(flow, ts, models)]
    elif flow.protocol in (6, 17):
        return [_process_tcp(flow, ts, models)]
    else:
        logger.debug("Skipped unsupported flow: protocol=%s", flow.protocol)
        return []


# ═══════════════════════════════════════════════════════════════════════════
# The worker-thread entry point
# ═══════════════════════════════════════════════════════════════════════════

def run_pipeline(state: AppState, interface: str, models_dir: str) -> None:
    """
    Runs on a daemon thread, started by the Start button. Blocks for the
    life of the capture — never call this from the GUI thread.
    """
    models = load_models(models_dir)

    # Apply the user's tuned rule-engine thresholds for THIS capture. Reading
    # them here (not at import) is what gives "changes take effect on the next
    # capture" — an already-running capture keeps the values it started with.
    _apply_rule_config()

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
            QueryLengthPlugin(),
            FlowEntropyPlugin(),
            ExtraFeaturesPlugin(),
            ActiveIdlePlugin(idle_threshold_ms=5000),
            # Rule-based signature detectors (IGMP / OSPF / PIM).
            IGMPAlertPlugin(),
            OSPFAlertPlugin(),
            PIMAlertPlugin(),
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
        for event in process_flow(flow, models):
            state.record(event)

    state.stop()
    logger.info("Pipeline stopped.")


def _apply_rule_config() -> None:
    """Copy the persisted Settings values into the rule_based module globals so
    the detectors pick them up for the upcoming capture."""
    rule_based.IGMP_GENERAL_QUERY_FLOOD_IAT = CONFIG.get("IGMP_GENERAL_QUERY_FLOOD_IAT")
    rule_based.OSPF_LSA_IAT_THRESHOLD = CONFIG.get("OSPF_LSA_IAT_THRESHOLD")
    rule_based.OSPF_MAX_AGE_THRESHOLD = CONFIG.get("OSPF_MAX_AGE_THRESHOLD")
    rule_based.OSPF_HELLO_IAT_THRESHOLD = CONFIG.get("OSPF_HELLO_IAT_THRESHOLD")
    rule_based.PIM_HELLO_IAT_THRESHOLD = CONFIG.get("PIM_HELLO_IAT_THRESHOLD")
    logger.info("Rule thresholds applied: IGMP_flood_iat=%.1f OSPF_lsa_iat=%.1f "
                "OSPF_maxage=%.1f OSPF_hello_iat=%.1f PIM_hello_iat=%.1f",
                rule_based.IGMP_GENERAL_QUERY_FLOOD_IAT, rule_based.OSPF_LSA_IAT_THRESHOLD,
                rule_based.OSPF_MAX_AGE_THRESHOLD, rule_based.OSPF_HELLO_IAT_THRESHOLD,
                rule_based.PIM_HELLO_IAT_THRESHOLD)
