import os, csv, json
import numpy as np
import pandas as pd


def _udps(flow, attr, default=0.0):
    """Safe accessor for UDPS plugin attributes."""
    return getattr(flow.udps, attr, default)


def _safe_div(numerator, denominator, default=0.0):
    """Division that returns `default` on zero denominator."""
    return numerator / denominator if denominator else default


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE BUILDERS
# ═══════════════════════════════════════════════════════════════════════════════

def dump_full_flow(flow, pred, conf, row_dict, out_csv='/tmp/misclassified_flows.csv'):
    """
    Dumps every NFStream attribute + the model feature row to a CSV.
    Call this whenever pred != 'BENIGN' and you want to inspect the flow.
    """
    native = {
        'src_ip': str(flow.src_ip), 'dst_ip': str(flow.dst_ip),
        'src_port': flow.src_port, 'dst_port': flow.dst_port,
        'protocol': flow.protocol,
        'bidirectional_packets': flow.bidirectional_packets,
        'bidirectional_bytes': flow.bidirectional_bytes,
        'bidirectional_duration_ms': flow.bidirectional_duration_ms,
        'bidirectional_mean_ps': flow.bidirectional_mean_ps,
        'bidirectional_stddev_ps': flow.bidirectional_stddev_ps,
        'bidirectional_max_ps': flow.bidirectional_max_ps,
        'src2dst_packets': flow.src2dst_packets,
        'dst2src_packets': flow.dst2src_packets,
        'src2dst_psh_packets': flow.src2dst_psh_packets,
        'dst2src_psh_packets': flow.dst2src_psh_packets,
        'src2dst_rst_packets': flow.src2dst_rst_packets,
        'dst2src_rst_packets': flow.dst2src_rst_packets,
        'src2dst_syn_packets': flow.src2dst_syn_packets,
        'dst2src_syn_packets': flow.dst2src_syn_packets,
        'src2dst_fin_packets': flow.src2dst_fin_packets,
        'dst2src_fin_packets': flow.dst2src_fin_packets,
        'bidirectional_psh_packets': flow.bidirectional_psh_packets,
        'bidirectional_rst_packets': flow.bidirectional_rst_packets,
        'expiration_id': flow.expiration_id,  # 0=idle, 1=active, -1=custom
    }

    full_row = {**native, **row_dict, 'prediction': pred, 'confidence': round(conf, 4)}

    write_header = not os.path.exists(out_csv)
    with open(out_csv, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=full_row.keys())
        if write_header:
            writer.writeheader()
        writer.writerow(full_row)

    print(json.dumps(full_row, indent=2, default=str))

def build_icmp_row(flow):
    """
    Feature dict for the ICMP anomaly model.
    """
    dur = max(flow.bidirectional_duration_ms / 1000.0, 0.5)
    return {
        "bidirectional_duration_ms":       flow.bidirectional_duration_ms,
        "bidirectional_packets":            flow.bidirectional_packets,
        "bidirectional_bytes":              flow.bidirectional_bytes,
        "src2dst_duration_ms":              flow.src2dst_duration_ms,
        "src2dst_packets":                  flow.src2dst_packets,
        "src2dst_bytes":                    flow.src2dst_bytes,
        "bidirectional_min_ps":             flow.bidirectional_min_ps,
        "bidirectional_mean_ps":            flow.bidirectional_mean_ps,
        "bidirectional_stddev_ps":          flow.bidirectional_stddev_ps,
        "bidirectional_max_ps":             flow.bidirectional_max_ps,
        "src2dst_min_ps":                   flow.src2dst_min_ps,
        "src2dst_mean_ps":                  flow.src2dst_mean_ps,
        "src2dst_stddev_ps":                flow.src2dst_stddev_ps,
        "src2dst_max_ps":                   flow.src2dst_max_ps,
        "bidirectional_min_piat_ms":        flow.bidirectional_min_piat_ms,
        "bidirectional_mean_piat_ms":       flow.bidirectional_mean_piat_ms,
        "bidirectional_stddev_piat_ms":     flow.bidirectional_stddev_piat_ms,
        "bidirectional_max_piat_ms":        flow.bidirectional_max_piat_ms,
        "src2dst_min_piat_ms":              flow.src2dst_min_piat_ms,
        "src2dst_mean_piat_ms":             flow.src2dst_mean_piat_ms,
        "src2dst_stddev_piat_ms":           flow.src2dst_stddev_piat_ms,
        "src2dst_max_piat_ms":              flow.src2dst_max_piat_ms,
        "dst2src_packets":                  flow.dst2src_packets,
        "dst2src_bytes":                    flow.dst2src_bytes,
        "dst2src_duration_ms":              flow.dst2src_duration_ms,
        "dst2src_mean_ps":                  flow.dst2src_mean_ps,
        "dst2src_min_ps":                   flow.dst2src_min_ps,
        "dst2src_stddev_ps":                flow.dst2src_stddev_ps,
        "dst2src_max_ps":                   flow.dst2src_max_ps,
        "dst2src_min_piat_ms":              flow.dst2src_min_piat_ms,
        "dst2src_mean_piat_ms":             flow.dst2src_mean_piat_ms,
        "dst2src_stddev_piat_ms":           flow.dst2src_stddev_piat_ms,
        "dst2src_max_piat_ms":              flow.dst2src_max_piat_ms,
        "udps.bwd_byts_b_avg":              _udps(flow, 'bwd_byts_b_avg'),
        "udps.bwd_pkts_b_avg":              _udps(flow, 'bwd_pkts_b_avg'),
        "udps.bwd_blk_rate_avg":            _udps(flow, 'bwd_blk_rate_avg'),
        "udps.fwd_byts_b_avg":              _udps(flow, 'fwd_byts_b_avg'),
        "udps.fwd_pkts_b_avg":              _udps(flow, 'fwd_pkts_b_avg'),
        "udps.fwd_blk_rate_avg":            _udps(flow, 'fwd_blk_rate_avg'),
        "udps.fwd_header_len":              _udps(flow, 'fwd_header_len'),
        "udps.fwd_act_data_pkts":           _udps(flow, 'fwd_act_data_pkts', 0),
        "udps.active_mean":                 _udps(flow, 'active_mean'),
        "udps.active_max":                  _udps(flow, 'active_max'),
        "udps.active_min":                  _udps(flow, 'active_min'),
        "udps.idle_mean":                   _udps(flow, 'idle_mean'),
        "udps.idle_std":                    _udps(flow, 'idle_std'),
        "udps.idle_max":                    _udps(flow, 'idle_max'),
        "udps.idle_min":                    _udps(flow, 'idle_min'),
        "udps.fwd_seg_size_min":            _udps(flow, 'fwd_seg_size_min', 0),
        "udps.active_std":                  _udps(flow, 'active_std'),
        "Flow Byts/s":                      flow.bidirectional_bytes / dur,
        "Flow Pkts/s":                      flow.bidirectional_packets / dur,
        "Fwd Pkts/s":                       flow.src2dst_packets / dur,
        "Pkt Len Var":                      flow.bidirectional_stddev_ps ** 2,
        "Fwd Seg Size Avg":                 _safe_div(flow.src2dst_bytes, flow.src2dst_packets),
        "Fwd IAT Tot":                      flow.src2dst_duration_ms,
        "Bwd Pkts/s":                       flow.dst2src_packets / dur,
        "Bwd Seg Size Avg":                 _safe_div(flow.dst2src_bytes, flow.dst2src_packets),
        "Down/Up Ratio":                    (flow.dst2src_packets // flow.src2dst_packets
                                            if flow.src2dst_packets > 0 else 0),
        "Bwd IAT Tot":                      flow.dst2src_duration_ms,
    }


def build_tcp_row(flow):
    """
    Feature dict for the TCP multi-attack model (DNS Spoofing/Tunneling/PORTSCAN/SSH/FTP brute-force).
    """
    
    dur = max(flow.bidirectional_duration_ms / 1000.0, 0.5)

    fwd_syn = getattr(flow, 'src2dst_syn_packets', 0)
    bwd_syn = getattr(flow, 'dst2src_syn_packets', 0)
    fwd_rst = getattr(flow, 'src2dst_rst_packets', 0)
    bwd_rst = getattr(flow, 'dst2src_rst_packets', 0)
    fwd_psh = getattr(flow, 'src2dst_psh_packets', 0)
    bwd_psh = getattr(flow, 'dst2src_psh_packets', 0)
    fwd_ack = getattr(flow, 'src2dst_ack_packets', 0)
    bwd_ack = getattr(flow, 'dst2src_ack_packets', 0)
    fwd_fin = getattr(flow, 'src2dst_fin_packets', 0)
    bwd_fin = getattr(flow, 'dst2src_fin_packets', 0)
    fwd_ece = getattr(flow, 'src2dst_ece_packets', 0)
    bwd_ece = getattr(flow, 'dst2src_ece_packets', 0)

    return {
        # ── Standard NFStream bidirectional stats ────────────────────────────
        "bidirectional_duration_ms":       flow.bidirectional_duration_ms,
        "bidirectional_packets":            flow.bidirectional_packets,
        "bidirectional_bytes":              flow.bidirectional_bytes,
        "bidirectional_min_ps":             flow.bidirectional_min_ps,
        "bidirectional_mean_ps":            flow.bidirectional_mean_ps,
        "bidirectional_stddev_ps":          flow.bidirectional_stddev_ps,
        "bidirectional_max_ps":             flow.bidirectional_max_ps,
        "bidirectional_min_piat_ms":        flow.bidirectional_min_piat_ms,
        "bidirectional_mean_piat_ms":       flow.bidirectional_mean_piat_ms,
        "bidirectional_stddev_piat_ms":     flow.bidirectional_stddev_piat_ms,
        "bidirectional_max_piat_ms":        flow.bidirectional_max_piat_ms,
        
        # ── Source → Destination (forward) ──────────────────────────────────
        "src2dst_duration_ms":              flow.src2dst_duration_ms,
        "src2dst_packets":                  flow.src2dst_packets,
        "src2dst_bytes":                    flow.src2dst_bytes,
        "src2dst_min_ps":                   flow.src2dst_min_ps,
        "src2dst_mean_ps":                  flow.src2dst_mean_ps,
        "src2dst_stddev_ps":                flow.src2dst_stddev_ps,
        "src2dst_max_ps":                   flow.src2dst_max_ps,
        "src2dst_min_piat_ms":              flow.src2dst_min_piat_ms,
        "src2dst_mean_piat_ms":             flow.src2dst_mean_piat_ms,
        "src2dst_stddev_piat_ms":           flow.src2dst_stddev_piat_ms,
        "src2dst_max_piat_ms":              flow.src2dst_max_piat_ms,

        # ── Destination → Source (backward) ─────────────────────────────────
        "dst2src_duration_ms":              flow.dst2src_duration_ms,
        "dst2src_packets":                  flow.dst2src_packets,
        "dst2src_bytes":                    flow.dst2src_bytes,
        "dst2src_min_ps":                   flow.dst2src_min_ps,
        "dst2src_mean_ps":                  flow.dst2src_mean_ps,
        "dst2src_stddev_ps":                flow.dst2src_stddev_ps,   #1 feature (M2)
        "dst2src_max_ps":                   flow.dst2src_max_ps,
        "dst2src_min_piat_ms":              flow.dst2src_min_piat_ms,
        "dst2src_mean_piat_ms":             flow.dst2src_mean_piat_ms,
        "dst2src_stddev_piat_ms":           flow.dst2src_stddev_piat_ms,
        "dst2src_max_piat_ms":              flow.dst2src_max_piat_ms,

        # ── TCP flag packet counts (direction-level) — TOP features ─────────
        "src2dst_syn_packets":              fwd_syn,
        "dst2src_syn_packets":              bwd_syn,
        "src2dst_fin_packets":              fwd_fin,
        "dst2src_fin_packets":              bwd_fin,          # top-20 in M2
        "src2dst_rst_packets":              fwd_rst,
        "dst2src_rst_packets":              bwd_rst,          # #3 feature (M1, M2, M3)
        "src2dst_psh_packets":              fwd_psh,          # #1/#2 feature in M1/M3
        "dst2src_psh_packets":              bwd_psh,          # #1/#4 feature in M1/M3
        "src2dst_ack_packets":              fwd_ack,          # top-20 in M2, M3
        "dst2src_ack_packets":              bwd_ack,
        "src2dst_urg_packets":              flow.src2dst_urg_packets,
        # near-zero-variance but present in training — include to match training columns
        "src2dst_ece_packets":              fwd_ece,
        "dst2src_ece_packets":              bwd_ece,

        # ── CIC-style aggregated flag counts (used as named features in CSV) ─
        # SYN Flag Cnt / RST Flag Cnt appear by name in the merged training CSV.
        # They are the bidirectional totals of each flag.
        "SYN Flag Cnt":  flow.bidirectional_syn_packets,
        "PSH Flag Cnt":  flow.bidirectional_psh_packets,
        "RST Flag Cnt":  flow.bidirectional_rst_packets,
        "ACK Flag Cnt":  flow.bidirectional_ack_packets,
        "FIN Flag Cnt":  flow.bidirectional_fin_packets,
        "URG Flag Cnt":  flow.bidirectional_urg_packets,
        "ECE Flag Cnt":  flow.bidirectional_ece_packets,

        # ── Basic flow metadata (core NFlow fields, survived training feature selection) ─
        "protocol":      flow.protocol,
        "ip_version":    flow.ip_version,
        # ── UDPS plugin features ─────────────────────────────────────────────
        "udps.fwd_byts_b_avg":              _udps(flow, 'fwd_byts_b_avg'),
        "udps.fwd_pkts_b_avg":              _udps(flow, 'fwd_pkts_b_avg'),
        "udps.fwd_blk_rate_avg":            _udps(flow, 'fwd_blk_rate_avg'),
        "udps.bwd_byts_b_avg":              _udps(flow, 'bwd_byts_b_avg'),
        "udps.bwd_pkts_b_avg":              _udps(flow, 'bwd_pkts_b_avg'),
        "udps.bwd_blk_rate_avg":            _udps(flow, 'bwd_blk_rate_avg'),
        "udps.fwd_header_len":              _udps(flow, 'fwd_header_len'),    # top-20 all models
        "udps.bwd_header_len":              _udps(flow, 'bwd_header_len'),
        "udps.fwd_act_data_pkts":           _udps(flow, 'fwd_act_data_pkts', 0),
        "udps.fwd_seg_size_min":            _udps(flow, 'fwd_seg_size_min', 0),  # top-20 M1, M3
        "udps.init_fwd_win":                _udps(flow, 'init_fwd_win', -1),
        "udps.init_bwd_win":                _udps(flow, 'init_bwd_win', -1),  # top-20 M1
        "udps.active_mean":                 _udps(flow, 'active_mean'),
        "udps.active_std":                  _udps(flow, 'active_std'),
        "udps.active_max":                  _udps(flow, 'active_max'),
        "udps.active_min":                  _udps(flow, 'active_min'),
        "udps.idle_mean":                   _udps(flow, 'idle_mean'),
        "udps.idle_std":                    _udps(flow, 'idle_std'),
        "udps.idle_max":                    _udps(flow, 'idle_max'),
        "udps.idle_min":                    _udps(flow, 'idle_min'),
        "udps.l7_query_length":             len(flow.requested_server_name),
        # ── Derived / rate features ──────────────────────────────────────────
        "Flow Byts/s":     flow.bidirectional_bytes / dur,         # top-20 M2, M3
        "Flow Pkts/s":     flow.bidirectional_packets / dur,
        "Fwd Pkts/s":      flow.src2dst_packets / dur,
        "Bwd Pkts/s":      flow.dst2src_packets / dur,
        "Pkt Len Var":     flow.bidirectional_stddev_ps ** 2,      # top-20 all models
        "Fwd Seg Size Avg": _safe_div(flow.src2dst_bytes, flow.src2dst_packets),  # top-20 M1, M2, M3
        "Bwd Seg Size Avg": _safe_div(flow.dst2src_bytes, flow.dst2src_packets),
        "Fwd IAT Tot":     flow.src2dst_duration_ms,
        "Bwd IAT Tot":     flow.dst2src_duration_ms,
        "Down/Up Ratio":   (flow.dst2src_packets // flow.src2dst_packets
                            if flow.src2dst_packets > 0 else 0),
    }
