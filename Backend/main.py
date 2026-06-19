import os
import joblib
from datetime import datetime
from nfstream import NFStreamer

from plugins import BulkPlugin, HeaderLenPlugin, InitWindowPlugin, ExtraFeaturesPlugin, ActiveIdlePlugin
from feature_builders import build_icmp_row, build_tcp_row, dump_full_flow
from predictor import run_prediction
from display import _print_row, _HDR, _RESET

if __name__ == '__main__':

    ABS_PATH   = os.path.dirname(os.path.abspath(__file__))
    MODELS = os.path.join(ABS_PATH, "models")

    # ── Load ICMP model ──────────────────────────────────────────────────────
    BASE = os.path.join(MODELS,"ICMP")
    icmp_model  = joblib.load(f"{BASE}/xgboost_model3.pkl")
    icmp_le     = joblib.load(f"{BASE}/label_encoder3.pkl")
    icmp_fcols  = joblib.load(f"{BASE}/feature_columns3.pkl")
    print(f"[ICMP]  {len(icmp_fcols)} features | classes: {list(icmp_le.classes_)}")

    # ── Load TCP multi-attack model (Model 2 from notebook — see README) ─────
    BASE = os.path.join(MODELS,"ICMP")
    tcp_model   = joblib.load(f"{BASE}/tcp_model2.pkl")
    tcp_le      = joblib.load(f"{BASE}/tcp_label_encoder2.pkl")
    tcp_fcols   = joblib.load(f"{BASE}/tcp_feature_columns2.pkl")
    print(f"[TCP ]  {len(tcp_fcols)} features | classes: {list(tcp_le.classes_)}")

    INTERFACE = "enp0s8"

    streamer = NFStreamer(
        source               = INTERFACE,
        statistical_analysis = True,
        splt_analysis        = 0,
        accounting_mode      = 3,
        idle_timeout         = 2,
        active_timeout       = 5,
        udps=[
            BulkPlugin(),
            HeaderLenPlugin(),
            InitWindowPlugin(),
            ExtraFeaturesPlugin(),
            ActiveIdlePlugin(idle_threshold_ms=5000),
        ]
    )

    print(f"\nPipeline live on [{INTERFACE}]")
    print(_HDR)
    print("─" * len(_HDR))

    for flow in streamer:
        ts = datetime.now().strftime("%H:%M:%S")

        # ────────────────────────────────────────────────────────────────────
        #  ICMP branch
        # ────────────────────────────────────────────────────────────────────
        if flow.protocol == 1:
            print("\n--- Features ---")
            udps_fields = [
            'fwd_byts_b_avg', 'fwd_pkts_b_avg', 'fwd_blk_rate_avg',
            'fwd_header_len', 'fwd_act_data_pkts',
            'active_mean', 'active_max', 'active_min',
            'idle_mean', 'idle_std', 'idle_max', 'idle_min'
            ]
            ex = ['src2dst_min_piat_ms','src2dst_packets']  
            
            for field in udps_fields:
                val = getattr(flow.udps, field, "MISSING")
                status = "⚠ MISSING" if val == "MISSING" else ("✓" if val != 0 else "zero")
                print(f"  {field:<25} = {val}  {status}")
            
            for field in ex:
                val = getattr(flow, field, "MISSING")
                status = "⚠ MISSING" if val == "MISSING" else ("✓" if val != 0 else "zero")
                print(f"  {field:<25} = {val}  {status}")
            print("------------------\n")

            if flow.bidirectional_packets < 5 and flow.bidirectional_duration_ms < 10:
                _print_row(ts, "ICMP", flow, "BENIGN", 1.0, " [gate]")
                continue
            
            try:
                row  = build_icmp_row(flow)
                pred, conf = run_prediction(icmp_model, icmp_le, icmp_fcols, row)
            except Exception as e:
                pred, conf = f"ERR:{e}", 0.0
                
        
            _print_row(ts, "ICMP", flow, pred, conf)
        
        # ────────────────────────────────────────────────────────────────────
        #  DNS branch  (DNS Spoofing,Tunneling)
        # ────────────────────────────────────────────────────────────────────
        
        elif flow.protocol == 17 and (flow.dst_port == 53 or flow.src_port == 53):
            
            try:
                row = build_dns_row(flow)   
                pred, conf = run_prediction(dns_model, dns_le, dns_fcols, row)
            except Exception as e:
                pred, conf = f"ERR:{e}", 0.0
                
                
            _print_row(ts, "DNS", flow, pred, conf)
            
        # ────────────────────────────────────────────────────────────────────
        #  TCP branch  (HTTP/HTTPS, SQLI, PORTSCAN, SSH, FTP)
        # ────────────────────────────────────────────────────────────────────
        elif flow.protocol == 6 or flow.protocol == 17:
            try:

                TCP_KEY_FEATURES = [
                'src2dst_psh_packets', 'dst2src_rst_packets', 'dst2src_psh_packets',
                'RST Flag Cnt', 'PSH Flag Cnt',
                'dst2src_stddev_ps', 'bidirectional_stddev_ps', 'Pkt Len Var',
                'src2dst_min_ps', 'bidirectional_mean_ps', 'bidirectional_max_ps',
                'udps.fwd_seg_size_min', 'udps.init_fwd_win'
                ]

                row  = build_tcp_row(flow)

                print("\n--- TCP Model Features ---")
                for feat in TCP_KEY_FEATURES:
                    val = row.get(feat, 'MISSING')
                    print(f"  {feat:<35} = {val}")
                print("--------------------------\n")
                pred, conf = run_prediction(tcp_model, tcp_le, tcp_fcols, row)
                #dump_full_flow(flow, pred, conf, row,out_csv='/tmp/live_flows_dump.csv')

                init_win = row.get('udps.init_fwd_win', 0)
                if pred == 'SSH-BRUTEFORCE' and init_win == -1 and row.get('dst2src_rst_packets', 0) == 0:
                    pred = 'G_BENIGN'              
                
            except Exception as e:
                pred, conf = f"ERR:{e}", 0.0
            _print_row(ts,"TCP/UDP", flow, pred, conf)

        # ────────────────────────────────────────────────────────────────────
        #  All other protocols (ARP, …) — skip
        # ────────────────────────────────────────────────────────────────────
        else:
            print("--- Skipped an non TCP,UDP,ICMP Flow ------")
            continue
