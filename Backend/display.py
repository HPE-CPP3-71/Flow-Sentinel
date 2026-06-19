_RED    = "\033[91m"
_YELLOW = "\033[93m"
_GREEN  = "\033[92m"
_RESET  = "\033[0m"

_LABEL_COLOR = {
    "BENIGN":          _GREEN,
    "ICMP_FLOOD":      _RED,
    "ICMP_TUNNEL":     _YELLOW,
    "PORTSCAN":        _YELLOW,
    "SQLI":            _RED,
    "FTP-BRUTEFORCE":  _RED,
    "SSH-BRUTEFORCE":  _RED,
    "WEB-BRUTEFORCE":  _RED,
}

_HDR = (f"{'Time':<10} {'Model':<5} {'Src IP':<18} {'Dst IP':<18} "
        f"{'Pkts':>6} {'Bytes':>8} {'Prediction':<16} {'Conf':>8}")

def _print_row(ts, model_tag, flow, prediction, confidence, suffix=""):
    color = _LABEL_COLOR.get(prediction, _RED)
    print(f"{ts:<10} {model_tag:<5} {flow.src_ip:<18} {flow.dst_ip:<18} "
          f"{flow.bidirectional_packets:>6} {flow.bidirectional_bytes:>8} "
          f"{color}{prediction:<16}{_RESET} {confidence:>8.4f}{suffix}")
