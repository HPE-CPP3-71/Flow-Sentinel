"""
rule_based.py
═══════════════════════════════════════════════════════════════════════════════
Signature / rule-based detectors for the IDS — all run as live NFStream plugins.

Each plugin records its verdicts for a flow on `flow.udps.<proto>_verdicts`
(a LIST — a single flow can trip several rules at once), plus a small
`flow.udps.<proto>_info` dict of supporting values (sequence numbers, ages,
inter-arrival times, router identities, …) for the Detection Details panel.

  • IGMPAlertPlugin   – IP protocol 2.   Handles ALL Type 0x11 (Membership
                        Query / router-side) traffic exclusively: General-Query
                        floods (IGMP_QRY_FLOOD), illegal Group-Specific queries
                        (IGMP_ILLEGAL_QRY), and rogue/spoofed queriers
                        (IGMP_ROGUE_QUERIER). Type != 0x11 (host-side reports /
                        leaves) carries no rule logic — those flows go to the
                        IGMP ML model instead (see pipeline.py routing).
  • OSPFAlertPlugin   – IP protocol 89.  Reconstructs the raw IP bytes
                        (packet.ip_packet) into a Scapy packet for deep packet
                        inspection: Disguised LSAs, Seq++ / replay, LSA floods,
                        Max-Age attacks, Hello floods and rogue routers.
  • PIMAlertPlugin    – IP protocol 103. Rogue routers, Hello floods/anomalies,
                        and malicious Hold-Time=0 adjacency drops (raw TLV parse).

NOTE: The ML feature-extraction plugins (ActiveIdlePlugin, HeaderLenPlugin,
ExtraFeaturesPlugin, …) already live in plugins.py — they are reused from there
and are NOT re-defined here. This file only adds the *rule-based* logic.

The ICMP / TCP code is untouched.

MULTIPLE VERDICTS PER FLOW
--------------------------
The detectors append to a verdict list (deduplicated, order preserved) instead
of overwriting a single string. backend/pipeline.py then turns that list into a
single FlowEvent whose prediction is the verdicts joined with " | ", so one
flow yields exactly one row no matter how many rules trip.

THRESHOLDS
----------
The constants below are DEFAULTS. backend/pipeline.run_pipeline() overwrites
them from core.config.CONFIG at the start of each capture, which is how the
Settings page retunes detection without a code change (and why a change only
takes effect on the next capture).
═══════════════════════════════════════════════════════════════════════════════
"""
import sys
from datetime import datetime
from collections import defaultdict
from nfstream import NFStreamer, NFPlugin

# Scapy is only needed for OSPF deep-packet inspection. Import it defensively so
# the IGMP / PIM plugins still work on machines where scapy/OSPF contrib is missing.
try:
    from scapy.all import IP, sniff, load_contrib
    from scapy.contrib.ospf import OSPF_Hello, OSPF_LSUpd
    load_contrib("ospf")
    _SCAPY_OK = True
except Exception:
    _SCAPY_OK = False


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTION THRESHOLDS  —  every tunable value lives here, in one place.
# (Overridden per-capture from core.config — see module docstring.)
# ═══════════════════════════════════════════════════════════════════════════════

BENIGN = "BENIGN"   # verdict shown when no rule fires

# ── IGMP ────────────────────────────────────────────────────────────────────────
IGMP_GENERAL_QUERY_FLOOD_IAT = 120.0    # sec — back-to-back general queries faster than this = flood
IGMP_LEAVE_WINDOW            = 5.0       # sec — group-specific query without a Leave seen within this = illegal
IGMP_LEAVE_TRACKER_MAX       = 10000     # entries — cap on the leave-tracker before it is cleared
IGMP_MAX_QUERIERS            = 1         # only the elected querier should source Type 0x11; any extra IP = rogue

# ── OSPF ────────────────────────────────────────────────────────────────────────
OSPF_MAX_UNIQUE_ROUTERS      = 2         # first N distinct speakers are legit; every IP after = rogue
OSPF_SEQ_JUMP_THRESHOLD      = 1         # LSA seq increasing by more than this = Seq++ attack
OSPF_LSA_IAT_THRESHOLD       = 1690      # sec — LSAs refreshing faster than this = flood (default refresh 1800s)
OSPF_MAX_AGE_THRESHOLD       = 3600      # LS Age >= this = Max-Age attack (3600 is the protocol max)
OSPF_DISGUISED_WINDOW        = 10        # sec — window to compare same-seq LSAs for disguised content
OSPF_HELLO_IAT_THRESHOLD     = 9         # sec — Hellos faster than this = flood (actual is 10, allow jitter)

# ── PIM ─────────────────────────────────────────────────────────────────────────
PIM_HELLO_IAT_THRESHOLD      = 25.0      # sec — Hellos faster than this = flood/anomaly
PIM_MAX_UNIQUE_ROUTERS       = 2         # first N distinct speakers are legit; every IP after = rogue


def _add_verdict(verdicts: list, label: str) -> None:
    """Append a verdict once, preserving first-seen order (no duplicate rows)."""
    if label not in verdicts:
        verdicts.append(label)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. NATIVE RULE-BASED IGMP DETECTOR (NFSTREAM PLUGIN)
# ═══════════════════════════════════════════════════════════════════════════════

class IGMPAlertPlugin(NFPlugin):
    last_general_query_time = None     # None = no general query seen yet (first-packet-safe)
    leave_tracker = {}
    querier_ips = set()        # learned source IPs of Type 0x11 (querier) traffic

    def on_init(self, packet, flow):
        # Counters drive the strict routing in pipeline.py: query_count > 0 means
        # this flow is router-side Type 0x11 traffic (rule engine only); otherwise
        # it is host-side report/leave traffic (IGMP ML only). The verdict list
        # carries any rule results.
        flow.udps.igmp_query_count = 0
        flow.udps.igmp_report_leave_count = 0
        flow.udps.igmp_rule_verdicts = []      # empty = no rule fired
        flow.udps.igmp_info = {}               # supporting values for Detection Details
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if packet.ip_version == 4 and packet.protocol == 2:
            current_time = packet.time / 1000.0
            try:
                raw_bytes = packet.ip_packet
                ip_hl = (raw_bytes[0] & 0x0F) * 4

                if len(raw_bytes) >= ip_hl + 8:
                    igmp_type = raw_bytes[ip_hl]

                    if igmp_type == 0x11:  # Membership Query (router-side control)
                        flow.udps.igmp_query_count += 1

                        # Rogue querier: in a stable network only the elected
                        # querier should source Type 0x11. Learn the first
                        # querier silently; any later distinct source IP is a
                        # rogue / spoofed querier. Catches spoofed-IP floods even
                        # at a low rate (no IAT threshold involved).
                        src_ip = f"{raw_bytes[12]}.{raw_bytes[13]}.{raw_bytes[14]}.{raw_bytes[15]}"
                        flow.udps.igmp_info["Querier IP"] = src_ip
                        if src_ip not in IGMPAlertPlugin.querier_ips:
                            if len(IGMPAlertPlugin.querier_ips) < IGMP_MAX_QUERIERS:
                                IGMPAlertPlugin.querier_ips.add(src_ip)
                            else:
                                _add_verdict(flow.udps.igmp_rule_verdicts, "IGMP_ROGUE_QUERIER")

                        gaddr = f"{raw_bytes[ip_hl+4]}.{raw_bytes[ip_hl+5]}.{raw_bytes[ip_hl+6]}.{raw_bytes[ip_hl+7]}"
                        if gaddr == "0.0.0.0":
                            # First general query ever seen never flags a flood —
                            # there is no prior timestamp to diff against.
                            if IGMPAlertPlugin.last_general_query_time is not None:
                                iat = current_time - IGMPAlertPlugin.last_general_query_time
                                flow.udps.igmp_info["General-Query IAT (s)"] = round(iat, 3)
                                if iat < IGMP_GENERAL_QUERY_FLOOD_IAT:
                                    _add_verdict(flow.udps.igmp_rule_verdicts, "IGMP_QRY_FLOOD")
                            IGMPAlertPlugin.last_general_query_time = current_time
                        else:
                            flow.udps.igmp_info["Group Address"] = gaddr
                            last_leave = IGMPAlertPlugin.leave_tracker.get(gaddr, 0)
                            if last_leave == 0 or (current_time - last_leave) > IGMP_LEAVE_WINDOW:
                                _add_verdict(flow.udps.igmp_rule_verdicts, "IGMP_ILLEGAL_QRY")

                    else:
                        # Covers v1/v2/v3 Reports and Leaves (0x12, 0x16, 0x17, 0x22)
                        flow.udps.igmp_report_leave_count += 1

                        if igmp_type == 0x17:  # v2 Leave Group
                            gaddr = f"{raw_bytes[ip_hl+4]}.{raw_bytes[ip_hl+5]}.{raw_bytes[ip_hl+6]}.{raw_bytes[ip_hl+7]}"
                            IGMPAlertPlugin.leave_tracker[gaddr] = current_time
                            if len(IGMPAlertPlugin.leave_tracker) > IGMP_LEAVE_TRACKER_MAX:
                                IGMPAlertPlugin.leave_tracker.clear()

                        elif igmp_type == 0x22:  # v3 Membership Report
                            num_records = (raw_bytes[ip_hl+6] << 8) | raw_bytes[ip_hl+7]
                            offset = ip_hl + 8
                            for _ in range(num_records):
                                if offset + 8 > len(raw_bytes):
                                    break
                                rtype = raw_bytes[offset]
                                numsrc = (raw_bytes[offset+2] << 8) | raw_bytes[offset+3]
                                # rtype 3 = CHANGE_TO_INCLUDE with 0 sources == a leave
                                if rtype == 3 and numsrc == 0:
                                    gaddr = f"{raw_bytes[offset+4]}.{raw_bytes[offset+5]}.{raw_bytes[offset+6]}.{raw_bytes[offset+7]}"
                                    IGMPAlertPlugin.leave_tracker[gaddr] = current_time
                                    if len(IGMPAlertPlugin.leave_tracker) > IGMP_LEAVE_TRACKER_MAX:
                                        IGMPAlertPlugin.leave_tracker.clear()
                                offset += 8 + (numsrc * 4)
            except IndexError:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# 2. NATIVE RULE-BASED OSPF DETECTOR (NFSTREAM PLUGIN + SCAPY DPI)
# ═══════════════════════════════════════════════════════════════════════════════
#
# OSPF carries Link-State data inside complex nested structures (LSA headers
# inside LS-Update headers inside the OSPF header), so raw byte-offset parsing is
# impractical. Instead we lift the raw IP bytes out of NFStream (packet.ip_packet)
# and let Scapy parse them. Detection state is held on class-level dicts so it
# persists across every flow globally.
# ═══════════════════════════════════════════════════════════════════════════════

class OSPFAlertPlugin(NFPlugin):
    # Class-level detection state shared across all flows
    seq_db = {}
    last_lsa_seen = {}
    disguise_db = defaultdict(list)
    last_hello_seen = {}
    known_routers = set()                   # first OSPF_MAX_UNIQUE_ROUTERS speakers = legit
    _warned_no_scapy = False

    def on_init(self, packet, flow):
        flow.udps.ospf_verdicts = []
        flow.udps.ospf_info = {}
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        # Protocol 89 is OSPF (runs directly over IP)
        if packet.ip_version == 4 and packet.protocol == 89:
            if not _SCAPY_OK:
                if not OSPFAlertPlugin._warned_no_scapy:
                    print("\033[93m[NF RULE] ⚠ OSPF packet seen but scapy/OSPF contrib is unavailable — install scapy to enable OSPF detection.\033[0m")
                    OSPFAlertPlugin._warned_no_scapy = True
                return
            try:
                # Reconstruct a Scapy packet from NFStream raw bytes for DPI
                pkt = IP(packet.ip_packet)
                pkt.time = packet.time / 1000.0   # ms -> seconds
                flow.udps.ospf_info["Source Router"] = pkt[IP].src

                if pkt.haslayer(OSPF_Hello):
                    self.detect_hello_flood(pkt, flow)

                if pkt.haslayer(OSPF_LSUpd):
                    for info in self.extract_lsa_info(pkt):
                        self.detect_disguised_lsa(info, flow)
                        self.detect_seq_jump(info, flow)
                        self.detect_lsa_flood(info, flow)
                        self.detect_max_age_attack(info, flow)
            except Exception:
                pass  # Silently drop malformed OSPF packets

    # ── HELPER ──────────────────────────────────────────────────────────────────
    def extract_lsa_info(self, pkt):
        lsa_infos = []
        ip  = pkt[IP]
        lsu = pkt[OSPF_LSUpd]
        for lsa in lsu.lsalist:
            lsa_infos.append({
                "src_ip":        ip.src,
                "adv_router":    getattr(lsa, 'adrouter', 'Unknown'),
                "link_state_id": getattr(lsa, 'id', 'Unknown'),
                "lsa_type":      getattr(lsa, 'type', 0),
                "seq":           getattr(lsa, 'seq', 0),
                "checksum":      getattr(lsa, 'chksum', 0),
                "age":           getattr(lsa, 'age', 0),
                "length":        getattr(lsa, 'len', 0),
                "time":          pkt.time,
            })
        return lsa_infos

    # ── RULE 1 : DISGUISED LSA DETECTION ────────────────────────────────────────
    def detect_disguised_lsa(self, info, flow):
        key = (info["adv_router"], info["link_state_id"], info["lsa_type"])
        current_time = info["time"]

        OSPFAlertPlugin.disguise_db[key] = [
            x for x in OSPFAlertPlugin.disguise_db[key]
            if current_time - x["time"] <= OSPF_DISGUISED_WINDOW
        ]

        for old in OSPFAlertPlugin.disguise_db[key]:
            # SAME identity + SAME seq but DIFFERENT metadata
            if (old["seq"] == info["seq"] and
                    (old["checksum"] != info["checksum"]
                     or old["length"] != info["length"]
                     or old["age"]   != info["age"])):
                _add_verdict(flow.udps.ospf_verdicts, "OSPF_DISGUISE")
                flow.udps.ospf_info["Adv Router"] = info["adv_router"]

        OSPFAlertPlugin.disguise_db[key].append(info)

    # ── RULE 2 : SEQ++ / REPLAY DETECTION ───────────────────────────────────────
    def detect_seq_jump(self, info, flow):
        key = (info["src_ip"], info["adv_router"], info["link_state_id"], info["lsa_type"])
        seq = info["seq"]

        if key not in OSPFAlertPlugin.seq_db:
            OSPFAlertPlugin.seq_db[key] = seq
            return

        old_seq = OSPFAlertPlugin.seq_db[key]

        if seq < old_seq:                                   # Replay / rollback
            _add_verdict(flow.udps.ospf_verdicts, "OSPF_SEQ_REPLAY")
            flow.udps.ospf_info["Sequence Number"] = seq
        elif (seq - old_seq) > OSPF_SEQ_JUMP_THRESHOLD:     # Seq++ jump
            _add_verdict(flow.udps.ospf_verdicts, "OSPF_SEQ_JUMP")
            flow.udps.ospf_info["Sequence Number"] = seq

        OSPFAlertPlugin.seq_db[key] = seq

    # ── RULE 3 : LSA FLOOD DETECTION ────────────────────────────────────────────
    def detect_lsa_flood(self, info, flow):
        key = (info["src_ip"], info["adv_router"], info["link_state_id"], info["lsa_type"])
        seq          = info["seq"]
        current_time = float(info["time"])

        if key not in OSPFAlertPlugin.last_lsa_seen:
            OSPFAlertPlugin.last_lsa_seen[key] = {"time": current_time, "seq": seq}
            return

        iat = current_time - OSPFAlertPlugin.last_lsa_seen[key]["time"]
        if iat < OSPF_LSA_IAT_THRESHOLD:
            _add_verdict(flow.udps.ospf_verdicts, "OSPF_LSA_FLOOD")
            flow.udps.ospf_info["LSA IAT (s)"] = round(iat, 3)

        OSPFAlertPlugin.last_lsa_seen[key] = {"time": current_time, "seq": seq}

    # ── RULE 4 : MAX AGE ATTACK DETECTION ───────────────────────────────────────
    def detect_max_age_attack(self, info, flow):
        if info["age"] >= OSPF_MAX_AGE_THRESHOLD:
            _add_verdict(flow.udps.ospf_verdicts, "OSPF_MAXAGE_LSA")
            flow.udps.ospf_info["LSA Age"] = info["age"]

    # ── RULE 5 : HELLO FLOOD + ROGUE ROUTER DETECTION ───────────────────────────
    def detect_hello_flood(self, pkt, flow):
        src_ip       = pkt[IP].src
        current_time = pkt.time

        # --- Rogue Router: first N distinct speakers are legit, every IP after = rogue ---
        if src_ip not in OSPFAlertPlugin.known_routers:
            if len(OSPFAlertPlugin.known_routers) < OSPF_MAX_UNIQUE_ROUTERS:
                OSPFAlertPlugin.known_routers.add(src_ip)
            else:
                _add_verdict(flow.udps.ospf_verdicts, "OSPF_ROGUE_RTR")

        # --- Hello Flood ---
        if src_ip in OSPFAlertPlugin.last_hello_seen:
            iat = current_time - OSPFAlertPlugin.last_hello_seen[src_ip]
            if iat < OSPF_HELLO_IAT_THRESHOLD:
                _add_verdict(flow.udps.ospf_verdicts, "OSPF_HELLO_FLOOD")
                flow.udps.ospf_info["Hello IAT (s)"] = round(iat, 3)

        OSPFAlertPlugin.last_hello_seen[src_ip] = current_time


# ═══════════════════════════════════════════════════════════════════════════════
# 3. NATIVE RULE-BASED PIM DETECTOR (NFSTREAM PLUGIN)
# ═══════════════════════════════════════════════════════════════════════════════
#
# PIM (Protocol Independent Multicast) runs directly over IP as protocol 103.
# We parse the raw bytes to spot rogue routers, Hello floods and malicious
# Hold-Time=0 TLVs that force neighbour adjacency drops.
# ═══════════════════════════════════════════════════════════════════════════════

class PIMAlertPlugin(NFPlugin):
    last_hello_seen = {}
    known_routers = set()                   # first PIM_MAX_UNIQUE_ROUTERS speakers = legit

    def on_init(self, packet, flow):
        flow.udps.pim_verdicts = []
        flow.udps.pim_info = {}
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if packet.ip_version == 4 and packet.protocol == 103:
            current_time = packet.time / 1000.0
            try:
                raw_bytes = packet.ip_packet
                ip_hl = (raw_bytes[0] & 0x0F) * 4

                if len(raw_bytes) >= ip_hl + 4:
                    pim_ver_type = raw_bytes[ip_hl]

                    # ========================================================
                    # PIM HELLO (0x20) - Discovery & Adjacency Attacks
                    # ========================================================
                    if pim_ver_type == 0x20:
                        src_ip = f"{raw_bytes[12]}.{raw_bytes[13]}.{raw_bytes[14]}.{raw_bytes[15]}"
                        flow.udps.pim_info["Source Router"] = src_ip

                        # --- Rogue Router: first N distinct speakers are legit, every IP after = rogue ---
                        if src_ip not in PIMAlertPlugin.known_routers:
                            if len(PIMAlertPlugin.known_routers) < PIM_MAX_UNIQUE_ROUTERS:
                                PIMAlertPlugin.known_routers.add(src_ip)
                            else:
                                _add_verdict(flow.udps.pim_verdicts, "PIM_ROGUE_RTR")

                        # --- Hello Flood / Stealth Anomaly Check ---
                        if src_ip in PIMAlertPlugin.last_hello_seen:
                            iat = current_time - PIMAlertPlugin.last_hello_seen[src_ip]
                            if iat < PIM_HELLO_IAT_THRESHOLD:
                                _add_verdict(flow.udps.pim_verdicts, "PIM_HELLO_FLOOD")
                                flow.udps.pim_info["Hello IAT (s)"] = round(iat, 3)

                        PIMAlertPlugin.last_hello_seen[src_ip] = current_time

                        # --- Malicious TLV Parsing (Hold Time = 0) ---
                        offset = ip_hl + 4
                        while offset + 4 <= len(raw_bytes):
                            tlv_type = (raw_bytes[offset] << 8) | raw_bytes[offset+1]
                            tlv_len  = (raw_bytes[offset+2] << 8) | raw_bytes[offset+3]

                            # Hold Time = 0
                            if tlv_type == 1 and tlv_len == 2 and offset + 6 <= len(raw_bytes):
                                hold_time = (raw_bytes[offset+4] << 8) | raw_bytes[offset+5]
                                if hold_time == 0:
                                    _add_verdict(flow.udps.pim_verdicts, "PIM_HOLDTIME_0")
                                    flow.udps.pim_info["Hold Time (s)"] = 0

                            # Move to the next TLV (guard against a zero-length TLV stalling the loop)
                            offset += 4 + (tlv_len if tlv_len > 0 else 1)

            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# STANDALONE RUNNER  (live NIC or offline pcap — prints one verdict row per flow)
# ═══════════════════════════════════════════════════════════════════════════════

def _join(verdicts):
    return " | ".join(verdicts) if verdicts else BENIGN


def _print_flow_verdict(flow):
    from display import _print_row
    ts = datetime.now().strftime("%H:%M:%S")
    if flow.protocol == 2:
        _print_row(ts, "IGMP", flow, _join(getattr(flow.udps, 'igmp_rule_verdicts', [])), 1.0)
    elif flow.protocol == 89:
        _print_row(ts, "OSPF", flow, _join(getattr(flow.udps, 'ospf_verdicts', [])), 1.0)
    elif flow.protocol == 103:
        _print_row(ts, "PIM", flow, _join(getattr(flow.udps, 'pim_verdicts', [])), 1.0)


def run_pcap(pcap_file, plugins=None):
    """Replay a pcap through the rule-based plugins (one verdict row per flow)."""
    if plugins is None:
        plugins = [IGMPAlertPlugin(), OSPFAlertPlugin(), PIMAlertPlugin()]
    print(f"[+] Replaying {pcap_file} through rule-based detectors...\n")
    for flow in NFStreamer(source=pcap_file, udps=plugins):
        _print_flow_verdict(flow)
    print("\n[+] Analysis Complete.")


# ═══════════════════════════════════════════════════════════════════════════════
# STANDALONE ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
#   python rule_based.py <interface>          -> live IGMP + OSPF + PIM rule detection
#   python rule_based.py pcap <file.pcap>     -> replay a pcap through the rules
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "pcap":
        PCAP_FILE = sys.argv[2] if len(sys.argv) > 2 else \
            r"C:\Users\pmjpr\OneDrive\Desktop\gns3 pcaps\OSPF\maxage\r1-r3_max.pcap"
        run_pcap(PCAP_FILE)
    else:
        INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "enp0s8"
        print(f"[*] Live IGMP + OSPF + PIM rule detection on [{INTERFACE}]")
        for flow in NFStreamer(source=INTERFACE,
                               udps=[IGMPAlertPlugin(), OSPFAlertPlugin(), PIMAlertPlugin()]):
            _print_flow_verdict(flow)
