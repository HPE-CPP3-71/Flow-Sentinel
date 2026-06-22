import math
from datetime import datetime
from nfstream import NFPlugin, NFStreamer


class BulkPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.fwd_helper_count = 0
        flow.udps.fwd_helper_bytes = 0
        flow.udps.fwd_helper_start_ts = 0
        flow.udps.fwd_last_payload_ts = 0
        flow.udps.fwd_bulk_state_count = 0
        flow.udps.fwd_bulk_packet_count = 0
        flow.udps.fwd_bulk_size_total = 0
        flow.udps.fwd_bulk_duration_ms = 0

        flow.udps.bwd_helper_count = 0
        flow.udps.bwd_helper_bytes = 0
        flow.udps.bwd_helper_start_ts = 0
        flow.udps.bwd_last_payload_ts = 0
        flow.udps.bwd_bulk_state_count = 0
        flow.udps.bwd_bulk_packet_count = 0
        flow.udps.bwd_bulk_size_total = 0
        flow.udps.bwd_bulk_duration_ms = 0

        flow.udps.fwd_byts_b_avg = 0.0
        flow.udps.fwd_pkts_b_avg = 0.0
        flow.udps.fwd_blk_rate_avg = 0.0
        flow.udps.bwd_byts_b_avg = 0.0
        flow.udps.bwd_pkts_b_avg = 0.0
        flow.udps.bwd_blk_rate_avg = 0.0
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if packet.payload_size == 0:
            return
        if packet.direction == 0:
            if flow.udps.fwd_helper_count > 0:
                time_exceeded = (packet.time - flow.udps.fwd_last_payload_ts) > 1000
                opp_interrupted = flow.udps.bwd_last_payload_ts > flow.udps.fwd_helper_start_ts
                if time_exceeded or opp_interrupted:
                    flow.udps.fwd_helper_count = 0
                    flow.udps.fwd_helper_bytes = 0
            if flow.udps.fwd_helper_count == 0:
                flow.udps.fwd_helper_start_ts = packet.time
            prev_ts = flow.udps.fwd_last_payload_ts
            flow.udps.fwd_helper_count += 1
            flow.udps.fwd_helper_bytes += packet.payload_size
            flow.udps.fwd_last_payload_ts = packet.time
            if flow.udps.fwd_helper_count == 4:
                flow.udps.fwd_bulk_state_count += 1
                flow.udps.fwd_bulk_packet_count += 4
                flow.udps.fwd_bulk_size_total += flow.udps.fwd_helper_bytes
                flow.udps.fwd_bulk_duration_ms += (packet.time - flow.udps.fwd_helper_start_ts)
            elif flow.udps.fwd_helper_count > 4:
                flow.udps.fwd_bulk_packet_count += 1
                flow.udps.fwd_bulk_size_total += packet.payload_size
                flow.udps.fwd_bulk_duration_ms += (packet.time - prev_ts)
        else:
            if flow.udps.bwd_helper_count > 0:
                time_exceeded = (packet.time - flow.udps.bwd_last_payload_ts) > 1000
                opp_interrupted = flow.udps.fwd_last_payload_ts > flow.udps.bwd_helper_start_ts
                if time_exceeded or opp_interrupted:
                    flow.udps.bwd_helper_count = 0
                    flow.udps.bwd_helper_bytes = 0
            if flow.udps.bwd_helper_count == 0:
                flow.udps.bwd_helper_start_ts = packet.time
            prev_ts = flow.udps.bwd_last_payload_ts
            flow.udps.bwd_helper_count += 1
            flow.udps.bwd_helper_bytes += packet.payload_size
            flow.udps.bwd_last_payload_ts = packet.time
            if flow.udps.bwd_helper_count == 4:
                flow.udps.bwd_bulk_state_count += 1
                flow.udps.bwd_bulk_packet_count += 4
                flow.udps.bwd_bulk_size_total += flow.udps.bwd_helper_bytes
                flow.udps.bwd_bulk_duration_ms += (packet.time - flow.udps.bwd_helper_start_ts)
            elif flow.udps.bwd_helper_count > 4:
                flow.udps.bwd_bulk_packet_count += 1
                flow.udps.bwd_bulk_size_total += packet.payload_size
                flow.udps.bwd_bulk_duration_ms += (packet.time - prev_ts)

    def on_expire(self, flow):
        if flow.udps.fwd_bulk_state_count > 0:
            flow.udps.fwd_byts_b_avg = flow.udps.fwd_bulk_size_total / flow.udps.fwd_bulk_state_count
            flow.udps.fwd_pkts_b_avg = flow.udps.fwd_bulk_packet_count / flow.udps.fwd_bulk_state_count
            fwd_dur_sec = flow.udps.fwd_bulk_duration_ms / 1000.0
            if fwd_dur_sec > 0:
                flow.udps.fwd_blk_rate_avg = flow.udps.fwd_bulk_size_total / fwd_dur_sec
        if flow.udps.bwd_bulk_state_count > 0:
            flow.udps.bwd_byts_b_avg = flow.udps.bwd_bulk_size_total / flow.udps.bwd_bulk_state_count
            flow.udps.bwd_pkts_b_avg = flow.udps.bwd_bulk_packet_count / flow.udps.bwd_bulk_state_count
            bwd_dur_sec = flow.udps.bwd_bulk_duration_ms / 1000.0
            if bwd_dur_sec > 0:
                flow.udps.bwd_blk_rate_avg = flow.udps.bwd_bulk_size_total / bwd_dur_sec


class HeaderLenPlugin(NFPlugin):
    def on_init(self, packet, flow):
        if packet.ip_version not in [4, 6]:
            flow.udps.fwd_header_len = 0
            flow.udps.bwd_header_len = 0
            return
        header_bytes = packet.ip_size - packet.payload_size
        if packet.direction == 0:
            flow.udps.fwd_header_len = header_bytes
            flow.udps.bwd_header_len = 0
        else:
            flow.udps.fwd_header_len = 0
            flow.udps.bwd_header_len = header_bytes

    def on_update(self, packet, flow):
        if packet.ip_version not in [4, 6]:
            return
        header_bytes = packet.ip_size - packet.payload_size
        if packet.direction == 0:
            flow.udps.fwd_header_len += header_bytes
        else:
            flow.udps.bwd_header_len += header_bytes


class InitWindowPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.init_fwd_win = -1
        flow.udps.init_bwd_win = -1
        if packet.protocol == 6:
            is_syn     = packet.syn and not packet.ack
            is_syn_ack = packet.syn and packet.ack
            if is_syn:
                flow.udps.init_fwd_win = self._extract_tcp_window(packet)
            elif is_syn_ack:
                flow.udps.init_bwd_win = self._extract_tcp_window(packet)

    def on_update(self, packet, flow):
        if packet.protocol != 6:
            return
        is_syn     = packet.syn and not packet.ack
        is_syn_ack = packet.syn and packet.ack
        if is_syn and flow.udps.init_fwd_win == -1:
            flow.udps.init_fwd_win = self._extract_tcp_window(packet)
        elif is_syn_ack and flow.udps.init_bwd_win == -1:
            flow.udps.init_bwd_win = self._extract_tcp_window(packet)

    def _extract_tcp_window(self, packet):
        try:
            raw_bytes = packet.ip_packet
            ip_hl = (raw_bytes[0] & 0x0F) * 4 if packet.ip_version == 4 else 40
            return (raw_bytes[ip_hl + 14] << 8) | raw_bytes[ip_hl + 15]
        except IndexError:
            return -1


class ExtraFeaturesPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.fwd_act_data_pkts = 0
        flow.udps.fwd_seg_size_min  = -1
        self._update_features(packet, flow)

    def on_update(self, packet, flow):
        self._update_features(packet, flow)

    def _update_features(self, packet, flow):
        if packet.ip_version not in [4, 6]:
            return
        if packet.direction == 0:
            if packet.payload_size > 0:
                flow.udps.fwd_act_data_pkts += 1
            header_length = packet.ip_size - packet.payload_size
            if flow.udps.fwd_seg_size_min == -1 or header_length < flow.udps.fwd_seg_size_min:
                flow.udps.fwd_seg_size_min = header_length


class ActiveIdlePlugin(NFPlugin):
    def __init__(self, idle_threshold_ms=5000, **kwargs):
        super().__init__(**kwargs)
        self.idle_threshold_ms = idle_threshold_ms

    def on_init(self, packet, flow):
        flow.udps._start_active_time = packet.time
        flow.udps._end_active_time   = packet.time
        flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2 = 0, 0.0, 0.0
        flow.udps._act_max, flow.udps._act_min = 0.0, -1.0
        flow.udps._idle_n, flow.udps._idle_mean, flow.udps._idle_M2 = 0, 0.0, 0.0
        flow.udps._idle_max, flow.udps._idle_min = 0.0, -1.0
        flow.udps.active_mean = flow.udps.active_std = flow.udps.active_max = flow.udps.active_min = 0.0
        flow.udps.idle_mean   = flow.udps.idle_std   = flow.udps.idle_max   = flow.udps.idle_min   = 0.0

    @staticmethod
    def _welford(n, mean, M2, new_val):
        n  += 1
        delta = new_val - mean
        mean += delta / n
        M2   += delta * (new_val - mean)
        return n, mean, M2

    def on_update(self, packet, flow):
        current_time = packet.time
        gap = current_time - flow.udps._end_active_time
        if gap > self.idle_threshold_ms:
            active_dur = flow.udps._end_active_time - flow.udps._start_active_time
            if active_dur > 0:
                n, m, M2 = self._welford(flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2, active_dur)
                flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2 = n, m, M2
                if active_dur > flow.udps._act_max: flow.udps._act_max = active_dur
                if flow.udps._act_min == -1.0 or active_dur < flow.udps._act_min: flow.udps._act_min = active_dur
            n, m, M2 = self._welford(flow.udps._idle_n, flow.udps._idle_mean, flow.udps._idle_M2, gap)
            flow.udps._idle_n, flow.udps._idle_mean, flow.udps._idle_M2 = n, m, M2
            if gap > flow.udps._idle_max: flow.udps._idle_max = gap
            if flow.udps._idle_min == -1.0 or gap < flow.udps._idle_min: flow.udps._idle_min = gap
            flow.udps._start_active_time = current_time
            flow.udps._end_active_time   = current_time
        else:
            flow.udps._end_active_time = current_time

    def on_expire(self, flow):
        active_dur = flow.udps._end_active_time - flow.udps._start_active_time
        if active_dur > 0:
            n, m, M2 = self._welford(flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2, active_dur)
            flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2 = n, m, M2
            if active_dur > flow.udps._act_max: flow.udps._act_max = active_dur
            if flow.udps._act_min == -1.0 or active_dur < flow.udps._act_min: flow.udps._act_min = active_dur

        n = flow.udps._act_n
        flow.udps.active_mean = flow.udps._act_mean if n > 0 else 0.0
        flow.udps.active_std  = math.sqrt(flow.udps._act_M2 / (n - 1)) if n > 1 else 0.0
        flow.udps.active_max  = flow.udps._act_max if n > 0 else 0.0
        flow.udps.active_min  = flow.udps._act_min if flow.udps._act_min != -1.0 else 0.0

        n = flow.udps._idle_n
        flow.udps.idle_mean = flow.udps._idle_mean if n > 0 else 0.0
        flow.udps.idle_std  = math.sqrt(flow.udps._idle_M2 / (n - 1)) if n > 1 else 0.0
        flow.udps.idle_max  = flow.udps._idle_max if n > 0 else 0.0
        flow.udps.idle_min  = flow.udps._idle_min if flow.udps._idle_min != -1.0 else 0.0
        
class FlowEntropyPlugin(NFPlugin):
    def on_init(self, packet, flow):
        # Internal counters for byte frequencies (0-255)
        flow.udps._fwd_byte_counts = [0] * 256
        flow.udps._bwd_byte_counts = [0] * 256
        
        flow.udps._fwd_total_bytes = 0
        flow.udps._bwd_total_bytes = 0
        
        # Final exported features
        flow.udps.fwd_payload_entropy = 0.0
        flow.udps.bwd_payload_entropy = 0.0
        flow.udps.flow_payload_entropy = 0.0
        
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if packet.payload_size > 0:
            try:
                # TRICK: The payload is the last 'payload_size' bytes of the raw IP packet
                payload_bytes = packet.ip_packet[-packet.payload_size:]
                
                if packet.direction == 0:  # Forward Packet
                    for byte in payload_bytes:
                        flow.udps._fwd_byte_counts[byte] += 1
                    flow.udps._fwd_total_bytes += packet.payload_size
                    
                else:  # Backward Packet
                    for byte in payload_bytes:
                        flow.udps._bwd_byte_counts[byte] += 1
                    flow.udps._bwd_total_bytes += packet.payload_size
            except Exception:
                # Fail gracefully if packet.ip_packet is malformed
                pass

    def _calculate_shannon_entropy(self, counts, total):
        if total == 0:
            return 0.0
            
        entropy = 0.0
        for count in counts:
            if count > 0:
                probability = count / total
                entropy -= probability * math.log2(probability)
                
        return entropy

    def on_expire(self, flow):
        # Calculate Forward Entropy
        flow.udps.fwd_payload_entropy = self._calculate_shannon_entropy(
            flow.udps._fwd_byte_counts, 
            flow.udps._fwd_total_bytes
        )
        
        # Calculate Backward Entropy
        flow.udps.bwd_payload_entropy = self._calculate_shannon_entropy(
            flow.udps._bwd_byte_counts, 
            flow.udps._bwd_total_bytes
        )
        
        # Calculate Overall Flow Entropy
        combined_counts = [
            f + b for f, b in zip(flow.udps._fwd_byte_counts, flow.udps._bwd_byte_counts)
        ]
        total_bytes = flow.udps._fwd_total_bytes + flow.udps._bwd_total_bytes
        
        flow.udps.flow_payload_entropy = self._calculate_shannon_entropy(
            combined_counts, 
            total_bytes
        )

class QueryLengthPlugin(NFPlugin):
   
    def on_init(self, packet, flow):
        # Initialize default values
        flow.udps.initial_query_payload_len = 0
        flow.udps.l7_query_length = 0
        
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        # Capture the length of the VERY FIRST forward packet that contains a payload.
        # This acts as the raw byte size of the initial query.
        if packet.direction == 0 and packet.payload_size > 0:
            if flow.udps.initial_query_payload_len == 0:
                flow.udps.initial_query_payload_len = packet.payload_size

    def on_expire(self, flow):
        # nfstream natively parses L7 application data (via nDPI).
        # If the flow is DNS, TLS, or HTTP, 'requested_server_name' 
        # contains the domain being queried (e.g., 'www.google.com').
        if flow.requested_server_name:
            flow.udps.l7_query_length = len(flow.requested_server_name)

