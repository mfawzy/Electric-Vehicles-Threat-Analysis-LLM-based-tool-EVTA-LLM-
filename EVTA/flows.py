from __future__ import annotations

import struct
from typing import Dict, List, Tuple

import dpkt

from .constants import BURST_GAP_SECONDS, DNS_PORT, TLS_PORTS
from .models import CanonicalFlowKey, DirectionState, DNSStats, Endpoint, ExportMetadata, FlowEmission, PacketInfo, PartialExportConfig, TLSStats
from .utils import average_qname_entropy, average_qname_len, basic_stats, burst_features, diffs, finalize_row, safe_div


class FlowStats:
    def __init__(
        self,
        flow_id: str,
        protocol: int,
        initiator: Endpoint,
        responder: Endpoint,
        start_ts: float,
        last_ts: float,
        partial_config: PartialExportConfig | None = None,
    ):
        self.flow_id = flow_id
        self.protocol = protocol
        self.initiator = initiator
        self.responder = responder
        self.start_ts = start_ts
        self.last_ts = last_ts
        self.partial_config = partial_config or PartialExportConfig()
        self.fwd = DirectionState()
        self.bwd = DirectionState()
        self.all_times: List[float] = []
        self.ttls: List[int] = []
        self.tcp_windows: List[int] = []
        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.fin_count = 0
        self.psh_count = 0
        self.seen_syn_fwd = False
        self.seen_synack_bwd = False
        self.seen_ack_after_synack_fwd = False
        self.tcp_retransmissions = 0
        self.dup_ack_count = 0
        self.out_of_order_count = 0
        self.zero_window_count = 0
        self.tls = TLSStats()
        self.dns = DNSStats()
        self.emitted_packet_steps: set[int] = set()
        self.emitted_time_steps: set[float] = set()

    def update(self, pkt: PacketInfo) -> None:
        self.last_ts = pkt.ts
        self.all_times.append(pkt.ts)
        self.ttls.append(pkt.ttl)
        if pkt.tcp_window > 0:
            self.tcp_windows.append(pkt.tcp_window)
        elif pkt.protocol == 6:
            self.zero_window_count += 1
            self.tcp_windows.append(0)

        is_fwd = pkt.src_ip == self.initiator.ip and pkt.src_port == self.initiator.port
        state = self.fwd if is_fwd else self.bwd

        state.packet_times.append(pkt.ts)
        state.packet_sizes.append(pkt.ip_total_len)
        state.bytes_total += pkt.ip_total_len
        state.header_bytes += pkt.header_len
        state.payload_bytes += pkt.payload_len

        if pkt.protocol == 6:
            self._update_tcp_flags(pkt, is_fwd)
            self._update_tcp_reliability(state, pkt)
            self._update_tls(pkt)

        if self._is_dns_packet(pkt):
            self._update_dns(pkt)

    def _update_tcp_flags(self, pkt: PacketInfo, is_fwd: bool) -> None:
        flags = pkt.tcp_flags
        if flags & dpkt.tcp.TH_SYN:
            self.syn_count += 1
        if flags & dpkt.tcp.TH_ACK:
            self.ack_count += 1
        if flags & dpkt.tcp.TH_RST:
            self.rst_count += 1
        if flags & dpkt.tcp.TH_FIN:
            self.fin_count += 1
        if flags & dpkt.tcp.TH_PUSH:
            self.psh_count += 1

        syn = bool(flags & dpkt.tcp.TH_SYN)
        ack = bool(flags & dpkt.tcp.TH_ACK)
        if is_fwd and syn and not ack:
            self.seen_syn_fwd = True
        elif (not is_fwd) and syn and ack and self.seen_syn_fwd:
            self.seen_synack_bwd = True
        elif is_fwd and ack and self.seen_syn_fwd and self.seen_synack_bwd:
            self.seen_ack_after_synack_fwd = True

    def _update_tcp_reliability(self, state: DirectionState, pkt: PacketInfo) -> None:
        if pkt.tcp_seq is None or pkt.tcp_ackno is None:
            return

        payload_span = max(pkt.payload_len, 1 if pkt.tcp_flags & (dpkt.tcp.TH_SYN | dpkt.tcp.TH_FIN) else 0)
        segment = (pkt.tcp_seq, payload_span)
        seq_end = pkt.tcp_seq + payload_span

        if segment in state.seq_seen:
            self.tcp_retransmissions += 1
        else:
            state.seq_seen.add(segment)

        if pkt.payload_len > 0 and pkt.tcp_seq < state.max_seq_end:
            self.out_of_order_count += 1
        state.max_seq_end = max(state.max_seq_end, seq_end)

        if (pkt.tcp_flags & dpkt.tcp.TH_ACK) and pkt.payload_len == 0:
            if state.last_ack_number == pkt.tcp_ackno:
                state.ack_repeat_count += 1
                if state.ack_repeat_count >= 1:
                    self.dup_ack_count += 1
            else:
                state.last_ack_number = pkt.tcp_ackno
                state.ack_repeat_count = 0

    def _is_dns_packet(self, pkt: PacketInfo) -> bool:
        return pkt.src_port == DNS_PORT or pkt.dst_port == DNS_PORT

    def _update_dns(self, pkt: PacketInfo) -> None:
        payload = pkt.raw_payload
        if pkt.protocol == 17:
            dns_payload = payload
        elif pkt.protocol == 6:
            if len(payload) < 2:
                return
            tcp_length = struct.unpack("!H", payload[:2])[0]
            if tcp_length == 0 or len(payload) < tcp_length + 2:
                return
            dns_payload = payload[2 : 2 + tcp_length]
        else:
            return

        try:
            dns = dpkt.dns.DNS(dns_payload)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return

        if dns.qr == dpkt.dns.DNS_Q:
            self.dns.query_count += 1
            for question in dns.qd:
                if getattr(question, "name", None):
                    self.dns.qnames.add(question.name.lower())
        else:
            self.dns.response_count += 1
            if dns.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN:
                self.dns.nxdomain_responses += 1
            for answer in dns.an:
                if hasattr(answer, "ttl"):
                    self.dns.answer_ttls.append(answer.ttl)

    def _update_tls(self, pkt: PacketInfo) -> None:
        from .tls_parser import parse_tls_records

        if not (pkt.src_port in TLS_PORTS or pkt.dst_port in TLS_PORTS):
            return
        for event in parse_tls_records(pkt.raw_payload):
            self.tls.record_count += 1
            if event["type"] == "client_hello":
                self.tls.client_hello_seen = 1
                if self.tls.first_client_hello_ts is None:
                    self.tls.first_client_hello_ts = pkt.ts
                if event.get("version"):
                    self.tls.version = int(event["version"])
                if event.get("cipher_suites_count"):
                    self.tls.cipher_suites_count = int(event["cipher_suites_count"])
                if event.get("extensions_count") is not None:
                    self.tls.extensions_count = int(event["extensions_count"])
                if event.get("sni"):
                    self.tls.sni_present = 1
                    self.tls.sni_len = len(str(event["sni"]))
            elif event["type"] == "server_hello":
                self.tls.server_hello_seen = 1
                if self.tls.first_server_hello_ts is None:
                    self.tls.first_server_hello_ts = pkt.ts
                if not self.tls.version and event.get("version"):
                    self.tls.version = int(event["version"])

    def tcp_handshake_completed(self) -> int:
        return int(self.seen_syn_fwd and self.seen_synack_bwd and self.seen_ack_after_synack_fwd)

    def packet_count(self) -> int:
        return len(self.fwd.packet_sizes) + len(self.bwd.packet_sizes)

    def duration(self) -> float:
        return max(self.last_ts - self.start_ts, 1e-9)

    def snapshot_rows(self) -> List[Dict[str, object]]:
        if not self.partial_config.enabled:
            return []

        rows: List[Dict[str, object]] = []
        packets_seen = self.packet_count()
        duration = self.last_ts - self.start_ts

        for step in self.partial_config.packet_steps:
            if packets_seen >= step and step not in self.emitted_packet_steps:
                self.emitted_packet_steps.add(step)
                rows.append(
                    self.to_row(
                        ExportMetadata(
                            export_reason="partial_packet",
                            snapshot_kind=f"packet_{step}",
                            packets_seen_at_export=packets_seen,
                            is_partial_snapshot=1,
                        )
                    )
                )

        for step in self.partial_config.time_steps:
            if duration >= step and step not in self.emitted_time_steps:
                self.emitted_time_steps.add(step)
                step_label = str(step).replace(".", "_")
                rows.append(
                    self.to_row(
                        ExportMetadata(
                            export_reason="partial_time",
                            snapshot_kind=f"time_{step_label}s",
                            packets_seen_at_export=packets_seen,
                            is_partial_snapshot=1,
                        )
                    )
                )
        return rows

    def to_row(self, metadata: ExportMetadata | None = None) -> Dict[str, object]:
        metadata = metadata or ExportMetadata(
            export_reason="flow_end",
            snapshot_kind="final",
            packets_seen_at_export=self.packet_count(),
            is_partial_snapshot=0,
        )

        total_fwd_packets = len(self.fwd.packet_sizes)
        total_bwd_packets = len(self.bwd.packet_sizes)
        total_fwd_bytes = self.fwd.bytes_total
        total_bwd_bytes = self.bwd.bytes_total
        total_packets = total_fwd_packets + total_bwd_packets
        total_bytes = total_fwd_bytes + total_bwd_bytes
        duration = self.duration()

        flow_iats = diffs(self.all_times)
        fwd_iats = diffs(self.fwd.packet_times)
        bwd_iats = diffs(self.bwd.packet_times)
        fwd_pkt = basic_stats(self.fwd.packet_sizes)
        bwd_pkt = basic_stats(self.bwd.packet_sizes)
        flow_iat_stats = basic_stats(flow_iats)
        active_mean, idle_mean, burst_count, max_silence_gap = burst_features(self.all_times, BURST_GAP_SECONDS)

        row = {
            "flow_id": self.flow_id,
            "src_ip": self.initiator.ip,
            "src_port": self.initiator.port,
            "dst_ip": self.responder.ip,
            "dst_port": self.responder.port,
            "protocol": self.protocol,
            "flow_start_ts": f"{self.start_ts:.6f}",
            "flow_end_ts": f"{self.last_ts:.6f}",
            "total_fwd_packets": total_fwd_packets,
            "total_bwd_packets": total_bwd_packets,
            "total_fwd_bytes": total_fwd_bytes,
            "total_bwd_bytes": total_bwd_bytes,
            "down_up_ratio": safe_div(total_bwd_packets, total_fwd_packets),
            "byte_asymmetry_ratio": safe_div(total_bwd_bytes, total_fwd_bytes),
            "flow_duration": duration,
            "flow_packets_per_sec": safe_div(total_packets, duration),
            "flow_bytes_per_sec": safe_div(total_bytes, duration),
            "flow_iat_mean": flow_iat_stats["mean"],
            "flow_iat_std": flow_iat_stats["std"],
            "flow_iat_max": flow_iat_stats["max"],
            "fwd_iat_mean": basic_stats(fwd_iats)["mean"],
            "bwd_iat_mean": basic_stats(bwd_iats)["mean"],
            "fwd_pkt_len_mean": fwd_pkt["mean"],
            "fwd_pkt_len_std": fwd_pkt["std"],
            "fwd_pkt_len_max": fwd_pkt["max"],
            "bwd_pkt_len_mean": bwd_pkt["mean"],
            "bwd_pkt_len_std": bwd_pkt["std"],
            "bwd_pkt_len_max": bwd_pkt["max"],
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "rst_count": self.rst_count,
            "fin_count": self.fin_count,
            "psh_count": self.psh_count,
            "tcp_handshake_completed": self.tcp_handshake_completed(),
            "active_mean": active_mean,
            "idle_mean": idle_mean,
            "burst_count": burst_count,
            "max_silence_gap": max_silence_gap,
            "ttl_mean": basic_stats(self.ttls)["mean"],
            "window_size_mean": basic_stats(self.tcp_windows)["mean"],
            "tcp_retransmissions": self.tcp_retransmissions,
            "dup_ack_count": self.dup_ack_count,
            "out_of_order_count": self.out_of_order_count,
            "zero_window_count": self.zero_window_count,
            "tls_version": self.tls.version,
            "tls_sni_present": self.tls.sni_present,
            "tls_sni_len": self.tls.sni_len,
            "tls_cipher_suites_count": self.tls.cipher_suites_count,
            "tls_extensions_count": self.tls.extensions_count,
            "tls_handshake_duration": self.tls.handshake_duration(),
            "dns_query_count": self.dns.query_count,
            "dns_unique_qnames": len(self.dns.qnames),
            "dns_nxdomain_ratio": safe_div(self.dns.nxdomain_responses, self.dns.response_count),
            "dns_qname_avg_len": average_qname_len(self.dns.qnames),
            "dns_qname_entropy": average_qname_entropy(self.dns.qnames),
            "dns_ttl_mean": basic_stats(self.dns.answer_ttls)["mean"],
            "unique_dst_count_1m": 0,
            "new_port_count_1m": 0,
            "failed_connections_1m": 0,
            "scan_rate_1m": 0.0,
            "tls_client_hello_seen": self.tls.client_hello_seen,
            "tls_server_hello_seen": self.tls.server_hello_seen,
            "tls_record_count": self.tls.record_count,
            "unique_peer_ips_1m": 0,
            "service_diversity_1m": 0,
            "fan_out_ratio_1m": 0.0,
            "failed_ratio_1m": 0.0,
            "export_reason": metadata.export_reason,
            "snapshot_kind": metadata.snapshot_kind,
            "packets_seen_at_export": metadata.packets_seen_at_export,
            "is_partial_snapshot": metadata.is_partial_snapshot,
            "feature_completeness_score": 0.0,
            "capture_confidence_score": 0.0,
            "stability_score": 0.0,
            "timeliness_score": 0.0,
            "robustness_score": 0.0,
            "live_readiness_score": 0.0,
            "heuristic_label": "",
            "heuristic_score": 0.0,
            "heuristic_reasons": "",
            "flow_summary": "",
        }
        return finalize_row(row)


def canonicalize_flow(pkt: PacketInfo) -> Tuple[CanonicalFlowKey, Endpoint, Endpoint]:
    src = Endpoint(pkt.src_ip, pkt.src_port)
    dst = Endpoint(pkt.dst_ip, pkt.dst_port)
    if (src.ip, src.port) <= (dst.ip, dst.port):
        key = CanonicalFlowKey(src, dst, pkt.protocol)
    else:
        key = CanonicalFlowKey(dst, src, pkt.protocol)
    return key, src, dst


class FlowManager:
    def __init__(
        self,
        tcp_timeout: float,
        udp_timeout: float,
        other_timeout: float,
        partial_config: PartialExportConfig | None = None,
    ):
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.other_timeout = other_timeout
        self.partial_config = partial_config or PartialExportConfig()
        self.active: Dict[CanonicalFlowKey, FlowStats] = {}
        self.counter = 0

    def update(self, pkt: PacketInfo) -> FlowEmission:
        emission = FlowEmission()
        expire_emission = self.expire(pkt.ts)
        emission.rows.extend(expire_emission.rows)
        emission.completed += expire_emission.completed

        key, initiator, responder = canonicalize_flow(pkt)
        flow = self.active.get(key)
        if flow is None:
            self.counter += 1
            flow = FlowStats(
                flow_id=f"flow_{self.counter}",
                protocol=pkt.protocol,
                initiator=initiator,
                responder=responder,
                start_ts=pkt.ts,
                last_ts=pkt.ts,
                partial_config=self.partial_config,
            )
            self.active[key] = flow
        flow.update(pkt)
        emission.rows.extend(flow.snapshot_rows())

        if pkt.protocol == 6 and (pkt.tcp_flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST)):
            closed = self.active.pop(key)
            emission.rows.append(
                closed.to_row(
                    ExportMetadata(
                        export_reason="flow_end",
                        snapshot_kind="final",
                        packets_seen_at_export=closed.packet_count(),
                        is_partial_snapshot=0,
                    )
                )
            )
            emission.completed += 1
        return emission

    def expire(self, current_ts: float) -> FlowEmission:
        emission = FlowEmission()
        for key, flow in list(self.active.items()):
            timeout = self._timeout_for(flow.protocol)
            if current_ts - flow.last_ts > timeout:
                expired = self.active.pop(key)
                emission.rows.append(
                    expired.to_row(
                        ExportMetadata(
                            export_reason="timeout",
                            snapshot_kind="final",
                            packets_seen_at_export=expired.packet_count(),
                            is_partial_snapshot=0,
                        )
                    )
                )
                emission.completed += 1
        return emission

    def flush(self) -> FlowEmission:
        emission = FlowEmission()
        for flow in list(self.active.values()):
            emission.rows.append(
                flow.to_row(
                    ExportMetadata(
                        export_reason="flush",
                        snapshot_kind="final",
                        packets_seen_at_export=flow.packet_count(),
                        is_partial_snapshot=0,
                    )
                )
            )
            emission.completed += 1
        self.active.clear()
        return emission

    def _timeout_for(self, protocol: int) -> float:
        if protocol == 6:
            return self.tcp_timeout
        if protocol == 17:
            return self.udp_timeout
        return self.other_timeout
