from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List

from .utils import finalize_row, safe_div


class HostWindowAggregator:
    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds

    def enrich(self, rows: List[Dict[str, object]]) -> None:
        rows.sort(key=lambda row: float(row["flow_start_ts"]))
        windows: Dict[str, Deque[Dict[str, object]]] = defaultdict(deque)

        for row in rows:
            host = str(row["src_ip"])
            current_ts = float(row["flow_start_ts"])
            dq = windows[host]
            self._evict(dq, current_ts)
            self._apply_metrics(row, dq)
            dq.append(dict(row))

        for index, row in enumerate(rows):
            rows[index] = finalize_row(row)

    def _evict(self, dq: Deque[Dict[str, object]], current_ts: float) -> None:
        while dq and current_ts - float(dq[0]["flow_start_ts"]) > self.window_seconds:
            dq.popleft()

    def _apply_metrics(self, row: Dict[str, object], dq: Deque[Dict[str, object]]) -> None:
        destinations = {f"{x['dst_ip']}:{x['dst_port']}" for x in dq}
        peer_ips = {str(x["dst_ip"]) for x in dq}
        ports = {x["dst_port"] for x in dq}
        failed = sum(int(x.get("tcp_handshake_completed", 0) == 0) for x in dq)

        row["unique_dst_count_1m"] = len(destinations | {f"{row['dst_ip']}:{row['dst_port']}"})
        row["new_port_count_1m"] = len(ports | {row["dst_port"]})
        row["failed_connections_1m"] = failed + int(row.get("tcp_handshake_completed", 0) == 0)
        row["scan_rate_1m"] = round(len(dq) / self.window_seconds, 6)
        row["unique_peer_ips_1m"] = len(peer_ips | {str(row["dst_ip"])})
        row["service_diversity_1m"] = len(ports | {row["dst_port"]})
        row["fan_out_ratio_1m"] = safe_div(row["unique_peer_ips_1m"], max(len(dq) + 1, 1))
        row["failed_ratio_1m"] = safe_div(row["failed_connections_1m"], max(len(dq) + 1, 1))


class OnlineHostWindowAggregator:
    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        self.windows: Dict[str, Deque[Dict[str, object]]] = defaultdict(deque)

    def enrich_row(self, row: Dict[str, object]) -> Dict[str, object]:
        host = str(row["src_ip"])
        current_ts = float(row["flow_start_ts"])
        dq = self.windows[host]

        while dq and current_ts - float(dq[0]["flow_start_ts"]) > self.window_seconds:
            dq.popleft()

        destinations = {f"{x['dst_ip']}:{x['dst_port']}" for x in dq}
        peer_ips = {str(x["dst_ip"]) for x in dq}
        ports = {x["dst_port"] for x in dq}
        failed = sum(int(x.get("tcp_handshake_completed", 0) == 0) for x in dq)

        row["unique_dst_count_1m"] = len(destinations | {f"{row['dst_ip']}:{row['dst_port']}"})
        row["new_port_count_1m"] = len(ports | {row["dst_port"]})
        row["failed_connections_1m"] = failed + int(row.get("tcp_handshake_completed", 0) == 0)
        row["scan_rate_1m"] = round(len(dq) / self.window_seconds, 6)
        row["unique_peer_ips_1m"] = len(peer_ips | {str(row["dst_ip"])})
        row["service_diversity_1m"] = len(ports | {row["dst_port"]})
        row["fan_out_ratio_1m"] = safe_div(row["unique_peer_ips_1m"], max(len(dq) + 1, 1))
        row["failed_ratio_1m"] = safe_div(row["failed_connections_1m"], max(len(dq) + 1, 1))

        finalized = finalize_row(row)
        dq.append(dict(finalized))
        return finalized
