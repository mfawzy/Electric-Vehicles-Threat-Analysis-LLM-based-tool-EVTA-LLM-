from __future__ import annotations

from typing import Dict

from .constants import FEATURE_GROUPS, FEATURE_SCORE_WEIGHTS
from .utils import is_populated


def _group_presence(row: Dict[str, object], columns: list[str]) -> float:
    if not columns:
        return 0.0
    populated = sum(1 for column in columns if is_populated(row.get(column, 0)))
    return populated / len(columns)


def feature_completeness_score(row: Dict[str, object]) -> float:
    feature_columns = []
    for columns in FEATURE_GROUPS.values():
        feature_columns.extend(columns)
    populated = sum(1 for column in feature_columns if is_populated(row.get(column, 0)))
    return populated / len(feature_columns) if feature_columns else 0.0


def capture_confidence_score(row: Dict[str, object]) -> float:
    score = 0.35
    if float(row.get("flow_duration", 0.0)) > 0:
        score += 0.15
    if int(row.get("total_fwd_packets", 0)) + int(row.get("total_bwd_packets", 0)) >= 2:
        score += 0.15
    if float(row.get("ttl_mean", 0.0)) > 0:
        score += 0.1
    if int(row.get("protocol", 0)) in (6, 17):
        score += 0.1
    if int(row.get("tcp_handshake_completed", 0)) == 1 or int(row.get("protocol", 0)) != 6:
        score += 0.15
    return min(score, 1.0)


def stability_score(row: Dict[str, object]) -> float:
    weighted = 0.0
    weight_total = 0.0
    for group_name, columns in FEATURE_GROUPS.items():
        availability, stability, _timeliness, _robustness = FEATURE_SCORE_WEIGHTS[group_name]
        presence = _group_presence(row, columns)
        weighted += presence * availability * stability
        weight_total += availability
    return weighted / weight_total if weight_total else 0.0


def timeliness_score(row: Dict[str, object]) -> float:
    packets_seen = int(row.get("packets_seen_at_export", 0))
    duration = float(row.get("flow_duration", 0.0))
    partial = int(row.get("is_partial_snapshot", 0)) == 1

    if partial:
        packet_term = 1.0 if packets_seen <= 5 else 0.8 if packets_seen <= 10 else 0.6
        time_term = 1.0 if duration <= 1.0 else 0.8 if duration <= 5.0 else 0.6
        return min((packet_term + time_term) / 2.0, 1.0)

    packet_term = 0.75 if packets_seen <= 10 else 0.6 if packets_seen <= 25 else 0.45
    time_term = 0.75 if duration <= 5.0 else 0.6 if duration <= 30.0 else 0.45
    return min((packet_term + time_term) / 2.0, 1.0)


def robustness_score(row: Dict[str, object]) -> float:
    stable_presence = _group_presence(row, FEATURE_GROUPS["stable_core"])
    host_presence = _group_presence(row, FEATURE_GROUPS["host_window"])
    protocol_penalty = 0.0
    if int(row.get("tls_client_hello_seen", 0)) == 0 and int(row.get("dns_query_count", 0)) == 0:
        protocol_penalty = 0.05
    return max(min((0.7 * stable_presence) + (0.25 * host_presence) + 0.1 - protocol_penalty, 1.0), 0.0)


def apply_readiness_scores(row: Dict[str, object]) -> Dict[str, object]:
    row["feature_completeness_score"] = feature_completeness_score(row)
    row["capture_confidence_score"] = capture_confidence_score(row)
    row["stability_score"] = stability_score(row)
    row["timeliness_score"] = timeliness_score(row)
    row["robustness_score"] = robustness_score(row)
    row["live_readiness_score"] = (
        float(row["capture_confidence_score"])
        + float(row["stability_score"])
        + float(row["timeliness_score"])
        + float(row["robustness_score"])
    ) / 4.0
    return row
