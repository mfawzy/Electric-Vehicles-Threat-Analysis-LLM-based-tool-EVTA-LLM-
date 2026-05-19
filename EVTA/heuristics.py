from __future__ import annotations

from typing import Dict, List


def apply_heuristics(row: Dict[str, object]) -> Dict[str, object]:
    reasons: List[str] = []
    score = 0.0
    label = "benign_like"

    scan_rate = float(row.get("scan_rate_1m", 0.0))
    unique_dst = int(row.get("unique_dst_count_1m", 0))
    unique_peers = int(row.get("unique_peer_ips_1m", 0))
    failed_connections = int(row.get("failed_connections_1m", 0))
    failed_ratio = float(row.get("failed_ratio_1m", 0.0))
    dns_entropy = float(row.get("dns_qname_entropy", 0.0))
    dns_queries = int(row.get("dns_query_count", 0))
    dns_unique = int(row.get("dns_unique_qnames", 0))
    nxdomain_ratio = float(row.get("dns_nxdomain_ratio", 0.0))
    handshake = int(row.get("tcp_handshake_completed", 0))
    burst_count = int(row.get("burst_count", 0))
    idle_mean = float(row.get("idle_mean", 0.0))
    retrans = int(row.get("tcp_retransmissions", 0))
    dup_acks = int(row.get("dup_ack_count", 0))
    out_of_order = int(row.get("out_of_order_count", 0))
    tls_sni_present = int(row.get("tls_sni_present", 0))
    tls_client_hello = int(row.get("tls_client_hello_seen", 0))

    if unique_dst >= 10 or unique_peers >= 10 or scan_rate >= 0.3:
        label = "scan_suspected"
        score += 0.35
        reasons.append("High short-window destination diversity")

    if failed_connections >= 8 or (failed_ratio >= 0.6 and (unique_dst >= 3 or unique_peers >= 3 or failed_connections >= 4)):
        if label == "benign_like":
            label = "bruteforce_or_failed_connection_burst"
        score += 0.25
        reasons.append("Repeated failed or incomplete connections")

    if dns_queries >= 8 and dns_unique >= 6 and (dns_entropy >= 3.5 or nxdomain_ratio >= 0.5):
        label = "dns_abuse_or_dga_suspected"
        score += 0.3
        reasons.append("DNS behavior shows high entropy or elevated NXDOMAIN ratio")

    if burst_count >= 3 and idle_mean > 0.5 and scan_rate < 0.1:
        if label == "benign_like":
            label = "beaconing_like"
        score += 0.2
        reasons.append("Periodic burst and idle pattern resembles beaconing")

    if retrans + dup_acks + out_of_order >= 5:
        if label == "benign_like":
            label = "transport_instability"
        score += 0.15
        reasons.append("Transport reliability anomalies are elevated")

    if tls_client_hello == 1 and tls_sni_present == 0:
        score += 0.1
        reasons.append("TLS client hello observed without SNI")

    if handshake == 0 and int(row.get("protocol", 0)) == 6:
        score += 0.05
        reasons.append("TCP handshake did not complete")

    score = min(score, 1.0)
    row["heuristic_label"] = label
    row["heuristic_score"] = score
    row["heuristic_reasons"] = "; ".join(reasons) if reasons else "No strong heuristic trigger"
    row["flow_summary"] = build_flow_summary(row)
    return row


def build_flow_summary(row: Dict[str, object]) -> str:
    packets = int(row.get("total_fwd_packets", 0)) + int(row.get("total_bwd_packets", 0))
    duration = float(row.get("flow_duration", 0.0))
    readiness = float(row.get("live_readiness_score", 0.0))
    label = str(row.get("heuristic_label", "benign_like"))
    reasons = str(row.get("heuristic_reasons", "No strong heuristic trigger"))
    return (
        f"Flow {row.get('flow_id', '')} observed {packets} packets over {duration:.3f}s; "
        f"heuristic={label}; live_readiness={readiness:.2f}; rationale={reasons}."
    )
