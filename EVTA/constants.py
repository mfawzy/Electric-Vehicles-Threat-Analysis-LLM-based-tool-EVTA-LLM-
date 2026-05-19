DEFAULT_TCP_TIMEOUT = 120.0
DEFAULT_UDP_TIMEOUT = 60.0
DEFAULT_OTHER_TIMEOUT = 30.0
DEFAULT_HOST_WINDOW_SECONDS = 60.0
DEFAULT_POLL_INTERVAL = 1.0
DEFAULT_PARTIAL_PACKET_STEPS = (1, 3, 5, 10)
DEFAULT_PARTIAL_TIME_STEPS = (1.0, 5.0, 10.0)
DEFAULT_COMPARE_TOLERANCE = 1e-6
BURST_GAP_SECONDS = 1.0
DEFAULT_LLM_MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"
DEFAULT_LLM_MAX_NEW_TOKENS = 96
DNS_PORT = 53
TLS_PORTS = {443, 8443, 9443}

IDENTITY_COLUMNS = [
    "flow_id",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "flow_start_ts",
    "flow_end_ts",
]

MANDATORY_FEATURE_COLUMNS = [
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "down_up_ratio",
    "byte_asymmetry_ratio",
    "flow_duration",
    "flow_packets_per_sec",
    "flow_bytes_per_sec",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    "fwd_pkt_len_max",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_std",
    "bwd_pkt_len_max",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "psh_count",
    "tcp_handshake_completed",
    "active_mean",
    "idle_mean",
    "burst_count",
    "max_silence_gap",
    "ttl_mean",
    "window_size_mean",
]

BENEFICIAL_FEATURE_COLUMNS = [
    "tcp_retransmissions",
    "dup_ack_count",
    "out_of_order_count",
    "zero_window_count",
    "tls_version",
    "tls_sni_present",
    "tls_sni_len",
    "tls_cipher_suites_count",
    "tls_extensions_count",
    "tls_handshake_duration",
    "dns_query_count",
    "dns_unique_qnames",
    "dns_nxdomain_ratio",
    "dns_qname_avg_len",
    "dns_qname_entropy",
    "dns_ttl_mean",
    "unique_dst_count_1m",
    "new_port_count_1m",
    "failed_connections_1m",
    "scan_rate_1m",
]

ADVANCED_FEATURE_COLUMNS = [
    "tls_client_hello_seen",
    "tls_server_hello_seen",
    "tls_record_count",
    "unique_peer_ips_1m",
    "service_diversity_1m",
    "fan_out_ratio_1m",
    "failed_ratio_1m",
    "export_reason",
    "snapshot_kind",
    "packets_seen_at_export",
    "is_partial_snapshot",
    "feature_completeness_score",
    "capture_confidence_score",
    "stability_score",
    "timeliness_score",
    "robustness_score",
    "live_readiness_score",
    "heuristic_label",
    "heuristic_score",
    "heuristic_reasons",
    "flow_summary",
    "llm_context",
]

LABEL_COLUMNS = [
    "binary_classification",
    "multiclass_classification",
]

ALL_COLUMNS = IDENTITY_COLUMNS + MANDATORY_FEATURE_COLUMNS + BENEFICIAL_FEATURE_COLUMNS + ADVANCED_FEATURE_COLUMNS + LABEL_COLUMNS

PROFILE_COLUMNS = {
    "full": ALL_COLUMNS,
    "research": ALL_COLUMNS,
    "stable-core": IDENTITY_COLUMNS
    + MANDATORY_FEATURE_COLUMNS
    + [
        "unique_dst_count_1m",
        "new_port_count_1m",
        "failed_connections_1m",
        "scan_rate_1m",
        "unique_peer_ips_1m",
        "service_diversity_1m",
        "fan_out_ratio_1m",
        "failed_ratio_1m",
        "export_reason",
        "snapshot_kind",
        "packets_seen_at_export",
        "is_partial_snapshot",
        "feature_completeness_score",
        "capture_confidence_score",
        "stability_score",
        "timeliness_score",
        "robustness_score",
        "live_readiness_score",
        "heuristic_label",
        "heuristic_score",
        "heuristic_reasons",
        "flow_summary",
        "llm_context",
    ]
    + LABEL_COLUMNS,
    "live-safe": IDENTITY_COLUMNS
    + MANDATORY_FEATURE_COLUMNS
    + [
        "tcp_retransmissions",
        "dup_ack_count",
        "out_of_order_count",
        "zero_window_count",
        "dns_query_count",
        "dns_unique_qnames",
        "dns_nxdomain_ratio",
        "dns_qname_avg_len",
        "dns_qname_entropy",
        "unique_dst_count_1m",
        "new_port_count_1m",
        "failed_connections_1m",
        "scan_rate_1m",
        "unique_peer_ips_1m",
        "service_diversity_1m",
        "fan_out_ratio_1m",
        "failed_ratio_1m",
        "export_reason",
        "snapshot_kind",
        "packets_seen_at_export",
        "is_partial_snapshot",
        "feature_completeness_score",
        "capture_confidence_score",
        "stability_score",
        "timeliness_score",
        "robustness_score",
        "live_readiness_score",
        "heuristic_label",
        "heuristic_score",
        "heuristic_reasons",
        "flow_summary",
        "llm_context",
    ]
    + LABEL_COLUMNS,
}

FEATURE_SCORE_WEIGHTS = {
    "stable_core": (0.95, 0.95, 0.9, 0.95),
    "transport_extended": (0.85, 0.85, 0.85, 0.85),
    "tls_metadata": (0.65, 0.6, 0.75, 0.7),
    "dns_metadata": (0.75, 0.7, 0.8, 0.75),
    "host_window": (0.85, 0.85, 0.8, 0.85),
    "text_outputs": (0.8, 0.8, 0.8, 0.8),
}

FEATURE_GROUPS = {
    "stable_core": MANDATORY_FEATURE_COLUMNS,
    "transport_extended": [
        "tcp_retransmissions",
        "dup_ack_count",
        "out_of_order_count",
        "zero_window_count",
    ],
    "tls_metadata": [
        "tls_version",
        "tls_sni_present",
        "tls_sni_len",
        "tls_cipher_suites_count",
        "tls_extensions_count",
        "tls_handshake_duration",
        "tls_client_hello_seen",
        "tls_server_hello_seen",
        "tls_record_count",
    ],
    "dns_metadata": [
        "dns_query_count",
        "dns_unique_qnames",
        "dns_nxdomain_ratio",
        "dns_qname_avg_len",
        "dns_qname_entropy",
        "dns_ttl_mean",
    ],
    "host_window": [
        "unique_dst_count_1m",
        "new_port_count_1m",
        "failed_connections_1m",
        "scan_rate_1m",
        "unique_peer_ips_1m",
        "service_diversity_1m",
        "fan_out_ratio_1m",
        "failed_ratio_1m",
    ],
    "text_outputs": [
        "heuristic_label",
        "heuristic_score",
        "heuristic_reasons",
        "flow_summary",
        "llm_context",
        "binary_classification",
        "multiclass_classification",
    ],
}

CONSISTENCY_COMPARE_COLUMNS = [
    "protocol",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "flow_duration",
    "flow_packets_per_sec",
    "flow_bytes_per_sec",
    "flow_iat_mean",
    "flow_iat_std",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "tcp_handshake_completed",
    "ttl_mean",
    "window_size_mean",
    "tcp_retransmissions",
    "dup_ack_count",
    "out_of_order_count",
    "zero_window_count",
    "dns_query_count",
    "dns_unique_qnames",
    "dns_nxdomain_ratio",
    "tls_version",
    "tls_sni_present",
    "tls_cipher_suites_count",
    "tls_extensions_count",
    "tls_client_hello_seen",
    "tls_server_hello_seen",
    "tls_record_count",
]
