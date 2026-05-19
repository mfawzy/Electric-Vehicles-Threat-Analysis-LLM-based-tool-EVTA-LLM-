from pathlib import Path
from typing import Dict, List, Optional

from .consistency import write_consistency_report
from .drift import write_drift_outputs
from .exporter import write_csv
from .flows import FlowManager
from .heuristics import apply_heuristics
from .host_window import HostWindowAggregator
from .live_capture import run_live_capture_to_csv
from .llm_context import LocalQwenContextGenerator, apply_llm_context
from .models import LLMContextConfig, UserLabelConfig
from .packet_parser import SUPPORTED_DATALINKS, open_pcap_reader, parse_packet
from .readiness import apply_readiness_scores
from .utils import apply_user_labels


def enrich_rows(
    rows: List[Dict[str, object]],
    host_window_seconds: float = 60.0,
    label_config: UserLabelConfig | None = None,
    llm_config: LLMContextConfig | None = None,
) -> List[Dict[str, object]]:
    HostWindowAggregator(window_seconds=host_window_seconds).enrich(rows)
    llm_generator = LocalQwenContextGenerator(llm_config) if llm_config and llm_config.enabled else None
    enriched = []
    for row in rows:
        row = apply_readiness_scores(dict(row))
        row = apply_heuristics(row)
        row = apply_llm_context(row, generator=llm_generator)
        row = apply_user_labels(row, label_config=label_config)
        enriched.append(row)
    return enriched


def extract_rows(
    input_path: Path,
    tcp_timeout: float,
    udp_timeout: float,
    other_timeout: float,
    partial_config=None,
    host_window_seconds: float = 60.0,
    label_config: UserLabelConfig | None = None,
    llm_config: LLMContextConfig | None = None,
) -> List[Dict[str, object]]:
    manager = FlowManager(
        tcp_timeout=tcp_timeout,
        udp_timeout=udp_timeout,
        other_timeout=other_timeout,
        partial_config=partial_config,
    )
    rows: List[Dict[str, object]] = []

    file_handle, reader, datalink = open_pcap_reader(input_path)
    if datalink not in SUPPORTED_DATALINKS:
        file_handle.close()
        raise ValueError(
            f"Unsupported capture datalink type {datalink}. Supported types are: {sorted(SUPPORTED_DATALINKS)}"
        )

    try:
        for ts, buf in reader:
            packet = parse_packet(ts, buf, datalink=datalink)
            if packet is None:
                continue
            emission = manager.update(packet)
            rows.extend(emission.rows)
    finally:
        file_handle.close()

    rows.extend(manager.flush().rows)
    return enrich_rows(
        rows,
        host_window_seconds=host_window_seconds,
        label_config=label_config,
        llm_config=llm_config,
    )


def extract_rows_to_csv(
    input_path: Path,
    output_path: Path,
    tcp_timeout: float,
    udp_timeout: float,
    other_timeout: float,
    profile: str = "full",
    partial_config=None,
    host_window_seconds: float = 60.0,
    label_config: UserLabelConfig | None = None,
    llm_config: LLMContextConfig | None = None,
) -> tuple[int, List[Dict[str, object]]]:
    rows = extract_rows(
        input_path=input_path,
        tcp_timeout=tcp_timeout,
        udp_timeout=udp_timeout,
        other_timeout=other_timeout,
        partial_config=partial_config,
        host_window_seconds=host_window_seconds,
        label_config=label_config,
        llm_config=llm_config,
    )
    row_count = write_csv(rows, output_path, profile=profile)
    return row_count, rows


def run_extractor(
    mode: str,
    output_path: Path,
    tcp_timeout: float,
    udp_timeout: float,
    other_timeout: float,
    input_path: Optional[Path] = None,
    interface: Optional[str] = None,
    bpf_filter: str = "",
    duration: float = 0.0,
    max_packets: int = 0,
    poll_interval: float = 1.0,
    promiscuous: bool = True,
    profile: str = "full",
    partial_config=None,
    host_window_seconds: float = 60.0,
    baseline_csv: Optional[Path] = None,
    report_prefix: Optional[Path] = None,
    label_config: UserLabelConfig | None = None,
    llm_config: LLMContextConfig | None = None,
) -> Dict[str, object]:
    summary: Dict[str, object] = {
        "mode": mode,
        "output_path": output_path,
        "row_count": 0,
        "drift_csv": None,
        "drift_md": None,
        "consistency_csv": None,
        "consistency_md": None,
        "llm_context_enabled": bool(llm_config and llm_config.enabled),
    }

    if mode == "offline":
        if input_path is None:
            raise ValueError("Offline mode requires --input")
        row_count, rows = extract_rows_to_csv(
            input_path=input_path,
            output_path=output_path,
            tcp_timeout=tcp_timeout,
            udp_timeout=udp_timeout,
            other_timeout=other_timeout,
            profile=profile,
            partial_config=partial_config,
            host_window_seconds=host_window_seconds,
            label_config=label_config,
            llm_config=llm_config,
        )
        summary["row_count"] = row_count
        if baseline_csv is not None and report_prefix is not None:
            drift_csv, drift_md = write_drift_outputs(baseline_csv, output_path, report_prefix)
            summary["drift_csv"] = drift_csv
            summary["drift_md"] = drift_md
        if report_prefix is not None:
            consistency_csv, consistency_md = write_consistency_report(
                offline_rows=rows,
                input_path=input_path,
                report_prefix=report_prefix,
                tcp_timeout=tcp_timeout,
                udp_timeout=udp_timeout,
                other_timeout=other_timeout,
            )
            summary["consistency_csv"] = consistency_csv
            summary["consistency_md"] = consistency_md
        return summary

    if mode == "live":
        if not interface:
            raise ValueError("Live mode requires --interface")
        summary["row_count"] = run_live_capture_to_csv(
            interface=interface,
            output_path=output_path,
            tcp_timeout=tcp_timeout,
            udp_timeout=udp_timeout,
            other_timeout=other_timeout,
            bpf_filter=bpf_filter,
            duration=duration,
            max_packets=max_packets,
            poll_interval=poll_interval,
            promiscuous=promiscuous,
            profile=profile,
            partial_config=partial_config,
            host_window_seconds=host_window_seconds,
            baseline_csv=baseline_csv,
            report_prefix=report_prefix,
            label_config=label_config,
            llm_config=llm_config,
        )
        if baseline_csv is not None and report_prefix is not None:
            summary["drift_csv"] = report_prefix.with_suffix(".drift.csv")
            summary["drift_md"] = report_prefix.with_suffix(".drift.md")
        return summary

    raise ValueError(f"Unsupported mode: {mode}")
