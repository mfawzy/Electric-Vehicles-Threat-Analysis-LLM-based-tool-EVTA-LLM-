from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from .constants import CONSISTENCY_COMPARE_COLUMNS, DEFAULT_COMPARE_TOLERANCE
from .flows import FlowManager
from .host_window import HostWindowAggregator
from .packet_parser import SUPPORTED_DATALINKS, open_pcap_reader, parse_packet
from .utils import csv_key


def _extract_live_style_rows(
    input_path: Path,
    tcp_timeout: float,
    udp_timeout: float,
    other_timeout: float,
) -> List[Dict[str, object]]:
    manager = FlowManager(tcp_timeout=tcp_timeout, udp_timeout=udp_timeout, other_timeout=other_timeout)
    rows: List[Dict[str, object]] = []

    file_handle, reader, datalink = open_pcap_reader(input_path)
    if datalink not in SUPPORTED_DATALINKS:
        file_handle.close()
        raise ValueError(f"Unsupported capture datalink type {datalink}. Supported types are: {sorted(SUPPORTED_DATALINKS)}")

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
    HostWindowAggregator(window_seconds=60.0).enrich(rows)
    return [row for row in rows if int(row.get("is_partial_snapshot", 0)) == 0]


def write_consistency_report(
    offline_rows: List[Dict[str, object]],
    input_path: Path,
    report_prefix: Path,
    tcp_timeout: float,
    udp_timeout: float,
    other_timeout: float,
    tolerance: float = DEFAULT_COMPARE_TOLERANCE,
) -> tuple[Path, Path]:
    live_rows = _extract_live_style_rows(
        input_path=input_path,
        tcp_timeout=tcp_timeout,
        udp_timeout=udp_timeout,
        other_timeout=other_timeout,
    )

    offline_map = {csv_key(row): row for row in offline_rows if int(row.get("is_partial_snapshot", 0)) == 0}
    live_map = {csv_key(row): row for row in live_rows}
    keys = sorted(set(offline_map) | set(live_map))

    mismatch_rows = []
    for key in keys:
        offline_row = offline_map.get(key)
        live_row = live_map.get(key)
        if offline_row is None or live_row is None:
            mismatch_rows.append({"row_key": key, "column": "__row_presence__", "offline": int(offline_row is not None), "live": int(live_row is not None), "abs_diff": 1.0})
            continue
        for column in CONSISTENCY_COMPARE_COLUMNS:
            off = offline_row.get(column, 0)
            liv = live_row.get(column, 0)
            try:
                off_num = float(off)
                liv_num = float(liv)
                diff = abs(off_num - liv_num)
            except (TypeError, ValueError):
                diff = 0.0 if str(off) == str(liv) else 1.0
            if diff > tolerance:
                mismatch_rows.append({"row_key": key, "column": column, "offline": off, "live": liv, "abs_diff": round(diff, 6)})

    csv_path = report_prefix.with_suffix(".consistency.csv")
    md_path = report_prefix.with_suffix(".consistency.md")

    import csv

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["row_key", "column", "offline", "live", "abs_diff"])
        writer.writeheader()
        writer.writerows(mismatch_rows)

    mismatch_preview = mismatch_rows[:20]
    if mismatch_preview:
        lines = ["| row_key | column | offline | live | abs_diff |", "|---|---|---:|---:|---:|"]
        for item in mismatch_preview:
            lines.append(f"| {item['row_key']} | {item['column']} | {item['offline']} | {item['live']} | {item['abs_diff']} |")
        table = "\n".join(lines)
    else:
        table = "No mismatches were detected within the configured tolerance."

    md_text = (
        "# Offline-Live Consistency Report\n\n"
        f"Input capture: `{input_path}`\n\n"
        f"Offline rows: {len(offline_rows)}\n\n"
        f"Replay-live rows: {len(live_rows)}\n\n"
        f"Mismatch count: {len(mismatch_rows)}\n\n"
        "## Mismatch preview\n\n"
        f"{table}\n"
    )
    md_path.write_text(md_text, encoding="utf-8")
    return csv_path, md_path
