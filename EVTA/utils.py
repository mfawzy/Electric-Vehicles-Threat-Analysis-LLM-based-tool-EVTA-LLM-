from __future__ import annotations

import math
from collections import Counter
from statistics import mean, pstdev
from typing import Dict, Iterable, List, Sequence, Set, Tuple

from .models import UserLabelConfig

from .constants import ALL_COLUMNS


def safe_div(num: float, den: float) -> float:
    return float(num) / float(den) if den else 0.0


def basic_stats(values: Iterable[float]) -> Dict[str, float]:
    values = list(values)
    if not values:
        return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0}
    if len(values) == 1:
        v = float(values[0])
        return {"mean": v, "std": 0.0, "max": v, "min": v}
    return {
        "mean": float(mean(values)),
        "std": float(pstdev(values)),
        "max": float(max(values)),
        "min": float(min(values)),
    }


def diffs(times: List[float]) -> List[float]:
    if len(times) < 2:
        return []
    return [times[i] - times[i - 1] for i in range(1, len(times))]


def burst_features(times: List[float], gap_threshold: float) -> Tuple[float, float, int, float]:
    if not times:
        return 0.0, 0.0, 0, 0.0
    if len(times) == 1:
        return 0.0, 0.0, 1, 0.0

    bursts = []
    current_start = times[0]
    current_prev = times[0]
    idle_gaps = []

    for ts in times[1:]:
        gap = ts - current_prev
        if gap > gap_threshold:
            bursts.append(max(current_prev - current_start, 0.0))
            idle_gaps.append(gap)
            current_start = ts
        current_prev = ts
    bursts.append(max(current_prev - current_start, 0.0))

    return (
        basic_stats(bursts)["mean"],
        basic_stats(idle_gaps)["mean"],
        len(bursts),
        basic_stats(idle_gaps)["max"],
    )


def average_qname_len(qnames: Set[str]) -> float:
    if not qnames:
        return 0.0
    return sum(len(q) for q in qnames) / len(qnames)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def average_qname_entropy(qnames: Set[str]) -> float:
    if not qnames:
        return 0.0
    return sum(shannon_entropy(q) for q in qnames) / len(qnames)


def is_populated(value: object) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (int, float)):
        return value != 0
    return value is not None


def finalize_row(row: Dict[str, object], columns: Sequence[str] | None = None) -> Dict[str, object]:
    finalized = {}
    target_columns = list(columns) if columns is not None else ALL_COLUMNS
    for col in target_columns:
        value = row.get(col, 0)
        if isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                value = 0.0
            value = round(value, 6)
        finalized[col] = value
    return finalized


def csv_key(row: Dict[str, object]) -> str:
    return "|".join(
        str(row.get(col, ""))
        for col in ["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "flow_start_ts", "flow_end_ts", "snapshot_kind"]
    )


def apply_user_labels(row: Dict[str, object], label_config: UserLabelConfig | None = None) -> Dict[str, object]:
    config = label_config or UserLabelConfig()
    row["binary_classification"] = config.binary_label.strip()
    row["multiclass_classification"] = config.multiclass_label.strip()
    return row


def parse_packet_steps(text: str) -> Tuple[int, ...]:
    if not text.strip():
        return tuple()
    values = sorted({int(item.strip()) for item in text.split(",") if item.strip()})
    return tuple(v for v in values if v > 0)


def parse_time_steps(text: str) -> Tuple[float, ...]:
    if not text.strip():
        return tuple()
    values = sorted({float(item.strip()) for item in text.split(",") if item.strip()})
    return tuple(v for v in values if v > 0)
