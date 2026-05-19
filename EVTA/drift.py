from __future__ import annotations

from pathlib import Path
from typing import List

import pandas as pd

from .constants import ALL_COLUMNS, IDENTITY_COLUMNS


EXCLUDED_COLUMNS = set(IDENTITY_COLUMNS) | {
    "heuristic_label",
    "heuristic_reasons",
    "flow_summary",
    "llm_context",
    "export_reason",
    "snapshot_kind",
    "binary_classification",
    "multiclass_classification",
}


def _numeric_columns(df: pd.DataFrame) -> List[str]:
    numeric = []
    for column in df.columns:
        if column in EXCLUDED_COLUMNS:
            continue
        series = pd.to_numeric(df[column], errors="coerce")
        if series.notna().any():
            numeric.append(column)
    return numeric


def build_drift_summary(baseline_csv: Path, comparison_csv: Path) -> pd.DataFrame:
    baseline = pd.read_csv(baseline_csv)
    comparison = pd.read_csv(comparison_csv)

    common_columns = [column for column in _numeric_columns(baseline) if column in comparison.columns]
    rows = []
    for column in common_columns:
        base = pd.to_numeric(baseline[column], errors="coerce")
        comp = pd.to_numeric(comparison[column], errors="coerce")
        base_mean = float(base.mean()) if base.notna().any() else 0.0
        comp_mean = float(comp.mean()) if comp.notna().any() else 0.0
        base_std = float(base.std(ddof=0)) if base.notna().any() else 0.0
        comp_std = float(comp.std(ddof=0)) if comp.notna().any() else 0.0
        mean_shift = comp_mean - base_mean
        normalized_mean_shift = mean_shift / (base_std + 1e-9)
        rows.append(
            {
                "feature": column,
                "baseline_mean": round(base_mean, 6),
                "comparison_mean": round(comp_mean, 6),
                "baseline_std": round(base_std, 6),
                "comparison_std": round(comp_std, 6),
                "baseline_missing_ratio": round(float(base.isna().mean()), 6),
                "comparison_missing_ratio": round(float(comp.isna().mean()), 6),
                "mean_shift": round(mean_shift, 6),
                "normalized_mean_shift": round(normalized_mean_shift, 6),
                "drift_flag": int(abs(normalized_mean_shift) >= 1.0),
            }
        )
    summary = pd.DataFrame(rows).sort_values(by=["drift_flag", "normalized_mean_shift"], ascending=[False, False])
    return summary


def write_drift_outputs(baseline_csv: Path, comparison_csv: Path, report_prefix: Path) -> tuple[Path, Path]:
    summary = build_drift_summary(baseline_csv, comparison_csv)
    csv_path = report_prefix.with_suffix(".drift.csv")
    md_path = report_prefix.with_suffix(".drift.md")
    summary.to_csv(csv_path, index=False)

    flagged = summary[summary["drift_flag"] == 1].head(20)
    top_table = flagged.to_markdown(index=False) if not flagged.empty else "No features exceeded the configured drift threshold."
    md_text = (
        "# Drift Analysis Report\n\n"
        f"Baseline CSV: `{baseline_csv}`\n\n"
        f"Comparison CSV: `{comparison_csv}`\n\n"
        f"Rows analysed: baseline={len(pd.read_csv(baseline_csv))}, comparison={len(pd.read_csv(comparison_csv))}\n\n"
        "## Top flagged features\n\n"
        f"{top_table}\n"
    )
    md_path.write_text(md_text, encoding="utf-8")
    return csv_path, md_path
