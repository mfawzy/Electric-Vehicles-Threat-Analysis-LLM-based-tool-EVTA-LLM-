"""EV-IDS Sentinel feature extraction and live monitoring package."""

from .constants import ALL_COLUMNS, BENEFICIAL_FEATURE_COLUMNS, IDENTITY_COLUMNS, MANDATORY_FEATURE_COLUMNS


def extract_rows_to_csv(*args, **kwargs):
    """Lazy wrapper for CSV extraction so package metadata imports stay lightweight."""
    from .pipeline import extract_rows_to_csv as _extract_rows_to_csv

    return _extract_rows_to_csv(*args, **kwargs)


__all__ = [
    "ALL_COLUMNS",
    "BENEFICIAL_FEATURE_COLUMNS",
    "IDENTITY_COLUMNS",
    "MANDATORY_FEATURE_COLUMNS",
    "extract_rows_to_csv",
]
