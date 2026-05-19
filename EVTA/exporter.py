from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, Iterable, Sequence

from .constants import PROFILE_COLUMNS
from .utils import finalize_row


class CsvRowWriter:
    def __init__(self, path: Path, columns: Sequence[str]):
        self.path = path
        self.columns = list(columns)
        self._fh = None
        self._writer = None
        self.row_count = 0

    def __enter__(self) -> "CsvRowWriter":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("w", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._fh, fieldnames=self.columns)
        self._writer.writeheader()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fh is not None:
            self._fh.close()

    def write_row(self, row: Dict[str, object]) -> None:
        if self._writer is None:
            raise RuntimeError("CSV writer is not open")
        self._writer.writerow(finalize_row(row, self.columns))
        self.row_count += 1


def columns_for_profile(profile: str) -> Sequence[str]:
    if profile not in PROFILE_COLUMNS:
        raise ValueError(f"Unsupported output profile: {profile}")
    return PROFILE_COLUMNS[profile]


def write_csv(rows: Iterable[Dict[str, object]], output_path: Path, profile: str = "full") -> int:
    columns = columns_for_profile(profile)
    with CsvRowWriter(output_path, columns) as writer:
        for row in rows:
            writer.write_row(row)
    return writer.row_count
