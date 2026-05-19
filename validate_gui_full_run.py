import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from ev_ids_sentinel.gui import MainWindow
from ev_ids_sentinel.pipeline import run_extractor


def main() -> int:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()

    root = Path.cwd()
    input_pcap = root / "dual_mode_test.pcap"
    output_csv = root / "ev_ids_sentinel_gui_validation_features.csv"

    window.profile_combo.setCurrentText("full")
    window.input_edit.setText(str(input_pcap))
    window.output_edit.setText(str(output_csv))
    window.enable_partial_check.setChecked(True)
    window.partial_packet_edit.setText("1,3,5")
    window.partial_time_edit.setText("1,5")
    window.binary_label_edit.setText("attack")
    window.multiclass_label_edit.setText("ev_ids_sentinel_gui_validation")
    window.enable_llm_check.setChecked(False)

    error = window._validate_offline()
    if error:
        raise RuntimeError(error)

    params = window._build_runtime_params("offline")
    summary = run_extractor(**params)
    print(summary)

    window.close()
    app.quit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
