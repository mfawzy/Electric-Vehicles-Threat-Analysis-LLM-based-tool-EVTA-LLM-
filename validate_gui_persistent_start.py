import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from ev_ids_sentinel.gui import launch_gui


def main() -> int:
    app = QApplication.instance() or QApplication([])
    QTimer.singleShot(1000, app.quit)
    return launch_gui()


if __name__ == "__main__":
    raise SystemExit(main())
