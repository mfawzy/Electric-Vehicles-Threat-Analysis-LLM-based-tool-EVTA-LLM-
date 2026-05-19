import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from ev_ids_sentinel.gui import MainWindow


def main() -> int:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    summary = {
        "title": window.windowTitle(),
        "profile_items": [window.profile_combo.itemText(i) for i in range(window.profile_combo.count())],
        "llm_enabled_checkbox": window.enable_llm_check.text(),
        "start_live_button": window.start_live_button.text(),
        "run_offline_button": window.run_offline_button.text(),
        "side_activity_placeholder": window.activity_log.placeholderText(),
    }
    print(summary)
    window.close()
    app.quit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
