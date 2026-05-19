from __future__ import annotations

import time
from collections import Counter, deque
from pathlib import Path
from typing import Optional

from .constants import (
    DEFAULT_HOST_WINDOW_SECONDS,
    DEFAULT_LLM_MAX_NEW_TOKENS,
    DEFAULT_LLM_MODEL_NAME,
    DEFAULT_OTHER_TIMEOUT,
    DEFAULT_PARTIAL_PACKET_STEPS,
    DEFAULT_PARTIAL_TIME_STEPS,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_TCP_TIMEOUT,
    DEFAULT_UDP_TIMEOUT,
    PROFILE_COLUMNS,
)
from .models import LLMContextConfig, PartialExportConfig, UserLabelConfig
from .utils import parse_packet_steps, parse_time_steps


class _GuiImportError(RuntimeError):
    pass


try:
    from PySide6.QtCore import Qt, QThread, Signal
    from PySide6.QtGui import QColor, QFont, QPainter, QPen
    from PySide6.QtWidgets import (
        QApplication,
        QComboBox,
        QFileDialog,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPlainTextEdit,
        QPushButton,
        QScrollArea,
        QSizePolicy,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # pragma: no cover
    raise _GuiImportError(
        "The GUI requires PySide6. Install it with: python -m pip install PySide6"
    ) from exc


EV_CLASSES = [
    "",
    "benign",
    "AFS_DoS",
    "AFS_Overflow",
    "DDoS_UDP",
    "DoS_SYN",
    "Exploit_SIP",
    "GPS_Injection",
    "SIP_Enum",
    "SIP_Flood",
    "SIP_Malformed",
]


BPF_PRESETS = [
    ("All traffic", ""),
    ("TCP only", "tcp"),
    ("UDP only", "udp"),
    ("ICMP only", "icmp"),
    ("DNS traffic", "port 53"),
    ("HTTP traffic", "port 80"),
    ("HTTPS traffic", "port 443"),
    ("TCP or UDP", "tcp or udp"),
]


DURATION_PRESETS = [
    ("Unlimited", 0.0),
    ("30 seconds", 30.0),
    ("1 minute", 60.0),
    ("5 minutes", 300.0),
    ("10 minutes", 600.0),
    ("30 minutes", 1800.0),
    ("1 hour", 3600.0),
]


MAX_PACKET_PRESETS = [
    ("Unlimited", 0),
    ("100 packets", 100),
    ("500 packets", 500),
    ("1,000 packets", 1000),
    ("5,000 packets", 5000),
    ("10,000 packets", 10000),
    ("50,000 packets", 50000),
]


POLL_INTERVAL_PRESETS = [
    ("Fast refresh - 0.5 sec", 0.5),
    ("Normal refresh - 1 sec", 1.0),
    ("Slow refresh - 2 sec", 2.0),
    ("Very slow refresh - 5 sec", 5.0),
]


TIMEOUT_PRESETS = [
    ("15 seconds", 15.0),
    ("30 seconds", 30.0),
    ("60 seconds", 60.0),
    ("120 seconds", 120.0),
    ("300 seconds", 300.0),
]


HOST_WINDOW_PRESETS = [
    ("30 seconds", 30.0),
    ("60 seconds", 60.0),
    ("120 seconds", 120.0),
    ("300 seconds", 300.0),
    ("600 seconds", 600.0),
]


LLM_TOKEN_PRESETS = [
    ("64 tokens", 64),
    ("128 tokens", 128),
    ("256 tokens", 256),
    ("512 tokens", 512),
]


APP_STYLE = """
QMainWindow, QWidget {
    background: #0f172a;
    color: #e5e7eb;
    font-family: Segoe UI, Arial, sans-serif;
    font-size: 12px;
}
QScrollArea {
    border: none;
    background: #0f172a;
}
QScrollBar:vertical {
    background: #0b1220;
    width: 12px;
    margin: 0;
    border-radius: 6px;
}
QScrollBar::handle:vertical {
    background: #334155;
    min-height: 30px;
    border-radius: 6px;
}
QScrollBar::handle:vertical:hover {
    background: #475569;
}
QScrollBar:horizontal {
    background: #0b1220;
    height: 12px;
    margin: 0;
    border-radius: 6px;
}
QScrollBar::handle:horizontal {
    background: #334155;
    min-width: 30px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal:hover {
    background: #475569;
}
QGroupBox {
    border: 1px solid #263449;
    border-radius: 14px;
    margin-top: 16px;
    padding: 14px;
    background: #111c2f;
    font-weight: 700;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 8px;
    color: #93c5fd;
}
QLineEdit, QComboBox, QPlainTextEdit, QTableWidget {
    background: #0b1220;
    border: 1px solid #334155;
    border-radius: 9px;
    padding: 7px;
    color: #e5e7eb;
    selection-background-color: #2563eb;
}
QComboBox::drop-down {
    border: none;
    width: 28px;
}
QPlainTextEdit, QTableWidget {
    border-radius: 14px;
}
QHeaderView::section {
    background: #1e293b;
    color: #bfdbfe;
    border: none;
    padding: 8px;
    font-weight: 700;
}
QPushButton {
    background: #2563eb;
    color: white;
    border: none;
    border-radius: 10px;
    padding: 9px 14px;
    font-weight: 700;
}
QPushButton:hover { background: #1d4ed8; }
QPushButton:disabled {
    background: #334155;
    color: #94a3b8;
}
QPushButton#dangerButton { background: #dc2626; }
QPushButton#dangerButton:hover { background: #b91c1c; }
QPushButton#secondaryButton { background: #334155; }
QPushButton#secondaryButton:hover { background: #475569; }
QFrame#card, QFrame#pictureCard {
    background: #111c2f;
    border: 1px solid #263449;
    border-radius: 16px;
}
QLabel#muted { color: #94a3b8; }
QLabel#title { font-size: 24px; font-weight: 800; color: #f8fafc; }
QLabel#subtitle { color: #94a3b8; font-size: 13px; }
QLabel#cardValue { font-size: 28px; font-weight: 900; color: #f8fafc; }
QLabel#cardTitle { color: #93c5fd; font-weight: 700; }
QLabel#statusLive {
    background: #064e3b;
    color: #a7f3d0;
    border-radius: 10px;
    padding: 6px 10px;
    font-weight: 800;
}
QLabel#statusIdle {
    background: #334155;
    color: #cbd5e1;
    border-radius: 10px;
    padding: 6px 10px;
    font-weight: 800;
}
"""


def get_available_interfaces() -> list[tuple[str, str]]:
    """
    Return available system network interfaces from Scapy.

    Returns:
        [(interface_name_for_scapy, display_text), ...]
    """
    interfaces: list[tuple[str, str]] = []

    try:
        from scapy.all import conf

        for iface in conf.ifaces.values():
            name = str(getattr(iface, "name", "") or "").strip()
            description = str(getattr(iface, "description", "") or "").strip()
            network_name = str(getattr(iface, "network_name", "") or "").strip()

            interface_value = name or network_name

            if not interface_value:
                continue

            display_parts = []

            if name:
                display_parts.append(name)

            if description and description != name:
                display_parts.append(description)

            if network_name and network_name not in display_parts:
                display_parts.append(network_name)

            display = " — ".join(display_parts) if display_parts else interface_value
            interfaces.append((interface_value, display))

    except Exception:
        pass

    seen = set()
    unique_interfaces: list[tuple[str, str]] = []

    for name, display in interfaces:
        if name not in seen:
            unique_interfaces.append((name, display))
            seen.add(name)

    return unique_interfaces


def add_combo_items(combo: QComboBox, items) -> None:
    combo.clear()
    combo.setEditable(False)

    for text, value in items:
        combo.addItem(text, value)


def set_combo_by_data(combo: QComboBox, value) -> None:
    for i in range(combo.count()):
        if combo.itemData(i) == value:
            combo.setCurrentIndex(i)
            return


class ExtractionWorker(QThread):
    succeeded = Signal(dict)
    failed = Signal(str)

    def __init__(self, params: dict):
        super().__init__()
        self.params = params

    def run(self) -> None:  # pragma: no cover
        try:
            from .pipeline import run_extractor

            summary = run_extractor(**self.params)
            self.succeeded.emit(summary)

        except Exception as exc:
            self.failed.emit(str(exc))


class LiveDashboardWorker(QThread):
    row_ready = Signal(dict)
    stats_ready = Signal(dict)
    log_ready = Signal(str)
    succeeded = Signal(dict)
    failed = Signal(str)

    def __init__(self, params: dict):
        super().__init__()
        self.params = params
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def run(self) -> None:  # pragma: no cover
        capture_fix_message = None

        try:
            from .live_capture import (
                LiveFlowExporter,
                sniff_with_windows_fallback,
                windows_capture_fix_message,
            )

            capture_fix_message = windows_capture_fix_message

            start = time.time()
            last_stats = start

            label_counts: Counter[str] = Counter()
            protocol_counts: Counter[str] = Counter()

            alert_count = 0
            total_bytes = 0

            def protocol_name(value: object) -> str:
                try:
                    proto = int(float(value or 0))
                except Exception:
                    return str(value or "Other")

                return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))

            def on_row(row: dict) -> None:
                nonlocal alert_count, total_bytes

                label = str(row.get("heuristic_label") or "unknown")
                protocol = protocol_name(row.get("protocol"))

                label_counts[label] += 1
                protocol_counts[protocol] += 1

                if label not in {"benign", "benign_like", "normal"}:
                    alert_count += 1

                total_bytes += int(float(row.get("total_fwd_bytes") or 0))
                total_bytes += int(float(row.get("total_bwd_bytes") or 0))

                self.row_ready.emit(row)

            output_path = self.params["output_path"]
            output_path.parent.mkdir(parents=True, exist_ok=True)

            self.log_ready.emit(
                f"Live capture started on {self.params['interface']} → {output_path}"
            )

            with LiveFlowExporter(
                output_path=output_path,
                tcp_timeout=self.params["tcp_timeout"],
                udp_timeout=self.params["udp_timeout"],
                other_timeout=self.params["other_timeout"],
                profile=self.params["profile"],
                partial_config=self.params["partial_config"],
                host_window_seconds=self.params["host_window_seconds"],
                label_config=self.params["label_config"],
                llm_config=self.params["llm_config"],
                row_callback=on_row,
            ) as exporter:
                while not self._stop_requested:
                    elapsed = time.time() - start
                    duration = float(self.params.get("duration") or 0.0)
                    max_packets = int(self.params.get("max_packets") or 0)

                    if duration > 0 and elapsed >= duration:
                        self.log_ready.emit("Duration limit reached.")
                        break

                    if max_packets > 0 and exporter.processed_packets >= max_packets:
                        self.log_ready.emit("Packet limit reached.")
                        break

                    timeout = float(
                        self.params.get("poll_interval") or DEFAULT_POLL_INTERVAL
                    )

                    if duration > 0:
                        timeout = min(timeout, max(duration - elapsed, 0.05))

                    sniff_with_windows_fallback(
                        interface=self.params["interface"],
                        packet_callback=exporter.handle_scapy_packet,
                        timeout=timeout,
                        bpf_filter=self.params.get("bpf_filter") or "",
                        promiscuous=bool(self.params.get("promiscuous", True)),
                        log_callback=self.log_ready.emit,
                    )

                    exporter.flush_expired(time.time())

                    now = time.time()

                    if now - last_stats >= 0.5:
                        self.stats_ready.emit(
                            {
                                "running": True,
                                "elapsed": now - start,
                                "packets": exporter.processed_packets,
                                "flows": exporter.exported_rows,
                                "alerts": alert_count,
                                "bytes": total_bytes,
                                "pps": exporter.processed_packets
                                / max(now - start, 1e-9),
                                "top_label": label_counts.most_common(1)[0][0]
                                if label_counts
                                else "-",
                                "output_path": str(output_path),
                                "label_counts": dict(label_counts),
                                "protocol_counts": dict(protocol_counts),
                            }
                        )
                        last_stats = now

                exporter.flush_all()

                final_packets = exporter.processed_packets
                final_flows = exporter.exported_rows

            finished = time.time()

            final_summary = {
                "mode": "live",
                "output_path": output_path,
                "row_count": final_flows,
                "flows": final_flows,
                "packets": final_packets,
                "elapsed": finished - start,
                "alerts": alert_count,
                "bytes": total_bytes,
                "top_label": label_counts.most_common(1)[0][0]
                if label_counts
                else "-",
                "label_counts": dict(label_counts),
                "protocol_counts": dict(protocol_counts),
                "pps": final_packets / max(finished - start, 1e-9),
                "running": False,
            }

            self.stats_ready.emit(final_summary)
            self.succeeded.emit(final_summary)

        except Exception as exc:
            message = str(exc)

            if (
                "winpcap is not installed" in message.lower()
                or "npcap" in message.lower()
                or "not available at layer 2" in message.lower()
                or "l3socket" in message.lower()
            ):
                if capture_fix_message is not None:
                    message = capture_fix_message(exc)

            self.failed.emit(message)


class StatCard(QFrame):
    def __init__(self, title: str, value: str = "0", subtitle: str = ""):
        super().__init__()
        self.setObjectName("card")
        self.setMinimumHeight(112)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("cardTitle")

        self.value_label = QLabel(value)
        self.value_label.setObjectName("cardValue")

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("muted")
        self.subtitle_label.setWordWrap(True)

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.subtitle_label)

    def set_value(self, value: object, subtitle: Optional[str] = None) -> None:
        self.value_label.setText(str(value))

        if subtitle is not None:
            self.subtitle_label.setText(subtitle)


class TrafficLinePicture(QWidget):
    def __init__(self):
        super().__init__()
        self.values = deque(maxlen=80)
        self.setMinimumHeight(190)

    def set_values(self, values) -> None:
        self.values = deque(values, maxlen=80)
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        rect = self.rect()
        painter.fillRect(rect, QColor("#0b1220"))

        margin_left = 38
        margin_right = 16
        margin_top = 32
        margin_bottom = 30

        chart_w = max(rect.width() - margin_left - margin_right, 1)
        chart_h = max(rect.height() - margin_top - margin_bottom, 1)

        painter.setPen(QColor("#bfdbfe"))
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(14, 20, "Live traffic rate picture")

        painter.setPen(QPen(QColor("#233047"), 1))

        for i in range(5):
            y = margin_top + int(chart_h * i / 4)
            painter.drawLine(margin_left, y, margin_left + chart_w, y)

        if not self.values:
            painter.setPen(QColor("#94a3b8"))
            painter.drawText(
                margin_left,
                margin_top + chart_h // 2,
                "Waiting for live traffic...",
            )
            return

        values = list(self.values)
        max_value = max(max(values), 1.0)

        painter.setPen(QColor("#94a3b8"))
        painter.drawText(8, margin_top + 8, f"{max_value:.1f}")
        painter.drawText(8, margin_top + chart_h, "0")

        points = []

        for i, value in enumerate(values):
            x = margin_left + int(chart_w * i / max(len(values) - 1, 1))
            y = margin_top + chart_h - int(chart_h * value / max_value)
            points.append((x, y))

        painter.setPen(QPen(QColor("#38bdf8"), 3))

        for i in range(1, len(points)):
            painter.drawLine(
                points[i - 1][0],
                points[i - 1][1],
                points[i][0],
                points[i][1],
            )

        painter.setPen(QColor("#e5e7eb"))
        painter.drawText(margin_left, rect.height() - 8, "recent time →")


class BarPicture(QWidget):
    def __init__(self, title: str):
        super().__init__()
        self.title = title
        self.data: dict[str, int] = {}
        self.setMinimumHeight(190)

    def set_data(self, data: dict[str, int]) -> None:
        self.data = dict(data or {})
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        rect = self.rect()
        painter.fillRect(rect, QColor("#0b1220"))

        painter.setPen(QColor("#bfdbfe"))
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(14, 20, self.title)

        if not self.data:
            painter.setPen(QColor("#94a3b8"))
            painter.drawText(14, rect.height() // 2, "No flow rows yet")
            return

        items = sorted(self.data.items(), key=lambda x: x[1], reverse=True)[:6]
        max_value = max([v for _, v in items] or [1])

        left = 118
        top = 42
        bar_h = 18
        gap = 10
        right_pad = 24
        max_bar_w = max(rect.width() - left - right_pad, 1)

        for i, (label, value) in enumerate(items):
            y = top + i * (bar_h + gap)
            bar_w = int(max_bar_w * value / max_value)

            painter.setPen(QColor("#e5e7eb"))
            painter.drawText(14, y + 14, str(label)[:16])

            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#1e293b"))
            painter.drawRoundedRect(left, y, max_bar_w, bar_h, 7, 7)

            if label in {"benign", "benign_like", "normal"}:
                painter.setBrush(QColor("#22c55e"))
            else:
                painter.setBrush(QColor("#f97316"))

            painter.drawRoundedRect(left, y, bar_w, bar_h, 7, 7)

            painter.setPen(QColor("#e5e7eb"))
            painter.drawText(left + max_bar_w - 42, y + 14, str(value))


class AlertGaugePicture(QWidget):
    def __init__(self):
        super().__init__()
        self.alerts = 0
        self.flows = 0
        self.setMinimumHeight(190)

    def set_values(self, alerts: int, flows: int) -> None:
        self.alerts = int(alerts or 0)
        self.flows = int(flows or 0)
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        rect = self.rect()
        painter.fillRect(rect, QColor("#0b1220"))

        painter.setPen(QColor("#bfdbfe"))
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(14, 20, "Alert pressure picture")

        ratio = self.alerts / max(self.flows, 1)
        ratio = max(0.0, min(ratio, 1.0))

        center_x = rect.width() // 2
        center_y = rect.height() // 2 + 22
        radius = min(rect.width(), rect.height()) // 3

        painter.setPen(QPen(QColor("#1e293b"), 18))
        painter.drawArc(
            center_x - radius,
            center_y - radius,
            radius * 2,
            radius * 2,
            180 * 16,
            -180 * 16,
        )

        color = QColor("#22c55e")

        if ratio >= 0.25:
            color = QColor("#f97316")

        if ratio >= 0.55:
            color = QColor("#ef4444")

        painter.setPen(QPen(color, 18))
        painter.drawArc(
            center_x - radius,
            center_y - radius,
            radius * 2,
            radius * 2,
            180 * 16,
            int(-180 * ratio * 16),
        )

        painter.setPen(QColor("#f8fafc"))
        painter.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{ratio * 100:.1f}%")

        painter.setPen(QColor("#94a3b8"))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(
            rect.adjusted(0, rect.height() - 34, 0, -8),
            Qt.AlignmentFlag.AlignCenter,
            f"{self.alerts:,} alerts / {self.flows:,} flows",
        )


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.worker: Optional[QThread] = None
        self.live_worker: Optional[LiveDashboardWorker] = None

        self.recent_rows_limit = 250
        self.alert_count = 0
        self.protocol_counts: Counter[str] = Counter()
        self.label_counts: Counter[str] = Counter()
        self.pps_history = deque(maxlen=80)

        self.setWindowTitle("EVTA-Traffic Dashboard")
        self.resize(1500, 940)

        self._build_ui()
        self._load_interfaces()
        self._toggle_llm_fields()

        self._append_log(
            "EVTA ready. Choose an available system interface, choose output CSV, then start live monitoring."
        )

    def _build_ui(self) -> None:
        central = QWidget()

        root = QHBoxLayout(central)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(16)

        sidebar_scroll = QScrollArea()
        sidebar_scroll.setWidgetResizable(True)
        sidebar_scroll.setFixedWidth(410)
        sidebar_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        sidebar_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        sidebar = QWidget()

        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(4, 4, 12, 4)
        sidebar_layout.setSpacing(12)

        side_title = QLabel("EVTA Controls")
        side_title.setObjectName("title")

        side_subtitle = QLabel(
            "System-only dropdown options for live EV traffic monitoring, offline extraction, and feature export."
        )
        side_subtitle.setObjectName("subtitle")
        side_subtitle.setWordWrap(True)

        sidebar_layout.addWidget(side_title)
        sidebar_layout.addWidget(side_subtitle)
        sidebar_layout.addWidget(self._build_live_controls())
        sidebar_layout.addWidget(self._build_offline_controls())
        sidebar_layout.addWidget(self._build_advanced_controls())
        sidebar_layout.addStretch(1)

        sidebar_scroll.setWidget(sidebar)

        dashboard = QWidget()
        dashboard.setMinimumWidth(980)

        dashboard_layout = QVBoxLayout(dashboard)
        dashboard_layout.setContentsMargins(0, 0, 0, 0)
        dashboard_layout.setSpacing(14)

        header = QHBoxLayout()

        header_text = QVBoxLayout()

        title = QLabel("EVTA Live Monitor")
        title.setObjectName("title")

        subtitle = QLabel(
            "Real-time Electric Vehicle network traffic capture, visual traffic pictures, flow export, and heuristic IDS alerts."
        )
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)

        self.status_label = QLabel("IDLE")
        self.status_label.setObjectName("statusIdle")

        header_text.addWidget(title)
        header_text.addWidget(subtitle)

        header.addLayout(header_text, stretch=1)
        header.addWidget(self.status_label, alignment=Qt.AlignmentFlag.AlignTop)

        dashboard_layout.addLayout(header)

        cards = QGridLayout()
        cards.setSpacing(12)

        self.card_packets = StatCard("Packets", "0", "Captured packets")
        self.card_flows = StatCard("Flows", "0", "Exported flow rows")
        self.card_alerts = StatCard("Alerts", "0", "Non-benign heuristic rows")
        self.card_rate = StatCard("Rate", "0.0 pps", "Packets per second")
        self.card_bytes = StatCard("Traffic", "0 B", "Total exported bytes")
        self.card_top = StatCard("Top label", "-", "Most frequent heuristic label")

        cards.addWidget(self.card_packets, 0, 0)
        cards.addWidget(self.card_flows, 0, 1)
        cards.addWidget(self.card_alerts, 0, 2)
        cards.addWidget(self.card_rate, 1, 0)
        cards.addWidget(self.card_bytes, 1, 1)
        cards.addWidget(self.card_top, 1, 2)

        dashboard_layout.addLayout(cards)

        dashboard_layout.addWidget(self._build_visual_picture_group())

        main_split = QHBoxLayout()
        main_split.setSpacing(14)

        main_split.addWidget(self._build_flow_table_group(), stretch=3)
        main_split.addWidget(self._build_side_activity_group(), stretch=1)

        dashboard_layout.addLayout(main_split, stretch=1)
        dashboard_layout.addWidget(self._build_log_group(), stretch=0)

        dashboard_scroll = QScrollArea()
        dashboard_scroll.setWidgetResizable(True)
        dashboard_scroll.setWidget(dashboard)
        dashboard_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        dashboard_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        root.addWidget(sidebar_scroll)
        root.addWidget(dashboard_scroll, stretch=1)

        self.setCentralWidget(central)

    def _build_live_controls(self) -> QWidget:
        group = QGroupBox("EV live dashboard")
        layout = QVBoxLayout(group)

        self.interface_combo = QComboBox()
        self.interface_combo.setEditable(False)

        self.refresh_interfaces_button = QPushButton("Refresh system interfaces")
        self.refresh_interfaces_button.setObjectName("secondaryButton")
        self.refresh_interfaces_button.clicked.connect(self._load_interfaces)

        self.output_edit = QLineEdit("ev_ids_sentinel_live.csv")

        self.output_button = QPushButton("Choose output CSV")
        self.output_button.setObjectName("secondaryButton")
        self.output_button.clicked.connect(self._browse_output)

        self.profile_combo = QComboBox()
        self.profile_combo.setEditable(False)
        self.profile_combo.addItems(sorted(PROFILE_COLUMNS))
        self.profile_combo.setCurrentText(
            "live-safe" if "live-safe" in PROFILE_COLUMNS else "full"
        )

        self.bpf_filter_combo = QComboBox()
        add_combo_items(self.bpf_filter_combo, BPF_PRESETS)

        self.duration_combo = QComboBox()
        add_combo_items(self.duration_combo, DURATION_PRESETS)

        self.max_packets_combo = QComboBox()
        add_combo_items(self.max_packets_combo, MAX_PACKET_PRESETS)

        self.poll_interval_combo = QComboBox()
        add_combo_items(self.poll_interval_combo, POLL_INTERVAL_PRESETS)
        set_combo_by_data(self.poll_interval_combo, DEFAULT_POLL_INTERVAL)

        self.promiscuous_combo = QComboBox()
        add_combo_items(
            self.promiscuous_combo,
            [
                ("Enabled", True),
                ("Disabled", False),
            ],
        )

        layout.addWidget(QLabel("Network interface - system detected only"))
        layout.addWidget(self.interface_combo)
        layout.addWidget(self.refresh_interfaces_button)

        layout.addWidget(QLabel("Output CSV"))
        layout.addWidget(self.output_edit)
        layout.addWidget(self.output_button)

        layout.addWidget(QLabel("Feature profile"))
        layout.addWidget(self.profile_combo)

        layout.addWidget(QLabel("Traffic filter"))
        layout.addWidget(self.bpf_filter_combo)

        layout.addWidget(QLabel("Capture duration"))
        layout.addWidget(self.duration_combo)

        layout.addWidget(QLabel("Maximum packets"))
        layout.addWidget(self.max_packets_combo)

        layout.addWidget(QLabel("Dashboard refresh interval"))
        layout.addWidget(self.poll_interval_combo)

        layout.addWidget(QLabel("Promiscuous mode"))
        layout.addWidget(self.promiscuous_combo)

        buttons = QHBoxLayout()

        self.start_live_button = QPushButton("Start EV live monitor")
        self.start_live_button.clicked.connect(self._start_live)

        self.stop_live_button = QPushButton("Stop")
        self.stop_live_button.setObjectName("dangerButton")
        self.stop_live_button.setEnabled(False)
        self.stop_live_button.clicked.connect(self._stop_live)

        buttons.addWidget(self.start_live_button)
        buttons.addWidget(self.stop_live_button)

        layout.addLayout(buttons)

        return group

    def _build_offline_controls(self) -> QWidget:
        group = QGroupBox("Offline EV dataset extraction")
        layout = QVBoxLayout(group)

        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText("Choose an EV traffic .pcap or .pcapng file")

        self.input_button = QPushButton("Browse EV PCAP")
        self.input_button.setObjectName("secondaryButton")
        self.input_button.clicked.connect(self._browse_input)

        self.run_offline_button = QPushButton("Run offline extraction")
        self.run_offline_button.clicked.connect(self._run_offline)

        layout.addWidget(QLabel("Input PCAP"))
        layout.addWidget(self.input_edit)
        layout.addWidget(self.input_button)
        layout.addWidget(self.run_offline_button)

        return group

    def _build_advanced_controls(self) -> QWidget:
        group = QGroupBox("Advanced settings")
        layout = QVBoxLayout(group)

        self.tcp_timeout_combo = QComboBox()
        add_combo_items(self.tcp_timeout_combo, TIMEOUT_PRESETS)
        set_combo_by_data(self.tcp_timeout_combo, DEFAULT_TCP_TIMEOUT)

        self.udp_timeout_combo = QComboBox()
        add_combo_items(self.udp_timeout_combo, TIMEOUT_PRESETS)
        set_combo_by_data(self.udp_timeout_combo, DEFAULT_UDP_TIMEOUT)

        self.other_timeout_combo = QComboBox()
        add_combo_items(self.other_timeout_combo, TIMEOUT_PRESETS)
        set_combo_by_data(self.other_timeout_combo, DEFAULT_OTHER_TIMEOUT)

        self.host_window_combo = QComboBox()
        add_combo_items(self.host_window_combo, HOST_WINDOW_PRESETS)
        set_combo_by_data(self.host_window_combo, DEFAULT_HOST_WINDOW_SECONDS)

        self.partial_combo = QComboBox()
        add_combo_items(
            self.partial_combo,
            [
                ("Disabled", False),
                ("Enabled", True),
            ],
        )

        self.partial_packet_combo = QComboBox()
        add_combo_items(
            self.partial_packet_combo,
            [
                (
                    "Default packet milestones",
                    ",".join(str(x) for x in DEFAULT_PARTIAL_PACKET_STEPS),
                ),
                ("Light: 5,10,20", "5,10,20"),
                ("Medium: 10,25,50,100", "10,25,50,100"),
                ("Heavy: 10,50,100,250,500", "10,50,100,250,500"),
            ],
        )

        self.partial_time_combo = QComboBox()
        add_combo_items(
            self.partial_time_combo,
            [
                (
                    "Default time milestones",
                    ",".join(str(x) for x in DEFAULT_PARTIAL_TIME_STEPS),
                ),
                ("Fast: 1,2,5", "1,2,5"),
                ("Medium: 5,10,30,60", "5,10,30,60"),
                ("Long: 10,30,60,120,300", "10,30,60,120,300"),
            ],
        )

        self.binary_label_combo = QComboBox()
        add_combo_items(
            self.binary_label_combo,
            [
                ("No manual binary label", ""),
                ("benign", "benign"),
                ("attack", "attack"),
            ],
        )

        self.multiclass_label_combo = QComboBox()
        add_combo_items(
            self.multiclass_label_combo,
            [("No manual multiclass label", "")]
            + [(x, x) for x in EV_CLASSES if x],
        )

        self.llm_enabled_combo = QComboBox()
        add_combo_items(
            self.llm_enabled_combo,
            [
                ("Disabled", False),
                ("Enabled", True),
            ],
        )
        self.llm_enabled_combo.currentIndexChanged.connect(self._toggle_llm_fields)

        self.llm_model_combo = QComboBox()
        add_combo_items(
            self.llm_model_combo,
            [
                (DEFAULT_LLM_MODEL_NAME, DEFAULT_LLM_MODEL_NAME),
            ],
        )

        self.llm_tokens_combo = QComboBox()
        add_combo_items(self.llm_tokens_combo, LLM_TOKEN_PRESETS)
        set_combo_by_data(self.llm_tokens_combo, DEFAULT_LLM_MAX_NEW_TOKENS)

        for label, widget in [
            ("TCP timeout", self.tcp_timeout_combo),
            ("UDP timeout", self.udp_timeout_combo),
            ("Other timeout", self.other_timeout_combo),
            ("Host window", self.host_window_combo),
            ("Partial-flow snapshots", self.partial_combo),
            ("Packet milestones", self.partial_packet_combo),
            ("Time milestones", self.partial_time_combo),
            ("Binary label", self.binary_label_combo),
            ("Multiclass label", self.multiclass_label_combo),
            ("LLM context", self.llm_enabled_combo),
            ("Qwen model", self.llm_model_combo),
            ("Max new tokens", self.llm_tokens_combo),
        ]:
            layout.addWidget(QLabel(label))
            layout.addWidget(widget)

        return group

    def _build_visual_picture_group(self) -> QWidget:
        group = QGroupBox("Live traffic pictures")
        layout = QGridLayout(group)
        layout.setSpacing(12)

        self.traffic_picture = TrafficLinePicture()
        self.protocol_picture = BarPicture("Protocol distribution picture")
        self.label_picture = BarPicture("Threat label picture")
        self.alert_gauge = AlertGaugePicture()

        for widget in [
            self.traffic_picture,
            self.protocol_picture,
            self.label_picture,
            self.alert_gauge,
        ]:
            frame = QFrame()
            frame.setObjectName("pictureCard")

            frame_layout = QVBoxLayout(frame)
            frame_layout.setContentsMargins(8, 8, 8, 8)
            frame_layout.addWidget(widget)

            widget.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Expanding,
            )

            if widget is self.traffic_picture:
                layout.addWidget(frame, 0, 0)
            elif widget is self.protocol_picture:
                layout.addWidget(frame, 0, 1)
            elif widget is self.label_picture:
                layout.addWidget(frame, 1, 0)
            else:
                layout.addWidget(frame, 1, 1)

        return group

    def _build_flow_table_group(self) -> QWidget:
        group = QGroupBox("Recent exported flows")
        layout = QVBoxLayout(group)

        self.flow_table = QTableWidget(0, 9)
        self.flow_table.setHorizontalHeaderLabels(
            [
                "Time",
                "Source",
                "Destination",
                "Proto",
                "Pkts",
                "Bytes",
                "Heuristic",
                "Score",
                "Reason",
            ]
        )

        self.flow_table.verticalHeader().setVisible(False)
        self.flow_table.setAlternatingRowColors(False)
        self.flow_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.flow_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        self.flow_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.flow_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.flow_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.flow_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.flow_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.ResizeToContents
        )
        self.flow_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.ResizeToContents
        )
        self.flow_table.horizontalHeader().setSectionResizeMode(
            6, QHeaderView.ResizeMode.ResizeToContents
        )
        self.flow_table.horizontalHeader().setSectionResizeMode(
            7, QHeaderView.ResizeMode.ResizeToContents
        )
        self.flow_table.horizontalHeader().setSectionResizeMode(
            8, QHeaderView.ResizeMode.Stretch
        )

        layout.addWidget(self.flow_table)

        return group

    def _build_side_activity_group(self) -> QWidget:
        group = QGroupBox("Side activity scroll")
        layout = QVBoxLayout(group)

        self.activity_log = QPlainTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setPlaceholderText(
            "EVTA live alerts and capture events appear here."
        )
        self.activity_log.setMinimumWidth(300)
        self.activity_log.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )

        clear = QPushButton("Clear side activity")
        clear.setObjectName("secondaryButton")
        clear.clicked.connect(lambda: self.activity_log.setPlainText(""))

        layout.addWidget(self.activity_log, stretch=1)
        layout.addWidget(clear)

        return group

    def _build_log_group(self) -> QWidget:
        group = QGroupBox("System log")
        layout = QVBoxLayout(group)

        self.log_edit = QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMaximumHeight(150)

        clear_log_button = QPushButton("Clear log")
        clear_log_button.setObjectName("secondaryButton")
        clear_log_button.clicked.connect(lambda: self.log_edit.setPlainText(""))

        layout.addWidget(self.log_edit)
        layout.addWidget(clear_log_button, alignment=Qt.AlignmentFlag.AlignRight)

        return group

    def _load_interfaces(self) -> None:
        previous = self.interface_combo.currentData()
        self.interface_combo.clear()

        interfaces = get_available_interfaces()

        if not interfaces:
            self.interface_combo.addItem("No interfaces found", None)
            self.interface_combo.setEnabled(False)
            self.start_live_button.setEnabled(False)

            self._append_log(
                "No network interfaces found. Install Npcap, restart Windows, then run EVTA as Administrator."
            )
            return

        self.interface_combo.setEnabled(True)
        self.start_live_button.setEnabled(True)

        for interface_name, display_text in interfaces:
            self.interface_combo.addItem(display_text, interface_name)

        if previous:
            set_combo_by_data(self.interface_combo, previous)

        self._append_log(f"Loaded {len(interfaces)} available network interface(s).")

    def _browse_input(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select EV PCAP",
            "",
            "PCAP Files (*.pcap *.pcapng);;All Files (*)",
        )

        if path:
            self.input_edit.setText(path)

    def _browse_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Select EVTA output CSV",
            "ev_ids_sentinel_live.csv",
            "CSV Files (*.csv)",
        )

        if path:
            self.output_edit.setText(path)

    def _toggle_llm_fields(self) -> None:
        enabled = bool(self.llm_enabled_combo.currentData())
        self.llm_model_combo.setEnabled(enabled)
        self.llm_tokens_combo.setEnabled(enabled)

    def _append_log(self, text: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self.log_edit.appendPlainText(f"[{stamp}] {text}")

    def _append_activity(self, text: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self.activity_log.appendPlainText(f"[{stamp}] {text}")

    def _validate_common(self) -> Optional[str]:
        if not self.output_edit.text().strip():
            return "Output CSV path is required."

        try:
            parse_packet_steps(str(self.partial_packet_combo.currentData()))
            parse_time_steps(str(self.partial_time_combo.currentData()))

        except Exception as exc:
            return f"Partial snapshot settings are invalid: {exc}"

        return None

    def _validate_live(self) -> Optional[str]:
        common = self._validate_common()

        if common:
            return common

        if not self.interface_combo.currentData():
            return (
                "No valid network interface is selected. "
                "Install Npcap, restart Windows, and run EVTA as Administrator."
            )

        return None

    def _validate_offline(self) -> Optional[str]:
        common = self._validate_common()

        if common:
            return common

        input_value = self.input_edit.text().strip()

        if not input_value:
            return "Offline extraction requires an input PCAP file."

        if not Path(input_value).expanduser().exists():
            return f"Input PCAP not found: {Path(input_value).expanduser()}"

        return None

    def _build_runtime_params(self, mode: str) -> dict:
        partial_config = PartialExportConfig(
            enabled=bool(self.partial_combo.currentData()),
            packet_steps=parse_packet_steps(str(self.partial_packet_combo.currentData())),
            time_steps=parse_time_steps(str(self.partial_time_combo.currentData())),
        )

        label_config = UserLabelConfig(
            binary_label=str(self.binary_label_combo.currentData() or ""),
            multiclass_label=str(self.multiclass_label_combo.currentData() or ""),
        )

        llm_config = LLMContextConfig(
            enabled=bool(self.llm_enabled_combo.currentData()),
            model_name=str(
                self.llm_model_combo.currentData() or DEFAULT_LLM_MODEL_NAME
            ),
            max_new_tokens=int(
                self.llm_tokens_combo.currentData() or DEFAULT_LLM_MAX_NEW_TOKENS
            ),
        )

        return {
            "mode": mode,
            "input_path": Path(self.input_edit.text()).expanduser()
            if self.input_edit.text().strip()
            else None,
            "interface": self.interface_combo.currentData(),
            "output_path": Path(self.output_edit.text()).expanduser(),
            "tcp_timeout": float(self.tcp_timeout_combo.currentData()),
            "udp_timeout": float(self.udp_timeout_combo.currentData()),
            "other_timeout": float(self.other_timeout_combo.currentData()),
            "bpf_filter": str(self.bpf_filter_combo.currentData() or ""),
            "duration": float(self.duration_combo.currentData() or 0.0),
            "max_packets": int(self.max_packets_combo.currentData() or 0),
            "poll_interval": float(
                self.poll_interval_combo.currentData() or DEFAULT_POLL_INTERVAL
            ),
            "promiscuous": bool(self.promiscuous_combo.currentData()),
            "profile": self.profile_combo.currentText(),
            "partial_config": partial_config,
            "host_window_seconds": float(self.host_window_combo.currentData()),
            "baseline_csv": None,
            "report_prefix": None,
            "label_config": label_config,
            "llm_config": llm_config,
        }

    def _start_live(self) -> None:
        error = self._validate_live()

        if error:
            QMessageBox.warning(self, "Invalid live configuration", error)
            return

        self._reset_dashboard()

        params = self._build_runtime_params("live")

        self.live_worker = LiveDashboardWorker(params)
        self.live_worker.row_ready.connect(self._handle_live_row)
        self.live_worker.stats_ready.connect(self._handle_live_stats)
        self.live_worker.log_ready.connect(self._append_log)
        self.live_worker.succeeded.connect(self._handle_live_success)
        self.live_worker.failed.connect(self._handle_live_failure)

        self.start_live_button.setEnabled(False)
        self.stop_live_button.setEnabled(True)
        self.run_offline_button.setEnabled(False)
        self.refresh_interfaces_button.setEnabled(False)

        self.status_label.setText("LIVE")
        self.status_label.setObjectName("statusLive")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

        self._append_activity(
            f"EVTA started monitoring {params['interface']}"
        )

        self.live_worker.start()

    def _stop_live(self) -> None:
        if self.live_worker is not None:
            self._append_log("Stop requested. Waiting for current capture poll to finish.")
            self._append_activity("Stop requested by user.")
            self.live_worker.stop()
            self.stop_live_button.setEnabled(False)

    def _run_offline(self) -> None:
        error = self._validate_offline()

        if error:
            QMessageBox.warning(self, "Invalid offline configuration", error)
            return

        params = self._build_runtime_params("offline")

        self.run_offline_button.setEnabled(False)
        self.start_live_button.setEnabled(False)
        self.refresh_interfaces_button.setEnabled(False)

        self._append_log(
            f"Starting offline extraction: {params['input_path']} → {params['output_path']}"
        )

        self.worker = ExtractionWorker(params)
        self.worker.succeeded.connect(self._handle_offline_success)
        self.worker.failed.connect(self._handle_offline_failure)
        self.worker.start()

    def _reset_dashboard(self) -> None:
        self.flow_table.setRowCount(0)
        self.activity_log.setPlainText("")

        self.alert_count = 0
        self.protocol_counts = Counter()
        self.label_counts = Counter()
        self.pps_history.clear()

        self.card_packets.set_value("0", "Captured packets")
        self.card_flows.set_value("0", "Exported flow rows")
        self.card_alerts.set_value("0", "Non-benign heuristic rows")
        self.card_rate.set_value("0.0 pps", "Packets per second")
        self.card_bytes.set_value("0 B", "Total exported bytes")
        self.card_top.set_value("-", "Most frequent heuristic label")

        self.traffic_picture.set_values([])
        self.protocol_picture.set_data({})
        self.label_picture.set_data({})
        self.alert_gauge.set_values(0, 0)

    def _handle_live_row(self, row: dict) -> None:
        label = str(row.get("heuristic_label") or "unknown")
        protocol = self._protocol_name(row.get("protocol"))

        self.label_counts[label] += 1
        self.protocol_counts[protocol] += 1

        if label not in {"benign", "benign_like", "normal"}:
            self.alert_count += 1

            src = self._endpoint(row, "src")
            dst = self._endpoint(row, "dst")
            score = self._fmt_float(row.get("heuristic_score"), 2)

            self._append_activity(f"ALERT {label} score={score}: {src} → {dst}")

        self.protocol_picture.set_data(dict(self.protocol_counts))
        self.label_picture.set_data(dict(self.label_counts))

        self._insert_flow_row(row)

    def _insert_flow_row(self, row: dict) -> None:
        row_index = 0
        self.flow_table.insertRow(row_index)

        total_packets = int(float(row.get("total_fwd_packets") or 0)) + int(
            float(row.get("total_bwd_packets") or 0)
        )

        total_bytes = int(float(row.get("total_fwd_bytes") or 0)) + int(
            float(row.get("total_bwd_bytes") or 0)
        )

        values = [
            self._format_ts(row.get("flow_end_ts") or row.get("flow_start_ts")),
            self._endpoint(row, "src"),
            self._endpoint(row, "dst"),
            self._protocol_name(row.get("protocol")),
            str(total_packets),
            self._format_bytes(total_bytes),
            str(row.get("heuristic_label") or "-"),
            self._fmt_float(row.get("heuristic_score"), 2),
            str(row.get("heuristic_reasons") or "-")[:180],
        ]

        for col, value in enumerate(values):
            item = QTableWidgetItem(value)

            if col in {3, 4, 5, 7}:
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            self.flow_table.setItem(row_index, col, item)

        while self.flow_table.rowCount() > self.recent_rows_limit:
            self.flow_table.removeRow(self.flow_table.rowCount() - 1)

    def _handle_live_stats(self, stats: dict) -> None:
        packets = int(stats.get("packets") or 0)
        flows = int(stats.get("flows") or stats.get("row_count") or 0)
        alerts = int(stats.get("alerts") or self.alert_count)
        pps = float(stats.get("pps") or 0.0)
        elapsed = float(stats.get("elapsed") or 0.0)
        bytes_total = int(stats.get("bytes") or 0)

        if "protocol_counts" in stats:
            self.protocol_counts = Counter(stats.get("protocol_counts") or {})
            self.protocol_picture.set_data(dict(self.protocol_counts))

        if "label_counts" in stats:
            self.label_counts = Counter(stats.get("label_counts") or {})
            self.label_picture.set_data(dict(self.label_counts))

        self.pps_history.append(pps)

        self.card_packets.set_value(f"{packets:,}", f"Elapsed {elapsed:.1f}s")

        self.card_flows.set_value(
            f"{flows:,}",
            f"Saved to {Path(str(stats.get('output_path', self.output_edit.text()))).name}",
        )

        self.card_alerts.set_value(f"{alerts:,}", "Non-benign heuristic rows")
        self.card_rate.set_value(f"{pps:.1f} pps", "Packets per second")
        self.card_bytes.set_value(self._format_bytes(bytes_total), "Total exported bytes")
        self.card_top.set_value(
            str(stats.get("top_label") or "-"),
            "Most frequent heuristic label",
        )

        self.traffic_picture.set_values(self.pps_history)
        self.alert_gauge.set_values(alerts, flows)

    def _handle_live_success(self, summary: dict) -> None:
        self.start_live_button.setEnabled(True)
        self.stop_live_button.setEnabled(False)
        self.run_offline_button.setEnabled(True)
        self.refresh_interfaces_button.setEnabled(True)

        self.status_label.setText("IDLE")
        self.status_label.setObjectName("statusIdle")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

        self._append_log(
            f"Live capture finished. Packets={summary.get('packets')}, rows={summary.get('row_count')}, output={summary.get('output_path')}"
        )
        self._append_activity("EVTA live monitor stopped.")

    def _handle_live_failure(self, error: str) -> None:
        self.start_live_button.setEnabled(True)
        self.stop_live_button.setEnabled(False)
        self.run_offline_button.setEnabled(True)
        self.refresh_interfaces_button.setEnabled(True)

        self.status_label.setText("IDLE")
        self.status_label.setObjectName("statusIdle")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

        self._append_log(f"Live capture error: {error}")
        QMessageBox.critical(self, "Live capture failed", error)

    def _handle_offline_success(self, summary: dict) -> None:
        self.run_offline_button.setEnabled(True)
        self.start_live_button.setEnabled(True)
        self.refresh_interfaces_button.setEnabled(True)

        self._append_log(
            f"Offline extraction completed. Rows={summary.get('row_count')}, output={summary.get('output_path')}"
        )

        QMessageBox.information(
            self,
            "Extraction completed",
            "Offline extraction finished successfully.",
        )

    def _handle_offline_failure(self, error: str) -> None:
        self.run_offline_button.setEnabled(True)
        self.start_live_button.setEnabled(True)
        self.refresh_interfaces_button.setEnabled(True)

        self._append_log(f"Offline extraction error: {error}")
        QMessageBox.critical(self, "Extraction failed", error)

    def closeEvent(self, event) -> None:  # pragma: no cover
        if self.live_worker is not None and self.live_worker.isRunning():
            self.live_worker.stop()
            self.live_worker.wait(3000)

        super().closeEvent(event)

    @staticmethod
    def _endpoint(row: dict, prefix: str) -> str:
        ip = row.get(f"{prefix}_ip") or "-"
        port = row.get(f"{prefix}_port") or "0"
        return f"{ip}:{port}"

    @staticmethod
    def _protocol_name(value: object) -> str:
        try:
            proto = int(float(value or 0))
        except Exception:
            return str(value or "-")

        return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))

    @staticmethod
    def _format_ts(value: object) -> str:
        try:
            return time.strftime("%H:%M:%S", time.localtime(float(value)))
        except Exception:
            return "-"

    @staticmethod
    def _fmt_float(value: object, digits: int = 2) -> str:
        try:
            return f"{float(value):.{digits}f}"
        except Exception:
            return "-"

    @staticmethod
    def _format_bytes(value: int) -> str:
        units = ["B", "KB", "MB", "GB", "TB"]
        size = float(value)

        for unit in units:
            if size < 1024.0 or unit == units[-1]:
                return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"

            size /= 1024.0

        return f"{value} B"


_GUI_APP = None
_GUI_WINDOW = None


def launch_gui() -> int:
    global _GUI_APP, _GUI_WINDOW

    _GUI_APP = QApplication.instance() or QApplication([])
    _GUI_APP.setStyle("Fusion")
    _GUI_APP.setStyleSheet(APP_STYLE)

    _GUI_WINDOW = MainWindow()
    _GUI_WINDOW.show()

    return _GUI_APP.exec()


def main() -> int:
    return launch_gui()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())