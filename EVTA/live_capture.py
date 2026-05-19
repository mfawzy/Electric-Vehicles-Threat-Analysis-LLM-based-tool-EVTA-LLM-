import time
from pathlib import Path
from typing import Callable, Optional

from .drift import write_drift_outputs
from .exporter import CsvRowWriter, columns_for_profile
from .flows import FlowManager
from .heuristics import apply_heuristics
from .host_window import OnlineHostWindowAggregator
from .llm_context import LocalQwenContextGenerator, apply_llm_context
from .models import LLMContextConfig, PacketInfo, UserLabelConfig
from .readiness import apply_readiness_scores
from .utils import apply_user_labels


def is_windows_l2_capture_unavailable(error: Exception) -> bool:
    """
    Detect Scapy Windows Layer-2 capture errors caused by missing Npcap/WinPcap.
    """
    text = str(error).lower()

    return (
        "winpcap is not installed" in text
        or "npcap" in text
        or "not available at layer 2" in text
        or "conf.l3socket" in text
        or "l3socket" in text
        or "layer-2" in text
        or "layer 2" in text
    )


def windows_capture_fix_message(original_error: Optional[Exception] = None) -> str:
    """
    Clear Windows fix message for EV-IDS Sentinel live monitoring.

    EV-IDS Sentinel needs real Layer-2 packet capture on Windows.
    That requires Npcap. Layer-3 fallback is intentionally not used because
    it is limited, does not properly support BPF filters, and often still
    requires Administrator privileges.
    """

    message = (
        "EV-IDS Sentinel live monitoring requires Npcap on Windows.\n\n"
        "Fix:\n"
        "1. Install Npcap.\n"
        "2. During installation, enable:\n"
        "   Install Npcap in WinPcap API-compatible Mode\n"
        "3. Restart your computer.\n"
        "4. Open Command Prompt, PowerShell, or PyCharm as Administrator.\n"
        "5. Run EV-IDS Sentinel again.\n\n"
        "To check your interfaces, run:\n"
        "py -c \"from scapy.all import show_interfaces; show_interfaces()\"\n\n"
        "Then use the exact interface name shown, such as Ethernet or Wi-Fi."
    )

    if original_error is not None:
        message += f"\n\nOriginal Scapy error:\n{original_error}"

    return message


def sniff_with_windows_fallback(
    *,
    interface: str,
    packet_callback: Callable,
    timeout: float,
    bpf_filter: str = "",
    promiscuous: bool = True,
    allow_l3_fallback: bool = False,
    log_callback: Optional[Callable[[str], None]] = None,
) -> str:
    """
    Run Scapy live capture.

    On Windows, EV-IDS Sentinel requires Npcap for real Layer-2 live traffic
    monitoring. Layer-3 fallback is disabled because it is limited, does not
    support BPF filters properly, and usually requires Administrator privileges.

    Returns:
        "layer2" if capture works.
    """

    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError(
            "Live capture requires Scapy.\n\n"
            "Install it with:\n"
            "py -m pip install scapy"
        ) from exc

    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            store=False,
            timeout=timeout,
            filter=bpf_filter or None,
            promisc=promiscuous,
        )
        return "layer2"

    except Exception as exc:
        if is_windows_l2_capture_unavailable(exc):
            if log_callback is not None:
                log_callback("Npcap/WinPcap is missing or unavailable.")
            raise RuntimeError(windows_capture_fix_message(exc)) from exc

        raise


def packetinfo_from_scapy(packet) -> Optional[PacketInfo]:
    """
    Convert a Scapy packet into the internal PacketInfo format.
    """

    try:
        from scapy.layers.dns import DNS
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
    except ImportError as exc:
        raise RuntimeError(
            "Live capture requires Scapy.\n\n"
            "Install it with:\n"
            "py -m pip install scapy"
        ) from exc

    if IP in packet:
        ip = packet[IP]
        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
        protocol = int(ip.proto)
        ttl = int(getattr(ip, "ttl", 0))
        ip_total_len = int(getattr(ip, "len", 0) or len(bytes(ip)))
        ip_header_words = getattr(ip, "ihl", None)
        header_len = int(ip_header_words or 5) * 4

    elif IPv6 in packet:
        ip = packet[IPv6]
        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
        protocol = int(getattr(ip, "nh", 0))
        ttl = int(getattr(ip, "hlim", 0))
        payload_len_ipv6 = int(getattr(ip, "plen", 0))
        ip_total_len = payload_len_ipv6 + 40 if payload_len_ipv6 else len(bytes(ip))
        header_len = 40

    else:
        return None

    src_port = 0
    dst_port = 0
    tcp_window = 0
    tcp_seq = None
    tcp_ackno = None
    tcp_flags = 0
    raw_payload = b""
    payload_len = max(ip_total_len - header_len, 0)

    if TCP in packet:
        tcp = packet[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_window = int(getattr(tcp, "window", 0))
        tcp_seq = int(getattr(tcp, "seq", 0))
        tcp_ackno = int(getattr(tcp, "ack", 0))
        tcp_flags = int(tcp.flags)

        tcp_header_len = int(getattr(tcp, "dataofs", None) or 5) * 4
        raw_payload = bytes(tcp.payload) if bytes(tcp.payload) else b""
        payload_len = max(ip_total_len - header_len - tcp_header_len, 0)
        header_len += tcp_header_len

    elif UDP in packet:
        udp = packet[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)

        raw_payload = bytes(udp.payload) if bytes(udp.payload) else b""
        udp_header_len = 8
        payload_len = max(ip_total_len - header_len - udp_header_len, 0)
        header_len += udp_header_len

    elif DNS in packet:
        raw_payload = bytes(packet[DNS])

    ts = float(getattr(packet, "time", time.time()))

    return PacketInfo(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        ip_total_len=ip_total_len,
        header_len=header_len,
        payload_len=payload_len,
        ttl=ttl,
        tcp_window=tcp_window,
        tcp_seq=tcp_seq,
        tcp_ackno=tcp_ackno,
        tcp_flags=tcp_flags,
        raw_payload=raw_payload,
    )


class LiveFlowExporter:
    """
    Handles live packet-to-flow conversion and exports rows to CSV.
    """

    def __init__(
        self,
        output_path: Path,
        tcp_timeout: float,
        udp_timeout: float,
        other_timeout: float,
        profile: str,
        partial_config=None,
        host_window_seconds: float = 60.0,
        label_config: Optional[UserLabelConfig] = None,
        llm_config: Optional[LLMContextConfig] = None,
        row_callback: Optional[Callable[[dict], None]] = None,
    ):
        self.output_path = output_path

        self.manager = FlowManager(
            tcp_timeout=tcp_timeout,
            udp_timeout=udp_timeout,
            other_timeout=other_timeout,
            partial_config=partial_config,
        )

        self.host_window = OnlineHostWindowAggregator(
            window_seconds=host_window_seconds
        )

        self.writer = CsvRowWriter(
            output_path,
            columns_for_profile(profile),
        )

        self.processed_packets = 0
        self.exported_rows = 0
        self.label_config = label_config
        self.row_callback = row_callback

        self.llm_generator = (
            LocalQwenContextGenerator(llm_config)
            if llm_config and llm_config.enabled
            else None
        )

    def __enter__(self) -> "LiveFlowExporter":
        self.writer.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.flush_all()
        finally:
            self.writer.__exit__(exc_type, exc, tb)

    def handle_packetinfo(self, pkt: PacketInfo) -> None:
        self.processed_packets += 1
        emission = self.manager.update(pkt)
        self._export_rows(emission.rows)

    def handle_scapy_packet(self, packet) -> None:
        pkt = packetinfo_from_scapy(packet)

        if pkt is None:
            return

        self.handle_packetinfo(pkt)

    def flush_expired(self, current_ts: Optional[float] = None) -> None:
        now_ts = time.time() if current_ts is None else current_ts
        emission = self.manager.expire(now_ts)
        self._export_rows(emission.rows)

    def flush_all(self) -> None:
        emission = self.manager.flush()
        self._export_rows(emission.rows)

    def _export_rows(self, rows) -> None:
        for row in rows:
            row = self.host_window.enrich_row(dict(row))
            row = apply_readiness_scores(dict(row))
            row = apply_heuristics(row)
            row = apply_llm_context(row, generator=self.llm_generator)
            row = apply_user_labels(row, label_config=self.label_config)

            self.writer.write_row(row)
            self.exported_rows += 1

            if self.row_callback is not None:
                self.row_callback(dict(row))


def run_live_capture_to_csv(
    interface: str,
    output_path: Path,
    tcp_timeout: float,
    udp_timeout: float,
    other_timeout: float,
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
    label_config: Optional[UserLabelConfig] = None,
    llm_config: Optional[LLMContextConfig] = None,
    row_callback: Optional[Callable[[dict], None]] = None,
) -> int:
    """
    Capture live traffic from an interface and export flow features to CSV.
    """

    start = time.time()

    with LiveFlowExporter(
        output_path=output_path,
        tcp_timeout=tcp_timeout,
        udp_timeout=udp_timeout,
        other_timeout=other_timeout,
        profile=profile,
        partial_config=partial_config,
        host_window_seconds=host_window_seconds,
        label_config=label_config,
        llm_config=llm_config,
        row_callback=row_callback,
    ) as exporter:

        while True:
            remaining_duration = 0.0

            if duration > 0:
                remaining_duration = duration - (time.time() - start)

                if remaining_duration <= 0:
                    break

            timeout = poll_interval

            if duration > 0:
                timeout = min(timeout, max(remaining_duration, 0.01))

            sniff_with_windows_fallback(
                interface=interface,
                packet_callback=exporter.handle_scapy_packet,
                timeout=timeout,
                bpf_filter=bpf_filter,
                promiscuous=promiscuous,
            )

            exporter.flush_expired(time.time())

            if max_packets > 0 and exporter.processed_packets >= max_packets:
                break

        exporter.flush_all()
        row_count = exporter.exported_rows

    if baseline_csv is not None and report_prefix is not None:
        write_drift_outputs(baseline_csv, output_path, report_prefix)

    return row_count