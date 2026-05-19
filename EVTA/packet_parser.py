"""Packet parsing functions for PCAP and PCAPNG inputs."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Optional, Tuple

import dpkt

from .models import PacketInfo

SUPPORTED_DATALINKS = {
    dpkt.pcap.DLT_EN10MB,
    dpkt.pcap.DLT_LINUX_SLL,
    dpkt.pcap.DLT_LINUX_SLL2,
    dpkt.pcap.DLT_NULL,
    dpkt.pcap.DLT_LOOP,
    dpkt.pcap.DLT_RAW,
}


def _decode_network_layer(buf: bytes, datalink: int):
    try:
        if datalink == dpkt.pcap.DLT_EN10MB:
            frame = dpkt.ethernet.Ethernet(buf)
            return frame.data
        if datalink == dpkt.pcap.DLT_LINUX_SLL:
            frame = dpkt.sll.SLL(buf)
            return frame.data
        if datalink == dpkt.pcap.DLT_LINUX_SLL2:
            frame = dpkt.sll2.SLL2(buf)
            return frame.data
        if datalink in (dpkt.pcap.DLT_NULL, dpkt.pcap.DLT_LOOP):
            frame = dpkt.loopback.Loopback(buf)
            return frame.data
        if datalink == dpkt.pcap.DLT_RAW:
            version = buf[0] >> 4
            if version == 4:
                return dpkt.ip.IP(buf)
            if version == 6:
                return dpkt.ip6.IP6(buf)
            return None
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
        return None
    return None


def parse_packet(ts: float, buf: bytes, datalink: int) -> Optional[PacketInfo]:
    ip = _decode_network_layer(buf, datalink)
    if ip is None:
        return None

    if isinstance(ip, dpkt.ip.IP):
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        protocol = ip.p
        ttl = int(ip.ttl)
        ip_total_len = int(ip.len) if ip.len else len(bytes(ip))
        header_len = int(ip.hl) * 4
        transport = ip.data
    elif isinstance(ip, dpkt.ip6.IP6):
        src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
        protocol = ip.nxt
        ttl = int(ip.hlim)
        ip_total_len = int(ip.plen) + 40
        header_len = 40
        transport = ip.data
    else:
        return None

    src_port = 0
    dst_port = 0
    tcp_window = 0
    tcp_seq = None
    tcp_ackno = None
    tcp_flags = 0
    raw_payload = b""
    payload_len = 0

    if protocol == 6 and isinstance(transport, dpkt.tcp.TCP):
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
        tcp_window = int(transport.win)
        tcp_seq = int(transport.seq)
        tcp_ackno = int(transport.ack)
        tcp_flags = int(transport.flags)
        raw_payload = bytes(transport.data)
        tcp_header_len = int(transport.off) * 4
        payload_len = max(ip_total_len - header_len - tcp_header_len, 0)
        header_len += tcp_header_len
    elif protocol == 17 and isinstance(transport, dpkt.udp.UDP):
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
        raw_payload = bytes(transport.data)
        udp_header_len = 8
        payload_len = max(ip_total_len - header_len - udp_header_len, 0)
        header_len += udp_header_len
    else:
        raw_payload = bytes(getattr(transport, "data", b"")) if hasattr(transport, "data") else b""
        payload_len = max(ip_total_len - header_len, 0)

    return PacketInfo(
        ts=float(ts),
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


def open_pcap_reader(path: Path) -> Tuple[object, object, int]:
    with path.open("rb") as f:
        magic = f.read(4)
    fh = path.open("rb")
    try:
        if magic in (b"\x0a\x0d\x0d\x0a", b"\x4d\x3c\x2b\x1a"):
            reader = dpkt.pcapng.Reader(fh)
        else:
            reader = dpkt.pcap.Reader(fh)

        datalink_attr = getattr(reader, "datalink")
        datalink = datalink_attr() if callable(datalink_attr) else int(datalink_attr)
        return fh, reader, int(datalink)
    except (ValueError, dpkt.dpkt.NeedData, AttributeError) as exc:
        fh.close()
        raise ValueError(f"Unsupported or corrupted capture file: {path}") from exc
