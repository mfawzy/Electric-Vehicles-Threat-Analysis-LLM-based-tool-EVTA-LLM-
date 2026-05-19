"""Minimal TLS parsing helpers for extracting handshake metadata."""

from __future__ import annotations

import struct
from typing import Dict, List


class TLSReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read_u8(self) -> int:
        if self.remaining() < 1:
            raise ValueError
        val = self.data[self.pos]
        self.pos += 1
        return val

    def read_u16(self) -> int:
        if self.remaining() < 2:
            raise ValueError
        val = struct.unpack("!H", self.data[self.pos : self.pos + 2])[0]
        self.pos += 2
        return val

    def read_u24(self) -> int:
        if self.remaining() < 3:
            raise ValueError
        chunk = self.data[self.pos : self.pos + 3]
        self.pos += 3
        return (chunk[0] << 16) | (chunk[1] << 8) | chunk[2]

    def read_bytes(self, n: int) -> bytes:
        if self.remaining() < n:
            raise ValueError
        val = self.data[self.pos : self.pos + n]
        self.pos += n
        return val

    def skip(self, n: int) -> None:
        _ = self.read_bytes(n)


def parse_tls_records(payload: bytes) -> List[Dict[str, object]]:
    events: List[Dict[str, object]] = []
    reader = TLSReader(payload)
    try:
        while reader.remaining() >= 5:
            content_type = reader.read_u8()
            version = reader.read_u16()
            length = reader.read_u16()
            if reader.remaining() < length:
                break
            body = reader.read_bytes(length)
            if content_type != 22:
                continue
            events.extend(parse_tls_handshake_messages(body, version))
    except ValueError:
        return events
    return events


def parse_tls_handshake_messages(body: bytes, outer_version: int) -> List[Dict[str, object]]:
    events: List[Dict[str, object]] = []
    reader = TLSReader(body)
    try:
        while reader.remaining() >= 4:
            handshake_type = reader.read_u8()
            msg_len = reader.read_u24()
            msg = reader.read_bytes(msg_len)
            if handshake_type == 1:
                events.append(parse_client_hello(msg, outer_version))
            elif handshake_type == 2:
                events.append(parse_server_hello(msg, outer_version))
    except ValueError:
        return events
    return events


def parse_client_hello(msg: bytes, outer_version: int) -> Dict[str, object]:
    event: Dict[str, object] = {
        "type": "client_hello",
        "version": outer_version,
        "sni": "",
        "cipher_suites_count": 0,
        "extensions_count": 0,
    }
    reader = TLSReader(msg)
    try:
        version = reader.read_u16()
        event["version"] = version
        reader.skip(32)
        session_len = reader.read_u8()
        reader.skip(session_len)
        cipher_len = reader.read_u16()
        cipher_bytes = reader.read_bytes(cipher_len)
        event["cipher_suites_count"] = len(cipher_bytes) // 2
        comp_len = reader.read_u8()
        reader.skip(comp_len)
        if reader.remaining() >= 2:
            ext_len = reader.read_u16()
            exts = TLSReader(reader.read_bytes(ext_len))
            ext_count = 0
            while exts.remaining() >= 4:
                ext_type = exts.read_u16()
                ext_size = exts.read_u16()
                ext_body = exts.read_bytes(ext_size)
                ext_count += 1
                if ext_type == 0:
                    sni = parse_sni_extension(ext_body)
                    if sni:
                        event["sni"] = sni
            event["extensions_count"] = ext_count
    except ValueError:
        return event
    return event


def parse_server_hello(msg: bytes, outer_version: int) -> Dict[str, object]:
    event: Dict[str, object] = {"type": "server_hello", "version": outer_version}
    reader = TLSReader(msg)
    try:
        version = reader.read_u16()
        event["version"] = version
    except ValueError:
        return event
    return event


def parse_sni_extension(data: bytes) -> str:
    reader = TLSReader(data)
    try:
        list_len = reader.read_u16()
        server_list = TLSReader(reader.read_bytes(list_len))
        while server_list.remaining() >= 3:
            name_type = server_list.read_u8()
            name_len = server_list.read_u16()
            name = server_list.read_bytes(name_len)
            if name_type == 0:
                return name.decode("utf-8", errors="ignore")
    except ValueError:
        return ""
    return ""
