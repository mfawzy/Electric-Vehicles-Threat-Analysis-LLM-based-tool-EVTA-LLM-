from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass(frozen=True, order=True)
class Endpoint:
    ip: str
    port: int


@dataclass(frozen=True)
class CanonicalFlowKey:
    ep1: Endpoint
    ep2: Endpoint
    protocol: int


@dataclass
class PacketInfo:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    ip_total_len: int
    header_len: int
    payload_len: int
    ttl: int
    tcp_window: int
    tcp_seq: Optional[int]
    tcp_ackno: Optional[int]
    tcp_flags: int
    raw_payload: bytes


@dataclass
class DirectionState:
    packet_times: List[float] = field(default_factory=list)
    packet_sizes: List[int] = field(default_factory=list)
    bytes_total: int = 0
    header_bytes: int = 0
    payload_bytes: int = 0
    seq_seen: Set[Tuple[int, int]] = field(default_factory=set)
    max_seq_end: int = -1
    last_ack_number: Optional[int] = None
    ack_repeat_count: int = 0


@dataclass
class TLSStats:
    version: int = 0
    sni_present: int = 0
    sni_len: int = 0
    cipher_suites_count: int = 0
    extensions_count: int = 0
    first_client_hello_ts: Optional[float] = None
    first_server_hello_ts: Optional[float] = None
    client_hello_seen: int = 0
    server_hello_seen: int = 0
    record_count: int = 0

    def handshake_duration(self) -> float:
        if self.first_client_hello_ts is None or self.first_server_hello_ts is None:
            return 0.0
        return max(self.first_server_hello_ts - self.first_client_hello_ts, 0.0)


@dataclass
class DNSStats:
    query_count: int = 0
    qnames: Set[str] = field(default_factory=set)
    nxdomain_responses: int = 0
    response_count: int = 0
    answer_ttls: List[int] = field(default_factory=list)


@dataclass
class ExportMetadata:
    export_reason: str = "flow_end"
    snapshot_kind: str = "final"
    packets_seen_at_export: int = 0
    is_partial_snapshot: int = 0


@dataclass
class PartialExportConfig:
    enabled: bool = False
    packet_steps: Tuple[int, ...] = field(default_factory=tuple)
    time_steps: Tuple[float, ...] = field(default_factory=tuple)


@dataclass
class UserLabelConfig:
    binary_label: str = ""
    multiclass_label: str = ""


@dataclass
class LLMContextConfig:
    enabled: bool = False
    model_name: str = "Qwen/Qwen2.5-0.5B-Instruct"
    max_new_tokens: int = 96
    prompt_style: str = "analyst"


@dataclass
class FlowEmission:
    rows: List[Dict[str, object]] = field(default_factory=list)
    completed: int = 0
