from pathlib import Path
import csv
import dpkt
from scapy.layers.inet import IP, TCP
from ev_ids_sentinel.live_capture import LiveFlowExporter
from ev_ids_sentinel.pipeline import extract_rows_to_csv

base = Path('/home/ubuntu/ev_ids_sentinel_tool')
offline_pcap = base / 'dual_mode_test.pcap'
offline_csv = base / 'dual_mode_offline.csv'
live_csv = base / 'dual_mode_live.csv'

# Offline validation PCAP: simple TCP SYN and SYN-ACK exchange in Ethernet framing.
eth1 = dpkt.ethernet.Ethernet()
eth1.src = b'\xaa\xbb\xcc\xdd\xee\x01'
eth1.dst = b'\xaa\xbb\xcc\xdd\xee\x02'
eth1.type = dpkt.ethernet.ETH_TYPE_IP
tcp1 = dpkt.tcp.TCP(sport=12345, dport=80, seq=1, flags=dpkt.tcp.TH_SYN, win=64240)
tcp1.off = 5
ip1 = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=dpkt.ip.IP_PROTO_TCP, ttl=64)
ip1.v = 4
ip1.hl = 5
ip1.data = tcp1
ip1.len = 20 + len(tcp1)
eth1.data = ip1

eth2 = dpkt.ethernet.Ethernet()
eth2.src = b'\xaa\xbb\xcc\xdd\xee\x02'
eth2.dst = b'\xaa\xbb\xcc\xdd\xee\x01'
eth2.type = dpkt.ethernet.ETH_TYPE_IP
tcp2 = dpkt.tcp.TCP(sport=80, dport=12345, seq=10, ack=2, flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, win=65000)
tcp2.off = 5
ip2 = dpkt.ip.IP(src=b'\x0a\x00\x00\x02', dst=b'\x0a\x00\x00\x01', p=dpkt.ip.IP_PROTO_TCP, ttl=63)
ip2.v = 4
ip2.hl = 5
ip2.data = tcp2
ip2.len = 20 + len(tcp2)
eth2.data = ip2

with offline_pcap.open('wb') as fh:
    writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
    writer.writepkt(bytes(eth1), ts=1.0)
    writer.writepkt(bytes(eth2), ts=1.1)

rows_written = extract_rows_to_csv(
    input_path=offline_pcap,
    output_path=offline_csv,
    tcp_timeout=120.0,
    udp_timeout=60.0,
    other_timeout=30.0,
)

with offline_csv.open('r', encoding='utf-8', newline='') as fh:
    offline_rows = list(csv.DictReader(fh))

# Live validation without sniffing: feed Scapy packets directly into the live exporter.
with LiveFlowExporter(
    output_path=live_csv,
    tcp_timeout=120.0,
    udp_timeout=60.0,
    other_timeout=30.0,
) as exporter:
    p1 = IP(src='10.0.0.1', dst='10.0.0.2', ttl=64) / TCP(sport=22222, dport=443, flags='S', seq=1, window=64240)
    p1.time = 1.0
    p2 = IP(src='10.0.0.2', dst='10.0.0.1', ttl=63) / TCP(sport=443, dport=22222, flags='SA', seq=10, ack=2, window=65000)
    p2.time = 1.1
    exporter.handle_scapy_packet(p1)
    exporter.handle_scapy_packet(p2)

with live_csv.open('r', encoding='utf-8', newline='') as fh:
    live_rows = list(csv.DictReader(fh))

print('offline_rows_written', rows_written)
print('offline_csv_rows', len(offline_rows))
print('offline_first_syn_count', offline_rows[0]['syn_count'])
print('live_csv_rows', len(live_rows))
print('live_first_syn_count', live_rows[0]['syn_count'])
