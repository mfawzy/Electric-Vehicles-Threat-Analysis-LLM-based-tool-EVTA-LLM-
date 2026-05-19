from pathlib import Path
import dpkt
from ev_ids_sentinel.pipeline import extract_rows

base = Path('/home/ubuntu/ev_ids_sentinel_tool')
eth_pcap = base / 'test_eth.pcap'
raw_pcap = base / 'test_raw.pcap'

# Build a minimal IPv4 TCP SYN packet.
tcp = dpkt.tcp.TCP(sport=12345, dport=80, seq=1, flags=dpkt.tcp.TH_SYN, win=64240)
tcp.off = 5
ip = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=dpkt.ip.IP_PROTO_TCP, ttl=64)
ip.v = 4
ip.hl = 5
ip.data = tcp
ip.len = 20 + len(tcp)
eth = dpkt.ethernet.Ethernet(dst=b'\xaa\xbb\xcc\xdd\xee\xff', src=b'\x11\x22\x33\x44\x55\x66', type=dpkt.ethernet.ETH_TYPE_IP, data=ip)

with eth_pcap.open('wb') as fh:
    writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
    writer.writepkt(bytes(eth), ts=1.0)

with raw_pcap.open('wb') as fh:
    writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_RAW)
    writer.writepkt(bytes(ip), ts=1.0)

for path in [eth_pcap, raw_pcap]:
    rows = extract_rows(path, tcp_timeout=120.0, udp_timeout=60.0, other_timeout=30.0)
    print(path.name, len(rows), rows[0]['total_fwd_packets'], rows[0]['total_fwd_bytes'], rows[0]['syn_count'])
