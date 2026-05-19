from pathlib import Path
import dpkt
from ev_ids_sentinel.pipeline import extract_rows

base = Path('/home/ubuntu/ev_ids_sentinel_tool')
path = base / 'test_sll2.pcap'

tcp = dpkt.tcp.TCP(sport=12345, dport=80, seq=1, flags=dpkt.tcp.TH_SYN, win=64240)
tcp.off = 5
ip = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=dpkt.ip.IP_PROTO_TCP, ttl=64)
ip.v = 4
ip.hl = 5
ip.data = tcp
ip.len = 20 + len(tcp)
sll2 = dpkt.sll2.SLL2(ethtype=dpkt.ethernet.ETH_TYPE_IP, mbz=0, intindex=1, hrd=1, type=0, hlen=6, hdr=b'\x00\x11\x22\x33\x44\x55\x00\x00', data=ip)
with path.open('wb') as fh:
    writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_LINUX_SLL2)
    writer.writepkt(bytes(sll2), ts=1.0)
rows = extract_rows(path, tcp_timeout=120.0, udp_timeout=60.0, other_timeout=30.0)
print(path.name, len(rows), rows[0]['total_fwd_packets'], rows[0]['total_fwd_bytes'], rows[0]['syn_count'])
