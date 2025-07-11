from scapy.all import IP, ICMP, sr1, sr, conf
import time
from typing import Optional, List, Tuple, Dict
from ipaddress import ip_network

conf.verb = 0

class PacketUtils:
    @staticmethod
    def send_ping(target: str, ttl: int = 64, timeout: int = 2) -> Optional[Tuple[str, int]]:
        try:
            packet = IP(dst=target, ttl=ttl) / ICMP()
            reply = sr1(packet, timeout=timeout, verbose=0)
            if reply:
                return (reply.src, reply.ttl)
            return None
        except Exception as e:
            print(f"Błąd: {e}")
            return None
    
    @staticmethod
    def traceroute(target: str, max_hops: int = 30, timeout: int = 2) -> List[Dict]:
        results = []
        for ttl in range(1, max_hops + 1):
            start_time = time.time()
            packet = IP(dst=target, ttl=ttl) / ICMP()
            reply = sr1(packet, timeout=timeout, verbose=0)
            rtt = (time.time() - start_time) * 1000
            
            if reply:
                hop_info = {
                    'hop': ttl,
                    'ip': reply.src,
                    'rtt': round(rtt, 2),
                    'ttl': reply.ttl
                }
                results.append(hop_info)
                if reply.src == target:
                    break
            else:
                results.append({
                    'hop': ttl,
                    'ip': '*',
                    'rtt': None,
                    'ttl': None
                })
        return results
    
    @staticmethod
    def scan_network_range(network: str, timeout: int = 1) -> List[Dict]:
        active_hosts = []
        for ip in ip_network(network, strict=False):
            result = PacketUtils.send_ping(str(ip), timeout=timeout)
            if result:
                ip_addr, ttl = result
                active_hosts.append({'ip': ip_addr, 'ttl': ttl})
        return active_hosts