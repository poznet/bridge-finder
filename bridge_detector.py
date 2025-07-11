import subprocess
import re
from typing import List, Dict, Optional
from collections import defaultdict
from packet_utils import PacketUtils
from ttl_analyzer import TTLAnalyzer
import ipaddress

class BridgeDetector:
    def __init__(self):
        self.packet_utils = PacketUtils()
        self.ttl_analyzer = TTLAnalyzer()
    
    def simple_detect(self, networks: List[str]) -> Dict:
        print(f"\n🔍 Wykrywanie mostków...")
        print(f"Sieci: {', '.join(networks)}")
        
        results = {
            'networks': networks,
            'bridge_found': False,
            'bridge_devices': [],
            'anomalies': []
        }
        
        print("1️⃣ Sprawdzam dostępność...")
        reachable_hosts = self._check_reachability(networks)
        
        if not reachable_hosts:
            print("❌ Brak aktywnych hostów!")
            return results
        
        print("2️⃣ Analiza TTL...")
        ttl_analysis = self._analyze_ttl(reachable_hosts)
        
        print("3️⃣ Sprawdzam ARP...")
        arp_analysis = self._analyze_arp(networks)
        
        print("4️⃣ Test komunikacji...")
        comm_test = self._test_communication(networks)
        
        print("\n" + "=" * 50)
        print("📊 WYNIKI:")
        
        if ttl_analysis['anomalies'] or arp_analysis['bridges'] or comm_test['connected']:
            results['bridge_found'] = True
            results['bridge_devices'] = list(set(
                ttl_analysis.get('suspicious_hosts', []) +
                arp_analysis.get('bridges', []) +
                comm_test.get('bridge_candidates', [])
            ))
            
            print("✅ WYKRYTO MOSTKI!")
            for device in results['bridge_devices']:
                print(f"  • {device}")
        else:
            print("❌ Nie wykryto mostków")
        
        return results
    
    def _check_reachability(self, networks: List[str]) -> Dict[str, Dict]:
        reachable = {}
        for network in networks:
            print(f"  Skanowanie {network}...")
            net = ipaddress.ip_network(network, strict=False)
            hosts_to_check = list(net.hosts())[:10]
            
            for ip in hosts_to_check:
                result = self.packet_utils.send_ping(str(ip), timeout=1)
                if result:
                    ip_addr, ttl = result
                    reachable[ip_addr] = {
                        'ttl': ttl,
                        'network': network,
                        'os_guess': self.ttl_analyzer.detect_os(ttl)[0]
                    }
        
        print(f"  Znaleziono {len(reachable)} hostów")
        return reachable
    
    def _analyze_ttl(self, hosts: Dict[str, Dict]) -> Dict:
        analysis = {'anomalies': [], 'suspicious_hosts': []}
        
        by_network = defaultdict(list)
        for ip, info in hosts.items():
            by_network[info['network']].append((ip, info['ttl']))
        
        for network, host_list in by_network.items():
            ttls = [ttl for _, ttl in host_list]
            if ttls:
                unique_ttls = set(ttls)
                if len(unique_ttls) > 1:
                    max_diff = max(ttls) - min(ttls)
                    if max_diff <= 1:
                        analysis['anomalies'].append(
                            f"Sieć {network}: podobne TTL - mostek L2?"
                        )
        
        networks = list(by_network.keys())
        if len(networks) >= 2:
            for ip1, info1 in hosts.items():
                for ip2, info2 in hosts.items():
                    if info1['network'] != info2['network']:
                        if info1['ttl'] == info2['ttl']:
                            analysis['anomalies'].append(
                                f"Identyczne TTL: {ip1} i {ip2}"
                            )
                            analysis['suspicious_hosts'].extend([ip1, ip2])
        
        return analysis
    
    def _analyze_arp(self, networks: List[str]) -> Dict:
        analysis = {'bridges': [], 'suspicious_entries': []}
        
        try:
            arp_output = subprocess.getoutput("arp -a")
            mac_to_ips = defaultdict(list)
            
            for line in arp_output.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17}|[0-9a-fA-F-]{17})', line)
                if match:
                    ip, mac = match.groups()
                    mac = mac.lower().replace('-', ':')
                    mac_to_ips[mac].append(ip)
            
            for mac, ips in mac_to_ips.items():
                networks_for_mac = set()
                for ip in ips:
                    for network in networks:
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False):
                            networks_for_mac.add(network)
                
                if len(networks_for_mac) > 1:
                    analysis['bridges'].append(f"MAC {mac}")
                    analysis['suspicious_entries'].append(
                        f"MAC {mac} w wielu sieciach"
                    )
        except Exception as e:
            print(f"  Błąd ARP: {e}")
        
        return analysis
    
    def _test_communication(self, networks: List[str]) -> Dict:
        test_result = {'connected': False, 'bridge_candidates': []}
        
        if len(networks) < 2:
            return test_result
        
        try:
            net1 = ipaddress.ip_network(networks[0], strict=False)
            net2 = ipaddress.ip_network(networks[1], strict=False)
            
            router1 = str(net1.network_address + 1)
            router2 = str(net2.network_address + 1)
            
            traceroute_output = subprocess.getoutput(f"traceroute -n -m 5 -w 1 {router2}")
            hops = len([l for l in traceroute_output.split('\n') if re.search(r'^\s*\d+', l)])
            
            if hops <= 2 and "* * *" not in traceroute_output:
                test_result['connected'] = True
                
                for line in traceroute_output.split('\n'):
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        ip = match.group(1)
                        if ip != router1 and ip != router2:
                            test_result['bridge_candidates'].append(ip)
        except Exception as e:
            print(f"  Błąd testu: {e}")
        
        return test_result
    
    def generate_report(self, results: Dict, filename: str = "bridge_report.txt"):
        with open(filename, 'w') as f:
            f.write("RAPORT MOSTKÓW\n")
            f.write("=" * 30 + "\n\n")
            f.write(f"Sieci: {', '.join(results['networks'])}\n")
            f.write(f"Status: {'WYKRYTO' if results['bridge_found'] else 'NIE WYKRYTO'}\n\n")
            
            if results['bridge_devices']:
                f.write("Mostki:\n")
                for device in results['bridge_devices']:
                    f.write(f"  - {device}\n")
            
            if results['anomalies']:
                f.write("\nAnomalie:\n")
                for anomaly in results['anomalies']:
                    f.write(f"  - {anomaly}\n")
        
        print(f"\n📄 Raport: {filename}")

def interactive_mode():
    print("\n🌉 WYKRYWANIE MOSTKÓW")
    print("Podaj sieci do sprawdzenia:")
    
    networks = []
    while True:
        network = input(f"Sieć {len(networks) + 1} (lub 'koniec'): ").strip()
        if network.lower() == 'koniec':
            break
        try:
            ipaddress.ip_network(network, strict=False)
            networks.append(network)
        except ValueError:
            print("❌ Błędny format")
    
    if len(networks) < 2:
        print("❌ Potrzebujesz min. 2 sieci!")
        return
    
    detector = BridgeDetector()
    results = detector.simple_detect(networks)
    
    if input("\nZapisać raport? (t/n): ").lower() == 't':
        detector.generate_report(results)

if __name__ == "__main__":
    interactive_mode()