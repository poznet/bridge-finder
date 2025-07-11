# Instrukcja dla Sonneta - Narzędzie analizy topologii sieci

**WAŻNE**: Oszczędzaj tokeny! Implementuj kod bez zbędnych komentarzy i opisów.

## Cel
Stwórz narzędzie do analizy topologii sieci przez TTL + wykrywanie mostków między sieciami.

TTL: Linux/Mac=64, Windows=128, Cisco=255. Każdy router zmniejsza o 1.

## 1. Przygotowanie środowiska

### requirements.txt
```
scapy==2.5.0
networkx==3.1
matplotlib==3.7.1
tabulate==0.9.0
pyvis==0.3.2
```
Uruchom: `pip install -r requirements.txt`
WAŻNE: Wymaga sudo/admin do ICMP

## 2. ttl_analyzer.py

```python
import platform
from typing import Dict, Tuple, Optional

class TTLAnalyzer:
    DEFAULT_TTL_VALUES = {
        64: ["Linux", "macOS", "Android"],
        128: ["Windows"],
        255: ["Cisco IOS", "Solaris"]
    }
    
    @staticmethod
    def detect_os(ttl: int) -> Tuple[str, int]:
        for default_ttl in sorted(TTLAnalyzer.DEFAULT_TTL_VALUES.keys()):
            if ttl <= default_ttl:
                systems = TTLAnalyzer.DEFAULT_TTL_VALUES[default_ttl]
                return (systems[0], default_ttl)
        return ("Unknown", 255)
    
    @staticmethod
    def calculate_hop_count(ttl: int, initial_ttl: Optional[int] = None) -> int:
        if initial_ttl:
            return initial_ttl - ttl
        _, estimated_initial = TTLAnalyzer.detect_os(ttl)
        return estimated_initial - ttl
    
    @staticmethod
    def get_local_ttl() -> int:
        system = platform.system()
        if system == "Windows":
            return 128
        elif system in ["Linux", "Darwin"]:
            return 64
        else:
            return 64
```


## 3. packet_utils.py

```python
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
```


## 4. network_topology.py

```python
import networkx as nx
from typing import Dict, List, Tuple, Optional
from ttl_analyzer import TTLAnalyzer
from packet_utils import PacketUtils
import socket
import json
from networkx.readwrite import json_graph

class NetworkTopology:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.ttl_analyzer = TTLAnalyzer()
        self.packet_utils = PacketUtils()
        self.local_ip = self._get_local_ip()
        
    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def map_path_to_target(self, target: str) -> Dict:
        trace_results = self.packet_utils.traceroute(target)
        self.graph.add_node(self.local_ip, type='source', os='Local')
        
        previous_ip = self.local_ip
        for hop in trace_results:
            if hop['ip'] != '*':
                os_guess, _ = self.ttl_analyzer.detect_os(hop['ttl'])
                self.graph.add_node(
                    hop['ip'],
                    type='router' if hop['hop'] < len(trace_results) else 'target',
                    os=os_guess,
                    ttl=hop['ttl'],
                    hop_number=hop['hop']
                )
                self.graph.add_edge(
                    previous_ip,
                    hop['ip'],
                    weight=hop['rtt'] if hop['rtt'] else 0,
                    hop=hop['hop']
                )
                previous_ip = hop['ip']
        
        return {
            'target': target,
            'total_hops': len(trace_results),
            'path': trace_results,
            'graph': self.graph
        }
    
    def analyze_network_segment(self, network: str) -> Dict:
        active_hosts = self.packet_utils.scan_network_range(network)
        topology_info = {
            'network': network,
            'active_hosts': len(active_hosts),
            'hosts': []
        }
        
        for host in active_hosts:
            hop_count = self.ttl_analyzer.calculate_hop_count(host['ttl'])
            os_guess, _ = self.ttl_analyzer.detect_os(host['ttl'])
            
            host_info = {
                'ip': host['ip'],
                'ttl': host['ttl'],
                'estimated_hops': hop_count,
                'probable_os': os_guess
            }
            topology_info['hosts'].append(host_info)
            
            self.graph.add_node(
                host['ip'],
                type='host',
                os=os_guess,
                ttl=host['ttl'],
                hops_away=hop_count
            )
        
        return topology_info
    
    def find_shortest_path(self, source: str, target: str) -> Optional[List[str]]:
        try:
            return nx.shortest_path(self.graph, source, target)
        except nx.NetworkXNoPath:
            return None
    
    def get_network_stats(self) -> Dict:
        return {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'average_degree': sum(dict(self.graph.degree()).values()) / self.graph.number_of_nodes() if self.graph.number_of_nodes() > 0 else 0,
            'is_connected': nx.is_weakly_connected(self.graph)
        }
    
    def export_to_json(self, filename: str):
        data = json_graph.node_link_data(self.graph)
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

    def export_to_graphml(self, filename: str):
        nx.write_graphml(self.graph, filename)
```


## 5. visualization.py

```python
import matplotlib.pyplot as plt
import networkx as nx
from typing import Dict, Optional
import matplotlib.patches as mpatches
from pyvis.network import Network

class NetworkVisualizer:
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph
        
    def draw_topology(self, title: str = "Topologia sieci", 
                     save_path: Optional[str] = None,
                     show_labels: bool = True):
        plt.figure(figsize=(12, 8))
        
        node_colors = []
        node_sizes = []
        
        for node in self.graph.nodes():
            node_type = self.graph.nodes[node].get('type', 'unknown')
            if node_type == 'source':
                node_colors.append('green')
                node_sizes.append(1000)
            elif node_type == 'target':
                node_colors.append('red')
                node_sizes.append(1000)
            elif node_type == 'router':
                node_colors.append('blue')
                node_sizes.append(700)
            else:
                node_colors.append('gray')
                node_sizes.append(500)
        
        pos = self._hierarchical_layout()
        
        nx.draw(self.graph, pos,
                node_color=node_colors,
                node_size=node_sizes,
                with_labels=show_labels,
                font_size=8,
                font_weight='bold',
                arrows=True,
                arrowsize=20,
                edge_color='gray',
                width=2)
        
        source_patch = mpatches.Patch(color='green', label='Źródło')
        target_patch = mpatches.Patch(color='red', label='Cel')
        router_patch = mpatches.Patch(color='blue', label='Router')
        host_patch = mpatches.Patch(color='gray', label='Host')
        
        plt.legend(handles=[source_patch, target_patch, router_patch, host_patch],
                  loc='upper right')
        plt.title(title, fontsize=16, fontweight='bold')
        plt.axis('off')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    def _hierarchical_layout(self):
        levels = {}
        for node in self.graph.nodes():
            hop = self.graph.nodes[node].get('hop_number', 
                   self.graph.nodes[node].get('hops_away', 0))
            if hop not in levels:
                levels[hop] = []
            levels[hop].append(node)
        
        pos = {}
        y_gap = 1.0
        
        for level, nodes in sorted(levels.items()):
            x_gap = 2.0 / (len(nodes) + 1)
            for i, node in enumerate(nodes):
                pos[node] = ((i + 1) * x_gap - 1.0, -level * y_gap)
        
        return pos
    
    def draw_hop_distribution(self, save_path: Optional[str] = None):
        hop_counts = {}
        for node in self.graph.nodes():
            hops = self.graph.nodes[node].get('hops_away', 0)
            hop_counts[hops] = hop_counts.get(hops, 0) + 1
        
        plt.figure(figsize=(10, 6))
        plt.bar(hop_counts.keys(), hop_counts.values(), color='skyblue', edgecolor='black')
        plt.xlabel('Liczba skoków od źródła')
        plt.ylabel('Liczba hostów')
        plt.title('Rozkład liczby skoków w sieci')
        plt.grid(True, alpha=0.3)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    def draw_os_distribution(self, save_path: Optional[str] = None):
        os_counts = {}
        for node in self.graph.nodes():
            os = self.graph.nodes[node].get('os', 'Unknown')
            os_counts[os] = os_counts.get(os, 0) + 1
        
        plt.figure(figsize=(10, 6))
        plt.pie(os_counts.values(), labels=os_counts.keys(), autopct='%1.1f%%',
                startangle=90, colors=plt.cm.Set3.colors)
        plt.title('Rozkład systemów operacyjnych w sieci')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    def create_interactive_html(self, output_file: str = "network_topology.html"):
        net = Network(height="750px", width="100%", directed=True)
        
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            color = {
                'source': 'green',
                'target': 'red',
                'router': 'blue',
                'host': 'gray'
            }.get(node_data.get('type', 'unknown'), 'gray')
            
            label = f"{node}\n{node_data.get('os', 'Unknown')}"
            net.add_node(node, label=label, color=color)
        
        for edge in self.graph.edges():
            net.add_edge(edge[0], edge[1])
        
        net.barnes_hut()
        net.show(output_file)
        print(f"Interaktywna wizualizacja zapisana w: {output_file}")
```


## 6. main.py

```python
#!/usr/bin/env python3
import argparse
import sys
import os
from tabulate import tabulate
from network_topology import NetworkTopology
from visualization import NetworkVisualizer
from ttl_analyzer import TTLAnalyzer
from bridge_detector import BridgeDetector, interactive_mode

def check_privileges():
    if os.name == 'posix' and os.geteuid() != 0:
        print("UWAGA: Wymaga sudo")
        sys.exit(1)

def analyze_single_target(target: str):
    print(f"\nAnalizuję trasę do: {target}")
    print("-" * 50)
    
    topology = NetworkTopology()
    result = topology.map_path_to_target(target)
    
    print("\nTrasa pakietów:")
    headers = ["Skok", "Adres IP", "RTT (ms)", "TTL", "System"]
    table_data = []
    
    for hop in result['path']:
        if hop['ip'] != '*':
            os_guess, _ = TTLAnalyzer.detect_os(hop['ttl'])
            table_data.append([
                hop['hop'],
                hop['ip'],
                hop['rtt'],
                hop['ttl'],
                os_guess
            ])
        else:
            table_data.append([hop['hop'], '*', '*', '*', '*'])
    
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    stats = topology.get_network_stats()
    print(f"\nStatystyki:")
    print(f"  Całkowita liczba skoków: {result['total_hops']}")
    print(f"  Węzłów w grafie: {stats['total_nodes']}")
    
    return topology

def analyze_network_segment(network: str):
    print(f"\nSkanowanie sieci: {network}")
    print("-" * 50)
    
    topology = NetworkTopology()
    result = topology.analyze_network_segment(network)
    
    print(f"\nZnaleziono {result['active_hosts']} aktywnych hostów")
    
    headers = ["Adres IP", "TTL", "Szac. skoków", "Prawdopodobny OS"]
    table_data = []
    
    for host in result['hosts']:
        table_data.append([
            host['ip'],
            host['ttl'],
            host['estimated_hops'],
            host['probable_os']
        ])
    
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    return topology

def main():
    parser = argparse.ArgumentParser(
        description="Narzędzie do analizy topologii sieci na podstawie TTL"
    )
    
    parser.add_argument(
        'target',
        nargs='?',
        help='Adres IP lub hostname celu (lub zakres sieci np. 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '-v', '--visualize',
        action='store_true',
        help='Wizualizuj topologię'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Ścieżka do zapisania wizualizacji'
    )
    
    parser.add_argument(
        '-e', '--export',
        choices=['json', 'graphml'],
        help='Eksportuj topologię do pliku'
    )
    
    parser.add_argument(
        '--export-file',
        default='topology',
        help='Nazwa pliku do eksportu (bez rozszerzenia)'
    )
    
    parser.add_argument(
        '-b', '--bridge-detect',
        nargs='+',
        metavar='NETWORK',
        help='Wykryj mostki między podanymi sieciami (np. -b 192.168.1.0/24 192.168.2.0/24)'
    )

    parser.add_argument(
        '--bridge-interactive',
        action='store_true',
        help='Uruchom interaktywny tryb wykrywania mostków'
    )
    
    args = parser.parse_args()
    
    check_privileges()
    
    # Tryb wykrywania mostków
    if args.bridge_interactive:
        interactive_mode()
        sys.exit(0)

    if args.bridge_detect:
        detector = BridgeDetector()
        results = detector.simple_detect(args.bridge_detect)
        
        if args.output:
            detector.generate_report(results, args.output)
        
        sys.exit(0)
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    try:
        if '/' in args.target:
            topology = analyze_network_segment(args.target)
        else:
            topology = analyze_single_target(args.target)
        
        if args.visualize or args.output:
            visualizer = NetworkVisualizer(topology.graph)
            visualizer.draw_topology(
                title=f"Topologia: {args.target}",
                save_path=args.output
            )
            
            if args.output:
                base_name = args.output.rsplit('.', 1)[0]
                visualizer.draw_hop_distribution(f"{base_name}_hops.png")
                visualizer.draw_os_distribution(f"{base_name}_os.png")
        
        if args.export:
            if args.export == 'json':
                topology.export_to_json(f"{args.export_file}.json")
                print(f"\nEksportowano do: {args.export_file}.json")
            elif args.export == 'graphml':
                topology.export_to_graphml(f"{args.export_file}.graphml")
                print(f"\nEksportowano do: {args.export_file}.graphml")
        
    except KeyboardInterrupt:
        print("\n\nPrzerwano przez użytkownika")
    except Exception as e:
        print(f"\nBłąd: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

## 7. Testowanie

```bash
# Podstawowe
sudo python main.py google.com
sudo python main.py 8.8.8.8 -v
sudo python main.py 192.168.1.0/24

# Wykrywanie mostków
sudo python main.py --bridge-interactive
sudo python main.py -b 192.168.1.0/24 192.168.2.0/24
```

## 8. Problemy i bezpieczeństwo

- **Permission denied**: Użyj sudo
- **No route to host**: Sprawdź połączenie
- **Brak odpowiedzi ICMP**: Normalne dla niektórych routerów
- **Bezpieczeństwo**: Używaj tylko w swojej sieci!

## 9. bridge_detector.py - GŁÓWNA FUNKCJA WYKRYWANIA MOSTKÓW

### Krok 10.1: Utwórz plik bridge_detector.py

Ten moduł pozwala wykryć ukryte połączenia między segmentami sieci. Jest **prosty w obsłudze** - wystarczy podać zakresy sieci do sprawdzenia.

```python
import subprocess
import re
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
from packet_utils import PacketUtils
from ttl_analyzer import TTLAnalyzer
from tabulate import tabulate
import ipaddress

class BridgeDetector:
    """
    Wykrywa mostki (połączenia) między segmentami sieci.
    Prosta w obsłudze klasa do znajdowania ukrytych połączeń.
    """
    
    def __init__(self):
        self.packet_utils = PacketUtils()
        self.ttl_analyzer = TTLAnalyzer()
        self.arp_cache = {}
        self.ttl_anomalies = []
        self.potential_bridges = []
    
    def simple_detect(self, networks: List[str]) -> Dict:
        """
        GŁÓWNA FUNKCJA - Prosta detekcja mostków między sieciami
        
        Args:
            networks: Lista sieci do sprawdzenia, np. ['192.168.1.0/24', '192.168.2.0/24']
            
        Returns:
            Słownik z wynikami analizy
        """
        print(f"\n🔍 Rozpoczynam wykrywanie mostków między sieciami...")
        print(f"Analizowane sieci: {', '.join(networks)}")
        print("-" * 60)
        
        results = {
            'networks': networks,
            'bridge_found': False,
            'bridge_devices': [],
            'anomalies': [],
            'recommendations': []
        }
        
        # Krok 1: Sprawdź dostępność sieci
        print("\n1️⃣ Sprawdzam dostępność sieci...")
        reachable_hosts = self._check_network_reachability(networks)
        
        if not reachable_hosts:
            print("❌ Nie znaleziono aktywnych hostów w podanych sieciach!")
            results['recommendations'].append("Sprawdź czy sieci są dostępne z tego hosta")
            return results
        
        # Krok 2: Analiza TTL
        print("\n2️⃣ Analizuję wartości TTL...")
        ttl_analysis = self._analyze_ttl_patterns(reachable_hosts)
        
        # Krok 3: Sprawdź tablice ARP
        print("\n3️⃣ Sprawdzam tablice ARP...")
        arp_analysis = self._analyze_arp_tables(networks)
        
        # Krok 4: Test komunikacji między sieciami
        print("\n4️⃣ Testuję komunikację między sieciami...")
        cross_network_test = self._test_cross_network_communication(networks)
        
        # Krok 5: Podsumowanie
        print("\n" + "=" * 60)
        print("📊 WYNIKI ANALIZY:")
        print("=" * 60)
        
        # Analiza wyników
        if ttl_analysis['anomalies'] or arp_analysis['bridges'] or cross_network_test['connected']:
            results['bridge_found'] = True
            results['bridge_devices'] = list(set(
                ttl_analysis.get('suspicious_hosts', []) +
                arp_analysis.get('bridges', []) +
                cross_network_test.get('bridge_candidates', [])
            ))
            
            print(f"\n✅ WYKRYTO POŁĄCZENIE MIĘDZY SIECIAMI!")
            print(f"\nPotencjalne urządzenia mostkujące:")
            for device in results['bridge_devices']:
                print(f"  • {device}")
        else:
            print(f"\n❌ Nie wykryto bezpośredniego połączenia między sieciami")
        
        # Szczegóły anomalii
        if ttl_analysis['anomalies']:
            print(f"\n🔸 Anomalie TTL:")
            for anomaly in ttl_analysis['anomalies']:
                print(f"  • {anomaly}")
                results['anomalies'].append(anomaly)
        
        if arp_analysis['suspicious_entries']:
            print(f"\n🔸 Podejrzane wpisy ARP:")
            for entry in arp_analysis['suspicious_entries']:
                print(f"  • {entry}")
                results['anomalies'].append(entry)
        
        # Rekomendacje
        self._generate_recommendations(results)
        
        if results['recommendations']:
            print(f"\n💡 Rekomendacje:")
            for rec in results['recommendations']:
                print(f"  • {rec}")
        
        return results
    
    def _check_network_reachability(self, networks: List[str]) -> Dict[str, Dict]:
        """Sprawdza które hosty są osiągalne"""
        reachable = {}
        
        for network in networks:
            print(f"  Skanowanie {network}...")
            # Sprawdź kilka pierwszych hostów dla szybkości
            net = ipaddress.ip_network(network, strict=False)
            hosts_to_check = list(net.hosts())[:10]  # Pierwsze 10 hostów
            
            for ip in hosts_to_check:
                result = self.packet_utils.send_ping(str(ip), timeout=1)
                if result:
                    ip_addr, ttl = result
                    reachable[ip_addr] = {
                        'ttl': ttl,
                        'network': network,
                        'os_guess': self.ttl_analyzer.detect_os(ttl)[0]
                    }
        
        print(f"  Znaleziono {len(reachable)} aktywnych hostów")
        return reachable
    
    def _analyze_ttl_patterns(self, hosts: Dict[str, Dict]) -> Dict:
        """Analizuje wzorce TTL w poszukiwaniu anomalii"""
        analysis = {
            'anomalies': [],
            'suspicious_hosts': []
        }
        
        # Grupuj hosty według sieci
        by_network = defaultdict(list)
        for ip, info in hosts.items():
            by_network[info['network']].append((ip, info['ttl']))
        
        # Szukaj nietypowych wartości TTL
        for network, host_list in by_network.items():
            ttls = [ttl for _, ttl in host_list]
            if ttls:
                # Jeśli wszystkie TTL są identyczne w sieci lokalnej, to normalne
                # Jeśli są różnice > 1, może wskazywać na routing
                unique_ttls = set(ttls)
                if len(unique_ttls) > 1:
                    max_diff = max(ttls) - min(ttls)
                    if max_diff <= 1:
                        # Małe różnice - prawdopodobnie ta sama sieć
                        analysis['anomalies'].append(
                            f"Sieć {network}: minimalne różnice TTL ({unique_ttls}) - możliwy mostek L2"
                        )
        
        # Sprawdź komunikację między sieciami
        networks = list(by_network.keys())
        if len(networks) >= 2:
            # Jeśli widzimy hosty z różnych sieci z podobnym TTL
            for ip1, info1 in hosts.items():
                for ip2, info2 in hosts.items():
                    if info1['network'] != info2['network']:
                        ttl_diff = abs(info1['ttl'] - info2['ttl'])
                        if ttl_diff == 0:
                            analysis['anomalies'].append(
                                f"Hosty {ip1} i {ip2} z różnych sieci mają identyczne TTL={info1['ttl']}"
                            )
                            analysis['suspicious_hosts'].extend([ip1, ip2])
        
        return analysis
    
    def _analyze_arp_tables(self, networks: List[str]) -> Dict:
        """Analizuje tablice ARP w poszukiwaniu mostków"""
        analysis = {
            'bridges': [],
            'suspicious_entries': []
        }
        
        # Pobierz tablicę ARP
        try:
            arp_output = subprocess.getoutput("arp -a")
            
            # Parsuj wpisy ARP
            mac_to_ips = defaultdict(list)
            ip_to_mac = {}
            
            for line in arp_output.split('\n'):
                # Różne formaty dla różnych systemów
                match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17}|[0-9a-fA-F-]{17})', line)
                if match:
                    ip, mac = match.groups()
                    mac = mac.lower().replace('-', ':')
                    mac_to_ips[mac].append(ip)
                    ip_to_mac[ip] = mac
            
            # Sprawdź czy ten sam MAC obsługuje IP z różnych sieci
            for mac, ips in mac_to_ips.items():
                networks_for_mac = set()
                for ip in ips:
                    for network in networks:
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False):
                            networks_for_mac.add(network)
                
                if len(networks_for_mac) > 1:
                    analysis['bridges'].append(f"MAC {mac} (IP: {', '.join(ips)})")
                    analysis['suspicious_entries'].append(
                        f"MAC {mac} obsługuje IP z sieci: {', '.join(networks_for_mac)}"
                    )
            
        except Exception as e:
            print(f"  Błąd podczas analizy ARP: {e}")
        
        return analysis
    
    def _test_cross_network_communication(self, networks: List[str]) -> Dict:
        """Testuje bezpośrednią komunikację między sieciami"""
        test_result = {
            'connected': False,
            'bridge_candidates': []
        }
        
        if len(networks) < 2:
            return test_result
        
        # Próbuj ping między sieciami
        try:
            net1 = ipaddress.ip_network(networks[0], strict=False)
            net2 = ipaddress.ip_network(networks[1], strict=False)
            
            # Test: router z sieci 1 do routera sieci 2
            router1 = str(net1.network_address + 1)  # Zazwyczaj .1
            router2 = str(net2.network_address + 1)
            
            # Sprawdź trasę
            traceroute_output = subprocess.getoutput(f"traceroute -n -m 5 -w 1 {router2}")
            
            # Jeśli osiągamy cel w 1-2 skokach, sieci są połączone
            hops = len([l for l in traceroute_output.split('\n') if re.search(r'^\s*\d+', l)])
            
            if hops <= 2 and "* * *" not in traceroute_output:
                test_result['connected'] = True
                
                # Znajdź urządzenie pośredniczące
                for line in traceroute_output.split('\n'):
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        ip = match.group(1)
                        if ip != router1 and ip != router2:
                            test_result['bridge_candidates'].append(ip)
        
        except Exception as e:
            print(f"  Błąd podczas testu komunikacji: {e}")
        
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
```

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
```


## 10. Przykłady użycia

```bash
# Podstawowe wykrywanie mostków
sudo python main.py -b 192.168.1.0/24 192.168.2.0/24

# Tryb interaktywny (najprostszy!)
sudo python main.py --bridge-interactive

# Wiele sieci
sudo python main.py -b 192.168.1.0/24 192.168.2.0/24 10.0.0.0/24
```

## 11. Rozszerzenia

- Integracja z bazą danych
- Monitoring w czasie rzeczywistym
- API REST
- IPv6
- Analiza wydajności

## Podsumowanie

**OSZCZĘDZANIE TOKENÓW**: Implementuj bez zbędnych komentarzy!

Narzędzie:
- Mapuje topologię przez TTL
- Wykrywa mostki między sieciami  
- Wizualizuje wyniki
- Eksportuje dane

**UŻYCIE**: `sudo python main.py --bridge-interactive`