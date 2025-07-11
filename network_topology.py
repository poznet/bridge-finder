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