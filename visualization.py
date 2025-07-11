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