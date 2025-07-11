#!/usr/bin/env python3
import argparse
import sys
import os
from tabulate import tabulate
from network_topology import NetworkTopology
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
        sys.exit(0)
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    try:
        if '/' in args.target:
            topology = analyze_network_segment(args.target)
        else:
            topology = analyze_single_target(args.target)
        
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