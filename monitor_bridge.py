#!/usr/bin/env python3
from scapy.all import *
import time
import ipaddress

def get_network_input():
    """Pobiera adresy sieci od użytkownika"""
    print("🌐 Monitor ruchu między sieciami")
    print("=" * 40)
    
    networks = []
    while len(networks) < 2:
        try:
            network = input(f"Podaj sieć {len(networks) + 1} (np. 192.168.1.0/24): ").strip()
            ipaddress.ip_network(network, strict=False)
            networks.append(network)
        except ValueError:
            print("❌ Nieprawidłowy format sieci")
    
    return networks[0], networks[1]

def monitor_cross_network_traffic(interface="en0", network1=None, network2=None):
    """Monitoruje ruch między sieciami"""
    if not network1 or not network2:
        network1, network2 = get_network_input()
    
    # Wyciągnij prefiks sieci
    net1_prefix = str(ipaddress.ip_network(network1, strict=False).network_address).rsplit('.', 1)[0] + '.'
    net2_prefix = str(ipaddress.ip_network(network2, strict=False).network_address).rsplit('.', 1)[0] + '.'
    
    print(f"\n🔍 Monitoruję ruch między {network1} i {network2}")
    print("Naciśnij Ctrl+C aby zatrzymać\n")
    
    bridges = set()
    packet_count = 0
    
    def packet_handler(pkt):
        nonlocal packet_count
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            # Sprawdź czy pakiet przechodzi między sieciami
            if (src.startswith(net1_prefix) and dst.startswith(net2_prefix)) or \
               (src.startswith(net2_prefix) and dst.startswith(net1_prefix)):
                
                packet_count += 1
                
                # Zapisz MAC źródłowy jako potencjalny mostek
                if Ether in pkt:
                    mac = pkt[Ether].src
                    if mac not in bridges:
                        bridges.add(mac)
                        print(f"✅ Znaleziono mostek: MAC {mac}")
                        print(f"   Pakiet: {src} → {dst}")
                    else:
                        print(f"   [{packet_count}] {src} → {dst}")
    
    try:
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print(f"\n\n📊 Podsumowanie:")
        print(f"  Pakietów między sieciami: {packet_count}")
        print(f"  Znalezione mostki: {len(bridges)}")
        for mac in bridges:
            print(f"  • {mac}")
    except Exception as e:
        print(f"❌ Błąd: {e}")
        print("Spróbuj z sudo: sudo python monitor_bridge.py")

if __name__ == "__main__":
    monitor_cross_network_traffic()