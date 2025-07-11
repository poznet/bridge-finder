#!/bin/bash
echo "🔍 Szczegółowe wykrywanie mostka"
echo "================================"

# 1. Sprawdź tablice ARP
echo -e "\n1. Tablice ARP - szukam duplikatów MAC:"
arp -a | sort -k4 | awk '{print $4, $2}' | uniq -d

# 2. Sprawdź routing
echo -e "\n2. Tablica routingu:"
netstat -rn | grep -E "192.168.[12]"

# 3. Ping do drugiej sieci
echo -e "\n3. Test ping do drugiej sieci:"
ping -c 1 192.168.2.1 2>/dev/null && echo "✅ Sieci są połączone!"

# 4. Traceroute
echo -e "\n4. Śledzenie trasy:"
traceroute -n -m 5 192.168.2.1 2>/dev/null | grep -v "* * *"

echo -e "\n5. Uruchom detektor mostków:"
echo "sudo python main_simple.py --bridge-interactive"