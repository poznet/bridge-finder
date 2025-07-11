# 🌐 Skaner Topologii Sieci z Wykrywaniem Mostków

Narzędzie do analizy topologii sieci wykorzystujące TTL (Time To Live) oraz wykrywania ukrytych połączeń (mostków) między segmentami sieci.

## 📋 Spis treści
- [Funkcje](#-funkcje)
- [Instalacja](#-instalacja)
- [Podstawowe użycie](#-podstawowe-użycie)
- [Wykrywanie mostków](#-wykrywanie-mostków)
- [Monitorowanie ruchu](#-monitorowanie-ruchu)
- [Przykłady](#-przykłady)
- [Rozwiązywanie problemów](#-rozwiązywanie-problemów)

## 🚀 Funkcje

- **Analiza TTL** - wykrywanie liczby routerów na trasie
- **Identyfikacja systemów operacyjnych** - na podstawie domyślnych wartości TTL
- **Mapowanie topologii** - tworzenie mapy sieci
- **Wykrywanie mostków** - znajdowanie ukrytych połączeń między sieciami
- **Monitoring ruchu** - śledzenie pakietów między segmentami
- **Eksport danych** - JSON, GraphML

## 📦 Instalacja

### 1. Klonowanie repozytorium
```bash
git clone <repo-url>
cd skanersieci
```

### 2. Tworzenie środowiska wirtualnego
```bash
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# lub
venv\Scripts\activate  # Windows
```

### 3. Instalacja zależności

**Wersja pełna** (z wizualizacją):
```bash
pip install -r requirements.txt
```

**Wersja uproszczona** (bez wizualizacji, mniej problemów):
```bash
pip install -r requirements_simple.txt
```

## 🔧 Podstawowe użycie

### ⚠️ WAŻNE: Wymaga uprawnień administratora (sudo)

### 1. Analiza pojedynczego hosta
```bash
sudo python main.py google.com
```

Wyświetli:
- Trasę pakietów (jak traceroute)
- TTL na każdym skoku
- Prawdopodobny system operacyjny
- Liczbę skoków

### 2. Skanowanie sieci lokalnej
```bash
sudo python main.py 192.168.1.0/24
```

Pokaże:
- Aktywne hosty w sieci
- TTL każdego hosta
- Szacowaną odległość (liczbę skoków)
- Prawdopodobne systemy operacyjne

### 3. Wizualizacja topologii
```bash
# Wyświetl wykres
sudo python main.py google.com -v

# Zapisz do pliku
sudo python main.py 192.168.1.0/24 -o topologia.png
```

### 4. Eksport danych
```bash
# Format JSON
sudo python main.py 192.168.1.0/24 -e json

# Format GraphML (do Gephi, yEd)
sudo python main.py 192.168.1.0/24 -e graphml --export-file moja_siec
```

## 🌉 Wykrywanie mostków

### Tryb interaktywny (NAJPROSTSZY!)

```bash
sudo python main.py --bridge-interactive
```

Program poprowadzi Cię krok po kroku:
1. Poprosi o podanie sieci do sprawdzenia
2. Automatycznie przeanalizuje:
   - Dostępność hostów
   - Anomalie TTL
   - Tablice ARP
   - Komunikację między sieciami
3. Pokaże wyniki z emotikonami 📊

### Tryb bezpośredni

```bash
sudo python main.py -b 192.168.1.0/24 192.168.2.0/24
```

### Co wykrywa?

1. **Identyczne TTL** z różnych sieci → mostek warstwy 2 (switch/bridge)
2. **Ten sam MAC** dla IP z różnych sieci → urządzenie mostkujące
3. **Bezpośrednia komunikacja** między sieciami → aktywne połączenie

### Przykładowy wynik

```
🔍 Wykrywanie mostków...
Sieci: 192.168.1.0/24, 192.168.2.0/24

1️⃣ Sprawdzam dostępność...
  Skanowanie 192.168.1.0/24...
  Skanowanie 192.168.2.0/24...
  Znaleziono 15 hostów

2️⃣ Analiza TTL...
3️⃣ Sprawdzam ARP...
4️⃣ Test komunikacji...

==================================================
📊 WYNIKI:
✅ WYKRYTO MOSTKI!
  • MAC aa:bb:cc:dd:ee:ff
  • 192.168.1.50
  • 192.168.2.50
```

## 📡 Monitorowanie ruchu

### Monitor mostków (monitor_bridge.py)

```bash
sudo python monitor_bridge.py
```

Program zapyta o sieci do monitorowania, np.:
- Sieć 1: `192.168.1.0/24`
- Sieć 2: `192.168.0.0/24`

Następnie będzie wyświetlać:
```
🔍 Monitoruję ruch między 192.168.1.0/24 i 192.168.0.0/24

✅ Znaleziono mostek: MAC aa:bb:cc:dd:ee:ff
   Pakiet: 192.168.1.100 → 192.168.0.50
   [2] 192.168.0.50 → 192.168.1.100
   [3] 192.168.1.100 → 192.168.0.50
```

Zakończ przez Ctrl+C aby zobaczyć podsumowanie.

## 📚 Przykłady

### Scenariusz 1: Sprawdzenie czy dwie sieci są połączone

```bash
# Metoda 1: Interaktywna
sudo python main.py --bridge-interactive

# Metoda 2: Bezpośrednia
sudo python main.py -b 192.168.1.0/24 192.168.88.0/24

# Metoda 3: Monitoring ruchu
sudo python monitor_bridge.py
```

### Scenariusz 2: Pełna analiza sieci firmowej

```bash
# 1. Skanuj główną sieć
sudo python main.py 10.0.0.0/24 -o siec_glowna.png

# 2. Sprawdź połączenia z DMZ
sudo python main.py -b 10.0.0.0/24 10.0.100.0/24

# 3. Eksportuj do analizy
sudo python main.py 10.0.0.0/24 -e json --export-file topologia_firmy
```

### Scenariusz 3: Debugowanie problemów sieciowych

```bash
# Sprawdź trasę do problematycznego hosta
sudo python main.py 192.168.1.250

# Porównaj z działającym hostem
sudo python main.py 192.168.1.1

# Monitoruj ruch
sudo python monitor_bridge.py
```

## 🔍 Interpretacja wyników

### Wartości TTL i systemy operacyjne
- **TTL 64** → Linux, macOS, Android
- **TTL 128** → Windows
- **TTL 255** → Cisco IOS, routery

### Liczba skoków
- **0-1 skok** → ta sama sieć lokalna
- **2-5 skoków** → sieć firmowa/kampusowa
- **>10 skoków** → połączenie przez Internet

### Typy mostków
- **Mostek L2** → brak zmiany TTL, przepuszcza broadcast
- **Router** → zmniejsza TTL o 1, filtruje broadcast
- **Komputer-mostek** → 2 karty sieciowe, forwarding włączony

## ❗ Rozwiązywanie problemów

### "Permission denied"
```bash
# Zawsze używaj sudo
sudo python main.py [opcje]
```

### Problemy z matplotlib/numpy
```bash
# Użyj wersji uproszczonej
sudo python main_simple.py --bridge-interactive
```

### "No route to host"
- Sprawdź połączenie sieciowe
- Upewnij się, że cel jest osiągalny
- Niektóre routery blokują ICMP

### Brak wyników skanowania
- Firewall może blokować pakiety ICMP
- Spróbuj z krótszym timeoutem
- Użyj monitoringu pasywnego (monitor_bridge.py)

## 🛡️ Bezpieczeństwo

1. **Używaj tylko w swojej sieci** lub za zgodą administratora
2. **Nie skanuj obcych sieci** - może być traktowane jako atak
3. **Zachowaj ostrożność** przy wykrywaniu mostków - mogą być celowe
4. **Dokumentuj** swoje działania dla celów audytu

## 🔧 Zaawansowane opcje

### Własny zakres TTL
```python
# W kodzie ttl_analyzer.py można dodać własne wartości
DEFAULT_TTL_VALUES = {
    64: ["Linux", "macOS", "Android", "MojRouter"],
    # ...
}
```

### Zmiana interfejsu sieciowego
```python
# W monitor_bridge.py
monitor_cross_network_traffic(interface="eth0")  # Zmień z en0
```

## 📝 Licencja

Do użytku edukacyjnego i diagnostycznego. Nie używaj do nieautoryzowanego skanowania sieci.

## 🤝 Wsparcie

W razie problemów:
1. Sprawdź sekcję rozwiązywania problemów
2. Upewnij się, że używasz sudo
3. Spróbuj wersji uproszczonej (main_simple.py)

---

**Pamiętaj**: Zawsze przestrzegaj lokalnych przepisów i polityk bezpieczeństwa przy skanowaniu sieci!