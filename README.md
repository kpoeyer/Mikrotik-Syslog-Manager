# MikroTik Syslog Manager

Een professionele syslog-server met grafische interface voor **MikroTik RouterOS**, met realtime monitoring, dreigingsdetectie en DNS-verkeersanalyse.

> ⚠️ **Disclaimer:** Uitsluitend voor privégebruik. Aan het gebruik van deze tool kunnen geen rechten worden ontleend.

---

## Functies

| Functie | Beschrijving |
|---|---|
| **Live Logboek** | Realtime syslog-weergave (UDP/TCP) met kleurcodering per severity, zoeken, snelfilters en weergavemodi |
| **Dreigingsanalyse** | Automatische detectie van brute-force inlogpogingen en firewall drops in een sorteerbare tabel |
| **Verkeer & Grafieken** | Visuele dashboards met top-8 domeinen en actiefste clients (vereist `matplotlib`) |
| **Domeinen & IP's** | DNS-resolutie-overzicht per domein; dubbelklik om direct in het logboek te zoeken |
| **Apparaten & DHCP** | Client-overzicht met query-statistieken; importeer hostnamen via de MikroTik REST API |
| **Export & Rapportage** | Exporteer naar `.txt`/`.csv` of genereer een professioneel HTML security-auditrapport |
| **Live bestandslogging** | Schrijf inkomende berichten realtime weg naar een `.log`-bestand |

---

## Installatie

**Vereisten:** Python 3.8+ met `tkinter` (standaard meegeleverd op Windows/macOS).

```bash
# Optioneel: virtuele omgeving
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# Optioneel: grafieken inschakelen
pip install matplotlib
```

> **Linux:** installeer tkinter indien nodig via `sudo apt install python3-tk`.

---

## Gebruik

```bash
python Mikrotik-Syslog-Manager.py
```

1. Vul het **Router IP** en gewenste **poort** in (standaard `514`).
2. Vink **UDP** en/of **TCP** aan en klik op **▶ Start Server**.
3. Configureer je MikroTik-router om logs naar deze PC te sturen — gebruik hiervoor het menu **Hulpmiddelen → MikroTik setup & commando's...**, of voer handmatig uit in de MikroTik-terminal:

```routeros
/system/logging/action/set remote target=remote remote=<IP-van-deze-PC> remote-port=514
/system/logging/add action=remote topics=!debug
```

4. Gebruik **Stuur Testbericht** om de verbinding te verifiëren.

---

## Tests

```bash
python -m unittest tests.test_sorting
```

---

## Projectstructuur

| Bestand | Omschrijving |
|---|---|
| `Mikrotik-Syslog-Manager.py` | Hoofdapplicatie (GUI + syslog-server) |
| `tests/test_sorting.py` | Unit-tests voor sorteerlogica |
| `exe.bat` | Build-script voor een standalone Windows `.exe` via PyInstaller |

---

## Licentie

Vrij te gebruiken en aan te passen voor eigen beheer- en analysedoeleinden.

*Gemaakt door CdR & KvP*
