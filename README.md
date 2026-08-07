# MikroTik Syslog Manager
gemaakt door CdR & KvP
Een professionele Syslog-server voor MikroTik RouterOS met een grafische interface, realtime analyse en beveiligingsmonitoring.
## Disclaimer alleen voor prive gebruik. er kunnen geen rechten ontleent worden aan het gebruik van deze tool ##
## Beschrijving

Dit project biedt een lokale syslog-server die syslog-berichten kan ontvangen via UDP en/of TCP. Het is speciaal gericht op MikroTik-logboeken en levert:

- Live syslog-visualisatie met donkere UI
- Realtime zoek- en filterfuncties
- Dreigingsdetectie voor brute-force pogingen en firewall drops
- DNS-resolutie-analyse voor netwerkdiagnose
- Grafieken van topdomeinen en actieve clients
- Export naar tekst, CSV en HTML security audit-rapporten
- Import van MikroTik DHCP-lease hostnamen voor duidelijke apparaattaal

## Belangrijkste functies

- `parse_syslog(text)`
  - Parseert een syslog-regel met PRI-header.
  - Retourneert facility, severity en de overgebleven tekst.

- `classify_dns(text)`
  - Detecteert MikroTik DNS-logregels.
  - Identificeert query-, done- en resource-record-regels.
  - Extraheert client, domein, querytype en IP-resultaat.

- `detect_local_ip(router_ip)`
  - Bepaalt het lokale IP-adres van de machine.
  - Probeert verbinding te maken naar het opgegeven router-IP of een publieke DNS-server.

- `_UDPHandler` en `_TCPHandler`
  - Netwerkhandlers voor inkomende syslog-berichten.
  - Plaatsen ontvangen regels in de interne `log_queue`.

- `MikroTikSyslogProApp` (appklasse)
  - Bouwt de GUI-opzet.
  - Start en stopt syslog-servers op UDP/TCP.
  - Verwerkt inkomende berichten en detecteert dreigingen.
  - Houdt DNS-data, apparaten en bedreigingslijsten bij.

- `self._handle_message(src, raw)`
  - Verwerkt elk binnenkomend bericht.
  - Parseert syslog-velden, classifyert DNS-activiteit en detecteert dreigingen.
  - Voegt het bericht toe aan de GUI en aan de interne opslag.

- `self._process_dns(item)`
  - Koppelt DNS-query's aan hun resultaten.
  - Bouwt overzichten op van domeinen, clients en unieke IP's.

- `self._refresh_view()`
  - Vernieuwt het logscherm op basis van zoektekst, filters en weergavemodus.

- `self._refresh_tabs()`
  - Ververs dreigings-, domein- en apparaatdatasets.
  - Vernieuwt grafieken wanneer Matplotlib beschikbaar is.

- `self._refresh_charts()`
  - Genereert een grafische weergave van topdomeinen en actieve apparaten.
  - Maakt gebruik van Matplotlib als deze geïnstalleerd is.

- `self._export()`
  - Bewaart de huidige buffer als tekst- of CSV-bestand.

- `self._report()`
  - Genereert een HTML audit-rapport met statistieken, detecties en DNS-overzichten.

- `self._import_hosts()`
  - Leest MikroTik DHCP-leasegegevens via de REST API.
  - Vult de hostnaamdatabase aan voor meer herkenbare clientlabels.

- `self._toggle_filelog()`
  - Start of stopt live logging naar een bestand.

- `self._clear()`
  - Verwijdert alle opgeslagen berichten, dreigingen en DNS-data uit de app.

## GUI-overzicht

De interface bevat meerdere tabbladen:

1. **Live Logboek**
   - Realtime tekstlogboek met kleurcodering per severity.
   - Zoekveld, snelfilters en weergavemodi.

2. **Dreigingsanalyse**
   - Lijst met gefilterde brute-force meldingen en firewall drops.
   - Sorteerbare tabel voor snellere analyse.

3. **Verkeer & Grafieken**
   - Matplotlib-visualisaties van topdomeinen en actieve clients.
   - Grafieken ververst met één druk op de knop.

4. **Domeinen & IP's**
   - Overzicht van verzamelde DNS-domeinen en gerelateerde IP-adressen.
   - Dubbelklikken zoekt direct naar het domein in het logboek.

5. **Apparaten & DHCP**
   - Overzicht van clients, query-aantallen en laatst bekende activiteit.
   - Apparaatnamen kunnen handmatig worden aangepast.

## Installatie

Voorwaarde:

- Python 3.8+ met `tkinter`
- Optioneel: `matplotlib` voor grafieken

Gebruik een virtuele omgeving:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install matplotlib
```

## Gebruik

Start de applicatie met:

```bash
python Mikrotik-Syslog-Manager.py
```

Bepaal in de GUI:

- Router IP
- Poortnummer
- UDP en/of TCP
- Start de server

Je kunt daarna je MikroTik-router configureren om logs naar het lokale IP en poort te sturen.

## Tests

Er is een eenvoudige unit-test voor sorteerlogica:

```bash
python -m unittest tests.test_sorting
```

## Bestanden

- `Mikrotik-Syslog-Manager.py` — hoofdapplicatie met GUI en syslog-verwerking.
- `tests/test_sorting.py` — unit-test voor sorteerfunctie en waardenconversie.

## Tips

- Als `tkinter` ontbreekt, installeer het via je pakketbeheerder (`sudo apt install python3-tk`).

  
- Zonder `matplotlib` werkt de app gewoon, maar zijn de grafiek-tabbladen uitgeschakeld.

## Licentie

Gebruik en wijzig het project vrij voor eigen beheer- en analysetaken.
