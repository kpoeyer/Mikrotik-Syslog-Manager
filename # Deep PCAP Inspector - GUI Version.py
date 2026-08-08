# Deep PCAP Inspector - GUI Version

```python
#!/usr/bin/env python3
"""
Deep PCAP Inspector - GUI Version
Volledig geautomatiseerde PCAP analyse met moderne GUI
"""

import sys
import os
import re
import base64
import json
import hashlib
import struct
import threading
import queue
import time
import math
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

# GUI
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.font import Font

# ============================================================
# DEPENDENCY CHECK
# ============================================================
MISSING_DEPS = []

try:
    from scapy.all import rdpcap, TCP, UDP, IP, DNS, DNSQR, Raw
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    MISSING_DEPS.append("scapy")

try:
    import matplotlib
    matplotlib.use('TkAgg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import matplotlib.gridspec as gridspec
    MATPLOTLIB_OK = True
except ImportError:
    MATPLOTLIB_OK = False
    MISSING_DEPS.append("matplotlib")

try:
    import numpy as np
    NUMPY_OK = True
except ImportError:
    NUMPY_OK = False

# ============================================================
# DARK THEME KLEUREN
# ============================================================
THEME = {
    'bg_dark':      '#0d1117',
    'bg_medium':    '#161b22',
    'bg_light':     '#21262d',
    'bg_card':      '#1c2128',
    'accent_blue':  '#58a6ff',
    'accent_green': '#3fb950',
    'accent_red':   '#f85149',
    'accent_yellow':'#d29922',
    'accent_purple':'#bc8cff',
    'accent_cyan':  '#39d353',
    'text_primary': '#e6edf3',
    'text_secondary':'#8b949e',
    'text_muted':   '#484f58',
    'border':       '#30363d',
    'critical':     '#ff4444',
    'high':         '#ff8800',
    'medium':       '#ffcc00',
    'low':          '#44ff88',
    'info':         '#4488ff',
    'grid':         '#21262d',
}

SEVERITY_COLORS = {
    'CRITICAL': THEME['critical'],
    'HIGH':     THEME['high'],
    'MEDIUM':   THEME['medium'],
    'LOW':      THEME['low'],
    'INFO':     THEME['info'],
}

# ============================================================
# ANALYSE ENGINE (Volledig)
# ============================================================
SENSITIVE_PATTERNS = {
    'credit_card':    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
    'email':          r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'password_field': r'(?i)(?:password|passwd|pwd|wachtwoord)\s*[=:]\s*\S+',
    'api_key':        r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*[A-Za-z0-9_\-]{16,}',
    'aws_key':        r'AKIA[0-9A-Z]{16}',
    'private_key':    r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    'jwt_token':      r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    'windows_hash':   r'\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b',
    'ssh_private':    r'-----BEGIN OPENSSH PRIVATE KEY-----',
    'bearer_token':   r'(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*',
    'ssn':            r'\b\d{3}-\d{2}-\d{4}\b',
}

SUSPICIOUS_DOMAINS = [
    r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$', r'\.gq$',
    r'\.xyz$', r'\.top$', r'\.pw$', r'\.cc$', r'\.su$',
    r'dyn\.dns', r'no-ip\.', r'duckdns\.', r'ngrok\.io',
    r'pastebin\.com', r'raw\.githubusercontent',
]

C2_PATHS = [
    r'/c2/', r'/cmd/', r'/beacon/', r'/check-in/', r'/gate\.php',
    r'/panel/', r'/submit\.php', r'/connect/', r'/update/',
    r'\.php\?id=\d+', r'/[a-f0-9]{32}/', r'/checkin/',
]

SUSPICIOUS_UA = [
    r'python-requests', r'curl/', r'wget/', r'Go-http-client',
    r'libwww-perl', r'masscan', r'nmap', r'nikto', r'sqlmap',
    r'dirbuster', r'gobuster', r'meterpreter',
]

MAGIC_BYTES = {
    b'MZ':              ('Windows PE Executable', 'CRITICAL'),
    b'\x7fELF':         ('Linux ELF Binary',      'CRITICAL'),
    b'PK\x03\x04':      ('ZIP Archive',            'HIGH'),
    b'\x1f\x8b':        ('GZIP Compressed',        'HIGH'),
    b'#!/':             ('Shell Script',            'HIGH'),
    b'-----BEGIN':      ('PEM Key/Certificate',    'CRITICAL'),
    b'%PDF':            ('PDF Document',            'MEDIUM'),
    b'\xd0\xcf\x11\xe0':('MS Office OLE',          'HIGH'),
    b'Rar!':            ('RAR Archive',             'MEDIUM'),
    b'\x89PNG':         ('PNG Image',               'LOW'),
}

def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def xxd_dump(data: bytes, max_bytes: int = 512) -> str:
    lines = []
    data = data[:max_bytes]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk).ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:08x}: {hex_part}  {ascii_part}")
    return '\n'.join(lines)

def decode_b64_layers(data: bytes) -> list:
    results = []
    pattern = rb'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
    for match in re.finditer(pattern, data):
        candidate = match.group()
        if len(candidate) < 16: continue
        try:
            decoded = base64.b64decode(candidate)
            if len(decoded) > 8:
                results.append({
                    'b64': candidate[:80].decode('utf-8', errors='replace'),
                    'decoded': decoded[:150].decode('utf-8', errors='replace'),
                    'hex': decoded[:32].hex(),
                    'entropy': calculate_entropy(decoded),
                    'length': len(decoded),
                })
        except Exception:
            pass
    return results

class AnalysisEngine:
    """Kern analyse engine"""
    
    def __init__(self, progress_cb=None, log_cb=None):
        self.progress_cb = progress_cb or (lambda v, t: None)
        self.log_cb      = log_cb      or (lambda m, l: None)
        self.findings    = []
        self.stats       = defaultdict(int)
        self.flows       = defaultdict(list)
        self.dns_queries = defaultdict(list)
        self.iocs        = {'ips': set(), 'domains': set(), 'urls': set()}
        self.timeline    = []
        self.entropy_data= []
        self.port_data   = Counter()
        self.cancelled   = False

    def cancel(self):
        self.cancelled = True

    def analyze(self, pcap_path: str) -> dict:
        self.log_cb("🔍 PCAP laden...", "INFO")
        
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            self.log_cb(f"❌ Fout bij laden: {e}", "ERROR")
            return {}
        
        total = len(packets)
        self.log_cb(f"✅ {total} packets geladen", "SUCCESS")
        self.stats['total_packets'] = total
        
        # Fase 1: Flow analyse
        self.log_cb("📊 Fase 1: Flow analyse...", "INFO")
        self._analyze_flows(packets, total)
        
        if self.cancelled:
            return {}
        
        # Fase 2: Payload analyse
        self.log_cb("🔬 Fase 2: Payload & encoding analyse...", "INFO")
        self._analyze_payloads(packets, total)
        
        if self.cancelled:
            return {}
        
        # Fase 3: DNS analyse
        self.log_cb("🌐 Fase 3: DNS tunneling & DGA detectie...", "INFO")
        self._analyze_dns(packets, total)
        
        if self.cancelled:
            return {}
        
        # Fase 4: Patroon detectie
        self.log_cb("🎯 Fase 4: C2 & beaconing detectie...", "INFO")
        self._detect_patterns()
        
        self.log_cb("✅ Analyse voltooid!", "SUCCESS")
        
        return {
            'findings':   self.findings,
            'stats':      dict(self.stats),
            'iocs':       {k: list(v) for k, v in self.iocs.items()},
            'timeline':   self.timeline,
            'entropy':    self.entropy_data,
            'ports':      dict(self.port_data.most_common(20)),
            'flows':      dict(self.flows),
        }

    def _analyze_flows(self, packets, total):
        for i, pkt in enumerate(packets):
            if self.cancelled: return
            if i % 500 == 0:
                self.progress_cb(int(i/total*25), f"Flows: {i}/{total}")
            try:
                if IP not in pkt: continue
                src = pkt[IP].src
                dst = pkt[IP].dst
                ts  = float(pkt.time)
                sz  = len(pkt)
                
                self.iocs['ips'].add(src)
                self.iocs['ips'].add(dst)
                
                proto = 'TCP' if TCP in pkt else ('UDP' if UDP in pkt else 'OTHER')
                port  = 0
                
                if TCP in pkt:
                    port = pkt[TCP].dport
                    self.stats['tcp'] += 1
                elif UDP in pkt:
                    port = pkt[UDP].dport
                    self.stats['udp'] += 1
                
                self.port_data[port] += 1
                flow_key = f"{src}->{dst}:{port}"
                self.flows[flow_key].append({'ts': ts, 'sz': sz, 'proto': proto})
                
                self.timeline.append({
                    'ts': ts, 'src': src, 'dst': dst,
                    'port': port, 'size': sz, 'proto': proto
                })
                self.stats['total_bytes'] += sz
                
            except Exception:
                pass

    def _analyze_payloads(self, packets, total):
        for i, pkt in enumerate(packets):
            if self.cancelled: return
            if i % 200 == 0:
                self.progress_cb(25 + int(i/total*35), f"Payloads: {i}/{total}")
            try:
                if IP not in pkt or Raw not in pkt: continue
                
                src  = pkt[IP].src
                dst  = pkt[IP].dst
                port = 0
                
                if TCP in pkt:   port = pkt[TCP].dport
                elif UDP in pkt: port = pkt[UDP].dport
                
                payload = bytes(pkt[Raw].load)
                if len(payload) < 4: continue
                
                entropy = calculate_entropy(payload)
                self.entropy_data.append({
                    'pkt': i, 'entropy': entropy,
                    'size': len(payload), 'port': port,
                    'src': src, 'dst': dst
                })
                
                # HTTP analyse
                if port in [80, 8080, 8000, 3000, 8888] or \
                   any(payload.startswith(m) for m in
                       [b'GET ', b'POST ', b'PUT ', b'HEAD ', b'HTTP/']):
                    self._check_http(payload, src, dst, port)
                
                # Hoge entropie
                if entropy > 7.2 and len(payload) > 100:
                    self._add_finding({
                        'type': 'HIGH_ENTROPY_PAYLOAD',
                        'severity': 'HIGH',
                        'src': src, 'dst': f"{dst}:{port}",
                        'entropy': entropy,
                        'size': len(payload),
                        'hex_dump': xxd_dump(payload, 128),
                        'description': 'Encrypted/compressed payload – mogelijke C2/exfiltratie',
                        'pkt_num': i,
                    })
                
                # Magic bytes
                for magic, (ftype, sev) in MAGIC_BYTES.items():
                    if payload.startswith(magic) or magic in payload[:512]:
                        offset = payload.find(magic)
                        self._add_finding({
                            'type': 'BINARY_TRANSFER',
                            'severity': sev,
                            'src': src, 'dst': f"{dst}:{port}",
                            'file_type': ftype,
                            'offset': offset,
                            'hex_dump': xxd_dump(payload[max(0,offset):offset+128]),
                            'description': f'{ftype} gevonden in payload',
                            'pkt_num': i,
                        })
                
                # Base64 detectie
                b64_results = decode_b64_layers(payload)
                for res in b64_results:
                    if res['entropy'] > 4.0 or len(res['decoded']) > 20:
                        self._add_finding({
                            'type': 'BASE64_ENCODED_PAYLOAD',
                            'severity': 'HIGH',
                            'src': src, 'dst': f"{dst}:{port}",
                            'b64_snippet': res['b64'][:100],
                            'decoded': res['decoded'][:200],
                            'hex': res['hex'],
                            'entropy': res['entropy'],
                            'description': 'Base64 gecodeerde payload gevonden',
                            'pkt_num': i,
                        })
                
                # Shellcode
                self._check_shellcode(payload, src, dst, port, i)
                
                # Sensitive data
                payload_str = payload.decode('utf-8', errors='replace')
                for dtype, pattern in SENSITIVE_PATTERNS.items():
                    matches = re.findall(pattern, payload_str)
                    if matches:
                        self._add_finding({
                            'type': f'SENSITIVE_DATA_{dtype.upper()}',
                            'severity': 'CRITICAL',
                            'src': src, 'dst': f"{dst}:{port}",
                            'data_type': dtype,
                            'matches': matches[:5],
                            'description': f'Gevoelige data gelekt: {dtype}',
                            'pkt_num': i,
                        })
                
                self.stats['analyzed'] += 1
                
            except Exception:
                pass

    def _check_http(self, payload: bytes, src: str, dst: str, port: int):
        try:
            text = payload.decode('utf-8', errors='replace')
        except Exception:
            return
        
        # Method & path
        m = re.match(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP', text)
        if m:
            method, path = m.group(1), m.group(2)
            self.iocs['urls'].add(f"http://{dst}:{port}{path}")
            
            # C2 paths
            for pattern in C2_PATHS:
                if re.search(pattern, path, re.IGNORECASE):
                    self._add_finding({
                        'type': 'C2_URL_PATTERN',
                        'severity': 'CRITICAL',
                        'src': src, 'dst': f"{dst}:{port}",
                        'method': method, 'path': path,
                        'pattern': pattern,
                        'description': f'C2 URL patroon: {method} {path}',
                    })
            
            # User-Agent
            ua_m = re.search(r'User-Agent:\s*(.+?)(?:\r\n|\n)', text, re.IGNORECASE)
            if ua_m:
                ua = ua_m.group(1).strip()
                for ua_pat in SUSPICIOUS_UA:
                    if re.search(ua_pat, ua, re.IGNORECASE):
                        self._add_finding({
                            'type': 'SUSPICIOUS_USER_AGENT',
                            'severity': 'HIGH',
                            'src': src, 'dst': f"{dst}:{port}",
                            'user_agent': ua,
                            'description': f'Verdachte User-Agent: {ua}',
                        })
            
            # POST body gevoelige data
            if b'\r\n\r\n' in payload:
                body = payload.split(b'\r\n\r\n', 1)[1]
                if body:
                    body_entropy = calculate_entropy(body)
                    if body_entropy > 7.0 and len(body) > 200:
                        self._add_finding({
                            'type': 'HTTP_EXFILTRATION',
                            'severity': 'CRITICAL',
                            'src': src, 'dst': f"{dst}:{port}",
                            'body_size': len(body),
                            'entropy': body_entropy,
                            'hex_dump': xxd_dump(body, 128),
                            'description': 'HTTP POST met hoge entropie – mogelijke exfiltratie',
                        })

    def _check_shellcode(self, data: bytes, src: str, dst: str, port: int, pkt_num: int):
        indicators = []
        patterns = {
            'NOP_sled':    (b'\x90' * 8, 'CRITICAL'),
            'INT_0x80':    (b'\xcd\x80', 'CRITICAL'),
            'XOR_EAX':     (b'\x31\xc0', 'HIGH'),
            'SYSCALL_x64': (b'\x0f\x05', 'HIGH'),
            'PEB_access':  (b'\x64\xa1\x30\x00\x00\x00', 'CRITICAL'),
            'MSF_encoder': (b'\xdb\xc0\xd9\x74\x24\xf4', 'CRITICAL'),
        }
        for name, (pattern, sev) in patterns.items():
            if pattern in data:
                idx = data.find(pattern)
                indicators.append({
                    'name': name, 'offset': idx,
                    'ctx': data[max(0,idx-4):idx+12].hex()
                })
        
        if indicators:
            self._add_finding({
                'type': 'SHELLCODE_DETECTED',
                'severity': 'CRITICAL',
                'src': src, 'dst': f"{dst}:{port}",
                'indicators': indicators,
                'hex_dump': xxd_dump(data, 256),
                'description': f'Shellcode indicatoren: {[x["name"] for x in indicators]}',
                'pkt_num': pkt_num,
            })

    def _analyze_dns(self, packets, total):
        for i, pkt in enumerate(packets):
            if self.cancelled: return
            if i % 500 == 0:
                self.progress_cb(60 + int(i/total*20), f"DNS: {i}/{total}")
            try:
                if DNS not in pkt or IP not in pkt: continue
                src = pkt[IP].src
                ts  = float(pkt.time)
                
                if pkt[DNS].qr == 0 and DNSQR in pkt:  # Query
                    qname = pkt[DNSQR].qname.decode('utf-8', errors='replace').rstrip('.')
                    self.iocs['domains'].add(qname)
                    self.dns_queries[src].append({'q': qname, 'ts': ts})
                    self.stats['dns_queries'] += 1
                    
                    labels = qname.split('.')
                    for label in labels[:-2]:
                        # Lang subdomain
                        if len(label) > 40:
                            self._add_finding({
                                'type': 'DNS_TUNNELING',
                                'severity': 'CRITICAL',
                                'src': src, 'query': qname,
                                'label': label[:80],
                                'label_len': len(label),
                                'description': f'DNS tunneling – lang subdomain ({len(label)} chars)',
                            })
                        # Base64 in subdomain
                        if len(label) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', label):
                            try:
                                dec = base64.b64decode(label + '==')
                                if calculate_entropy(dec) > 3.5:
                                    self._add_finding({
                                        'type': 'DNS_B64_SUBDOMAIN',
                                        'severity': 'CRITICAL',
                                        'src': src, 'query': qname,
                                        'decoded': dec[:80].decode('utf-8', errors='replace'),
                                        'description': 'Base64 encoded data in DNS subdomain',
                                    })
                            except Exception:
                                pass
                        # Hex in subdomain
                        if len(label) > 16 and re.match(r'^[0-9a-fA-F]+$', label):
                            self._add_finding({
                                'type': 'DNS_HEX_SUBDOMAIN',
                                'severity': 'HIGH',
                                'src': src, 'query': qname,
                                'hex_data': label[:64],
                                'description': 'Hex data in DNS subdomain – mogelijke tunneling',
                            })
                    
                    # Verdachte TLD's
                    for pat in SUSPICIOUS_DOMAINS:
                        if re.search(pat, qname):
                            self._add_finding({
                                'type': 'SUSPICIOUS_DOMAIN',
                                'severity': 'MEDIUM',
                                'src': src, 'domain': qname,
                                'description': f'Verdacht domein: {qname}',
                            })
                            
            except Exception:
                pass

    def _detect_patterns(self):
        self.progress_cb(80, "Beaconing detectie...")
        
        # C2 Beaconing via flows
        for flow_key, pkts in self.flows.items():
            if len(pkts) < 6: continue
            timestamps = sorted(p['ts'] for p in pkts)
            intervals  = [timestamps[i+1]-timestamps[i] for i in range(len(timestamps)-1)]
            if not intervals: continue
            avg = sum(intervals) / len(intervals)
            if avg < 2: continue
            std = math.sqrt(sum((x-avg)**2 for x in intervals) / len(intervals))
            jitter = std / avg if avg > 0 else 1
            
            if jitter < 0.15 and len(intervals) >= 5:
                self._add_finding({
                    'type': 'C2_BEACONING',
                    'severity': 'CRITICAL',
                    'flow': flow_key,
                    'avg_interval': round(avg, 2),
                    'jitter': round(jitter, 4),
                    'count': len(pkts),
                    'description': f'C2 beacon – interval: {round(avg,1)}s, jitter: {round(jitter*100,1)}%',
                })
        
        self.progress_cb(85, "DGA detectie...")
        
        # DGA detectie
        base_domains = defaultdict(set)
        for src, queries in self.dns_queries.items():
            for q in queries:
                labels = q['q'].split('.')
                if len(labels) >= 2:
                    base = '.'.join(labels[-2:])
                    base_domains[base].add(q['q'])
        
        for base, subs in base_domains.items():
            if len(subs) > 8:
                sub_labels = [s.split('.')[0] for s in subs]
                avg_ent = sum(calculate_entropy(s.encode()) for s in sub_labels) / len(sub_labels)
                if avg_ent > 3.5:
                    self._add_finding({
                        'type': 'DGA_DETECTED',
                        'severity': 'CRITICAL',
                        'base_domain': base,
                        'unique_subs': len(subs),
                        'avg_entropy': round(avg_ent, 3),
                        'samples': list(subs)[:5],
                        'description': f'DGA gedetecteerd voor {base} ({len(subs)} subdomains)',
                    })
        
        self.progress_cb(90, "Grote uploads detecteren...")
        
        # Data exfiltratie (grote uploads)
        flow_volumes = defaultdict(int)
        for flow_key, pkts in self.flows.items():
            for p in pkts: flow_volumes[flow_key] += p['sz']
        
        for flow, vol in sorted(flow_volumes.items(), key=lambda x: -x[1]):
            if vol > 500_000:  # > 500KB
                self._add_finding({
                    'type': 'DATA_EXFILTRATION',
                    'severity': 'HIGH',
                    'flow': flow,
                    'volume_mb': round(vol/1024/1024, 2),
                    'packet_count': len(self.flows[flow]),
                    'description': f'Groot data volume: {round(vol/1024/1024,2)} MB – mogelijke exfiltratie',
                })
        
        self.progress_cb(95, "Port scanning detectie...")
        
        # Port scanning
        src_ports = defaultdict(set)
        for flow_key in self.flows:
            parts = flow_key.split('->')
            if len(parts) == 2:
                src = parts[0]
                if ':' in parts[1]:
                    src_ports[src].add(parts[1].split(':')[1])
        
        for src, ports in src_ports.items():
            if len(ports) > 20:
                self._add_finding({
                    'type': 'PORT_SCANNING',
                    'severity': 'HIGH',
                    'src': src,
                    'unique_ports': len(ports),
                    'description': f'Port scan van {src} – {len(ports)} unieke poorten',
                })
        
        self.progress_cb(100, "Klaar!")
        self.stats['total_findings'] = len(self.findings)
        self.stats['critical'] = sum(1 for f in self.findings if f.get('severity') == 'CRITICAL')
        self.stats['high']     = sum(1 for f in self.findings if f.get('severity') == 'HIGH')
        self.stats['medium']   = sum(1 for f in self.findings if f.get('severity') == 'MEDIUM')

    def _add_finding(self, finding: dict):
        finding['timestamp'] = datetime.now().isoformat()
        self.findings.append(finding)

# ============================================================
# CUSTOM WIDGETS
# ============================================================
class DarkTooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text   = text
        self.tip    = None
        widget.bind('<Enter>', self.show)
        widget.bind('<Leave>', self.hide)
    
    def show(self, event=None):
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 30
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(
            self.tip, text=self.text,
            background=THEME['bg_light'],
            foreground=THEME['text_primary'],
            relief='solid', borderwidth=1,
            font=('Consolas', 9), padx=6, pady=3
        )
        lbl.pack()
    
    def hide(self, event=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class AnimatedProgressBar(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=THEME['bg_dark'], **kwargs)
        self.canvas = tk.Canvas(
            self, bg=THEME['bg_light'],
            highlightthickness=0, height=20
        )
        self.canvas.pack(fill='x', expand=True)
        self._value   = 0
        self._animate = False
        self._bar     = None
        self._glow    = None
        self.canvas.bind('<Configure>', self._redraw)
    
    def set(self, value, color=None):
        self._value = max(0, min(100, value))
        color = color or THEME['accent_blue']
        self._color = color
        self._redraw()
    
    def _redraw(self, event=None):
        self.canvas.delete('all')
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 2: return
        fill_w = int(w * self._value / 100)
        
        # Background
        self.canvas.create_rectangle(
            0, 0, w, h,
            fill=THEME['bg_light'], outline=THEME['border']
        )
        # Progress
        if fill_w > 0:
            color = getattr(self, '_color', THEME['accent_blue'])
            self.canvas.create_rectangle(
                0, 0, fill_w, h, fill=color, outline=''
            )
            # Glow effect
            if fill_w > 4:
                self.canvas.create_rectangle(
                    fill_w-4, 0, fill_w, h,
                    fill='white', outline='', stipple='gray50'
                )
        # Percentage tekst
        self.canvas.create_text(
            w//2, h//2,
            text=f"{self._value}%",
            fill=THEME['text_primary'],
            font=('Consolas', 9, 'bold')
        )


class StatCard(tk.Frame):
    def __init__(self, parent, title, value, color, icon="■", **kwargs):
        super().__init__(
            parent,
            bg=THEME['bg_card'],
            relief='flat',
            bd=0,
            **kwargs
        )
        self.configure(highlightbackground=color, highlightthickness=1)
        
        # Header
        header = tk.Frame(self, bg=color, height=3)
        header.pack(fill='x', side='top')
        
        # Content
        content = tk.Frame(self, bg=THEME['bg_card'])
        content.pack(fill='both', expand=True, padx=12, pady=8)
        
        # Icon + Title
        tk.Label(
            content, text=f"{icon}  {title}",
            bg=THEME['bg_card'],
            fg=THEME['text_secondary'],
            font=('Segoe UI', 9)
        ).pack(anchor='w')
        
        # Value
        self.value_label = tk.Label(
            content, text=str(value),
            bg=THEME['bg_card'],
            fg=color,
            font=('Segoe UI', 24, 'bold')
        )
        self.value_label.pack(anchor='w')
    
    def update_value(self, value):
        self.value_label.configure(text=str(value))


class FindingRow(tk.Frame):
    def __init__(self, parent, finding: dict, on_click=None, **kwargs):
        super().__init__(
            parent,
            bg=THEME['bg_medium'],
            cursor='hand2',
            **kwargs
        )
        self.finding  = finding
        self.on_click = on_click
        self._hover   = False
        
        sev   = finding.get('severity', 'LOW')
        color = SEVERITY_COLORS.get(sev, THEME['text_primary'])
        
        # Severity badge
        badge = tk.Label(
            self, text=f" {sev} ",
            bg=color, fg='black',
            font=('Consolas', 8, 'bold'),
            padx=4, pady=2
        )
        badge.grid(row=0, column=0, padx=(8,6), pady=6, sticky='w')
        
        # Type
        tk.Label(
            self,
            text=finding.get('type', 'UNKNOWN').replace('_', ' '),
            bg=THEME['bg_medium'],
            fg=color,
            font=('Consolas', 10, 'bold'),
            anchor='w'
        ).grid(row=0, column=1, padx=4, pady=6, sticky='w')
        
        # Description
        desc = finding.get('description', '')
        tk.Label(
            self,
            text=desc[:80] + ('...' if len(desc) > 80 else ''),
            bg=THEME['bg_medium'],
            fg=THEME['text_secondary'],
            font=('Segoe UI', 9),
            anchor='w'
        ).grid(row=0, column=2, padx=4, pady=6, sticky='w')
        
        # Src/Dst
        src = finding.get('src', finding.get('flow', ''))
        tk.Label(
            self,
            text=str(src)[:40],
            bg=THEME['bg_medium'],
            fg=THEME['text_muted'],
            font=('Consolas', 8),
            anchor='e'
        ).grid(row=0, column=3, padx=(4,8), pady=6, sticky='e')
        
        self.columnconfigure(2, weight=1)
        
        # Separator
        sep = tk.Frame(self, bg=THEME['border'], height=1)
        sep.grid(row=1, column=0, columnspan=4, sticky='ew')
        
        # Hover & click
        for widget in [self, badge] + list(self.winfo_children()):
            widget.bind('<Button-1>', self._click)
            widget.bind('<Enter>',    self._hover_on)
            widget.bind('<Leave>',    self._hover_off)
    
    def _click(self, e=None):
        if self.on_click:
            self.on_click(self.finding)
    
    def _hover_on(self, e=None):
        self.configure(bg=THEME['bg_light'])
    
    def _hover_off(self, e=None):
        self.configure(bg=THEME['bg_medium'])


# ============================================================
# MAIN GUI APPLICATION
# ============================================================
class PCAPInspectorGUI:
    def __init__(self, root):
        self.root     = root
        self.engine   = None
        self.results  = {}
        self.analysis_thread = None
        self.log_queue = queue.Queue()
        self.current_pcap = tk.StringVar()
        self.filter_severity = tk.StringVar(value='ALL')
        self.filter_type     = tk.StringVar(value='ALL')
        self.search_var      = tk.StringVar()
        self.all_findings    = []
        
        self._setup_window()
        self._build_ui()
        self._poll_log_queue()

    def _setup_window(self):
        self.root.title("🔍 Deep PCAP Inspector v2.0")
        self.root.configure(bg=THEME['bg_dark'])
        self.root.geometry("1400x900")
        self.root.minsize(1100, 700)
        
        # App icon (canvas-gebaseerd)
        try:
            self.root.iconbitmap('')
        except Exception:
            pass
        
        # Ttk stijlen
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Dark.TFrame',       background=THEME['bg_dark'])
        style.configure('Card.TFrame',       background=THEME['bg_card'])
        style.configure('Dark.TLabel',       background=THEME['bg_dark'],
                        foreground=THEME['text_primary'])
        style.configure('Dark.TNotebook',    background=THEME['bg_dark'],
                        borderwidth=0)
        style.configure('Dark.TNotebook.Tab',
                        background=THEME['bg_medium'],
                        foreground=THEME['text_secondary'],
                        padding=[16, 8],
                        font=('Segoe UI', 10))
        style.map('Dark.TNotebook.Tab',
                  background=[('selected', THEME['bg_light'])],
                  foreground=[('selected', THEME['accent_blue'])])
        style.configure('Dark.Treeview',
                        background=THEME['bg_medium'],
                        foreground=THEME['text_primary'],
                        fieldbackground=THEME['bg_medium'],
                        borderwidth=0,
                        rowheight=28)
        style.configure('Dark.Treeview.Heading',
                        background=THEME['bg_light'],
                        foreground=THEME['accent_blue'],
                        font=('Segoe UI', 10, 'bold'))
        style.map('Dark.Treeview',
                  background=[('selected', THEME['accent_blue'])],
                  foreground=[('selected', 'white')])
        style.configure('Accent.TButton',
                        background=THEME['accent_blue'],
                        foreground='white',
                        font=('Segoe UI', 10, 'bold'),
                        padding=[16, 8],
                        borderwidth=0)
        style.map('Accent.TButton',
                  background=[('active', '#79b8ff'), ('pressed', '#388bfd')])
        style.configure('Danger.TButton',
                        background=THEME['accent_red'],
                        foreground='white',
                        font=('Segoe UI', 10, 'bold'),
                        padding=[16, 8])
        style.configure('Dark.TCombobox',
                        fieldbackground=THEME['bg_light'],
                        background=THEME['bg_light'],
                        foreground=THEME['text_primary'],
                        selectbackground=THEME['accent_blue'])
        style.configure('Dark.TEntry',
                        fieldbackground=THEME['bg_light'],
                        foreground=THEME['text_primary'],
                        insertcolor=THEME['text_primary'])
        style.configure('Dark.TScrollbar',
                        background=THEME['bg_medium'],
                        troughcolor=THEME['bg_dark'],
                        arrowcolor=THEME['text_secondary'])

    # ----------------------------------------------------------
    # UI OPBOUW
    # ----------------------------------------------------------
    def _build_ui(self):
        # Hoofd container
        main = tk.Frame(self.root, bg=THEME['bg_dark'])
        main.pack(fill='both', expand=True)
        
        # Sidebar
        self._build_sidebar(main)
        
        # Content area
        content = tk.Frame(main, bg=THEME['bg_dark'])
        content.pack(side='left', fill='both', expand=True)
        
        # Topbar
        self._build_topbar(content)
        
        # Notebook (tabbladen)
        self._build_notebook(content)
        
        # Status bar
        self._build_statusbar(content)

    def _build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=THEME['bg_medium'], width=220)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        
        # Logo
        logo_frame = tk.Frame(sidebar, bg=THEME['bg_medium'], pady=20)
        logo_frame.pack(fill='x')
        
        tk.Label(
            logo_frame,
            text="🔍",
            font=('Segoe UI', 28),
            bg=THEME['bg_medium'],
            fg=THEME['accent_blue']
        ).pack()
        
        tk.Label(
            logo_frame,
            text="PCAP INSPECTOR",
            font=('Segoe UI', 11, 'bold'),
            bg=THEME['bg_medium'],
            fg=THEME['text_primary']
        ).pack()
        
        tk.Label(
            logo_frame,
            text="v2.0 — Deep Analysis",
            font=('Segoe UI', 8),
            bg=THEME['bg_medium'],
            fg=THEME['text_muted']
        ).pack()
        
        # Separator
        tk.Frame(sidebar, bg=THEME['border'], height=1).pack(fill='x', padx=12)
        
        # Menu items
        self.nav_buttons = []
        nav_items = [
            ("📊", "Dashboard",   self._show_dashboard),
            ("🚨", "Bevindingen", self._show_findings),
            ("🌐", "Netwerk",     self._show_network),
            ("📈", "Statistieken",self._show_stats),
            ("💻", "Hex Viewer",  self._show_hex),
            ("📋", "Log",         self._show_log),
        ]
        
        nav_frame = tk.Frame(sidebar, bg=THEME['bg_medium'])
        nav_frame.pack(fill='x', pady=10)
        
        for icon, label, cmd in nav_items:
            btn = self._nav_button(nav_frame, icon, label, cmd)
            self.nav_buttons.append(btn)
        
        # Separator
        tk.Frame(sidebar, bg=THEME['border'], height=1).pack(fill='x', padx=12, pady=10)
        
        # File info
        self.file_info_frame = tk.Frame(sidebar, bg=THEME['bg_medium'])
        self.file_info_frame.pack(fill='x', padx=12, pady=5)
        
        tk.Label(
            self.file_info_frame,
            text="GELADEN BESTAND",
            font=('Segoe UI', 8),
            bg=THEME['bg_medium'],
            fg=THEME['text_muted']
        ).pack(anchor='w')
        
        self.file_label = tk.Label(
            self.file_info_frame,
            text="Geen bestand geladen",
            font=('Consolas', 8),
            bg=THEME['bg_medium'],
            fg=THEME['text_secondary'],
            wraplength=180,
            justify='left'
        )
        self.file_label.pack(anchor='w')
        
        # Progress
        tk.Frame(sidebar, bg=THEME['border'], height=1).pack(fill='x', padx=12, pady=10)
        
        prog_frame = tk.Frame(sidebar, bg=THEME['bg_medium'])
        prog_frame.pack(fill='x', padx=12)
        
        tk.Label(
            prog_frame,
            text="VOORTGANG",
            font=('Segoe UI', 8),
            bg=THEME['bg_medium'],
            fg=THEME['text_muted']
        ).pack(anchor='w')
        
        self.progress_bar = AnimatedProgressBar(prog_frame)
        self.progress_bar.pack(fill='x', pady=4)
        
        self.progress_label = tk.Label(
            prog_frame,
            text="Wachtend...",
            font=('Segoe UI', 8),
            bg=THEME['bg_medium'],
            fg=THEME['text_muted']
        )
        self.progress_label.pack(anchor='w')
        
        # Version footer
        tk.Label(
            sidebar,
            text="Deep PCAP Inspector\n© 2024",
            font=('Segoe UI', 7),
            bg=THEME['bg_medium'],
            fg=THEME['text_muted']
        ).pack(side='bottom', pady=10)

    def _nav_button(self, parent, icon, label, command):
        frame = tk.Frame(parent, bg=THEME['bg_medium'], cursor='hand2')
        frame.pack(fill='x', padx=8, pady=1)
        
        inner = tk.Frame(frame, bg=THEME['bg_medium'])
        inner.pack(fill='x', padx=4, pady=3)
        
        icon_lbl = tk.Label(
            inner, text=icon,
            font=('Segoe UI', 13),
            bg=THEME['bg_medium'],
            fg=THEME['accent_blue'],
            width=2
        )
        icon_lbl.pack(side='left', padx=(4,8))
        
        text_lbl = tk.Label(
            inner, text=label,
            font=('Segoe UI', 10),
            bg=THEME['bg_medium'],
            fg=THEME['text_primary'],
            anchor='w'
        )
        text_lbl.pack(side='left', fill='x', expand=True)
        
        def hover_on(e):
            frame.configure(bg=THEME['bg_light'])
            inner.configure(bg=THEME['bg_light'])
            for w in inner.winfo_children():
                w.configure(bg=THEME['bg_light'])
        
        def hover_off(e):
            frame.configure(bg=THEME['bg_medium'])
            inner.configure(bg=THEME['bg_medium'])
            for w in inner.winfo_children():
                w.configure(bg=THEME['bg_medium'])
        
        for w in [frame, inner, icon_lbl, text_lbl]:
            w.bind('<Button-1>', lambda e, c=command: c())
            w.bind('<Enter>', hover_on)
            w.bind('<Leave>', hover_off)
        
        return frame

    def _build_topbar(self, parent):
        topbar = tk.Frame(parent, bg=THEME['bg_medium'], height=60)
        topbar.pack(fill='x', side='top')
        topbar.pack_propagate(False)
        
        # Links: bestandsselectie
        left = tk.Frame(topbar, bg=THEME['bg_medium'])
        left.pack(side='left', fill='y', padx=16)
        
        file_frame = tk.Frame(left, bg=THEME['bg_medium'])
        file_frame.pack(side='left', fill='y', pady=10)
        
        self.file_entry = ttk.Entry(
            file_frame,
            textvariable=self.current_pcap,
            width=45,
            style='Dark.TEntry',
            font=('Consolas', 10)
        )
        self.file_entry.pack(side='left', ipady=4, padx=(0,6))
        
        browse_btn = ttk.Button(
            file_frame,
            text="📂 Browse",
            command=self._browse_file,
            style='Accent.TButton'
        )
        browse_btn.pack(side='left', padx=2)
        DarkTooltip(browse_btn, "Selecteer een PCAP bestand")
        
        self.analyze_btn = ttk.Button(
            file_frame,
            text="▶ Analyseer",
            command=self._start_analysis,
            style='Accent.TButton'
        )
        self.analyze_btn.pack(side='left', padx=2)
        
        self.stop_btn = ttk.Button(
            file_frame,
            text="⏹ Stop",
            command=self._stop_analysis,
            style='Danger.TButton',
            state='disabled'
        )
        self.stop_btn.pack(side='left', padx=2)
        
        # Rechts: export & stats snelweergave
        right = tk.Frame(topbar, bg=THEME['bg_medium'])
        right.pack(side='right', fill='y', padx=16)
        
        export_btn = ttk.Button(
            right,
            text="💾 Export JSON",
            command=self._export_json,
            style='Accent.TButton'
        )
        export_btn.pack(side='right', pady=15, padx=4)
        
        report_btn = ttk.Button(
            right,
            text="📄 HTML Report",
            command=self._export_html,
            style='Accent.TButton'
        )
        report_btn.pack(side='right', pady=15, padx=4)

    def _build_notebook(self, parent):
        self.notebook = ttk.Notebook(parent, style='Dark.TNotebook')
        self.notebook.pack(fill='both', expand=True, padx=0, pady=0)
        
        # Tab frames
        self.tab_dashboard = tk.Frame(self.notebook, bg=THEME['bg_dark'])
        self.tab_findings  = tk.Frame(self.notebook, bg=THEME['bg_dark'])
        self.tab_network   = tk.Frame(self.notebook, bg=THEME['bg_dark'])
        self.tab_stats     = tk.Frame(self.notebook, bg=THEME['bg_dark'])
        self.tab_hex       = tk.Frame(self.notebook, bg=THEME['bg_dark'])
        self.tab_log       = tk.Frame(self.notebook, bg=THEME['bg_dark'])
        
        self.notebook.add(self.tab_dashboard, text=' 📊 Dashboard ')
        self.notebook.add(self.tab_findings,  text=' 🚨 Bevindingen ')
        self.notebook.add(self.tab_network,   text=' 🌐 Netwerk ')
        self.notebook.add(self.tab_stats,     text=' 📈 Statistieken ')
        self.notebook.add(self.tab_hex,       text=' 💻 Hex Viewer ')
        self.notebook.add(self.tab_log,       text=' 📋 Log ')
        
        self._build_dashboard_tab()
        self._build_findings_tab()
        self._build_network_tab()
        self._build_stats_tab()
        self._build_hex_tab()
        self._build_log_tab()

    def _build_statusbar(self, parent):
        statusbar = tk.Frame(parent, bg=THEME['bg_medium'], height=28)
        statusbar.pack(fill='x', side='bottom')
        statusbar.pack_propagate(False)
        
        self.status_var = tk.StringVar(value="Klaar – Selecteer een PCAP bestand")
        
        tk.Label(
            statusbar,
            textvariable=self.status_var,
            bg=THEME['bg_medium'],
            fg=THEME['text_secondary'],
            font=('Consolas', 9),
            anchor='w'
        ).pack(side='left', padx=12, fill='y')
        
        # Rechterkant: tijd
        self.time_label = tk.Label(
            statusbar,
            text="",
            bg=THEME['bg_medium'],
            fg=THEME['text_muted'],
            font=('Consolas', 9)
        )
        self.time_label.pack(side='right', padx=12)
        self._update_clock()

    def _update_clock(self):
        self.time_label.configure(text=datetime.now().strftime("%H:%M:%S"))
        self.root.after(1000, self._update_clock)

    # ----------------------------------------------------------
    # DASHBOARD TAB
    # ----------------------------------------------------------
    def _build_dashboard_tab(self):
        # Stat cards row
        cards_frame = tk.Frame(self.tab_dashboard, bg=THEME['bg_dark'])
        cards_frame.pack(fill='x', padx=16, pady=16)
        
        self.card_total    = StatCard(cards_frame, "Totaal Packets",  "—", THEME['accent_blue'],  "📦")
        self.card_critical = StatCard(cards_frame, "Kritiek",         "—", THEME['critical'],     "🔴")
        self.card_high     = StatCard(cards_frame, "Hoog",            "—", THEME['high'],         "🟠")
        self.card_medium   = StatCard(cards_frame, "Gemiddeld",       "—", THEME['medium'],       "🟡")
        self.card_dns      = StatCard(cards_frame, "DNS Queries",     "—", THEME['accent_purple'],"🌐")
        self.card_findings = StatCard(cards_frame, "Bevindingen",     "—", THEME['accent_green'], "🎯")
        
        for card in [self.card_total, self.card_critical, self.card_high,
                     self.card_medium, self.card_dns, self.card_findings]:
            card.pack(side='left', fill='both', expand=True, padx=4)
        
        # Grafieken frame
        if MATPLOTLIB_OK:
            self._build_dashboard_charts()
        else:
            tk.Label(
                self.tab_dashboard,
                text="📦 Installeer matplotlib voor grafieken:\npip install matplotlib",
                bg=THEME['bg_dark'],
                fg=THEME['text_muted'],
                font=('Segoe UI', 12)
            ).pack(expand=True)

    def _build_dashboard_charts(self):
        charts_frame = tk.Frame(self.tab_dashboard, bg=THEME['bg_dark'])
        charts_frame.pack(fill='both', expand=True, padx=16, pady=(0,16))
        
        # Maak figure
        self.fig_dashboard = Figure(
            figsize=(14, 5),
            facecolor=THEME['bg_dark']
        )
        gs = gridspec.GridSpec(1, 3, figure=self.fig_dashboard,
                               wspace=0.3, left=0.06, right=0.97,
                               top=0.88, bottom=0.15)
        
        self.ax_severity  = self.fig_dashboard.add_subplot(gs[0])
        self.ax_timeline  = self.fig_dashboard.add_subplot(gs[1])
        self.ax_ports     = self.fig_dashboard.add_subplot(gs[2])
        
        for ax in [self.ax_severity, self.ax_timeline, self.ax_ports]:
            ax.set_facecolor(THEME['bg_medium'])
            ax.tick_params(colors=THEME['text_secondary'], labelsize=8)
            ax.spines['bottom'].set_color(THEME['border'])
            ax.spines['top'].set_color(THEME['border'])
            ax.spines['left'].set_color(THEME['border'])
            ax.spines['right'].set_color(THEME['border'])
        
        self._draw_placeholder_charts()
        
        canvas = FigureCanvasTkAgg(self.fig_dashboard, charts_frame)
        canvas.get_tk_widget().configure(bg=THEME['bg_dark'], highlightthickness=0)
        canvas.get_tk_widget().pack(fill='both', expand=True)
        self.dashboard_canvas = canvas

    def _draw_placeholder_charts(self):
        for ax, title in [(self.ax_severity, 'Bevindingen per Ernst'),
                          (self.ax_timeline, 'Traffic Timeline'),
                          (self.ax_ports,    'Top Poorten')]:
            ax.clear()
            ax.set_facecolor(THEME['bg_medium'])
            ax.set_title(title, color=THEME['text_primary'],
                        fontsize=10, fontweight='bold', pad=8)
            ax.text(0.5, 0.5, 'Geen data\nStart analyse',
                   ha='center', va='center',
                   color=THEME['text_muted'], fontsize=10,
                   transform=ax.transAxes)
            ax.tick_params(colors=THEME['text_muted'])
        
        if MATPLOTLIB_OK:
            try:
                self.dashboard_canvas.draw()
            except Exception:
                pass

    def _update_dashboard_charts(self):
        if not MATPLOTLIB_OK or not self.results: return
        
        findings  = self.results.get('findings', [])
        timeline  = self.results.get('timeline', [])
        ports     = self.results.get('ports', {})
        
        # Severity pie
        self.ax_severity.clear()
        self.ax_severity.set_facecolor(THEME['bg_medium'])
        sev_counts = Counter(f.get('severity', 'LOW') for f in findings)
        if sev_counts:
            labels  = list(sev_counts.keys())
            sizes   = list(sev_counts.values())
            colors  = [SEVERITY_COLORS.get(l, THEME['text_muted']) for l in labels]
            wedges, texts, autotexts = self.ax_severity.pie(
                sizes, labels=labels, colors=colors,
                autopct='%1.0f%%', startangle=90,
                textprops={'color': THEME['text_primary'], 'fontsize': 8},
                wedgeprops={'edgecolor': THEME['bg_dark'], 'linewidth': 2}
            )
            for at in autotexts:
                at.set_color(THEME['bg_dark'])
                at.set_fontweight('bold')
        self.ax_severity.set_title(
            'Bevindingen per Ernst',
            color=THEME['text_primary'], fontsize=10, fontweight='bold'
        )
        
        # Traffic timeline
        self.ax_timeline.clear()
        self.ax_timeline.set_facecolor(THEME['bg_medium'])
        if timeline:
            times = [t['ts'] for t in timeline]
            if times:
                t_min = min(times)
                t_norm = [t - t_min for t in times]
                # Buckets per 10 seconden
                max_t = max(t_norm) if t_norm else 1
                buckets = defaultdict(int)
                bucket_size = max(1, max_t / 60)
                for t in t_norm:
                    b = int(t / bucket_size)
                    buckets[b] += 1
                
                xs = sorted(buckets.keys())
                ys = [buckets[x] for x in xs]
                self.ax_timeline.fill_between(
                    xs, ys, alpha=0.4,
                    color=THEME['accent_blue']
                )
                self.ax_timeline.plot(
                    xs, ys,
                    color=THEME['accent_blue'], linewidth=1.5
                )
                self.ax_timeline.set_xlabel(
                    'Tijd (buckets)', color=THEME['text_secondary'], fontsize=8
                )
                self.ax_timeline.set_ylabel(
                    'Packets', color=THEME['text_secondary'], fontsize=8
                )
        
        self.ax_timeline.set_title(
            'Traffic Timeline',
            color=THEME['text_primary'], fontsize=10, fontweight='bold'
        )
        self.ax_timeline.tick_params(colors=THEME['text_secondary'], labelsize=7)
        for spine in self.ax_timeline.spines.values():
            spine.set_color(THEME['border'])
        
        # Top poorten
        self.ax_ports.clear()
        self.ax_ports.set_facecolor(THEME['bg_medium'])
        if ports:
            top_ports = sorted(ports.items(), key=lambda x: -x[1])[:12]
            port_labels = [str(p[0]) for p in top_ports]
            port_vals   = [p[1] for p in top_ports]
            colors_ports = [THEME['accent_blue']] * len(port_labels)
            # Markeer bekende gevaarlijke poorten
            danger_ports = {'4444', '5555', '31337', '1337', '8888', '9999'}
            colors_ports = [
                THEME['accent_red'] if p in danger_ports else THEME['accent_blue']
                for p in port_labels
            ]
            bars = self.ax_ports.barh(
                port_labels, port_vals,
                color=colors_ports, edgecolor=THEME['bg_dark']
            )
            self.ax_ports.set_xlabel(
                'Packets', color=THEME['text_secondary'], fontsize=8
            )
            self.ax_ports.invert_yaxis()
        
        self.ax_ports.set_title(
            'Top Poorten',
            color=THEME['text_primary'], fontsize=10, fontweight='bold'
        )
        self.ax_ports.tick_params(colors=THEME['text_secondary'], labelsize=7)
        for spine in self.ax_ports.spines.values():
            spine.set_color(THEME['border'])
        
        try:
            self.dashboard_canvas.draw()
        except Exception:
            pass

    # ----------------------------------------------------------
    # FINDINGS TAB
    # ----------------------------------------------------------
    def _build_findings_tab(self):
        # Filter bar
        filter_bar = tk.Frame(self.tab_findings, bg=THEME['bg_medium'])
        filter_bar.pack(fill='x', padx=0, pady=0)
        
        tk.Label(
            filter_bar, text="  🔍 Zoeken:",
            bg=THEME['bg_medium'], fg=THEME['text_secondary'],
            font=('Segoe UI', 9)
        ).pack(side='left', pady=10)
        
        self.search_entry = ttk.Entry(
            filter_bar, textvariable=self.search_var,
            style='Dark.TEntry', width=30,
            font=('Consolas', 10)
        )
        self.search_entry.pack(side='left', padx=8, pady=8, ipady=3)
        self.search_var.trace('w', lambda *a: self._filter_findings())
        
        tk.Label(
            filter_bar, text="Ernst:",
            bg=THEME['bg_medium'], fg=THEME['text_secondary'],
            font=('Segoe UI', 9)
        ).pack(side='left', padx=(16,4), pady=10)
        
        sev_combo = ttk.Combobox(
            filter_bar, textvariable=self.filter_severity,
            values=['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            style='Dark.TCombobox', width=12,
            state='readonly', font=('Segoe UI', 9)
        )
        sev_combo.pack(side='left', pady=8)
        self.filter_severity.trace('w', lambda *a: self._filter_findings())
        
        tk.Label(
            filter_bar, text="Type:",
            bg=THEME['bg_medium'], fg=THEME['text_secondary'],
            font=('Segoe UI', 9)
        ).pack(side='left', padx=(16,4))
        
        self.type_combo = ttk.Combobox(
            filter_bar, textvariable=self.filter_type,
            values=['ALL'],
            style='Dark.TCombobox', width=25,
            state='readonly', font=('Segoe UI', 9)
        )
        self.type_combo.pack(side='left', pady=8)
        self.filter_type.trace('w', lambda *a: self._filter_findings())
        
        # Count label
        self.findings_count = tk.Label(
            filter_bar,
            text="0 bevindingen",
            bg=THEME['bg_medium'],
            fg=THEME['text_muted'],
            font=('Segoe UI', 9)
        )
        self.findings_count.pack(side='right', padx=16)
        
        # Split pane: lijst + detail
        paned = tk.PanedWindow(
            self.tab_findings,
            orient='vertical',
            bg=THEME['bg_dark'],
            sashwidth=4,
            sashrelief='flat'
        )
        paned.pack(fill='both', expand=True)
        
        # Findings lijst
        list_frame = tk.Frame(paned, bg=THEME['bg_dark'])
        paned.add(list_frame, minsize=200)
        
        # Scrollable findings list
        self.findings_canvas = tk.Canvas(
            list_frame, bg=THEME['bg_dark'],
            highlightthickness=0
        )
        findings_scroll = ttk.Scrollbar(
            list_frame, orient='vertical',
            command=self.findings_canvas.yview,
            style='Dark.TScrollbar'
        )
        self.findings_inner = tk.Frame(
            self.findings_canvas, bg=THEME['bg_dark']
        )
        
        self.findings_canvas.configure(
            yscrollcommand=findings_scroll.set
        )
        
        findings_scroll.pack(side='right', fill='y')
        self.findings_canvas.pack(side='left', fill='both', expand=True)
        
        self.findings_window = self.findings_canvas.create_window(
            (0, 0), window=self.findings_inner, anchor='nw'
        )
        
        self.findings_inner.bind(
            '<Configure>',
            lambda e: self.findings_canvas.configure(
                scrollregion=self.findings_canvas.bbox('all')
            )
        )
        self.findings_canvas.bind(
            '<Configure>',
            lambda e: self.findings_canvas.itemconfig(
                self.findings_window, width=e.width
            )
        )
        self.findings_canvas.bind_all(
            '<MouseWheel>',
            lambda e: self.findings_canvas.yview_scroll(-1*(e.delta//120), 'units')
        )
        
        # Detail panel
        detail_frame = tk.Frame(paned, bg=THEME['bg_card'])
        paned.add(detail_frame, minsize=150)
        
        detail_header = tk.Frame(detail_frame, bg=THEME['bg_light'])
        detail_header.pack(fill='x')
        
        tk.Label(
            detail_header,
            text="  📋 DETAIL WEERGAVE",
            bg=THEME['bg_light'],
            fg=THEME['accent_blue'],
            font=('Segoe UI', 10, 'bold'),
            pady=8
        ).pack(side='left')
        
        self.detail_text = scrolledtext.ScrolledText(
            detail_frame,
            bg=THEME['bg_card'],
            fg=THEME['text_primary'],
            font=('Consolas', 10),
            insertbackground=THEME['text_primary'],
            selectbackground=THEME['accent_blue'],
            relief='flat',
            wrap='word',
            state='disabled'
        )
        self.detail_text.pack(fill='both', expand=True, padx=0, pady=0)
        
        # Tag configuraties voor gekleurde tekst
        self.detail_text.tag_configure('critical', foreground=THEME['critical'])
        self.detail_text.tag_configure('high',     foreground=THEME['high'])
        self.detail_text.tag_configure('medium',   foreground=THEME['medium'])
        self.detail_text.tag_configure('key',      foreground=THEME['accent_blue'])
        self.detail_text.tag_configure('hex',      foreground=THEME['accent_cyan'],
                                       font=('Consolas', 9))
        self.detail_text.tag_configure('header',   foreground=THEME['accent_purple'],
                                       font=('Consolas', 11, 'bold'))

    def _filter_findings(self):
        if not self.all_findings: return
        
        sev    = self.filter_severity.get()
        ftype  = self.filter_type.get()
        search = self.search_var.get().lower()
        
        filtered = self.all_findings
        
        if sev != 'ALL':
            filtered = [f for f in filtered if f.get('severity') == sev]
        
        if ftype != 'ALL':
            filtered = [f for f in filtered if f.get('type') == ftype]
        
        if search:
            filtered = [f for f in filtered if
                       search in str(f).lower()]
        
        self._populate_findings(filtered)
        self.findings_count.configure(
            text=f"{len(filtered)} / {len(self.all_findings)} bevindingen"
        )

    def _populate_findings(self, findings: list):
        # Verwijder bestaande rijen
        for widget in self.findings_inner.winfo_children():
            widget.destroy()
        
        if not findings:
            tk.Label(
                self.findings_inner,
                text="Geen bevindingen gevonden",
                bg=THEME['bg_dark'],
                fg=THEME['text_muted'],
                font=('Segoe UI', 12),
                pady=40
            ).pack()
            return
        
        for finding in findings:
            row = FindingRow(
                self.findings_inner,
                finding,
                on_click=self._show_finding_detail
            )
            row.pack(fill='x', padx=0, pady=0)

    def _show_finding_detail(self, finding: dict):
        self.detail_text.configure(state='normal')
        self.detail_text.delete('1.0', 'end')
        
        sev   = finding.get('severity', 'LOW')
        ftype = finding.get('type', 'UNKNOWN')
        
        # Header
        self.detail_text.insert('end', f"{'='*60}\n", 'header')
        self.detail_text.insert('end', f"  {ftype}\n", 'header')
        self.detail_text.insert('end', f"{'='*60}\n\n", 'header')
        
        # Severity
        self.detail_text.insert('end', "  Ernst:      ", 'key')
        self.detail_text.insert('end', f"{sev}\n", sev.lower())
        
        # Alle velden
        skip = {'hex_dump', 'type', 'severity', 'timestamp'}
        for key, val in finding.items():
            if key in skip: continue
            self.detail_text.insert('end', f"  {key:<14} ", 'key')
            if isinstance(val, list):
                self.detail_text.insert('end', f"{val[:5]}\n")
            elif isinstance(val, dict):
                self.detail_text.insert('end', '\n')
                for k2, v2 in val.items():
                    self.detail_text.insert('end', f"    {k2}: {v2}\n")
            else:
                self.detail_text.insert('end', f"{str(val)[:300]}\n")
        
        # Hex dump
        if 'hex_dump' in finding:
            self.detail_text.insert('end', "\n  HEX DUMP (xxd stijl):\n", 'key')
            self.detail_text.insert('end', "  " + "-"*58 + "\n", 'hex')
            for line in finding['hex_dump'].split('\n'):
                self.detail_text.insert('end', f"  {line}\n", 'hex')
        
        self.detail_text.configure(state='disabled')

    # ----------------------------------------------------------
    # NETWORK TAB
    # ----------------------------------------------------------
    def _build_network_tab(self):
        if not MATPLOTLIB_OK:
            tk.Label(
                self.tab_network,
                text="Installeer matplotlib:\npip install matplotlib",
                bg=THEME['bg_dark'], fg=THEME['text_muted'],
                font=('Segoe UI', 14)
            ).pack(expand=True)
            return
        
        # IOC treeview
        top = tk.Frame(self.tab_network, bg=THEME['bg_dark'])
        top.pack(fill='both', expand=True)
        
        # Linker panel: IP/Domein lijst
        left_panel = tk.Frame(top, bg=THEME['bg_card'], width=320)
        left_panel.pack(side='left', fill='y', padx=(16,8), pady=16)
        left_panel.pack_propagate(False)
        
        tk.Label(
            left_panel,
            text="🌐 IOC LIJST",
            bg=THEME['bg_card'],
            fg=THEME['accent_blue'],
            font=('Segoe UI', 11, 'bold'),
            pady=10
        ).pack(fill='x')
        
        # IP treeview
        ip_frame = tk.Frame(left_panel, bg=THEME['bg_card'])
        ip_frame.pack(fill='both', expand=True)
        
        tk.Label(
            ip_frame, text="IP Adressen",
            bg=THEME['bg_card'], fg=THEME['text_secondary'],
            font=('Segoe UI', 9, 'bold')
        ).pack(anchor='w', padx=8, pady=(8,2))
        
        self.ip_tree = ttk.Treeview(
            ip_frame,
            columns=('ip', 'count'),
            show='headings',
            style='Dark.Treeview',
            height=10
        )
        self.ip_tree.heading('ip',    text='IP Adres')
        self.ip_tree.heading('count', text='Packets')
        self.ip_tree.column('ip',    width=180)
        self.ip_tree.column('count', width=80, anchor='center')
        self.ip_tree.pack(fill='both', expand=True, padx=8)
        
        # Domain treeview
        tk.Label(
            ip_frame, text="Domeinen",
            bg=THEME['bg_card'], fg=THEME['text_secondary'],
            font=('Segoe UI', 9, 'bold')
        ).pack(anchor='w', padx=8, pady=(12,2))
        
        self.domain_tree = ttk.Treeview(
            ip_frame,
            columns=('domain',),
            show='headings',
            style='Dark.Treeview',
            height=8
        )
        self.domain_tree.heading('domain', text='Domein')
        self.domain_tree.column('domain', width=270)
        self.domain_tree.pack(fill='both', expand=True, padx=8, pady=(0,8))
        
        # Rechter panel: entropy grafiek
        right_panel = tk.Frame(top, bg=THEME['bg_dark'])
        right_panel.pack(side='left', fill='both', expand=True, padx=(0,16), pady=16)
        
        self.fig_network = Figure(figsize=(9, 6), facecolor=THEME['bg_dark'])
        self.ax_entropy  = self.fig_network.add_subplot(211)
        self.ax_flow     = self.fig_network.add_subplot(212)
        
        for ax in [self.ax_entropy, self.ax_flow]:
            ax.set_facecolor(THEME['bg_medium'])
            for spine in ax.spines.values():
                spine.set_color(THEME['border'])
            ax.tick_params(colors=THEME['text_secondary'], labelsize=8)
        
        self.ax_entropy.set_title(
            'Payload Entropy over Tijd',
            color=THEME['text_primary'], fontsize=10
        )
        self.ax_flow.set_title(
            'Top Flows (Data Volume)',
            color=THEME['text_primary'], fontsize=10
        )
        
        self.fig_network.tight_layout(pad=2.0)
        
        canvas = FigureCanvasTkAgg(self.fig_network, right_panel)
        canvas.get_tk_widget().configure(bg=THEME['bg_dark'], highlightthickness=0)
        canvas.get_tk_widget().pack(fill='both', expand=True)
        self.network_canvas = canvas

    def _update_network_tab(self):
        if not MATPLOTLIB_OK or not self.results: return
        
        # IP treeview
        for item in self.ip_tree.get_children():
            self.ip_tree.delete(item)
        
        iocs = self.results.get('iocs', {})
        for ip in sorted(iocs.get('ips', []))[:50]:
            self.ip_tree.insert('', 'end', values=(ip, ''))
        
        # Domain treeview
        for item in self.domain_tree.get_children():
            self.domain_tree.delete(item)
        
        for domain in sorted(iocs.get('domains', []))[:50]:
            self.domain_tree.insert('', 'end', values=(domain,))
        
        # Entropy grafiek
        entropy_data = self.results.get('entropy', [])
        self.ax_entropy.clear()
        self.ax_entropy.set_facecolor(THEME['bg_medium'])
        
        if entropy_data:
            pkts      = [e['pkt']     for e in entropy_data]
            entropies = [e['entropy'] for e in entropy_data]
            colors    = [
                THEME['critical'] if e > 7.2 else
                THEME['high']     if e > 6.0 else
                THEME['medium']   if e > 4.5 else
                THEME['accent_blue']
                for e in entropies
            ]
            self.ax_entropy.scatter(
                pkts, entropies, c=colors,
                s=4, alpha=0.6
            )
            self.ax_entropy.axhline(
                7.2, color=THEME['critical'],
                linestyle='--', linewidth=1,
                label='Encrypted threshold'
            )
            self.ax_entropy.set_ylabel(
                'Entropy', color=THEME['text_secondary'], fontsize=8
            )
            self.ax_entropy.legend(
                facecolor=THEME['bg_dark'],
                labelcolor=THEME['text_primary'],
                fontsize=7
            )
        
        self.ax_entropy.set_title(
            'Payload Entropy (rood=verdacht)',
            color=THEME['text_primary'], fontsize=10
        )
        for spine in self.ax_entropy.spines.values():
            spine.set_color(THEME['border'])
        self.ax_entropy.tick_params(colors=THEME['text_secondary'])
        
        # Flow chart
        flows = self.results.get('flows', {})
        self.ax_flow.clear()
        self.ax_flow.set_facecolor(THEME['bg_medium'])
        
        if flows:
            flow_vols = {
                k: sum(p['sz'] for p in v)
                for k, v in flows.items()
            }
            top_flows = sorted(
                flow_vols.items(), key=lambda x: -x[1]
            )[:10]
            
            if top_flows:
                labels = [k[:35] for k, _ in top_flows]
                values = [v/1024 for _, v in top_flows]
                colors_flow = [
                    THEME['critical'] if v > 1000 else
                    THEME['high']     if v > 500  else
                    THEME['accent_blue']
                    for v in values
                ]
                bars = self.ax_flow.barh(
                    labels, values,
                    color=colors_flow,
                    edgecolor=THEME['bg_dark']
                )
                self.ax_flow.set_xlabel(
                    'KB', color=THEME['text_secondary'], fontsize=8
                )
                self.ax_flow.invert_yaxis()
        
        self.ax_flow.set_title(
            'Top Flows (rood=groot volume)',
            color=THEME['text_primary'], fontsize=10
        )
        for spine in self.ax_flow.spines.values():
            spine.set_color(THEME['border'])
        self.ax_flow.tick_params(colors=THEME['text_secondary'], labelsize=7)
        
        self.fig_network.tight_layout(pad=2.0)
        
        try:
            self.network_canvas.draw()
        except Exception:
            pass

    # ----------------------------------------------------------
    # STATS TAB
    # ----------------------------------------------------------
    def _build_stats_tab(self):
        container = tk.Frame(self.tab_stats, bg=THEME['bg_dark'])
        container.pack(fill='both', expand=True, padx=16, pady=16)
        
        # Statistieken treeview
        left = tk.Frame(container, bg=THEME['bg_card'], width=350)
        left.pack(side='left', fill='y', padx=(0,16))
        left.pack_propagate(False)
        
        tk.Label(
            left,
            text="📊 ANALYSE STATISTIEKEN",
            bg=THEME['bg_card'],
            fg=THEME['accent_blue'],
            font=('Segoe UI', 11, 'bold'),
            pady=12
        ).pack(fill='x')
        
        self.stats_tree = ttk.Treeview(
            left,
            columns=('metric', 'value'),
            show='headings',
            style='Dark.Treeview'
        )
        self.stats_tree.heading('metric', text='Metriek')
        self.stats_tree.heading('value',  text='Waarde')
        self.stats_tree.column('metric', width=200)
        self.stats_tree.column('value',  width=120, anchor='center')
        self.stats_tree.pack(fill='both', expand=True, padx=8, pady=(0,8))
        
        # Rechter panel: finding types grafiek
        right = tk.Frame(container, bg=THEME['bg_dark'])
        right.pack(side='left', fill='both', expand=True)
        
        if MATPLOTLIB_OK:
            self.fig_stats = Figure(figsize=(8, 6), facecolor=THEME['bg_dark'])
            self.ax_types  = self.fig_stats.add_subplot(111)
            self.ax_types.set_facecolor(THEME['bg_medium'])
            
            canvas = FigureCanvasTkAgg(self.fig_stats, right)
            canvas.get_tk_widget().configure(bg=THEME['bg_dark'], highlightthickness=0)
            canvas.get_tk_widget().pack(fill='both', expand=True)
            self.stats_canvas = canvas

    def _update_stats_tab(self):
        if not self.results: return
        
        stats = self.results.get('stats', {})
        
        # Stats treeview
        for item in self.stats_tree.get_children():
            self.stats_tree.delete(item)
        
        display = {
            'Totaal Packets':    stats.get('total_packets', 0),
            'TCP Packets':       stats.get('tcp', 0),
            'UDP Packets':       stats.get('udp', 0),
            'DNS Queries':       stats.get('dns_queries', 0),
            'Geanalyseerd':      stats.get('analyzed', 0),
            'Totale Data (KB)':  f"{stats.get('total_bytes',0)//1024:,}",
            '─'*20:              '─'*10,
            'Totaal Bevindingen':stats.get('total_findings', 0),
            'CRITICAL':          stats.get('critical', 0),
            'HIGH':              stats.get('high', 0),
            'MEDIUM':            stats.get('medium', 0),
        }
        
        for metric, value in display.items():
            tags = []
            if 'CRITICAL' in str(metric):
                tags = ['critical']
            elif 'HIGH' in str(metric):
                tags = ['high']
            self.stats_tree.insert(
                '', 'end',
                values=(metric, value),
                tags=tags
            )
        
        self.stats_tree.tag_configure(
            'critical', foreground=THEME['critical']
        )
        self.stats_tree.tag_configure(
            'high', foreground=THEME['high']
        )
        
        # Bevinding types grafiek
        if MATPLOTLIB_OK:
            findings = self.results.get('findings', [])
            type_counts = Counter(f.get('type', 'UNKNOWN') for f in findings)
            
            self.ax_types.clear()
            self.ax_types.set_facecolor(THEME['bg_medium'])
            
            if type_counts:
                top_types = type_counts.most_common(12)
                labels    = [t[0].replace('_', '\n') for t in top_types]
                values    = [t[1] for t in top_types]
                colors    = []
                
                for ftype, _ in top_types:
                    # Kleur op basis van ernst van type
                    if any(x in ftype for x in ['CRITICAL', 'SHELL', 'C2', 'EXFIL']):
                        colors.append(THEME['critical'])
                    elif any(x in ftype for x in ['BASE64', 'BINARY', 'HIGH']):
                        colors.append(THEME['high'])
                    elif any(x in ftype for x in ['DNS', 'MEDIUM', 'SUSPICIOUS']):
                        colors.append(THEME['medium'])
                    else:
                        colors.append(THEME['accent_blue'])
                
                bars = self.ax_types.barh(
                    labels, values,
                    color=colors,
                    edgecolor=THEME['bg_dark'],
                    height=0.7
                )
                
                # Value labels
                for bar, val in zip(bars, values):
                    self.ax_types.text(
                        bar.get_width() + 0.1,
                        bar.get_y() + bar.get_height()/2,
                        str(val),
                        va='center',
                        color=THEME['text_primary'],
                        fontsize=9
                    )
                
                self.ax_types.invert_yaxis()
                self.ax_types.set_xlabel(
                    'Aantal', color=THEME['text_secondary']
                )
            
            self.ax_types.set_title(
                'Bevindingen per Type',
                color=THEME['text_primary'],
                fontsize=11, fontweight='bold'
            )
            for spine in self.ax_types.spines.values():
                spine.set_color(THEME['border'])
            self.ax_types.tick_params(
                colors=THEME['text_secondary'], labelsize=8
            )
            
            self.fig_stats.tight_layout()
            
            try:
                self.stats_canvas.draw()
            except Exception:
                pass

    # ----------------------------------------------------------
    # HEX VIEWER TAB
    # ----------------------------------------------------------
    def _build_hex_tab(self):
        # Toolbar
        toolbar = tk.Frame(self.tab_hex, bg=THEME['bg_medium'])
        toolbar.pack(fill='x')
        
        tk.Label(
            toolbar, text="  📁 Bestand:",
            bg=THEME['bg_medium'], fg=THEME['text_secondary'],
            font=('Segoe UI', 9)
        ).pack(side='left', pady=8)
        
        self.hex_file_var = tk.StringVar()
        hex_entry = ttk.Entry(
            toolbar, textvariable=self.hex_file_var,
            style='Dark.TEntry', width=40
        )
        hex_entry.pack(side='left', padx=8, ipady=3)
        
        ttk.Button(
            toolbar, text="📂 Open",
            command=self._hex_open_file,
            style='Accent.TButton'
        ).pack(side='left', padx=4, pady=6)
        
        ttk.Button(
            toolbar, text="🔍 Analyseer",
            command=self._hex_analyze,
            style='Accent.TButton'
        ).pack(side='left', padx=4)
        
        # Hex display
        hex_paned = tk.PanedWindow(
            self.tab_hex, orient='horizontal',
            bg=THEME['bg_dark'], sashwidth=4
        )
        hex_paned.pack(fill='both', expand=True, padx=8, pady=8)
        
        # Hex dump
        left_hex = tk.Frame(hex_paned, bg=THEME['bg_dark'])
        hex_paned.add(left_hex, minsize=500)
        
        tk.Label(
            left_hex,
            text="HEX DUMP (xxd stijl)",
            bg=THEME['bg_dark'],
            fg=THEME['accent_blue'],
            font=('Segoe UI', 9, 'bold')
        ).pack(anchor='w', padx=8, pady=4)
        
        self.hex_text = scrolledtext.ScrolledText(
            left_hex,
            bg='#0a0a0a',
            fg=THEME['accent_cyan'],
            font=('Consolas', 11),
            insertbackground=THEME['text_primary'],
            selectbackground=THEME['accent_blue'],
            relief='flat',
            wrap='none',
            state='disabled'
        )
        self.hex_text.pack(fill='both', expand=True, padx=8, pady=(0,8))
        
        # Analyse resultaten
        right_hex = tk.Frame(hex_paned, bg=THEME['bg_dark'])
        hex_paned.add(right_hex, minsize=300)
        
        tk.Label(
            right_hex,
            text="ANALYSE RESULTATEN",
            bg=THEME['bg_dark'],
            fg=THEME['accent_blue'],
            font=('Segoe UI', 9, 'bold')
        ).pack(anchor='w', padx=8, pady=4)
        
        self.hex_analysis_text = scrolledtext.ScrolledText(
            right_hex,
            bg=THEME['bg_card'],
            fg=THEME['text_primary'],
            font=('Consolas', 10),
            relief='flat',
            wrap='word',
            state='disabled'
        )
        self.hex_analysis_text.pack(fill='both', expand=True, padx=8, pady=(0,8))
        
        # Base64 decoder sectie
        b64_frame = tk.Frame(self.tab_hex, bg=THEME['bg_medium'])
        b64_frame.pack(fill='x', padx=8, pady=(0,8))
        
        tk.Label(
            b64_frame, text="  🔓 Base64 Decoder:",
            bg=THEME['bg_medium'], fg=THEME['text_secondary'],
            font=('Segoe UI', 9)
        ).pack(side='left', pady=8)
        
        self.b64_var = tk.StringVar()
        ttk.Entry(
            b64_frame, textvariable=self.b64_var,
            style='Dark.TEntry', width=50,
            font=('Consolas', 10)
        ).pack(side='left', padx=8, ipady=3, pady=6)
        
        ttk.Button(
            b64_frame, text="🔍 Decode",
            command=self._decode_b64,
            style='Accent.TButton'
        ).pack(side='left', padx=4)
        
        ttk.Button(
            b64_frame, text="↺ Chain Decode",
            command=self._chain_decode_b64,
            style='Accent.TButton'
        ).pack(side='left', padx=4)

    def _hex_open_file(self):
        path = filedialog.askopenfilename(
            title="Selecteer bestand voor hex analyse",
            filetypes=[("Alle bestanden", "*.*")]
        )
        if path:
            self.hex_file_var.set(path)
            self._hex_analyze()

    def _hex_analyze(self):
        path = self.hex_file_var.get()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Waarschuwing", "Selecteer eerst een geldig bestand")
            return
        
        try:
            with open(path, 'rb') as f:
                data = f.read(65536)  # Max 64KB
            
            # Hex dump
            dump = xxd_dump(data, min(len(data), 4096))
            self.hex_text.configure(state='normal')
            self.hex_text.delete('1.0', 'end')
            self.hex_text.insert('end', dump)
            self.hex_text.configure(state='disabled')
            
            # Analyse
            entropy = calculate_entropy(data)
            md5     = hashlib.md5(data).hexdigest()
            sha256  = hashlib.sha256(data).hexdigest()
            
            analysis = f"""{'='*50}
BESTAND ANALYSE
{'='*50}
Pad:        {path}
Grootte:    {len(data):,} bytes ({len(data)/1024:.1f} KB)
MD5:        {md5}
SHA256:     {sha256}
Entropy:    {entropy} {'⚠️ HOOG (encrypted?)' if entropy > 7.0 else '✓ Normaal'}
Printbaar:  {sum(1 for b in data if 32<=b<127)/len(data)*100:.1f}%

{'='*50}
MAGIC BYTES DETECTIE
{'='*50}
"""
            for magic, (ftype, sev) in MAGIC_BYTES.items():
                if data.startswith(magic):
                    analysis += f"[{sev}] {ftype} – Magic: {magic.hex()}\n"
                else:
                    idx = data.find(magic)
                    if 0 < idx < 1024:
                        analysis += f"[{sev}] {ftype} @ offset {idx}\n"
            
            # Shellcode
            analysis += f"\n{'='*50}\nSHELLCODE INDICATOREN\n{'='*50}\n"
            shellcode_patterns = {
                'NOP sled':     b'\x90'*8,
                'INT 0x80':     b'\xcd\x80',
                'XOR EAX':      b'\x31\xc0',
                'SYSCALL x64':  b'\x0f\x05',
                'PEB Access':   b'\x64\xa1\x30\x00\x00\x00',
            }
            found_sc = False
            for name, pat in shellcode_patterns.items():
                if pat in data:
                    idx = data.find(pat)
                    analysis += f"[!] {name} @ offset {idx}: {data[idx:idx+8].hex()}\n"
                    found_sc = True
            if not found_sc:
                analysis += "Geen shellcode patronen gevonden\n"
            
            # Base64 in bestand
            b64_results = decode_b64_layers(data[:8192])
            if b64_results:
                analysis += f"\n{'='*50}\nBASE64 GEVONDEN\n{'='*50}\n"
                for res in b64_results[:5]:
                    analysis += f"B64: {res['b64'][:60]}...\n"
                    analysis += f"  → {res['decoded'][:100]}\n"
                    analysis += f"  Entropy: {res['entropy']}\n\n"
            
            self.hex_analysis_text.configure(state='normal')
            self.hex_analysis_text.delete('1.0', 'end')
            self.hex_analysis_text.insert('end', analysis)
            self.hex_analysis_text.configure(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Fout", f"Analyse mislukt: {e}")

    def _decode_b64(self):
        text = self.b64_var.get().strip()
        if not text: return
        try:
            decoded = base64.b64decode(text + '==')
            result  = f"Decoded ({len(decoded)} bytes):\n"
            result += f"  Text:    {decoded[:200].decode('utf-8', errors='replace')}\n"
            result += f"  Hex:     {decoded[:32].hex()}\n"
            result += f"  Entropy: {calculate_entropy(decoded)}\n\n"
            result += f"Hex dump:\n{xxd_dump(decoded[:256])}"
            
            self.hex_analysis_text.configure(state='normal')
            self.hex_analysis_text.delete('1.0', 'end')
            self.hex_analysis_text.insert('end', result)
            self.hex_analysis_text.configure(state='disabled')
        except Exception as e:
            messagebox.showerror("Decode Fout", str(e))

    def _chain_decode_b64(self):
        text    = self.b64_var.get().strip()
        if not text: return
        current = text.encode()
        result  = "BASE64 CHAIN DECODE\n" + "="*40 + "\n\n"
        level   = 0
        
        while level < 10:
            try:
                decoded = base64.b64decode(current + b'==')
                result += f"Layer {level}:\n"
                result += f"  Input:   {current[:80].decode('utf-8','replace')}\n"
                result += f"  Output:  {decoded[:100].decode('utf-8','replace')}\n"
                result += f"  Hex:     {decoded[:16].hex()}\n"
                result += f"  Entropy: {calculate_entropy(decoded)}\n\n"
                result += xxd_dump(decoded[:64]) + "\n\n"
                current = decoded
                level  += 1
            except Exception:
                result += f"→ Niet verder te decoderen (level {level})\n"
                break
        
        self.hex_analysis_text.configure(state='normal')
        self.hex_analysis_text.delete('1.0', 'end')
        self.hex_analysis_text.insert('end', result)
        self.hex_analysis_text.configure(state='disabled')

    # ----------------------------------------------------------
    # LOG TAB
    # ----------------------------------------------------------
    def _build_log_tab(self):
        # Toolbar
        log_toolbar = tk.Frame(self.tab_log, bg=THEME['bg_medium'])
        log_toolbar.pack(fill='x')
        
        ttk.Button(
            log_toolbar, text="🗑 Wis Log",
            command=self._clear_log,
            style='Accent.TButton'
        ).pack(side='left', padx=8, pady=6)
        
        ttk.Button(
            log_toolbar, text="💾 Sla Log Op",
            command=self._save_log,
            style='Accent.TButton'
        ).pack(side='left', padx=4)
        
        self.auto_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            log_toolbar,
            text="Auto-scroll",
            variable=self.auto_scroll_var
        ).pack(side='right', padx=16)
        
        # Log text
        self.log_text = scrolledtext.ScrolledText(
            self.tab_log,
            bg='#050505',
            fg=THEME['accent_green'],
            font=('Consolas', 10),
            insertbackground=THEME['text_primary'],
            selectbackground=THEME['accent_blue'],
            relief='flat',
            state='disabled'
        )
        self.log_text.pack(fill='both', expand=True, padx=8, pady=8)
        
        # Log tags
        self.log_text.tag_configure(
            'INFO',    foreground=THEME['accent_blue']
        )
        self.log_text.tag_configure(
            'SUCCESS', foreground=THEME['accent_green']
        )
        self.log_text.tag_configure(
            'WARN',    foreground=THEME['medium']
        )
        self.log_text.tag_configure(
            'ERROR',   foreground=THEME['critical']
        )
        self.log_text.tag_configure(
            'time',    foreground=THEME['text_muted']
        )

    def _log(self, message: str, level: str = 'INFO'):
        """Voeg toe aan log queue (thread-safe)"""
        self.log_queue.put((message, level))

    def _poll_log_queue(self):
        """Verwerk log queue in main thread"""
        try:
            while True:
                message, level = self.log_queue.get_nowait()
                self._write_log(message, level)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_log_queue)

    def _write_log(self, message: str, level: str = 'INFO'):
        self.log_text.configure(state='normal')
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.log_text.insert('end', f"[{timestamp}] ", 'time')
        self.log_text.insert('end', f"{message}\n", level)
        
        if self.auto_scroll_var.get():
            self.log_text.see('end')
        
        self.log_text.configure(state='disabled')
        self.status_var.set(message[:100])

    def _clear_log(self):
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', 'end')
        self.log_text.configure(state='disabled')

    def _save_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension='.txt',
            filetypes=[("Text bestanden", "*.txt")]
        )
        if path:
            content = self.log_text.get('1.0', 'end')
            with open(path, 'w') as f:
                f.write(content)
            messagebox.showinfo("Opgeslagen", f"Log opgeslagen: {path}")

    # ----------------------------------------------------------
    # NAVIGATIE
    # ----------------------------------------------------------
    def _show_dashboard(self):  self.notebook.select(0)
    def _show_findings(self):   self.notebook.select(1)
    def _show_network(self):    self.notebook.select(2)
    def _show_stats(self):      self.notebook.select(3)
    def _show_hex(self):        self.notebook.select(4)
    def _show_log(self):        self.notebook.select(5)

    # ----------------------------------------------------------
    # ANALYSE CONTROLE
    # ----------------------------------------------------------
    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Selecteer PCAP bestand",
            filetypes=[
                ("PCAP bestanden", "*.pcap *.pcapng *.cap"),
                ("Alle bestanden", "*.*")
            ]
        )
        if path:
            self.current_pcap.set(path)
            fname = os.path.basename(path)
            fsize = os.path.getsize(path)
            self.file_label.configure(
                text=f"{fname}\n{fsize/1024/1024:.2f} MB"
            )
            self._log(f"Bestand geselecteerd: {fname} ({fsize/1024:.0f} KB)", "INFO")

    def _start_analysis(self):
        pcap_path = self.current_pcap.get().strip()
        
        if not pcap_path:
            messagebox.showwarning(
                "Geen bestand", "Selecteer eerst een PCAP bestand"
            )
            return
        
        if not os.path.exists(pcap_path):
            messagebox.showerror(
                "Bestand niet gevonden",
                f"Kan bestand niet vinden:\n{pcap_path}"
            )
            return
        
        if not SCAPY_OK:
            messagebox.showerror(
                "Scapy Ontbreekt",
                "Installeer scapy: pip install scapy"
            )
            return
        
        # Reset UI
        self.results     = {}
        self.all_findings = []
        self._draw_placeholder_charts()
        
        # Knoppen
        self.analyze_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        
        self._log("=" * 50, "INFO")
        self._log(f"🚀 Analyse gestart: {pcap_path}", "INFO")
        self._log("=" * 50, "INFO")
        
        # Engine
        self.engine = AnalysisEngine(
            progress_cb=self._update_progress,
            log_cb=self._log
        )
        
        # Thread
        self.analysis_thread = threading.Thread(
            target=self._run_analysis,
            args=(pcap_path,),
            daemon=True
        )
        self.analysis_thread.start()

    def _run_analysis(self, pcap_path: str):
        try:
            results = self.engine.analyze(pcap_path)
            if results:
                self.results = results
                self.root.after(0, self._analysis_complete)
        except Exception as e:
            self._log(f"❌ Analyse fout: {e}", "ERROR")
            self.root.after(0, self._analysis_failed, str(e))

    def _stop_analysis(self):
        if self.engine:
            self.engine.cancel()
            self._log("⏹ Analyse gestopt door gebruiker", "WARN")
        self.analyze_btn.configure(state='normal')
        self.stop_btn.configure(state='disabled')

    def _update_progress(self, value: int, text: str):
        def _update():
            self.progress_bar.set(value)
            self.progress_label.configure(text=text)
        self.root.after(0, _update)

    def _analysis_complete(self):
        self.analyze_btn.configure(state='normal')
        self.stop_btn.configure(state='disabled')
        
        findings  = self.results.get('findings', [])
        stats     = self.results.get('stats', {})
        
        self.all_findings = findings
        
        # Update type filter opties
        types = ['ALL'] + sorted(set(f.get('type', '') for f in findings))
        self.type_combo.configure(values=types)
        
        # Update stat cards
        self.card_total.update_value(stats.get('total_packets', 0))
        self.card_critical.update_value(stats.get('critical', 0))
        self.card_high.update_value(stats.get('high', 0))
        self.card_medium.update_value(stats.get('medium', 0))
        self.card_dns.update_value(stats.get('dns_queries', 0))
        self.card_findings.update_value(len(findings))
        
        # Populate findings
        self._populate_findings(findings)
        self.findings_count.configure(
            text=f"{len(findings)} bevindingen"
        )
        
        # Update grafieken
        self._update_dashboard_charts()
        self._update_network_tab()
        self._update_stats_tab()
        
        # Samenvatting log
        self._log("=" * 50, "SUCCESS")
        self._log(f"✅ Analyse voltooid!", "SUCCESS")
        self._log(f"   Packets:    {stats.get('total_packets', 0):,}", "INFO")
        self._log(f"   Bevindingen:{len(findings)}", "INFO")
        self._log(f"   CRITICAL:   {stats.get('critical', 0)}", "ERROR")
        self._log(f"   HIGH:       {stats.get('high', 0)}", "WARN")
        self._log("=" * 50, "SUCCESS")
        
        # Alert bij kritieke bevindingen
        if stats.get('critical', 0) > 0:
            self.notebook.select(1)  # Ga naar bevindingen tab
            messagebox.showwarning(
                "⚠️ Kritieke Bevindingen!",
                f"{stats.get('critical', 0)} KRITIEKE bevindingen gevonden!\n\n"
                f"Controleer de Bevindingen tab voor details."
            )

    def _analysis_failed(self, error: str):
        self.analyze_btn.configure(state='normal')
        self.stop_btn.configure(state='disabled')
        messagebox.showerror("Analyse Mislukt", f"Fout: {error}")

    # ----------------------------------------------------------
    # EXPORT FUNCTIES
    # ----------------------------------------------------------
    def _export_json(self):
        if not self.results:
            messagebox.showwarning("Geen Data", "Voer eerst een analyse uit")
            return
        
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            initialfile=f"pcap_rapport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            filetypes=[("JSON bestanden", "*.json")]
        )
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, default=str, ensure_ascii=False)
            self._log(f"💾 JSON rapport opgeslagen: {path}", "SUCCESS")
            messagebox.showinfo("Opgeslagen", f"Rapport opgeslagen:\n{path}")

    def _export_html(self):
        if not self.results:
            messagebox.showwarning("Geen Data", "Voer eerst een analyse uit")
            return
        
        path = filedialog.asksaveasfilename(
            defaultextension='.html',
            initialfile=f"pcap_rapport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            filetypes=[("HTML bestanden", "*.html")]
        )
        if path:
            html = self._generate_html_report()
            with open(path, 'w', encoding='utf-8') as f:
                f.write(html)
            self._log(f"📄 HTML rapport opgeslagen: {path}", "SUCCESS")
            messagebox.showinfo("Opgeslagen", f"HTML rapport opgeslagen:\n{path}")

    def _generate_html_report(self) -> str:
        findings  = self.results.get('findings', [])
        stats     = self.results.get('stats', {})
        iocs      = self.results.get('iocs', {})
        pcap_file = self.current_pcap.get()
        
        critical = [f for f in findings if f.get('severity') == 'CRITICAL']
        high     = [f for f in findings if f.get('severity') == 'HIGH']
        medium   = [f for f in findings if f.get('severity') == 'MEDIUM']
        
        findings_html = ""
        for f in findings[:200]:
            sev   = f.get('severity', 'LOW')
            color = {'CRITICAL':'#ff4444','HIGH':'#ff8800',
                     'MEDIUM':'#ffcc00','LOW':'#44ff88'}.get(sev,'#888')
            
            details = ""
            for k, v in f.items():
                if k not in ['hex_dump', 'severity', 'type']:
                    val = str(v)[:500]
                    details += f"<tr><td><b>{k}</b></td><td>{val}</td></tr>"
            
            hex_section = ""
            if 'hex_dump' in f:
                hex_section = f"""
                <div style="margin-top:10px">
                <b>HEX DUMP:</b>
                <pre style="background:#050505;color:#39d353;padding:10px;
                            border-radius:4px;overflow-x:auto;font-size:11px">
{f['hex_dump'][:1000]}</pre></div>"""
            
            findings_html += f"""
            <div class="finding" style="border-left:4px solid {color}">
                <div class="finding-header">
                    <span class="badge" style="background:{color}">{sev}</span>
                    <span class="finding-type">{f.get('type','UNKNOWN')}</span>
                    <span class="finding-desc">{f.get('description','')}</span>
                </div>
                <table class="detail-table">{details}</table>
                {hex_section}
            </div>"""
        
        ips_html = ''.join(
            f'<span class="ioc-badge">{ip}</span>'
            for ip in sorted(iocs.get('ips', []))[:50]
        )
        domains_html = ''.join(
            f'<span class="ioc-badge">{d}</span>'
            for d in sorted(iocs.get('domains', []))[:50]
        )
        
        return f"""<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<title>PCAP Rapport – {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
<style>
  * {{ margin:0;padding:0;box-sizing:border-box }}
  body {{ background:#0d1117;color:#e6edf3;font-family:'Segoe UI',sans-serif;padding:20px }}
  .header {{ background:#161b22;border:1px solid #30363d;border-radius:8px;
             padding:24px;margin-bottom:20px }}
  .header h1 {{ color:#58a6ff;font-size:28px;margin-bottom:8px }}
  .header .meta {{ color:#8b949e;font-size:13px }}
  .stats-grid {{ display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:20px }}
  .stat-card {{ background:#1c2128;border-radius:8px;padding:16px;text-align:center }}
  .stat-card .value {{ font-size:32px;font-weight:bold;margin:8px 0 }}
  .stat-card .label {{ color:#8b949e;font-size:12px }}
  .section {{ background:#161b22;border:1px solid #30363d;border-radius:8px;
              padding:20px;margin-bottom:16px }}
  .section h2 {{ color:#58a6ff;margin-bottom:16px;font-size:16px }}
  .finding {{ background:#1c2128;border-radius:6px;padding:16px;
              margin-bottom:10px }}
  .finding-header {{ display:flex;align-items:center;gap:12px;margin-bottom:10px }}
  .badge {{ padding:3px 10px;border-radius:4px;color:#000;font-weight:bold;
            font-size:12px }}
  .finding-type {{ color:#58a6ff;font-weight:bold;font-size:14px }}
  .finding-desc {{ color:#8b949e;font-size:13px }}
  .detail-table {{ width:100%;border-collapse:collapse;font-size:12px }}
  .detail-table td {{ padding:4px 8px;border-bottom:1px solid #21262d }}
  .detail-table td:first-child {{ color:#58a6ff;width:140px;font-weight:bold }}
  .ioc-badge {{ display:inline-block;background:#21262d;border:1px solid #30363d;
                border-radius:4px;padding:2px 8px;margin:3px;font-size:12px;
                font-family:Consolas,monospace;color:#39d353 }}
  .critical {{ color:#ff4444 }}
  .high     {{ color:#ff8800 }}
  .medium   {{ color:#ffcc00 }}
  pre {{ overflow-x:auto }}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 Deep PCAP Inspectie Rapport</h1>
  <div class="meta">
    Bestand: {pcap_file} |
    Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
    Tool: Deep PCAP Inspector v2.0
  </div>
</div>

<div class="stats-grid">
  <div class="stat-card">
    <div class="value" style="color:#58a6ff">{stats.get('total_packets',0):,}</div>
    <div class="label">Totaal Packets</div>
  </div>
  <div class="stat-card">
    <div class="value class=critical" style="color:#ff4444">{len(critical)}</div>
    <div class="label">CRITICAL</div>
  </div>
  <div class="stat-card">
    <div class="value" style="color:#ff8800">{len(high)}</div>
    <div class="label">HIGH</div>
  </div>
  <div class="stat-card">
    <div class="value" style="color:#ffcc00">{len(medium)}</div>
    <div class="label">MEDIUM</div>
  </div>
  <div class="stat-card">
    <div class="value" style="color:#bc8cff">{stats.get('dns_queries',0):,}</div>
    <div class="label">DNS Queries</div>
  </div>
  <div class="stat-card">
    <div class="value" style="color:#3fb950">{len(findings)}</div>
    <div class="label">Bevindingen</div>
  </div>
</div>

<div class="section">
  <h2>🌐 IOC's – IP Adressen</h2>
  {ips_html}
</div>

<div class="section">
  <h2>🌐 IOC's – Domeinen</h2>
  {domains_html}
</div>

<div class="section">
  <h2>🚨 Bevindingen ({len(findings)} totaal)</h2>
  {findings_html}
</div>

<div style="color:#484f58;text-align:center;padding:20px;font-size:12px">
  Gegenereerd door Deep PCAP Inspector v2.0 –
  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div>
</body>
</html>"""

# ============================================================
# DEPENDENCY CHECK DIALOG
# ============================================================
def check_and_install_deps(root):
    if not MISSING_DEPS:
        return True
    
    msg = (
        f"Ontbrekende dependencies: {', '.join(MISSING_DEPS)}\n\n"
        f"Installeer met:\n"
        f"pip install {' '.join(MISSING_DEPS)}\n\n"
        f"Wil je doorgaan zonder deze packages?"
    )
    return messagebox.askyesno("Dependencies Ontbreken", msg)

# ============================================================
# ENTRY POINT
# ============================================================
def main():
    root = tk.Tk()
    
    # Dependency check
    if not check_and_install_deps(root):
        root.destroy()
        return
    
    # Dark title bar (Windows)
    try:
        root.tk.call('source', 'azure.tcl')
        root.tk.call('set_theme', 'dark')
    except Exception:
        pass
    
    app = PCAPInspectorGUI(root)
    
    # Graceful sluiten
    def on_close():
        if app.engine:
            app.engine.cancel()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

if __name__ == '__main__':
    main()
```

## Installatie & Gebruik

```bash
# Installeer alle dependencies
pip install scapy matplotlib numpy

# Start de GUI
python pcap_inspector_gui.py

# Of met een direct bestand
python pcap_inspector_gui.py
```

## Feature Overzicht

| Tab | Functie |
|-----|---------|
| **📊 Dashboard** | Stat cards, severity pie, traffic timeline, top poorten |
| **🚨 Bevindingen** | Filterbaar, zoekbaar, klikbare detail view met hex dump |
| **🌐 Netwerk** | IOC lijst, entropy scatter plot, top flows grafiek |
| **📈 Statistieken** | Alle metrics + bevindingen per type grafiek |
| **💻 Hex Viewer** | xxd dump, magic bytes, shellcode, base64 chain decoder |
| **📋 Log** | Live analyse log met auto-scroll |

### Geautomatiseerde detectie
- 🔴 **C2 Beaconing** – timing analyse met jitter score
- 🔴 **Shellcode** – NOP sleds, syscalls, XOR encoding
- 🔴 **Data exfiltratie** – hoge entropie POST bodies
- 🔴 **DNS Tunneling** – lange subdomains, base64/hex in DNS
- 🔴 **DGA** – Domain Generation Algorithm detectie
- 🟠 **Gevoelige data** – wachtwoorden, API keys, NTLM hashes
- 🟠 **Binary transfers** – PE/ELF/ZIP via HTTP