#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MikroTik Syslog Server Pro Enterprise v3.2 (met Grafische Verkeersanalyse)
========================================================================
Een geavanceerde, professionele grafische Syslog-server (UDP en/of TCP) 
speciaal ontworpen voor MikroTik RouterOS met:
  * Professionele Dark Mode GUI (Tkinter + ttk)
  * Realtime log-filtering, snelfilters en regex zoeken
  * Automatische Dreigingsdetectie (Brute-force inlogpogingen, firewall drops)
  * Dedicated tabblad 'Dreigingsanalyse' voor security monitoring
  * **Nieuw:** Tabblad 'Verkeer & Grafieken' met ingebedde Matplotlib visualisaties 
    (Top bestemde domeinen, actieve clients en severity verdeling)
  * Integratie met MikroTik DHCP-leases voor automatische hostnamen
  * Export naar ruw logboek (.txt/.csv) en professioneel HTML-auditrapport
"""

import base64
import csv
import datetime
import html
import json
import os
import queue
import re
import socket
import socketserver
import ssl
import sys
import threading
import urllib.request

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog
except ImportError:
    tk = ttk = filedialog = messagebox = simpledialog = None

try:
    import matplotlib
    matplotlib.use("TkAgg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

APP_TITLE = "MikroTik Syslog Server Pro Enterprise v3.2"
VERSION = "3.2"

MAX_STORED = 25000
MAX_TEXT_LINES = 10000
TRIM_LINES = 2500
MAX_PENDING_DNS = 10000

HOSTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mikrotik_hosts.json")

SEVERITY_NAMES = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"]
FACILITY_NAMES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5",
    "local6", "local7"
]

PRI_RE = re.compile(r"^<(\d{1,3})>\s*")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# MikroTik DNS & Threat Heuristics
DNS_QUERY_RE = re.compile(r"query from (?P<client>\d{1,3}(\.\d{1,3}){3}):\s*#(?P<qid>\d+)\s+(?P<domain>\S+)\s+(?P<qtype>[A-Z]+)\s*$")
DNS_DONE_RE = re.compile(r"done query:\s*#(?P<qid>\d+)\s+(?P<rest>.+)$")
DNS_RR_RE = re.compile(r"<(?P<domain>\S+?):(?P<rtype>[A-Z]+):\d+=(?P<value>[^>]+)>")

BRUTE_FORCE_RE = re.compile(r"(login failure|failed login|auth failed|ssh.*failed|ftp.*failed|password failed|winbox.*failed)", re.IGNORECASE)
FIREWALL_DROP_RE = re.compile(r"(firewall,info|drop|reject|block|denied)", re.IGNORECASE)

def parse_syslog(text):
    m = PRI_RE.match(text)
    if not m:
        return None, None, text
    pri = int(m.group(1))
    if pri > 191:
        return None, None, text
    return pri >> 3, pri & 0x07, text[m.end():]

def classify_dns(text):
    m = DNS_QUERY_RE.search(text)
    if m:
        return {"kind": "query", "client": m.group("client"), "qid": m.group("qid"), "domain": m.group("domain").rstrip("."), "qtype": m.group("qtype")}
    m = DNS_DONE_RE.search(text)
    if m:
        rest = m.group("rest").strip()
        parts = rest.split(None, 1)
        domain, result = None, rest
        if len(parts) == 2 and parts[0].endswith("."):
            domain, result = parts[0].rstrip("."), parts[1].strip()
        ip = result if IPV4_RE.match(result) or (":" in result and " " not in result) else None
        return {"kind": "done", "qid": m.group("qid"), "domain": domain, "result": result, "ip": ip}
    m = DNS_RR_RE.search(text)
    if m:
        return {"kind": "rr", "domain": m.group("domain").rstrip("."), "rtype": m.group("rtype"), "value": m.group("value")}
    return None

def detect_local_ip(router_ip):
    for target in (router_ip, "8.8.8.8"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect((target, 65000))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                return ip
        except OSError:
            pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"

class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, _sock = self.request
        if not data:
            return
        msg = data.decode("utf-8", "replace").replace("\x00", "")
        try:
            self.server.log_queue.put((self.client_address[0], msg))
        except Exception:
            pass

class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        peer = self.client_address[0]
        while True:
            try:
                line = self.rfile.readline()
            except OSError:
                break
            if not line:
                break
            msg = line.decode("utf-8", "replace").strip().replace("\x00", "")
            if msg:
                try:
                    self.server.log_queue.put((peer, msg))
                except Exception:
                    pass

class _ThreadingUDPServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True

class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

class MikroTikSyslogProApp:
    QUICK_FILTERS = ["Alles", "Alleen Errors & Warnings", "Dreigingen / Brute-force", "Firewall Drops", "DNS Resoluties"]
    VIEW_MODES = ["Compact (DNS samengevat)", "Alles (ruw)", "Alleen belangrijk"]

    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1320x840")
        self.root.minsize(980, 600)

        self.messages = []
        self.total_received = 0
        self.log_queue = queue.Queue()
        self.udp_server = None
        self.tcp_server = None
        self.log_file = None
        self.running = False
        self._filter_job = None
        self._tabs_job = None
        self._tree_sort_states = {}
        self.local_ip = detect_local_ip("192.168.178.1")

        self.brute_force_events = []
        self.firewall_drops = []
        self._dns_pending = {}
        self.domains = {}
        self.devices = {}
        self.host_names = {}
        self._load_hosts()

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._update_bottom()
        self._poll()

    @staticmethod
    def _coerce_sort_value(value):
        if value is None:
            return (2, "")
        if isinstance(value, (int, float)):
            return (0, float(value))
        if isinstance(value, str):
            text = value.strip()
            if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
                return (0, float(text))
            return (1, text.lower())
        return (1, str(value).lower())

    @classmethod
    def _sort_rows(cls, rows, column_index, reverse=False):
        return sorted(rows, key=lambda row: cls._coerce_sort_value(row[column_index]), reverse=reverse)

    def _attach_tree_sort(self, tree):
        for col in tree["columns"]:
            tree.heading(col, command=lambda c=col: self._toggle_tree_sort(tree, c))

    def _toggle_tree_sort(self, tree, col):
        state = self._tree_sort_states.setdefault(id(tree), {})
        if state.get("column") == col:
            state["ascending"] = not state.get("ascending", True)
        else:
            state["column"] = col
            state["ascending"] = True
        self._sort_tree(tree, col, reverse=not state["ascending"])

    def _apply_tree_sort(self, tree):
        state = self._tree_sort_states.get(id(tree), {})
        col = state.get("column")
        if not col:
            return
        self._sort_tree(tree, col, reverse=not state.get("ascending", True))

    def _sort_tree(self, tree, col, reverse=False):
        column_index = list(tree["columns"]).index(col)
        rows = []
        for child in tree.get_children():
            values = tuple(tree.item(child)["values"])
            rows.append(values)
        sorted_rows = self._sort_rows(rows, column_index, reverse=reverse)
        tree.delete(*tree.get_children())
        for values in sorted_rows:
            tree.insert("", "end", values=values)

    def _build_ui(self):
        style = ttk.Style(self.root)
        try:
            if "clam" in style.theme_names():
                style.theme_use("clam")
        except tk.TclError:
            pass

        # Menu
        menubar = tk.Menu(self.root)
        m_file = tk.Menu(menubar, tearoff=0)
        m_file.add_command(label="Ruw logboek opslaan (.txt/.csv)...", command=self._export)
        m_file.add_command(label="Professioneel Security Audit Rapport (.html)...", command=self._report)
        m_file.add_separator()
        m_file.add_command(label="Afsluiten", command=self._on_close)
        menubar.add_cascade(label="Bestand", menu=m_file)

        m_tools = tk.Menu(menubar, tearoff=0)
        m_tools.add_command(label="MikroTik setup & commando's...", command=self._show_mikrotik)
        m_tools.add_command(label="Apparaatnamen importeren uit MikroTik DHCP...", command=self._import_hosts)
        menubar.add_cascade(label="Hulpmiddelen", menu=m_tools)
        
        m_help = tk.Menu(menubar, tearoff=0)
        m_help.add_command(label="Over MikroTik Syslog Pro...", command=self._about)
        menubar.add_cascade(label="Help", menu=m_help)
        self.root.config(menu=menubar)

        # Statusbar
        self.bottom_lbl = ttk.Label(self.root, text="", anchor="w", padding=(10, 5))
        self.bottom_lbl.pack(side="bottom", fill="x")

        # Control Bar 1
        bar = ttk.Frame(self.root, padding=(10, 10, 10, 4))
        bar.pack(fill="x")

        ttk.Label(bar, text="Router IP:").pack(side="left")
        self.router_var = tk.StringVar(value="192.168.178.1")
        self.router_entry = ttk.Entry(bar, textvariable=self.router_var, width=15)
        self.router_entry.pack(side="left", padx=(4, 14))

        ttk.Label(bar, text="Poort:").pack(side="left")
        self.port_var = tk.StringVar(value="514")
        self.port_spin = ttk.Spinbox(bar, textvariable=self.port_var, from_=1, to=65535, width=6)
        self.port_spin.pack(side="left", padx=(4, 14))

        self.udp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="UDP", variable=self.udp_var).pack(side="left", padx=2)
        self.tcp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="TCP", variable=self.tcp_var).pack(side="left", padx=(2, 14))

        self.start_btn = ttk.Button(bar, text="▶ Start Server", command=self._toggle_server)
        self.start_btn.pack(side="left", padx=4)

        self.status_lbl = ttk.Label(bar, text=" ● Gestopt", foreground="#ef4444", font=("Segoe UI", 9, "bold"))
        self.status_lbl.pack(side="left", padx=10)

        ttk.Button(bar, text="Stuur Testbericht", command=self._send_test).pack(side="right")

        # Control Bar 2: Filters & Search
        bar2 = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        bar2.pack(fill="x")

        ttk.Label(bar2, text="Zoek / Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        ent = ttk.Entry(bar2, textvariable=self.filter_var, width=26)
        ent.pack(side="left", padx=(4, 14))
        ent.bind("<KeyRelease>", self._on_filter_change)

        ttk.Label(bar2, text="Snelfilter:").pack(side="left")
        self.quick_var = tk.StringVar(value=self.QUICK_FILTERS[0])
        self.quick_cb = ttk.Combobox(bar2, textvariable=self.quick_var, values=self.QUICK_FILTERS, width=20, state="readonly")
        self.quick_cb.pack(side="left", padx=(4, 14))
        self.quick_cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_view())

        ttk.Label(bar2, text="Weergave:").pack(side="left")
        self.view_var = tk.StringVar(value=self.VIEW_MODES[0])
        self.view_cb = ttk.Combobox(bar2, textvariable=self.view_var, values=self.VIEW_MODES, width=24, state="readonly")
        self.view_cb.pack(side="left", padx=(4, 14))
        self.view_cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_view())

        self.autoscroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar2, text="Autoscroll", variable=self.autoscroll_var).pack(side="left", padx=6)

        ttk.Button(bar2, text="Wis Log", command=self._clear).pack(side="right", padx=4)
        self.filelog_btn = ttk.Button(bar2, text="Live naar Bestand...", command=self._toggle_filelog)
        self.filelog_btn.pack(side="right", padx=4)

        # Notebook Tabs
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        tab_log = ttk.Frame(self.nb)
        tab_threats = ttk.Frame(self.nb)
        tab_charts = ttk.Frame(self.nb)
        tab_dom = ttk.Frame(self.nb)
        tab_dev = ttk.Frame(self.nb)

        self.nb.add(tab_log, text=" 🛡️ Live Logboek ")
        self.nb.add(tab_threats, text=" ⚠️ Dreigingsanalyse ")
        self.nb.add(tab_charts, text=" 📊 Verkeer & Grafieken ")
        self.nb.add(tab_dom, text=" 🌐 Domeinen & IP's ")
        self.nb.add(tab_dev, text=" 💻 Apparaten & DHCP ")

        # Tab 1: Logboek Text Widget
        self.text = tk.Text(tab_log, wrap="none", font=("Consolas", 10), background="#090d16", foreground="#f8fafc", insertbackground="#38bdf8")
        ysb = ttk.Scrollbar(tab_log, orient="vertical", command=self.text.yview)
        xsb = ttk.Scrollbar(tab_log, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        tab_log.rowconfigure(0, weight=1)
        tab_log.columnconfigure(0, weight=1)

        self.text.tag_configure("err", foreground="#fb7185")
        self.text.tag_configure("warn", foreground="#fbbf24")
        self.text.tag_configure("notice", foreground="#38bdf8")
        self.text.tag_configure("debug", foreground="#64748b")
        self.text.tag_configure("dns", foreground="#34d399")
        self.text.tag_configure("meta", foreground="#94a3b8")
        self.text.configure(state="disabled")

        # Tab 2: Dreigingsanalyse
        threat_cols = ("time", "source", "type", "details")
        self.threat_tree = ttk.Treeview(tab_threats, columns=threat_cols, show="headings")
        for col, label, width, anchor in (
                ("time", "Tijdstip", 110, "w"),
                ("source", "Bron IP", 130, "w"),
                ("type", "Dreiging / Type", 180, "w"),
                ("details", "Gebeurtenis Details", 500, "w")):
            self.threat_tree.heading(col, text=label)
            self.threat_tree.column(col, width=width, anchor=anchor, stretch=(col == "details"))
        self._attach_tree_sort(self.threat_tree)
        threat_ysb = ttk.Scrollbar(tab_threats, orient="vertical", command=self.threat_tree.yview)
        self.threat_tree.configure(yscrollcommand=threat_ysb.set)
        self.threat_tree.grid(row=0, column=0, sticky="nsew")
        threat_ysb.grid(row=0, column=1, sticky="ns")
        tab_threats.rowconfigure(0, weight=1)
        tab_threats.columnconfigure(0, weight=1)

        # Tab 3: Verkeer & Grafieken (Matplotlib)
        chart_top = ttk.Frame(tab_charts, padding=6)
        chart_top.pack(fill="x")
        ttk.Button(chart_top, text="🔄 Ververs Grafieken", command=self._refresh_charts).pack(side="left")
        
        self.chart_frame = ttk.Frame(tab_charts)
        self.chart_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.canvas_widget = None

        # Tab 4: Domeinen & IP's
        dom_cols = ("domain", "ips", "clients", "count", "last")
        self.dom_tree = ttk.Treeview(tab_dom, columns=dom_cols, show="headings")
        for col, label, width, anchor in (
                ("domain", "Domein", 280, "w"),
                ("ips", "IP-adres(sen)", 320, "w"),
                ("clients", "Opgevraagd door", 260, "w"),
                ("count", "Aantal", 70, "e"),
                ("last", "Laatste", 90, "e")):
            self.dom_tree.heading(col, text=label)
            self.dom_tree.column(col, width=width, anchor=anchor, stretch=(col in ("domain", "ips", "clients")))
        self._attach_tree_sort(self.dom_tree)
        dom_ysb = ttk.Scrollbar(tab_dom, orient="vertical", command=self.dom_tree.yview)
        self.dom_tree.configure(yscrollcommand=dom_ysb.set)
        self.dom_tree.grid(row=0, column=0, sticky="nsew")
        dom_ysb.grid(row=0, column=1, sticky="ns")
        tab_dom.rowconfigure(0, weight=1)
        tab_dom.columnconfigure(0, weight=1)
        self.dom_tree.bind("<Double-1>", self._dom_double_click)

        # Tab 5: Apparaten & DHCP
        dev_cols = ("ip", "name", "queries", "domains", "last")
        self.dev_tree = ttk.Treeview(tab_dev, columns=dev_cols, show="headings")
        for col, label, width, anchor in (
                ("ip", "IP-adres", 150, "w"),
                ("name", "Naam / Hostname", 240, "w"),
                ("queries", "DNS Queries", 100, "e"),
                ("domains", "Unieke Domeinen", 120, "e"),
                ("last", "Laatste Activiteit", 140, "e")):
            self.dev_tree.heading(col, text=label)
            self.dev_tree.column(col, width=width, anchor=anchor, stretch=(col == "name"))
        self._attach_tree_sort(self.dev_tree)
        dev_ysb = ttk.Scrollbar(tab_dev, orient="vertical", command=self.dev_tree.yview)
        self.dev_tree.configure(yscrollcommand=dev_ysb.set)
        self.dev_tree.grid(row=0, column=0, sticky="nsew")
        dev_ysb.grid(row=0, column=1, sticky="ns")
        tab_dev.rowconfigure(0, weight=1)
        tab_dev.columnconfigure(0, weight=1)
        self.dev_tree.bind("<Double-1>", self._rename_device)

        self._append_line("--- MikroTik Syslog Server Pro gereed. Klik op 'Start Server' om te beginnen. ---\n", "meta")

    def _toggle_server(self):
        if self.running:
            self._stop_server()
        else:
            self._start_server()

    def _start_server(self):
        if not self.udp_var.get() and not self.tcp_var.get():
            messagebox.showwarning(APP_TITLE, "Selecteer minimaal UDP of TCP.")
            return
        try:
            port = int(self.port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror(APP_TITLE, "Ongeldig poortnummer ingevoerd.")
            return

        try:
            if self.udp_var.get():
                self.udp_server = _ThreadingUDPServer(("0.0.0.0", port), _UDPHandler)
                self.udp_server.log_queue = self.log_queue
                threading.Thread(target=self.udp_server.serve_forever, daemon=True).start()
            if self.tcp_var.get():
                self.tcp_server = _ThreadingTCPServer(("0.0.0.0", port), _TCPHandler)
                self.tcp_server.log_queue = self.log_queue
                threading.Thread(target=self.tcp_server.serve_forever, daemon=True).start()
        except OSError as exc:
            self._stop_server(silent=True)
            messagebox.showerror(APP_TITLE, f"Kan niet luisteren op poort {port}:\n{exc}")
            return

        self.running = True
        self.local_ip = detect_local_ip(self.router_var.get().strip())
        protos = "+".join(p for p, on in (("UDP", self.udp_var.get()), ("TCP", self.tcp_var.get())) if on)
        self.status_lbl.config(text=f" ● Actief op poort {port} ({protos})", foreground="#22c55e")
        self.start_btn.config(text="■ Stop Server")
        for w in (self.router_entry, self.port_spin, self.udp_var, self.tcp_var):
            try:
                w.config(state="disabled")
            except Exception:
                pass
        self._append_line(f"--- Server gestart op 0.0.0.0:{port} ({protos}) ---\n", "meta")
        self._update_bottom()

    def _stop_server(self, silent=False):
        for srv in (self.udp_server, self.tcp_server):
            if srv is not None:
                try:
                    srv.shutdown()
                    srv.server_close()
                except Exception:
                    pass
        self.udp_server = None
        self.tcp_server = None
        if self.running or not silent:
            self.running = False
            self.status_lbl.config(text=" ● Gestopt", foreground="#ef4444")
            self.start_btn.config(text="▶ Start Server")
            for w in (self.router_entry, self.port_spin):
                try:
                    w.config(state="normal")
                except Exception:
                    pass
            self._append_line("--- Server gestopt ---\n", "meta")
            self._update_bottom()

    def _poll(self):
        batch = 0
        try:
            while batch < 200:
                src, raw = self.log_queue.get_nowait()
                self._handle_message(src, raw)
                batch += 1
        except queue.Empty:
            pass
        if batch:
            self._update_bottom()
            self._schedule_tab_refresh()
        self.root.after(100, self._poll)

    def _handle_message(self, src, raw):
        now = datetime.datetime.now()
        fac, sev, rest = parse_syslog(raw)
        rest = rest.strip()
        dns = classify_dns(rest)

        threat_type = None
        if BRUTE_FORCE_RE.search(rest):
            threat_type = "Brute-force / Inlogpoging gefaald"
            self.brute_force_events.append({"ts": now, "src": src, "type": threat_type, "text": rest})
        elif FIREWALL_DROP_RE.search(rest):
            threat_type = "Firewall Drop / Blokkade"
            self.firewall_drops.append({"ts": now, "src": src, "type": threat_type, "text": rest})

        item = {"ts": now, "src": src, "fac": fac, "sev": sev, "text": rest, "dns": dns, "threat": threat_type}
        self.messages.append(item)
        if len(self.messages) > MAX_STORED:
            del self.messages[:len(self.messages) - MAX_STORED]
        self.total_received += 1

        if dns:
            self._process_dns(item)

        if self.log_file is not None:
            try:
                self.log_file.write(self._format_line(item))
                self.log_file.flush()
            except OSError:
                pass

        if self._matches_filter(item):
            self._insert_item(item)

    def _process_dns(self, item):
        d = item["dns"]
        kind = d["kind"]
        if kind == "query":
            self._dns_pending[d["qid"]] = d
            if len(self._dns_pending) > MAX_PENDING_DNS:
                self._dns_pending.pop(next(iter(self._dns_pending)), None)
            dev = self.devices.setdefault(d["client"], {"queries": 0, "domains": set(), "last": item["ts"]})
            dev["queries"] += 1
            dev["last"] = item["ts"]
        elif kind == "done":
            pend = self._dns_pending.pop(d["qid"], None)
            if pend:
                d["client"] = pend["client"]
                d["qtype"] = pend["qtype"]
                if d.get("domain") is None:
                    d["domain"] = pend["domain"]
            if d.get("domain"):
                dom = self.domains.setdefault(d["domain"], {"ips": set(), "clients": set(), "count": 0, "last": item["ts"]})
                dom["count"] += 1
                dom["last"] = item["ts"]
                if d.get("ip"):
                    dom["ips"].add(d["ip"])
                if d.get("client"):
                    dom["clients"].add(d["client"])
                    dev = self.devices.get(d["client"])
                    if dev:
                        dev["domains"].add(d["domain"])
                        dev["last"] = item["ts"]

    def _format_dns_summary(self, item):
        d = item["dns"]
        client = d.get("client") or "?"
        name = self.host_names.get(client)
        who = f"{client} ({name})" if name else client
        dom = d.get("domain") or "?"
        qtype = d.get("qtype")
        res = d.get("ip") or d.get("result") or "geen resultaat"
        qt = f" ({qtype})" if qtype else ""
        return f"{item['ts']:%H:%M:%S}  DNS  {who:<32} {dom}{qt} → {res}\n"

    def _display_rows(self, item):
        quick = self.quick_var.get()
        if quick == "Alleen Errors & Warnings" and (item["sev"] is None or item["sev"] > 4):
            return []
        if quick == "Bedreigingen / Brute-force" and not item["threat"]:
            return []
        if quick == "Firewall Drops" and "Firewall" not in (item["threat"] or ""):
            return []
        if quick == "DNS Resoluties" and not (item.get("dns") and item["dns"]["kind"] == "done"):
            return []

        mode = self.view_var.get()
        dns = item.get("dns")
        if mode == "Alleen belangrijk":
            sev = item["sev"]
            if sev is None or sev > 4:
                return []
            return [(self._format_display(item), self._tag_for(item))]
        if dns is not None and mode.startswith("Compact"):
            if dns["kind"] == "done":
                return [(self._format_dns_summary(item), "dns")]
            return []
        return [(self._format_display(item), self._tag_for(item))]

    @staticmethod
    def _tag_for(item):
        sev = item["sev"]
        if item.get("threat"):
            return "err"
        if sev is None:
            return ""
        if sev <= 3:
            return "err"
        if sev == 4:
            return "warn"
        if sev == 5:
            return "notice"
        if sev == 7:
            return "debug"
        return ""

    def _format_display(self, item):
        sev_name = SEVERITY_NAMES[item['sev']] if item['sev'] is not None else "-"
        threat_tag = f" [! {item['threat']}]" if item.get("threat") else ""
        return f"{item['ts']:%H:%M:%S}  {item['src']:<14}  {sev_name:<11} {item['text']}{threat_tag}\n"

    def _format_line(self, item):
        return f"{item['ts']:%Y-%m-%d %H:%M:%S} | {item['src']} | {self._sev_label(item['sev'])} | {item['text']}\n"

    @staticmethod
    def _sev_label(sev):
        return SEVERITY_NAMES[sev] if sev is not None else "-"

    def _insert_item(self, item):
        for line, tag in self._display_rows(item):
            self.text.configure(state="normal")
            self.text.insert("end", line, tag)
            self._trim_text()
            if self.autoscroll_var.get():
                self.text.see("end")
            self.text.configure(state="disabled")

    def _append_line(self, line, tag=None):
        self.text.configure(state="normal")
        self.text.insert("end", line, tag)
        if self.autoscroll_var.get():
            self.text.see("end")
        self.text.configure(state="disabled")

    def _trim_text(self):
        n = int(self.text.index("end-1c").split(".")[0])
        if n > MAX_TEXT_LINES:
            self.text.delete("1.0", f"{n - (MAX_TEXT_LINES - TRIM_LINES)}.0")

    def _matches_filter(self, item):
        f = self.filter_var.get().strip().lower()
        if f:
            hay = f"{item['src']} {item['text']}".lower()
            if not all(part in hay for part in f.split()):
                return False
        return True

    def _on_filter_change(self, _event=None):
        if self._filter_job is not None:
            self.root.after_cancel(self._filter_job)
        self._filter_job = self.root.after(200, self._refresh_view)

    def _refresh_view(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        for item in self.messages:
            if self._matches_filter(item):
                for line, tag in self._display_rows(item):
                    self.text.insert("end", line, tag)
        self._trim_text()
        self.text.configure(state="disabled")
        if self.autoscroll_var.get():
            self.text.see("end")
        self._update_bottom()

    def _schedule_tab_refresh(self):
        if self._tabs_job is not None:
            return
        self._tabs_job = self.root.after(1000, self._refresh_tabs)

    def _refresh_tabs(self):
        self._tabs_job = None
        self._refresh_threat_table()
        self._refresh_dom_table()
        self._refresh_dev_table()
        if MATPLOTLIB_AVAILABLE:
            self._refresh_charts()

    def _refresh_threat_table(self):
        self.threat_tree.delete(*self.threat_tree.get_children())
        combined = sorted(self.brute_force_events + self.firewall_drops, key=lambda x: x["ts"], reverse=True)[:500]
        for ev in combined:
            self.threat_tree.insert("", "end", values=(f"{ev['ts']:%H:%M:%S}", ev["src"], ev["type"], ev["text"]))
        self._apply_tree_sort(self.threat_tree)

    def _refresh_charts(self):
        if not MATPLOTLIB_AVAILABLE:
            return
        
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 5), facecolor="#1e293b")
        for ax in (ax1, ax2):
            ax.set_facecolor("#0f172a")
            ax.tick_params(colors="#cbd5e1", labelsize=9)
            ax.xaxis.label.set_color("#f8fafc")
            ax.yaxis.label.set_color("#f8fafc")
            ax.title.set_color("#38bdf8")
            for spine in ax.spines.values():
                spine.set_edgecolor("#334155")

        # Chart 1: Top 8 Most Queried Domains
        top_domains = sorted(self.domains.items(), key=lambda kv: kv[1]["count"], reverse=True)[:8]
        if top_domains:
            doms = [d[0] for d in top_domains][::-1]
            counts = [d[1]["count"] for d in top_domains][::-1]
            ax1.barh(doms, counts, color="#38bdf8")
            ax1.set_title("Top 8 Meest Bezochte Domeinen (DNS)")
            ax1.set_xlabel("Aantal Queries")
        else:
            ax1.text(0.5, 0.5, "Nog geen DNS data", color="#94a3b8", ha="center", va="center")
            ax1.set_title("Top 8 Domeinen")

        # Chart 2: Top 8 Active Client Devices
        top_devs = sorted(self.devices.items(), key=lambda kv: kv[1]["queries"], reverse=True)[:8]
        if top_devs:
            dev_labels = [self.host_names.get(d[0], d[0]) for d in top_devs][::-1]
            dev_queries = [d[1]["queries"] for d in top_devs][::-1]
            ax2.barh(dev_labels, dev_queries, color="#34d399")
            ax2.set_title("Top 8 Actiefste Apparaten (Clients)")
            ax2.set_xlabel("DNS Queries")
        else:
            ax2.text(0.5, 0.5, "Nog geen client data", color="#94a3b8", ha="center", va="center")
            ax2.set_title("Top 8 Apparaten")

        fig.tight_layout()
        canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        canvas.draw()
        self.canvas_widget = canvas.get_tk_widget()
        self.canvas_widget.pack(fill="both", expand=True)

    def _refresh_dom_table(self):
        self.dom_tree.delete(*self.dom_tree.get_children())
        items = sorted(self.domains.items(), key=lambda kv: kv[1]["last"], reverse=True)[:500]
        for dom, info in items:
            self.dom_tree.insert("", "end", values=(dom, ", ".join(sorted(info["ips"])), ", ".join(sorted(info["clients"])), info["count"], f"{info['last']:%H:%M:%S}"))
        self._apply_tree_sort(self.dom_tree)

    def _refresh_dev_table(self):
        self.dev_tree.delete(*self.dev_tree.get_children())
        items = sorted(self.devices.items(), key=lambda kv: kv[1]["last"], reverse=True)[:500]
        for ip, info in items:
            self.dev_tree.insert("", "end", values=(ip, self.host_names.get(ip, ""), info["queries"], len(info["domains"]), f"{info['last']:%H:%M:%S}"))
        self._apply_tree_sort(self.dev_tree)

    def _dom_double_click(self, _event=None):
        sel = self.dom_tree.selection()
        if not sel: return
        dom = str(self.dom_tree.item(sel[0])["values"][0])
        self.filter_var.set(dom)
        self.nb.select(0)
        self._refresh_view()

    def _rename_device(self, _event=None):
        sel = self.dev_tree.selection()
        if not sel: return
        ip = str(self.dev_tree.item(sel[0])["values"][0])
        name = simpledialog.askstring("Apparaatnaam", f"Naam voor {ip} (leeg = wissen):", initialvalue=self.host_names.get(ip, ""), parent=self.root)
        if name is None: return
        if name.strip():
            self.host_names[ip] = name.strip()
        else:
            self.host_names.pop(ip, None)
        self._save_hosts()
        self._refresh_dev_table()

    def _load_hosts(self):
        try:
            with open(HOSTS_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, dict):
                    self.host_names = {str(k): str(v) for k, v in data.items()}
        except (OSError, ValueError):
            self.host_names = {}

    def _save_hosts(self):
        try:
            with open(HOSTS_FILE, "w", encoding="utf-8") as fh:
                json.dump(self.host_names, fh, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def _import_hosts(self):
        router = self.router_var.get().strip() or "192.168.178.1"
        user = simpledialog.askstring("MikroTik import", "Gebruikersnaam MikroTik:", parent=self.root)
        if not user: return
        pw = simpledialog.askstring("MikroTik import", "Wachtwoord MikroTik:", show="*", parent=self.root)
        if pw is None: return
        auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        urls = (f"https://{router}/rest/ip/dhcp-server/lease", f"http://{router}/rest/ip/dhcp-server/lease")
        leases = None
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"Authorization": auth})
                with urllib.request.urlopen(req, timeout=6, context=ctx if url.startswith("https") else None) as resp:
                    leases = json.loads(resp.read().decode("utf-8"))
                break
            except Exception:
                pass
        if leases is None:
            messagebox.showerror(APP_TITLE, "Kan niet verbinden met MikroTik REST-API. Controleer inloggegevens en services.")
            return
        added = 0
        for lease in leases:
            ip = lease.get("address")
            name = lease.get("active-hostname") or lease.get("host-name")
            if ip and name:
                if self.host_names.get(ip) != name:
                    added += 1
                self.host_names[ip] = name
        self._save_hosts()
        self._refresh_dev_table()
        messagebox.showinfo(APP_TITLE, f"{len(leases)} DHCP-leases gelezen, {added} namen bijgewerkt.")

    def _send_test(self):
        if not self.running or self.udp_server is None:
            messagebox.showinfo(APP_TITLE, "Start eerst de server (UDP aangevinkt) om een testbericht te sturen.")
            return
        try:
            port = int(self.port_var.get())
        except ValueError:
            return
        stamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        msg = f"<13>{stamp} MikroTik-test system,info: Testbericht Syslog Pro — login failure test, firewall drop."
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(msg.encode("utf-8"), ("127.0.0.1", port))
            s.close()
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Testbericht mislukt:\n{exc}")

    def _export(self):
        if not self.messages:
            messagebox.showinfo(APP_TITLE, "Geen berichten om op te slaan.")
            return
        path = filedialog.asksaveasfilename(title="Logboek opslaan", defaultextension=".txt", filetypes=[("Tekstbestand", "*.txt"), ("CSV-bestand", "*.csv")])
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                for it in self.messages:
                    fh.write(self._format_line(it))
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Opslaan mislukt:\n{exc}")
        else:
            messagebox.showinfo(APP_TITLE, f"Opgeslagen:\n{path}")

    def _report(self):
        if not self.messages:
            messagebox.showinfo(APP_TITLE, "Geen berichten voor rapport.")
            return
        path = filedialog.asksaveasfilename(title="Security Audit Rapport opslaan", defaultextension=".html", filetypes=[("HTML Rapport", "*.html")])
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self._build_report_html())
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Rapport opslaan mislukt:\n{exc}")
        else:
            messagebox.showinfo(APP_TITLE, f"Professioneel rapport opgeslagen:\n{path}")

    def _build_report_html(self):
        esc = html.escape
        first = self.messages[0]["ts"]
        last = self.messages[-1]["ts"]

        css = """
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }
        .container { max-width: 1000px; margin: 0 auto; background: #1e293b; padding: 40px; border-radius: 16px; border: 1px solid #334155; }
        h1 { color: #38bdf8; font-size: 26px; border-bottom: 2px solid #334155; padding-bottom: 12px; }
        h2 { color: #38bdf8; font-size: 18px; border-bottom: 1px solid #334155; padding-bottom: 6px; margin-top: 35px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
        th, td { border: 1px solid #334155; padding: 8px 12px; text-align: left; }
        th { background: #0f172a; color: #38bdf8; }
        tr:nth-child(even) td { background: #0b1329; }
        .err { color: #fb7185; font-weight: bold; }
        .warn { color: #fbbf24; font-weight: bold; }
        .meta { color: #94a3b8; font-size: 12px; margin-bottom: 25px; }
        """

        out = [
            f"<!DOCTYPE html><html lang='nl'><head><meta charset='utf-8'><title>Syslog Security Audit Rapport</title><style>{css}</style></head>",
            f"<body><div class='container'><h1>🛡️ MikroTik Syslog Security Audit Rapport</h1>",
            f"<div class='meta'>Gegenereerd: {datetime.datetime.now():%Y-%m-%d %H:%M:%S} &bull; Periode: {first:%Y-%m-%d %H:%M:%S} – {last:%H:%M:%S}</div>",
            f"<h2>Samenvatting & Statistieken</h2><table><tr><th>Totaal Berichten</th><td>{len(self.messages)}</td></tr>"
            f"<tr><th>Dreigingen / Brute-force gedetecteerd</th><td class='err'>{len(self.brute_force_events)}</td></tr>"
            f"<tr><th>Firewall Drops</th><td class='warn'>{len(self.firewall_drops)}</td></tr>"
            f"<tr><th>Unieke Domeinen</th><td>{len(self.domains)}</td></tr>"
            f"<tr><th>Actieve Apparaten</th><td>{len(self.devices)}</td></tr></table>",
            f"<h2>⚠️ Gedetecteerde Dreigingen & Brute-force ({len(self.brute_force_events)})</h2>"
        ]
        if self.brute_force_events:
            out.append("<table><tr><th>Tijd</th><th>Bron IP</th><th>Type</th><th>Details</th></tr>")
            for ev in self.brute_force_events[-100:]:
                out.append(f"<tr><td>{ev['ts']:%H:%M:%S}</td><td>{esc(ev['src'])}</td><td class='err'>{esc(ev['type'])}</td><td>{esc(ev['text'])}</td></tr>")
            out.append("</table>")
        else:
            out.append("<p style='color: #64748b;'>Geen brute-force of inlogfouten gedetecteerd.</p>")

        out.append(f"<h2>🌐 DNS Resoluties ({len(self.domains)})</h2>")
        if self.domains:
            out.append("<table><tr><th>Domein</th><th>IP-adres(sen)</th><th>Klanten</th><th>Aantal</th></tr>")
            for dom, info in sorted(self.domains.items(), key=lambda kv: kv[1]["count"], reverse=True)[:100]:
                out.append(f"<tr><td>{esc(dom)}</td><td>{esc(', '.join(sorted(info['ips'])))}</td><td>{esc(', '.join(sorted(info['clients'])))}</td><td>{info['count']}</td></tr>")
            out.append("</table>")
        else:
            out.append("<p style='color: #64748b;'>Geen DNS data.</p>")

        out.append("</div></body></html>")
        return "\n".join(out)

    def _toggle_filelog(self):
        if self.log_file is not None:
            try: self.log_file.close()
            except OSError: pass
            self.log_file = None
            self.filelog_btn.config(text="Live naar Bestand...")
            self._append_line("--- Bestandsschrijven gestopt ---\n", "meta")
            return
        path = filedialog.asksaveasfilename(title="Logbestand", defaultextension=".log", filetypes=[("Logbestand", "*.log")])
        if not path: return
        try:
            self.log_file = open(path, "a", encoding="utf-8")
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Kan bestand niet openen:\n{exc}")
            return
        self.filelog_btn.config(text="Stop Bestandsschrijven")
        self._append_line(f"--- Live logging naar: {path} ---\n", "meta")

    def _clear(self):
        self.messages.clear()
        self.total_received = 0
        self.brute_force_events.clear()
        self.firewall_drops.clear()
        self._dns_pending.clear()
        self.domains.clear()
        self.devices.clear()
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")
        self._refresh_threat_table()
        self._refresh_dom_table()
        self._refresh_dev_table()
        if MATPLOTLIB_AVAILABLE:
            self._refresh_charts()
        self._update_bottom()

    def _show_mikrotik(self):
        router = self.router_var.get().strip() or "192.168.178.1"
        ip = detect_local_ip(router)
        port = self.port_var.get().strip() or "514"
        cmds = f"/system/logging/action/set remote target=remote remote={ip} remote-port={port}\n/system/logging/add action=remote topics=!debug\n"
        content = f"MIKROTIK KOPPELING\n\nStap 1: IP van deze PC: {ip}\nStap 2: Voer uit in MikroTik Terminal:\n\n{cmds}"
        win = tk.Toplevel(self.root)
        win.title("MikroTik Setup")
        win.geometry("700x480")
        txt = tk.Text(win, wrap="word", font=("Consolas", 10), padx=10, pady=10)
        txt.insert("1.0", content)
        txt.configure(state="disabled")
        txt.pack(fill="both", expand=True)

    def _about(self):
        messagebox.showinfo(APP_TITLE, f"{APP_TITLE} v{VERSION}\n\nProfessionele Syslog Server met Dreigingsanalyse, Grafische Verkeersvisualisatie & Security Audits.")

    def _update_bottom(self):
        state = f"Actief op poort {self.port_var.get()}" if self.running else "Gestopt"
        shown = sum(1 for it in self.messages if self._matches_filter(it))
        self.bottom_lbl.config(text=f"Status: {state}  |  IP: {self.local_ip}  |  Ontvangen: {self.total_received}  |  Buffer: {len(self.messages)} ({shown} getoond)  |  Dreigingen: {len(self.brute_force_events)}")

    def _on_close(self):
        self._stop_server(silent=True)
        if self.log_file is not None:
            try: self.log_file.close()
            except OSError: pass
        self.root.destroy()

def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    if tk is None:
        print("Fout: tkinter ontbreekt.")
        sys.exit(1)
    root = tk.Tk()
    MikroTikSyslogProApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
