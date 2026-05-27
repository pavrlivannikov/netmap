#!/usr/bin/env python3
"""
NetMap — Карта сети (GUI на tkinter)
Версия с десктопным интерфейсом для Windows/Linux.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
import os
import sys
from datetime import datetime

# Ensure we can import from the same directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netmap_scanner import (
    ScanResult, Device, ScanCallbacks,
    discover_networks, scan_quick, scan_discover, scan_deep, scan_topology,
    monitor_diff, save_result, load_result, COMMON_PORTS, SERVICE_MAP,
)
import netmap_snmp  # for PyInstaller bundling


class NetMapApp:
    """Main application window."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.version = self._load_version()
        self._settings_dir = os.path.dirname(os.path.abspath(__file__))
        self._settings_file = os.path.join(self._settings_dir, "netmap_settings.json")
        self._settings = self._load_settings()
        self._monitoring = False
        self._monitor_after_id = None
        self._merge_scan = False
        self.root.title(f"NetMap v{self.version} — Карта сети")
        self.root.geometry("1200x750")
        self.root.minsize(900, 600)

        # State
        self.networks = []
        self.current_result: ScanResult | None = None
        self.previous_result: ScanResult | None = None
        self.scanning = False
        self.scan_thread: threading.Thread | None = None

        # Style
        self._setup_style()
        self._build_ui()
        self._refresh_networks()

    def _load_version(self) -> str:
        """Загрузить версию из VERSION файла."""
        import os
        paths = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION"),
            os.path.join(sys._MEIPASS, "VERSION") if hasattr(sys, '_MEIPASS') else None,
        ]
        for p in paths:
            if p and os.path.exists(p):
                return open(p).read().strip()
        return "1.0.0"

    def _load_settings(self) -> dict:
        """Загрузить настройки из JSON-файла (с дефолтами)."""
        defaults = {"monitor_interval": 60, "sound": True, "snmp_community": "public"}
        try:
            if os.path.exists(self._settings_file):
                with open(self._settings_file, 'r') as f:
                    saved = json.load(f)
                defaults.update(saved)
        except Exception:
            pass
        return defaults

    # ── Style ───────────────────────────────────────────────────

    def _setup_style(self):
        style = ttk.Style()
        # Try to get native look
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Colors (dark-ish professional palette)
        self.colors = {
            "bg": "#2b2b2b",
            "fg": "#e0e0e0",
            "header": "#1e1e1e",
            "accent": "#0078d4",
            "online": "#4caf50",
            "offline": "#9e9e9e",
            "warn": "#ff9800",
            "row_even": "#333333",
            "row_odd": "#2b2b2b",
        }

        self.root.configure(bg=self.colors["bg"])

        style.configure("TFrame", background=self.colors["bg"])
        style.configure("TLabel", background=self.colors["bg"], foreground=self.colors["fg"])
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"),
                        background=self.colors["bg"], foreground=self.colors["fg"])
        style.configure("Status.TLabel", font=("Segoe UI", 9),
                        background=self.colors["bg"], foreground=self.colors["offline"])
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"),
                        background=self.colors["bg"], foreground=self.colors["fg"])
        style.configure("TButton", font=("Segoe UI", 10), padding=(16, 6))
        style.configure("Scan.TButton", font=("Segoe UI", 10, "bold"), padding=(20, 8))
        style.configure("TCombobox", font=("Segoe UI", 10))
        style.configure("TProgressbar", thickness=6)

        # Treeview
        style.configure("Treeview",
                        font=("Consolas", 9),
                        background=self.colors["bg"],
                        foreground=self.colors["fg"],
                        fieldbackground=self.colors["bg"])
        style.configure("Treeview.Heading",
                        font=("Segoe UI", 9, "bold"),
                        background=self.colors["header"],
                        foreground=self.colors["fg"])
        style.map("Treeview",
                  background=[("selected", self.colors["accent"])])

    # ── UI Construction ─────────────────────────────────────────

    def _build_ui(self):
        # Top bar
        self._build_topbar()

        # Main content: notebook with tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 4))

        # Tab 1: Devices table
        self.tab_devices = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_devices, text="  Устройства  ")
        self._build_devices_tab()

        # Tab 2: Topology (text)
        self.tab_topology = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_topology, text="  Топология  ")
        self._build_topology_tab()

        # Tab 3: Structure (tree)
        self.tab_structure = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_structure, text="  🗂 Структура  ")
        self._build_structure_tab()

        # Tab 4: Graph (interactive)
        self.tab_graph = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_graph, text="  Граф  ")
        self._build_graph_tab()

        # Tab 4: Settings
        self.tab_settings = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_settings, text="  ⚙  ")
        self._build_settings_tab()

        # Tab 5: Log
        self.tab_log = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_log, text="  Лог  ")
        self._build_log_tab()

        # Tab 6: Raw JSON
        self.tab_raw = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_raw, text="  JSON  ")
        self._build_raw_tab()

        # Status bar
        self._build_statusbar()

    def _build_topbar(self):
        top = ttk.Frame(self.root)
        top.pack(fill=tk.X, padx=12, pady=(10, 4))

        # Title
        title = ttk.Label(top, text="🖧 NetMap", style="Title.TLabel")
        title.pack(side=tk.LEFT)

        # Network selector
        net_frame = ttk.Frame(top)
        net_frame.pack(side=tk.LEFT, padx=(30, 10))

        ttk.Label(net_frame, text="Сеть:").pack(side=tk.LEFT, padx=(0, 6))
        self.net_combo = ttk.Combobox(net_frame, width=24, state="readonly")
        self.net_combo.pack(side=tk.LEFT)
        self.net_combo.bind("<<ComboboxSelected>>", self._on_network_selected)

        btn_refresh = ttk.Button(net_frame, text="🔄", width=3, command=self._refresh_networks)
        btn_refresh.pack(side=tk.LEFT, padx=(4, 0))

        # Scan buttons
        btn_frame = ttk.Frame(top)
        btn_frame.pack(side=tk.LEFT, padx=(20, 10))

        self.btn_quick = ttk.Button(btn_frame, text="⚡ Быстрый", command=lambda: self._scan("quick"))
        self.btn_quick.pack(side=tk.LEFT, padx=3)

        self.btn_discover = ttk.Button(btn_frame, text="🔍 Обзор", command=lambda: self._scan("discover"))
        self.btn_discover.pack(side=tk.LEFT, padx=3)

        self.btn_deep = ttk.Button(btn_frame, text="🕳 Глубокий", command=lambda: self._scan("deep"))
        self.btn_deep.pack(side=tk.LEFT, padx=3)

        self.btn_topology = ttk.Button(btn_frame, text="🔗 Топология", command=lambda: self._scan("topology"))
        self.btn_topology.pack(side=tk.LEFT, padx=3)

        self.btn_stop = ttk.Button(btn_frame, text="⏹ Стоп", command=self._stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=(8, 0))

        # Export / Monitor
        action_frame = ttk.Frame(top)
        action_frame.pack(side=tk.RIGHT)

        self.btn_export = ttk.Button(action_frame, text="💾 Экспорт", command=self._export_result)
        self.btn_export.pack(side=tk.LEFT, padx=3)

        self.btn_monitor = ttk.Button(action_frame, text="📊 Монитор", command=self._monitor)
        self.btn_monitor.pack(side=tk.LEFT, padx=3)

        self.btn_load = ttk.Button(action_frame, text="📂 Загрузить", command=self._load_result)
        self.btn_load.pack(side=tk.LEFT, padx=3)

    def _build_devices_tab(self):
        """Devices table with scrollbar."""
        frame = self.tab_devices

        # Treeview with alert checkbox
        columns = ("alert", "ip", "mac", "hostname", "vendor", "type", "os", "ports", "status")
        self.device_tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="extended")

        col_defs = [
            ("alert", "🔔", 35),
            ("ip", "IP адрес", 130),
            ("mac", "MAC", 140),
            ("hostname", "Hostname", 150),
            ("vendor", "Вендор", 120),
            ("type", "Тип", 100),
            ("os", "OS", 140),
            ("ports", "Порты", 180),
            ("status", "Статус", 70),
        ]

        for col_id, col_name, col_width in col_defs:
            self.device_tree.heading(col_id, text=col_name, command=lambda c=col_id: self._sort_tree(c))
            self.device_tree.column(col_id, width=col_width, minwidth=60)

        # Scrollbars
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.device_tree.xview)
        self.device_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.device_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Right-click menu
        self.tree_menu = tk.Menu(frame, tearoff=0)
        self.tree_menu.add_command(label="🔔 Вкл/выкл оповещение", command=self._toggle_alert)
        self.tree_menu.add_separator()
        self.tree_menu.add_command(label="📋 Копировать IP", command=self._copy_tree_ip)
        self.tree_menu.add_command(label="🔍 Копировать MAC", command=self._copy_tree_mac)
        self.tree_menu.add_separator()
        self.tree_menu.add_command(label="🖥 Сканировать порты выбранного", command=self._scan_selected_ports)
        self.device_tree.bind("<Button-3>", self._tree_right_click)
        self._alerted_ips: set = set()  # ips with alert enabled

    def _build_graph_tab(self):
        """Graph: интерактивная граф-карта сети на Canvas."""
        frame = self.tab_graph

        # Canvas с панорамированием
        canvas_frame = ttk.Frame(frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        # Canvas frame with scrollbars
        self._topo_outer = ttk.Frame(canvas_frame)
        self._topo_outer.pack(fill=tk.BOTH, expand=True)

        self._topo_hbar = ttk.Scrollbar(self._topo_outer, orient=tk.HORIZONTAL)
        self._topo_vbar = ttk.Scrollbar(self._topo_outer, orient=tk.VERTICAL)

        self.topo_canvas = tk.Canvas(
            self._topo_outer, bg="#1a1a2e", highlightthickness=0,
            xscrollcommand=self._topo_hbar.set,
            yscrollcommand=self._topo_vbar.set,
        )
        self._topo_hbar.config(command=self.topo_canvas.xview)
        self._topo_vbar.config(command=self.topo_canvas.yview)

        self.topo_canvas.grid(row=0, column=0, sticky="nsew")
        self._topo_vbar.grid(row=0, column=1, sticky="ns")
        self._topo_hbar.grid(row=1, column=0, sticky="ew")
        self._topo_outer.grid_rowconfigure(0, weight=1)
        self._topo_outer.grid_columnconfigure(0, weight=1)

        # Pan/drag/zoom
        self.topo_canvas.bind("<ButtonPress-1>", self._topo_click)
        self.topo_canvas.bind("<B1-Motion>", self._topo_drag)
        self.topo_canvas.bind("<ButtonRelease-1>", self._topo_release)
        self.topo_canvas.bind("<MouseWheel>", self._topo_zoom)
        self.topo_canvas.bind("<Button-4>", self._topo_zoom)
        self.topo_canvas.bind("<Button-5>", self._topo_zoom)
        # Keyboard navigation
        self.topo_canvas.bind("<Left>", lambda e: self._topo_nudge(-80, 0))
        self.topo_canvas.bind("<Right>", lambda e: self._topo_nudge(80, 0))
        self.topo_canvas.bind("<Up>", lambda e: self._topo_nudge(0, -80))
        self.topo_canvas.bind("<Down>", lambda e: self._topo_nudge(0, 80))
        self.topo_canvas.focus_set()

        # Topo state
        self._topo_row_map: dict[str, str] = {}  # ip -> treeview item id
        self._topo_nodes: dict[str, str] = {}   # device_id -> tag
        self._topo_edges: list[int] = []
        self._topo_positions: dict[str, tuple] = {}  # device_id -> (x, y)
        self._topo_drag_tag: str | None = None
        self._topo_drag_start = (0, 0)
        self._topo_drag_did: str | None = None

        # Mini-map (small overview in corner — avoid scrollbars)
        self._topo_minimap = tk.Canvas(
            self._topo_outer, width=150, height=110,
            bg="#111122", highlightthickness=1, highlightbackground="#334455"
        )
        self._topo_minimap.place(relx=1.0, rely=1.0, x=-172, y=-132, anchor="nw")
        self._topo_minimap.bind("<Button-1>", self._topo_minimap_click)

        # Toolbar
        topo_bar = ttk.Frame(frame)
        topo_bar.pack(fill=tk.X, padx=4, pady=2)
        ttk.Button(topo_bar, text="🔍 Уместить всё",
                  command=self._topo_reset_view).pack(side=tk.LEFT, padx=2)
        ttk.Button(topo_bar, text="📐 Авто-раскладка",
                  command=self._topo_auto_layout).pack(side=tk.LEFT, padx=2)
        # Nav buttons
        nav_frame = ttk.Frame(topo_bar)
        nav_frame.pack(side=tk.LEFT, padx=(10, 0))
        for sym, dx, dy in [("◀", 80, 0), ("▶", -80, 0), ("▲", 0, 80), ("▼", 0, -80)]:
            ttk.Button(nav_frame, text=sym, width=2,
                      command=lambda dx=dx, dy=dy: self._topo_nudge(dx, dy)).pack(side=tk.LEFT)
        # Zoom buttons
        zoom_frame = ttk.Frame(topo_bar)
        zoom_frame.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(zoom_frame, text="🔍−", width=3,
                  command=lambda: self._topo_zoom_step(0.9)).pack(side=tk.LEFT)
        ttk.Button(zoom_frame, text="🔍+", width=3,
                  command=lambda: self._topo_zoom_step(1.1)).pack(side=tk.LEFT)
        ttk.Label(topo_bar, text="🖱 ЛКМ: узел | Ctrl+ЛКМ: панорама | Колёсико: зум | Стрелки: навигация",
                 font=("Segoe UI", 8), foreground=self.colors["offline"],
                 background=self.colors["bg"]).pack(side=tk.RIGHT, padx=(10, 0))

    def _build_topology_tab(self):
        """Topology text tab."""
        frame = self.tab_topology
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        self.topo_text = tk.Text(frame, wrap=tk.NONE, font=("Consolas", 10),
                                 bg=self.colors["bg"], fg=self.colors["fg"],
                                 insertbackground=self.colors["fg"],
                                 relief=tk.FLAT, borderwidth=0)
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.topo_text.yview)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.topo_text.xview)
        self.topo_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.topo_text.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self._add_copy_bindings(self.topo_text)

    def _build_structure_tab(self):
        """Structure tab: tree view (сеть → подсеть → устройство → порты)."""
        frame = self.tab_structure
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        columns = ("value",)
        self.structure_tree = ttk.Treeview(frame, columns=columns, show="tree",
                                            style="Structure.Treeview")
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.structure_tree.yview)
        self.structure_tree.configure(yscrollcommand=vsb.set)
        self.structure_tree.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        vsb.grid(row=0, column=1, sticky="ns")

        # Bind double-click to expand/collapse
        self.structure_tree.bind("<Double-1>", lambda e: self._toggle_tree_node())

    def _populate_structure(self, result: ScanResult):
        """Заполнить дерево из результатов сканирования."""
        tree = self.structure_tree
        tree.delete(*tree.get_children())

        # Root: network
        net_iid = tree.insert("", tk.END, text=f"🌐 {result.network}", open=True)

        # Group devices by type
        groups: dict[str, list] = {}
        for d in result.devices:
            dtype = d.device_type or "unknown"
            groups.setdefault(dtype, []).append(d)

        type_icons = {
            "router": "📡", "switch": "🔀", "network-device": "🔀",
            "server": "🖥", "printer": "🖨", "camera": "📷",
            "phone": "📱", "laptop": "💻", "desktop": "🖥",
            "iot": "🔌", "unknown": "❓"
        }

        type_names = {
            "router": "Маршрутизаторы", "switch": "Коммутаторы",
            "network-device": "Сетевое оборудование", "server": "Серверы",
            "printer": "Принтеры", "camera": "Камеры",
            "phone": "Телефоны", "laptop": "Ноутбуки",
            "desktop": "Компьютеры", "iot": "IoT устройства",
            "unknown": "Неизвестные"
        }

        for dtype in sorted(groups):
            devs = groups[dtype]
            icon = type_icons.get(dtype, "❓")
            name = type_names.get(dtype, dtype.capitalize())
            gid = tree.insert(net_iid, tk.END, text=f"{icon} {name} ({len(devs)})", open=True)

            for d in sorted(devs, key=lambda x: _ip_sort_key(x.ip)):
                status = "🟢" if d.status == "online" else "🔴"
                label = f"{status} {d.ip}"
                if d.hostname:
                    label += f" — {d.hostname}"
                if d.mac:
                    label += f"  [{d.mac}]"
                if d.vendor:
                    label += f" ({d.vendor})"

                did = tree.insert(gid, tk.END, text=label)

                # Ports
                if d.ports:
                    ports_iid = tree.insert(did, tk.END, text=f"🔌 Порты ({len(d.ports)})", open=False)
                    for p in sorted(d.ports, key=lambda x: x.port):
                        svc = f" — {p.service}" if p.service else ""
                        tree.insert(ports_iid, tk.END,
                                    text=f"  {p.port}/{p.protocol}{svc}")

                # OS info
                if d.os:
                    tree.insert(did, tk.END, text=f"💿 OS: {d.os}")

    def _toggle_tree_node(self):
        """Toggle expand/collapse on double-click."""
        sel = self.structure_tree.selection()
        if sel:
            item = sel[0]
            if self.structure_tree.get_children(item):
                if self.structure_tree.item(item, "open"):
                    self.structure_tree.item(item, open=False)
                else:
                    self.structure_tree.item(item, open=True)

    def _build_settings_tab(self):
        """Settings tab."""
        frame = self.tab_settings
        pad = {"padx": 12, "pady": 6}

        # Monitor section
        monitor_frame = ttk.LabelFrame(frame, text="Мониторинг", padding=10)
        monitor_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        ttk.Label(monitor_frame, text="Интервал (сек):").grid(row=0, column=0, sticky="w", **pad)
        self.monitor_interval_var = tk.IntVar(value=self._settings.get("monitor_interval", 60))
        ttk.Spinbox(monitor_frame, from_=10, to=3600, width=8,
                   textvariable=self.monitor_interval_var).grid(row=0, column=1, sticky="w", **pad)

        self.sound_var = tk.BooleanVar(value=self._settings.get("sound", True))
        ttk.Checkbutton(monitor_frame, text="Звук при изменениях",
                       variable=self.sound_var).grid(row=1, column=0, columnspan=2, sticky="w", **pad)

        # SNMP section
        snmp_frame = ttk.LabelFrame(frame, text="SNMP", padding=10)
        snmp_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        ttk.Label(snmp_frame, text="Community:").grid(row=0, column=0, sticky="w", **pad)
        self.snmp_community_var = tk.StringVar(value=self._settings.get("snmp_community", "public"))
        ttk.Entry(snmp_frame, textvariable=self.snmp_community_var, width=20).grid(row=0, column=1, sticky="w", **pad)
        ttk.Label(snmp_frame, text="(по умолчанию: public)", foreground="#888888").grid(row=0, column=2, sticky="w", **pad)

        ttk.Button(monitor_frame, text="Сохранить настройки",
                  command=self._save_settings).grid(row=2, column=0, columnspan=2, pady=(8, 0))

        # Alerted devices section
        alert_frame = ttk.LabelFrame(frame, text="Устройства с оповещением (🔔)", padding=10)
        alert_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.alert_listbox = tk.Listbox(alert_frame, bg="#111111", fg="#00ff88",
                                        font=("Consolas", 10), selectmode=tk.EXTENDED)
        self.alert_listbox.pack(fill=tk.BOTH, expand=True)

        btn_row = ttk.Frame(alert_frame)
        btn_row.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(btn_row, text="Обновить список",
                  command=self._refresh_alert_list).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Удалить выбранные",
                  command=self._remove_alerted).pack(side=tk.LEFT, padx=2)

    def _save_settings(self):
        self._settings["monitor_interval"] = self.monitor_interval_var.get()
        self._settings["sound"] = self.sound_var.get()
        self._settings["snmp_community"] = self.snmp_community_var.get().strip() or "public"
        # Persist to disk
        try:
            with open(self._settings_file, 'w') as f:
                json.dump(self._settings, f, indent=2)
        except Exception as e:
            self._log(f"Ошибка сохранения настроек: {e}")
            return
        self._log(f"Настройки сохранены: интервал={self._settings['monitor_interval']}с, "
                  f"звук={'вкл' if self._settings['sound'] else 'выкл'}, "
                  f"SNMP={self._settings['snmp_community']}")
        if self._monitoring:
            self.monitor_indicator.config(
                text=f"🟢 Мониторинг ({self._settings['monitor_interval']}с)"
            )

    def _refresh_alert_list(self):
        self.alert_listbox.delete(0, tk.END)
        for ip in sorted(self._alerted_ips):
            self.alert_listbox.insert(tk.END, ip)

    def _remove_alerted(self):
        selected = self.alert_listbox.curselection()
        for idx in reversed(selected):
            ip = self.alert_listbox.get(idx)
            self._alerted_ips.discard(ip)
            # Clear alert mark in table
            if ip in self._topo_row_map:
                item = self._topo_row_map[ip]
                vals = list(self.device_tree.item(item)["values"])
                vals[0] = ""
                self.device_tree.item(item, values=tuple(vals))
        self._refresh_alert_list()

    def _build_log_tab(self):
        frame = self.tab_log
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        self.log_text = tk.Text(frame, wrap=tk.WORD, font=("Consolas", 9),
                                bg="#111111", fg="#00ff88",
                                insertbackground="#00ff88",
                                relief=tk.FLAT, borderwidth=0)
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vsb.set)

        self.log_text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        # Copy support
        self._add_copy_bindings(self.log_text)

    def _log(self, msg: str):
        """Добавить сообщение в лог."""
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_text.see(tk.END)

    def _clear_log(self):
        self.log_text.delete("1.0", tk.END)

    def _add_copy_bindings(self, widget: tk.Text):
        """Добавить Ctrl+C, Ctrl+A, ПКМ-меню для копирования."""
        widget.bind("<Control-c>", lambda e: self._copy_selection(widget))
        widget.bind("<Control-a>", lambda e: self._select_all(widget))
        # Right-click menu
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Копировать", command=lambda: self._copy_selection(widget))
        menu.add_command(label="Выделить всё", command=lambda: self._select_all(widget))
        widget.bind("<Button-3>", lambda e, m=menu: m.tk_popup(e.x_root, e.y_root))

    def _copy_selection(self, widget: tk.Text):
        try:
            text = widget.selection_get()
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except tk.TclError:
            pass

    def _select_all(self, widget: tk.Text):
        widget.tag_add(tk.SEL, "1.0", tk.END)
        widget.mark_set(tk.INSERT, "1.0")
        widget.see(tk.INSERT)
        return "break"

    def _build_raw_tab(self):
        frame = self.tab_raw
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        self.raw_text = tk.Text(frame, wrap=tk.NONE, font=("Consolas", 9),
                                bg=self.colors["bg"], fg=self.colors["fg"],
                                insertbackground=self.colors["fg"],
                                relief=tk.FLAT, borderwidth=0)
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.raw_text.yview)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.raw_text.xview)
        self.raw_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.raw_text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self._add_copy_bindings(self.raw_text)

    def _build_statusbar(self):
        st = ttk.Frame(self.root)
        st.pack(fill=tk.X, padx=12, pady=(0, 6))

        self.status_label = ttk.Label(st, text="Готов", style="Status.TLabel")
        self.status_label.pack(side=tk.LEFT)

        self.monitor_indicator = ttk.Label(st, text="", style="Status.TLabel")
        self.monitor_indicator.pack(side=tk.LEFT, padx=(8, 0))

        self.version_label = ttk.Label(st, text=f"v{self.version}", style="Status.TLabel")
        self.version_label.pack(side=tk.LEFT, padx=(8, 0))

        self.progress = ttk.Progressbar(st, mode="determinate", length=300)
        self.progress.pack(side=tk.RIGHT, padx=(10, 0))

        self.status_count = ttk.Label(st, text="", style="Status.TLabel")
        self.status_count.pack(side=tk.RIGHT, padx=(10, 0))

        # Monitor indicator initialized in __init__

    # ── Actions ─────────────────────────────────────────────────

    def _refresh_networks(self):
        """Discover available networks."""
        self.status_label.config(text="Поиск сетей...")
        self.root.update_idletasks()
        try:
            self.networks = discover_networks()
            items = [f"{n.cidr} — {n.description}" for n in self.networks]
            self.net_combo["values"] = items
            if items:
                self.net_combo.current(0)
        except Exception as e:
            self.networks = []
            self.net_combo["values"] = [f"Manual — {e}"]
        self.status_label.config(text=f"Сетей: {len(self.networks)}")

    def _on_network_selected(self, event=None):
        pass

    def _get_selected_subnet(self) -> str:
        idx = self.net_combo.current()
        if 0 <= idx < len(self.networks):
            return self.networks[idx].cidr
        # Manual entry
        text = self.net_combo.get()
        if "/" in text:
            return text.split("—")[0].strip()
        return ""

    def _scan(self, mode: str):
        """Start scan in background thread."""
        if self.scanning:
            messagebox.showwarning("Занято", "Сканирование уже выполняется. Дождитесь завершения.")
            return
        subnet = self._get_selected_subnet()
        if not subnet:
            messagebox.showwarning("Нет сети", "Выберите сеть для сканирования.")
            return

        # If table has data, ask
        merge = False
        if self.device_tree.get_children():
            answer = messagebox.askyesnocancel(
                "Устройства уже найдены",
                "В таблице уже есть устройства.\n\n«Да» — пересканировать заново\n«Нет» — добавить новые к существующим\n«Отмена» — не сканировать"
            )
            if answer is None:  # Cancel
                return
            merge = not answer  # No = merge

        self.scanning = True
        self._merge_scan = merge
        self._set_buttons_state(tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.progress["value"] = 0
        self.status_label.config(text=f"Сканирование ({mode})...")
        self._clear_log()

        # Clear previous unless merging
        if not merge:
            self.device_tree.delete(*self.device_tree.get_children())
            self.current_result = None
        self.topo_text.delete("1.0", tk.END)
        self.raw_text.delete("1.0", tk.END)

        callbacks = _GuiCallbacks(self)

        scan_funcs = {
            "quick": scan_quick,
            "discover": scan_discover,
            "deep": scan_deep,
            "topology": scan_topology,
        }

        def scan_worker():
            try:
                kwargs = {}
                if mode == "topology":
                    kwargs["community"] = self._settings.get("snmp_community", "public")
                result = scan_funcs[mode](subnet, callbacks, **kwargs)
                self.root.after(0, lambda: self._on_scan_done(result))
            except Exception as e:
                self.root.after(0, lambda: self._on_scan_error(str(e)))

        self.scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self.scan_thread.start()

    def _stop_scan(self):
        """Stop scanning (don't actually kill thread, just mark stopped)."""
        self.scanning = False
        self.status_label.config(text="Остановлено")
        self._set_buttons_state(tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)

    def _on_scan_done(self, result: ScanResult):
        """Called from GUI thread when scan completes."""
        if not self.scanning:
            return
        self.scanning = False
        merge = getattr(self, '_merge_scan', False)
        self._merge_scan = False

        if merge and self.current_result:
            # Merge: add new devices, update existing
            old_ips = {d.ip: d for d in self.current_result.devices}
            for d in result.devices:
                if d.ip not in old_ips:
                    self.current_result.devices.append(d)
                else:
                    old_ips[d.ip].ports = d.ports or old_ips[d.ip].ports
                    old_ips[d.ip].os = d.os or old_ips[d.ip].os
                    old_ips[d.ip].mac = d.mac or old_ips[d.ip].mac
            result = self.current_result
        else:
            self.current_result = result

        self._set_buttons_state(tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.progress["value"] = 100

        self.status_label.config(text=f"Готово: {len(result.devices)} устройств")
        self.status_count.config(text=f"Устройств: {len(result.devices)} | Рёбер: {len(result.edges)}")

        self._populate_devices(result)
        self._populate_structure(result)
        self._render_topology(result)
        self._render_graph(result)
        self._show_raw(result)

    def _on_scan_error(self, msg: str):
        self.scanning = False
        self._set_buttons_state(tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.status_label.config(text=f"Ошибка: {msg}")
        self.raw_text.delete("1.0", tk.END)
        self.raw_text.insert(tk.END, f"Ошибка сканирования:\n{msg}")
        messagebox.showerror("Ошибка сканирования", msg)

    def _set_buttons_state(self, state):
        for btn in [self.btn_quick, self.btn_discover, self.btn_deep, self.btn_topology]:
            btn.config(state=state)

    # ── Populate devices table ──────────────────────────────────

    def _populate_devices(self, result: ScanResult):
        self.device_tree.delete(*self.device_tree.get_children())
        self._topo_row_map.clear()

        # Sort: online first, then by IP
        def sort_key(d: Device):
            return (0 if d.status == "online" else 1, _ip_sort_key(d.ip))

        for d in sorted(result.devices, key=sort_key):
            ports_str = ", ".join(
                f"{p.port}/{p.protocol}" + (f"({p.service})" if p.service else "")
                for p in d.ports[:8]
            )
            if len(d.ports) > 8:
                ports_str += f" +{len(d.ports)-8}"

            # Determine color tag
            tag = "online" if d.status == "online" else "offline"

            self.device_tree.insert("", tk.END, values=(
                "", d.ip, d.mac, d.hostname or "", d.vendor or "",
                d.device_type, d.os or "", ports_str, d.status,
            ), tags=(tag,))

        # Color tags
        self.device_tree.tag_configure("online", foreground=self.colors["online"])
        self.device_tree.tag_configure("offline", foreground=self.colors["offline"])

    def _sort_tree(self, col: str):
        """Simple column sort."""
        rows = [(self.device_tree.set(item, col), item)
                for item in self.device_tree.get_children("")]
        # Try numeric sort for IP
        if col == "ip":
            rows.sort(key=lambda x: _ip_sort_key(x[0]))
        else:
            rows.sort(key=lambda x: x[0].lower())

        for idx, (_, item) in enumerate(rows):
            self.device_tree.move(item, "", idx)

    def _tree_right_click(self, event):
        item = self.device_tree.identify_row(event.y)
        if item:
            self.device_tree.selection_set(item)
            self.tree_menu.post(event.x_root, event.y_root)

    def _toggle_alert(self):
        """Включить/выключить оповещение для выбранных устройств."""
        for item in self.device_tree.selection():
            vals = self.device_tree.item(item)["values"]
            ip = vals[1]  # IP is second column now
            if ip in self._alerted_ips:
                self._alerted_ips.discard(ip)
                vals_list = list(vals)
                vals_list[0] = ""
                self.device_tree.item(item, values=tuple(vals_list))
            else:
                self._alerted_ips.add(ip)
                vals_list = list(vals)
                vals_list[0] = "🔔"
                self.device_tree.item(item, values=tuple(vals_list))
        self.status_label.config(text=f"Оповещение: {len(self._alerted_ips)} устройств")

    def _copy_tree_ip(self):
        sel = self.device_tree.selection()
        if sel:
            ip = self.device_tree.item(sel[0])["values"][1]  # IP is second column now
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)
            self.status_label.config(text=f"Скопировано: {ip}")

    def _copy_tree_mac(self):
        sel = self.device_tree.selection()
        if sel:
            mac = self.device_tree.item(sel[0])["values"][2]  # MAC is 3rd
            self.root.clipboard_clear()
            self.root.clipboard_append(mac)
            self.status_label.config(text=f"Скопировано: {mac}")

    def _scan_selected_ports(self):
        from netmap_scanner import scan_ports
        sel = self.device_tree.selection()
        if sel and self.current_result:
            ip = self.device_tree.item(sel[0])["values"][1]  # IP is 2nd
            self.status_label.config(text=f"Сканирование портов {ip}...")
            self.root.update_idletasks()

            def worker():
                ports = scan_ports(ip, COMMON_PORTS, timeout=0.5)
                ports_str = ", ".join(
                    f"{p.port}/{p.protocol}" + (f"({p.service})" if p.service else "")
                    for p in ports
                )
                self.root.after(0, lambda: self._on_ports_done(ip, ports, ports_str))

            threading.Thread(target=worker, daemon=True).start()

    def _on_ports_done(self, ip: str, ports, ports_str: str):
        self.status_label.config(text=f"Порты {ip}: {ports_str}")
        # Update in tree
        for item in self.device_tree.get_children(""):
            if self.device_tree.set(item, "ip") == ip:
                self.device_tree.set(item, "ports", ports_str)
                break

    # ── Topology: граф на Canvas ─────────────────────────────

    def _render_topology(self, result: ScanResult):
        """Текстовая топология."""
        self.topo_text.delete("1.0", tk.END)

        if not result.devices:
            self.topo_text.insert(tk.END, "Нет данных.\n")
            return

        groups = {}
        for d in result.devices:
            groups.setdefault(d.device_type, []).append(d)

        self.topo_text.insert(tk.END, f"═══ Топология сети {result.network} ═══\n")
        self.topo_text.insert(tk.END, f"Время: {result.scan_time}\n\n")

        for dtype, devs in sorted(groups.items()):
            self.topo_text.insert(tk.END, f"▸ {dtype.upper()} ({len(devs)}):\n")
            for d in devs:
                icon = _device_icon(d.device_type)
                name = d.hostname or d.ip
                self.topo_text.insert(tk.END, f"  {icon} {name} — {d.ip}")
                if d.mac:
                    self.topo_text.insert(tk.END, f" | {d.mac}")
                if d.vendor:
                    self.topo_text.insert(tk.END, f" | {d.vendor}")
                if d.os:
                    self.topo_text.insert(tk.END, f" | OS: {d.os}")
                self.topo_text.insert(tk.END, "\n")
            self.topo_text.insert(tk.END, "\n")

        if result.edges:
            self.topo_text.insert(tk.END, "─── Связи ───\n")
            for e in result.edges[:50]:
                self.topo_text.insert(tk.END, f"  {e.source} ───► {e.target}\n")

    # Цвета по типам устройств
    TOPO_COLORS = {
        "router": ("#e74c3c", "#c0392b"),
        "switch": ("#2ecc71", "#27ae60"),
        "server": ("#3498db", "#2980b9"),
        "workstation": ("#f39c12", "#d68910"),
        "printer": ("#9b59b6", "#7d3c98"),
        "camera": ("#1abc9c", "#16a085"),
        "access-point": ("#e67e22", "#d35400"),
        "unknown": ("#95a5a6", "#7f8c8d"),
        "network-device": ("#2ecc71", "#27ae60"),
    }

    def _render_graph(self, result: ScanResult):
        """Отрисовать граф сети на Canvas."""
        self.topo_canvas.delete("all")
        self._topo_nodes.clear()
        self._topo_edges.clear()
        self._topo_positions.clear()

        if not result.devices:
            self.topo_canvas.create_text(0, 0, text="Нет данных",
                                        fill="#95a5a6", font=("Segoe UI", 14))
            return

        # Auto-layout: circular + grid
        self._topo_auto_layout()

        # Draw edges first (behind nodes)
        gw = self._get_topo_gateway(result)
        for edge in result.edges:
            src_pos = self._topo_positions.get(edge.source)
            tgt_pos = self._topo_positions.get(edge.target)
            if src_pos and tgt_pos:
                eid = self.topo_canvas.create_line(
                    src_pos[0], src_pos[1], tgt_pos[0], tgt_pos[1],
                    fill="#556677", width=2, smooth=True,
                    arrow="last", arrowshape=(10, 12, 5)
                )
                self._topo_edges.append(eid)

        # Draw nodes
        for device in result.devices:
            did = device.id
            pos = self._topo_positions.get(did, (0, 0))
            self._draw_topo_node(device, pos)

        # Title
        self.topo_canvas.create_text(
            0, -self._topo_grid_radius() - 80,
            text=f"Сеть {result.network}  •  {len(result.devices)} устройств",
            fill="#cccccc", font=("Segoe UI", 12, "bold")
        )

        self._topo_reset_view()

    def _topo_grid_radius(self) -> int:
        n = max(len(self._topo_positions), 1)
        return max(200, int(n ** 0.5 * 120))

    def _topo_auto_layout(self):
        """Раскладка: gateway в центре, остальные по кругу."""
        if not self.current_result:
            return

        result = self.current_result
        gw = self._get_topo_gateway(result)
        devices = result.devices

        # Find gateway device
        gw_dev = None
        others = []
        for d in devices:
            if d.ip == gw or d.id == gw:
                gw_dev = d
            else:
                others.append(d)

        # Gateway at center
        self._topo_positions[gw] = (0, 0)

        # Others in circle
        import math
        n = len(others)
        radius = max(220, n * 35)
        for i, d in enumerate(others):
            angle = 2 * math.pi * i / max(n, 1) - math.pi / 2
            x = radius * math.cos(angle)
            y = radius * math.sin(angle)
            self._topo_positions[d.id] = (x, y)

    def _get_topo_gateway(self, result: ScanResult) -> str:
        """Find gateway IP."""
        import ipaddress
        gw = ""
        try:
            net = ipaddress.IPv4Network(result.network, strict=False)
            gw = str(net.network_address + 1)
        except ValueError:
            pass
        return gw

    def _draw_topo_node(self, device: Device, pos: tuple):
        """Нарисовать один узел графа."""
        x, y = pos
        node_r = 28
        node_tag = f"node-{device.id}"  # unique tag for all items in this node
        colors = self.TOPO_COLORS.get(device.device_type, self.TOPO_COLORS["unknown"])

        # Shadow
        self.topo_canvas.create_oval(
            x - node_r + 2, y - node_r + 2,
            x + node_r + 2, y + node_r + 2,
            fill="#00000033", outline="", tags=(node_tag, "node", "node_shadow")
        )

        # Main circle
        self.topo_canvas.create_oval(
            x - node_r, y - node_r, x + node_r, y + node_r,
            fill=colors[0], outline=colors[1], width=3,
            tags=(node_tag, "node")
        )

        # Icon
        icon = _device_icon(device.device_type)
        self.topo_canvas.create_text(
            x, y - 2, text=icon, font=("Segoe UI", 14),
            tags=(node_tag, "node")
        )

        # IP label below
        label = device.hostname or device.ip
        if len(label) > 14:
            label = label[:13] + "…"
        self.topo_canvas.create_text(
            x, y + node_r + 14, text=label,
            fill="#cccccc", font=("Segoe UI", 8),
            tags=(node_tag, "node")
        )

        # Vendor below IP
        if device.vendor:
            self.topo_canvas.create_text(
                x, y + node_r + 28, text=device.vendor,
                fill="#888888", font=("Segoe UI", 7),
                tags=(node_tag, "node")
            )

        self._topo_nodes[device.id] = node_tag

        # Tooltip
        tooltip_text = f"{device.ip}\n{device.mac}\n{device.device_type}"
        if device.os:
            tooltip_text += f"\nOS: {device.os}"
        if device.ports:
            ports_preview = ", ".join(str(p.port) for p in device.ports[:6])
            tooltip_text += f"\nПорты: {ports_preview}"

        self.topo_canvas.tag_bind(node_tag, "<Enter>",
            lambda e, t=tooltip_text: self._topo_show_tooltip(e, t))
        self.topo_canvas.tag_bind(node_tag, "<Leave>",
            lambda e: self._topo_hide_tooltip())

    # ── Topology interaction ─────────────────────────────────

    def _topo_show_tooltip(self, event, text):
        x = self.topo_canvas.canvasx(event.x)
        y = self.topo_canvas.canvasy(event.y)
        self._topo_tooltip = self.topo_canvas.create_text(
            x + 15, y - 15, text=text, anchor="w",
            fill="#fff", font=("Consolas", 8),
            tags=("tooltip",)
        )
        # Tooltip background
        bbox = self.topo_canvas.bbox(self._topo_tooltip)
        if bbox:
            self.topo_canvas.create_rectangle(
                bbox[0] - 4, bbox[1] - 2, bbox[2] + 4, bbox[3] + 2,
                fill="#2c3e50", outline="#3498db", tags=("tooltip",)
            )
            self.topo_canvas.tag_raise(self._topo_tooltip)

    def _topo_hide_tooltip(self):
        self.topo_canvas.delete("tooltip")

    def _topo_click(self, event):
        """Нажатие: панорама или перетаскивание узла."""
        # Alt/Ctrl = pan
        if event.state & 0x20000 or event.state & 0x4:  # Alt or Ctrl
            self.topo_canvas.scan_mark(event.x, event.y)
            self._topo_drag_tag = None
            return

        # Find if clicking on a node
        x = self.topo_canvas.canvasx(event.x)
        y = self.topo_canvas.canvasy(event.y)
        overlapping = self.topo_canvas.find_overlapping(x - 2, y - 2, x + 2, y + 2)

        for item_id in overlapping:
            for did, tag in self._topo_nodes.items():
                if tag in self.topo_canvas.gettags(item_id):
                    self._topo_drag_tag = tag
                    self._topo_drag_start = (x, y)
                    self._topo_drag_did = did
                    return

        # Not on a node — pan
        self._topo_drag_tag = None
        self.topo_canvas.scan_mark(event.x, event.y)

    def _topo_drag(self, event):
        x = self.topo_canvas.canvasx(event.x)
        y = self.topo_canvas.canvasy(event.y)

        if self._topo_drag_tag:
            # Drag node
            dx = x - self._topo_drag_start[0]
            dy = y - self._topo_drag_start[1]
            self.topo_canvas.move(self._topo_drag_tag, dx, dy)
            self._topo_drag_start = (x, y)
            if hasattr(self, '_topo_drag_did'):
                cur = self._topo_positions.get(self._topo_drag_did, (0, 0))
                self._topo_positions[self._topo_drag_did] = (cur[0] + dx, cur[1] + dy)
            self._redraw_edges()
        else:
            # Pan canvas
            self.topo_canvas.scan_dragto(event.x, event.y, gain=1)

    def _topo_release(self, event):
        self._topo_drag_tag = None
        self._topo_update_minimap()

    def _topo_zoom(self, event):
        """Zoom: колесико (Windows) или кнопки 4/5 (Linux)."""
        scale = 1.0
        if hasattr(event, 'delta') and event.delta:
            scale = 1.1 if event.delta > 0 else 0.9
        elif hasattr(event, 'num'):
            scale = 1.1 if event.num == 4 else 0.9
        else:
            return

        self.topo_canvas.scale("all", event.x, event.y, scale, scale)
        self.topo_canvas.configure(scrollregion=self.topo_canvas.bbox("all"))
        self._topo_update_minimap()

    def _redraw_edges(self):
        """Перерисовать рёбра по новым позициям узлов (оптимизировано)."""
        # Delete old edges
        for eid in self._topo_edges:
            self.topo_canvas.delete(eid)
        self._topo_edges.clear()
        if not self.current_result or not self.current_result.edges:
            return
        # Batch: compute all coordinates, then draw
        new_edges = []
        for edge in self.current_result.edges:
            src = self._topo_positions.get(edge.source)
            tgt = self._topo_positions.get(edge.target)
            if src and tgt:
                new_edges.append((src[0], src[1], tgt[0], tgt[1]))
        # Draw all at once
        for src_x, src_y, tgt_x, tgt_y in new_edges:
            eid = self.topo_canvas.create_line(
                src_x, src_y, tgt_x, tgt_y,
                fill="#556677", width=2, smooth=True,
                arrow="last", arrowshape=(10, 12, 5)
            )
            self._topo_edges.append(eid)
        # Push nodes above edges
        self.topo_canvas.tag_raise("node")

    def _topo_reset_view(self):
        """Сбросить зум и панораму, показать всё."""
        bbox = self.topo_canvas.bbox("all")
        if bbox:
            pad = 80
            self.topo_canvas.configure(scrollregion=(
                bbox[0] - pad, bbox[1] - pad,
                bbox[2] + pad, bbox[3] + pad
            ))
            self.topo_canvas.xview_moveto(0)
            self.topo_canvas.yview_moveto(0)
        self._topo_update_minimap()

    def _topo_nudge(self, dx, dy):
        """Сдвинуть вид на dx,dy."""
        self.topo_canvas.xview_scroll(dx, "units")
        self.topo_canvas.yview_scroll(dy, "units")
        self._topo_update_minimap()

    def _topo_zoom_step(self, factor):
        """Зум с заданным коэффициентом (для кнопок)."""
        w = self.topo_canvas.winfo_width()
        h = self.topo_canvas.winfo_height()
        cx, cy = w // 2, h // 2
        self.topo_canvas.scale("all", cx, cy, factor, factor)
        self.topo_canvas.configure(scrollregion=self.topo_canvas.bbox("all"))
        self._topo_update_minimap()

    def _topo_minimap_click(self, event):
        """Клик по мини-карте — переместить основной вид."""
        bbox = self.topo_canvas.bbox("all")
        if not bbox:
            return
        mw, mh = 150, 110
        pad_x, pad_y = 80, 40
        total_w = bbox[2] - bbox[0] + 2 * pad_x
        total_h = bbox[3] - bbox[1] + 2 * pad_y
        if total_w <= 0 or total_h <= 0:
            return
        # Map minimap click to canvas coordinates
        fx = (event.x / mw)
        fy = (event.y / mh)
        self.topo_canvas.xview_moveto(max(0, fx - 0.3))
        self.topo_canvas.yview_moveto(max(0, fy - 0.3))

    def _topo_update_minimap(self):
        """Отрисовать мини-карту в углу."""
        self._topo_minimap.delete("minimap")
        bbox = self.topo_canvas.bbox("all")
        if not bbox:
            return
        mw, mh = 150, 110
        total_w = bbox[2] - bbox[0] + 160
        total_h = bbox[3] - bbox[1] + 160
        if total_w <= 0 or total_h <= 0:
            return
        scale_x = mw / max(total_w, 1)
        scale_y = mh / max(total_h, 1)
        scale = min(scale_x, scale_y)

        pad_x, pad_y = 80, 40
        # Draw all nodes as small dots
        for did, tag in self._topo_nodes.items():
            coords = self.topo_canvas.coords(tag)
            if coords:
                cx = (coords[0] - bbox[0] + pad_x) * scale
                cy = (coords[1] - bbox[1] + pad_y) * scale
                r = 3
                self._topo_minimap.create_oval(
                    cx - r, cy - r, cx + r, cy + r,
                    fill="#3498db", outline="", tags="minimap"
                )

        # Draw viewport rectangle
        vx1 = self.topo_canvas.canvasx(0)
        vy1 = self.topo_canvas.canvasy(0)
        vx2 = vx1 + self.topo_canvas.winfo_width()
        vy2 = vy1 + self.topo_canvas.winfo_height()
        rx1 = (vx1 - bbox[0] + 80) * scale
        ry1 = (vy1 - bbox[1] + 40) * scale
        rx2 = (vx2 - bbox[0] + 80) * scale
        ry2 = (vy2 - bbox[1] + 40) * scale
        self._topo_minimap.create_rectangle(
            max(0, rx1), max(0, ry1), min(mw, rx2), min(mh, ry2),
            outline="#e74c3c", width=2, tags="minimap"
        )

    # ── Raw JSON ────────────────────────────────────────────────

    def _show_raw(self, result: ScanResult):
        self.raw_text.delete("1.0", tk.END)
        if not result or not result.devices:
            self.raw_text.insert(tk.END, "Нет данных")
            return
        try:
            from dataclasses import asdict
            data = asdict(result)
            json_str = json.dumps(data, indent=2, ensure_ascii=False, default=str)
            self.raw_text.insert(tk.END, json_str)
        except Exception as e:
            self.raw_text.insert(tk.END, f"Ошибка: {e}")

    # ── Export / Load / Monitor ────────────────────────────────

    def _export_result(self):
        if not self.current_result:
            messagebox.showinfo("Нечего экспортировать", "Сначала выполните сканирование.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"netmap-{datetime.now():%Y%m%d-%H%M}.json"
        )
        if path:
            try:
                save_result(self.current_result, path)
                self.status_label.config(text=f"Сохранено: {path}")
            except Exception as e:
                messagebox.showerror("Ошибка экспорта", str(e))

    def _load_result(self):
        path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            result = load_result(path)
            self.current_result = result
            self._populate_devices(result)
            self._render_topology(result)
            self._render_graph(result)
            self._show_raw(result)
            self.status_label.config(text=f"Загружено: {path}")
            self.status_count.config(text=f"Устройств: {len(result.devices)}")
        except Exception as e:
            messagebox.showerror("Ошибка загрузки", str(e))

    def _monitor(self):
        """Toggle periodic monitoring."""
        if self._monitoring:
            self._stop_monitoring()
            return

        subnet = self._get_selected_subnet()
        if not subnet:
            messagebox.showwarning("Нет сети", "Выберите сеть.")
            return

        if not self.current_result:
            messagebox.showinfo("Нет данных", "Сначала выполните сканирование для baseline.")
            return

        self._monitoring = True
        self.btn_monitor.config(text="⏹ Стоп монитор")
        self.monitor_indicator.config(text="🟢 Мониторинг", foreground="#4caf50")
        self.status_label.config(text="Мониторинг запущен")
        self._run_monitor_scan()

    def _stop_monitoring(self):
        self._monitoring = False
        if self._monitor_after_id:
            self.root.after_cancel(self._monitor_after_id)
            self._monitor_after_id = None
        self.btn_monitor.config(text="📊 Монитор")
        self.monitor_indicator.config(text="")
        self.status_label.config(text="Мониторинг остановлен")

    def _run_monitor_scan(self):
        """Выполнить одно сканирование в режиме мониторинга."""
        if not self._monitoring or self.scanning:
            return

        subnet = self._get_selected_subnet()
        self.status_label.config(text="Мониторинг: сканирование...")

        callbacks = _GuiCallbacks(self)

        def worker():
            try:
                new_result = scan_quick(subnet, callbacks)
                diff = monitor_diff(self.current_result, new_result)
                self.root.after(0, lambda: self._on_monitor_tick(new_result, diff))
            except Exception as e:
                self.root.after(0, lambda: self._on_scan_error(str(e)))

        self.scanning = True
        threading.Thread(target=worker, daemon=True).start()

    def _on_monitor_tick(self, new_result: ScanResult, diff: dict):
        """Обработка одного тика мониторинга."""
        self.scanning = False

        appeared = len(diff.get("appeared", []))
        disappeared = len(diff.get("disappeared", []))
        changed = len(diff.get("changed", []))

        if appeared or disappeared or changed:
            # Sound alert
            if self._settings.get("sound", True):
                self._play_alert_sound()

            # Update table with diff colors
            appeared_ips = {d.get("ip") for d in diff.get("appeared", [])}
            disappeared_ips = {d.get("ip") for d in diff.get("disappeared", [])}
            self._populate_devices_monitor(new_result, appeared_ips, disappeared_ips)

            # Check for watched devices
            alerted = appeared_ips & self._alerted_ips
            gone = disappeared_ips & self._alerted_ips
            alert_msg = ""
            if alerted:
                alert_msg += f"🟢 Появились: {', '.join(sorted(alerted)[:5])}"
            if gone:
                alert_msg += f"\n🔴 Пропали: {', '.join(sorted(gone)[:5])}"
            if alert_msg:
                self.root.after(500, lambda: messagebox.showwarning("🔔 Оповещение", alert_msg))

            self.status_label.config(
                text=f"Мониторинг: 🟢{appeared} 🔴{disappeared} 🟡{changed}",
                foreground="#ff9800"
            )
        else:
            self.status_label.config(text="Мониторинг: без изменений")

        self.current_result = new_result
        self.progress["value"] = 100
        self._show_raw(new_result)

        # Schedule next scan
        if self._monitoring:
            interval = self._settings.get("monitor_interval", 60) * 1000
            self._monitor_after_id = self.root.after(interval, self._run_monitor_scan)
            self.monitor_indicator.config(
                text=f"🟢 Мониторинг ({self._settings['monitor_interval']}с)"
            )

    def _play_alert_sound(self):
        """Звуковой сигнал (кроссплатформенно)."""
        try:
            import sys
            if sys.platform == 'win32':
                import winsound
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            else:
                print('\a')  # bell
        except Exception:
            pass

    def _on_monitor_done(self, new_result: ScanResult, diff: dict):
        self.scanning = False
        self.current_result = new_result
        self._set_buttons_state(tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)

        # Populate with color-coded diff
        appeared_ips = {d.get("ip") for d in diff.get("appeared", [])}
        disappeared_ips = {d.get("ip") for d in diff.get("disappeared", [])}
        self._populate_devices_monitor(new_result, appeared_ips, disappeared_ips)
        self._populate_structure(new_result)

        # Update status
        self.status_label.config(
            text=f"Мониторинг: {diff['previous_count']}→{diff['current_count']} | "
                 f"🟢{len(appeared_ips)} 🔴{len(disappeared_ips)}"
        )

    def _populate_devices_monitor(self, result, appeared_ips, disappeared_ips):
        """Заполнить таблицу с цветовой индикацией diff."""
        self.device_tree.delete(*self.device_tree.get_children())

        def sort_key(d: Device):
            return (0 if d.status == "online" else 1, _ip_sort_key(d.ip))

        for d in sorted(result.devices, key=sort_key):
            ports_str = ", ".join(
                f"{p.port}/{p.protocol}" + (f"({p.service})" if p.service else "")
                for p in d.ports[:8]
            )
            # Color tag
            if d.ip in appeared_ips:
                tag = "appeared"
            elif d.ip in disappeared_ips:
                tag = "disappeared"
            else:
                tag = "online" if d.status == "online" else "offline"

            self.device_tree.insert("", tk.END, values=(
                "", d.ip, d.mac, d.hostname or "", d.vendor or "",
                d.device_type, d.os or "", ports_str, d.status,
            ), tags=(tag,))

        # Color tags
        self.device_tree.tag_configure("online", foreground="#4caf50")
        self.device_tree.tag_configure("offline", foreground="#9e9e9e")
        self.device_tree.tag_configure("appeared", foreground="#00e676", background="#1b5e20")
        self.device_tree.tag_configure("disappeared", foreground="#ff5252", background="#3e1010")


# ── GUI Callbacks (bridges scanner → GUI thread) ────────────────

class _GuiCallbacks(ScanCallbacks):
    def __init__(self, app: NetMapApp):
        self.app = app

    def on_device_found(self, device: Device):
        self.app.root.after(0, lambda: self._add_device(device))

    def on_progress(self, msg: str, pct: int):
        self.app.root.after(0, lambda: self._update_progress(msg, pct))

    def on_complete(self, result: ScanResult):
        self.app.root.after(0, lambda: self.app._on_scan_done(result))

    def on_error(self, msg: str):
        self.app.root.after(0, lambda: self.app.status_label.config(text=f"Ошибка: {msg}"))

    def _add_device(self, device: Device):
        ports_str = ", ".join(
            f"{p.port}/{p.protocol}" + (f"({p.service})" if p.service else "")
            for p in device.ports[:8]
        )
        # Use dict for O(1) lookup
        if device.ip in self.app._topo_row_map:
            item = self.app._topo_row_map[device.ip]
            alert_val = self.app.device_tree.item(item)["values"][0]
            old_vals = self.app.device_tree.item(item)["values"]
            self.app.device_tree.item(item, values=(
                alert_val, device.ip,
                device.mac or old_vals[2],
                device.hostname or old_vals[3],
                device.vendor or old_vals[4],
                device.device_type,
                device.os or old_vals[6],
                ports_str or old_vals[7],
                device.status,
            ))
            return
        # Insert new row
        item = self.app.device_tree.insert("", tk.END, values=(
            "", device.ip, device.mac, device.hostname or "", device.vendor or "",
            device.device_type, device.os or "", ports_str, device.status,
        ))
        self.app._topo_row_map[device.ip] = item

    def _update_progress(self, msg: str, pct: int):
        self.app.status_label.config(text=msg)
        self.app.progress["value"] = pct
        self.app._log(msg)


# ── Helpers ──────────────────────────────────────────────────────

def _ip_sort_key(ip: str) -> tuple:
    try:
        return tuple(int(x) for x in ip.split("."))
    except Exception:
        return (0,)


def _device_icon(dtype: str) -> str:
    icons = {
        "router": "🖧", "switch": "🔀", "server": "🖥", "workstation": "💻",
        "printer": "🖨", "camera": "📷", "access-point": "📡", "unknown": "❓",
    }
    return icons.get(dtype, "❓")


# ── Entry point ──────────────────────────────────────────────────

def main():
    root = tk.Tk()

    # Try to set icon
    try:
        if os.name == "nt":
            root.iconbitmap(default="icon.ico")
    except Exception:
        pass

    app = NetMapApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
