#!/usr/bin/env python3
"""
NetMap v2 — PyQt6 GUI
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'python'))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QStatusBar, QToolBar,
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QProgressBar, QTableView, QHeaderView, QPlainTextEdit, QMessageBox,
    QSplitter, QFrame, QCheckBox, QSpinBox, QListWidget, QGroupBox,
    QGraphicsView, QGraphicsScene,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QAbstractTableModel, QModelIndex
from PyQt6.QtGui import QAction, QColor, QPen, QBrush, QFont, QPainter

from netmap_scanner import (
    ScanResult, Device, ScanCallbacks,
    discover_networks, scan_quick, scan_discover, scan_deep, scan_topology,
    monitor_diff, save_result, load_result, COMMON_PORTS, SERVICE_MAP,
)


class ScannerThread(QThread):
    """Фоновый поток сканирования."""
    progress = pyqtSignal(str, int)
    device_found = pyqtSignal(object)
    scan_done = pyqtSignal(object)
    scan_error = pyqtSignal(str)

    def __init__(self, mode: str, subnet: str):
        super().__init__()
        self.mode = mode
        self.subnet = subnet

    def run(self):
        callbacks = _ThreadCallbacks(self)
        modes = {
            "quick": scan_quick,
            "discover": scan_discover,
            "deep": scan_deep,
            "topology": scan_topology,
        }
        try:
            result = modes[self.mode](self.subnet, callbacks)
            self.scan_done.emit(result)
        except Exception as e:
            self.scan_error.emit(str(e))


class _ThreadCallbacks(ScanCallbacks):
    def __init__(self, thread: ScannerThread):
        self._t = thread

    def on_device_found(self, device: Device):
        self._t.device_found.emit(device)

    def on_progress(self, msg: str, pct: int):
        self._t.progress.emit(msg, pct)

    def on_error(self, msg: str):
        self._t.progress.emit(msg, 0)


class DeviceTableModel(QAbstractTableModel):
    """Модель данных для таблицы устройств."""
    COLUMNS = ["🔔", "IP", "MAC", "Hostname", "Вендор", "Тип", "OS", "Порты", "Статус"]

    def __init__(self):
        super().__init__()
        self.devices: list[Device] = []

    def set_devices(self, devices: list):
        self.beginResetModel()
        self.devices = devices
        self.endResetModel()

    def add_device(self, device: Device):
        self.beginInsertRows(QModelIndex(), len(self.devices), len(self.devices))
        self.devices.append(device)
        self.endInsertRows()

    def rowCount(self, parent=QModelIndex()):
        return len(self.devices)

    def columnCount(self, parent=QModelIndex()):
        return len(self.COLUMNS)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        d = self.devices[index.row()]
        col = index.column()
        vals = [
            "", d.ip, d.mac, d.hostname or "", d.vendor or "",
            d.device_type, d.os or "",
            ", ".join(f"{p.port}/{p.protocol}" for p in d.ports[:6]),
            d.status,
        ]
        return vals[col] if col < len(vals) else ""

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section] if section < len(self.COLUMNS) else ""
        return None


class NetMapWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.version = self._load_version()
        self.setWindowTitle(f"NetMap v{self.version} — Карта сети")
        self.setGeometry(100, 100, 1280, 800)
        self.setMinimumSize(900, 600)

        # Dark theme
        self.setStyleSheet("""
            QMainWindow, QTabWidget, QWidget { background: #1e1e2e; color: #cdd6f4; }
            QTabWidget::pane { border: 1px solid #45475a; }
            QTabBar::tab { background: #313244; color: #cdd6f4; padding: 8px 16px; border: none; }
            QTabBar::tab:selected { background: #45475a; }
            QPushButton { background: #45475a; color: #cdd6f4; border: none; padding: 6px 16px; border-radius: 4px; }
            QPushButton:hover { background: #585b70; }
            QPushButton:pressed { background: #6c7086; }
            QComboBox { background: #313244; color: #cdd6f4; border: 1px solid #45475a; padding: 4px; border-radius: 4px; }
            QProgressBar { border: 1px solid #45475a; border-radius: 4px; text-align: center; }
            QProgressBar::chunk { background: #89b4fa; border-radius: 3px; }
            QTableView { background: #1e1e2e; color: #cdd6f4; gridline-color: #45475a; border: none; }
            QHeaderView::section { background: #313244; color: #cdd6f4; padding: 4px; border: 1px solid #45475a; }
            QPlainTextEdit { background: #11111b; color: #a6e3a1; border: 1px solid #45475a; }
            QStatusBar { background: #313244; color: #6c7086; }
            QToolBar { background: #313244; spacing: 4px; border: none; }
            QGroupBox { color: #cdd6f4; border: 1px solid #45475a; border-radius: 4px; margin-top: 8px; padding-top: 12px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
            QListWidget { background: #11111b; color: #cdd6f4; border: 1px solid #45475a; }
            QSpinBox { background: #313244; color: #cdd6f4; border: 1px solid #45475a; padding: 4px; }
            QCheckBox { color: #cdd6f4; }
        """)

        # State
        self.networks = []
        self.current_result: ScanResult | None = None
        self.scanner: ScannerThread | None = None

        self._setup_ui()
        self._refresh_networks()

    def _load_version(self) -> str:
        paths = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python", "VERSION"),
        ]
        for p in paths:
            if os.path.exists(p):
                return open(p).read().strip()
        return "2.0.0"

    def _setup_ui(self):
        # Toolbar
        tb = self.addToolBar("Основная")
        tb.setMovable(False)

        self.net_combo = QComboBox()
        self.net_combo.setMinimumWidth(220)
        tb.addWidget(QLabel("Сеть:"))
        tb.addWidget(self.net_combo)

        refresh_btn = QPushButton("🔄")
        refresh_btn.setFixedWidth(36)
        refresh_btn.clicked.connect(self._refresh_networks)
        tb.addWidget(refresh_btn)

        tb.addSeparator()

        for label, mode in [("⚡ Быстрый", "quick"), ("🔍 Обзор", "discover"),
                            ("🕳 Глубокий", "deep"), ("🔗 Топология", "topology")]:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, m=mode: self._scan(m))
            tb.addWidget(btn)

        tb.addSeparator()

        self.monitor_btn = QPushButton("📊 Монитор")
        self.monitor_btn.clicked.connect(self._toggle_monitor)
        tb.addWidget(self.monitor_btn)

        export_btn = QPushButton("💾 Экспорт")
        export_btn.clicked.connect(self._export_result)
        tb.addWidget(export_btn)

        # Tabs
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.tab_devices = QWidget()
        self.tab_topology = QWidget()
        self.tab_graph = QWidget()
        self.tab_settings = QWidget()
        self.tab_log = QWidget()
        self.tab_json = QWidget()

        self.tabs.addTab(self.tab_devices, "📋 Устройства")
        self.tabs.addTab(self.tab_topology, "📝 Топология")
        self.tabs.addTab(self.tab_graph, "🕸 Граф")
        self.tabs.addTab(self.tab_settings, "⚙")
        self.tabs.addTab(self.tab_log, "📝 Лог")
        self.tabs.addTab(self.tab_json, "📄 JSON")

        self._build_devices_tab()
        self._build_topology_tab()
        self._build_graph_tab()
        self._build_settings_tab()
        self._build_log_tab()
        self._build_json_tab()

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Готов")
        self.status_bar.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(300)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

        self.count_label = QLabel("")
        self.status_bar.addPermanentWidget(self.count_label)

        self.ver_label = QLabel(f"v{self.version}")
        self.status_bar.addPermanentWidget(self.ver_label)

    def _build_devices_tab(self):
        layout = QVBoxLayout(self.tab_devices)
        self.device_table = QTableView()
        self.device_model = DeviceTableModel()
        self.device_table.setModel(self.device_model)
        self.device_table.horizontalHeader().setStretchLastSection(True)
        self.device_table.setAlternatingRowColors(True)
        self.device_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        layout.addWidget(self.device_table)

    def _build_topology_tab(self):
        layout = QVBoxLayout(self.tab_topology)
        self.topo_text = QPlainTextEdit()
        self.topo_text.setReadOnly(True)
        self.topo_text.setFont(QFont("Consolas", 10))
        layout.addWidget(self.topo_text)

    def _build_graph_tab(self):
        layout = QVBoxLayout(self.tab_graph)
        self.graph_view = QGraphicsView()
        self.graph_scene = QGraphicsScene()
        self.graph_view.setScene(self.graph_scene)
        self.graph_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.graph_view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        layout.addWidget(self.graph_view)

    def _build_settings_tab(self):
        layout = QVBoxLayout(self.tab_settings)

        monitor_group = QGroupBox("Мониторинг")
        ml = QVBoxLayout(monitor_group)

        hl = QHBoxLayout()
        hl.addWidget(QLabel("Интервал (сек):"))
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(10, 3600)
        self.interval_spin.setValue(60)
        hl.addWidget(self.interval_spin)
        hl.addStretch()
        ml.addLayout(hl)

        self.sound_check = QCheckBox("Звук при изменениях")
        self.sound_check.setChecked(True)
        ml.addWidget(self.sound_check)

        layout.addWidget(monitor_group)

        alert_group = QGroupBox("Устройства с оповещением 🔔")
        al = QVBoxLayout(alert_group)
        self.alert_list = QListWidget()
        al.addWidget(self.alert_list)
        layout.addWidget(alert_group)

    def _build_log_tab(self):
        layout = QVBoxLayout(self.tab_log)
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        layout.addWidget(self.log_text)

    def _build_json_tab(self):
        layout = QVBoxLayout(self.tab_json)
        self.json_text = QPlainTextEdit()
        self.json_text.setReadOnly(True)
        self.json_text.setFont(QFont("Consolas", 9))
        layout.addWidget(self.json_text)

    def _refresh_networks(self):
        self.networks = discover_networks()
        self.net_combo.clear()
        for n in self.networks:
            self.net_combo.addItem(f"{n.cidr} — {n.description}")
        self.status_label.setText(f"Сетей: {len(self.networks)}")

    def _get_selected_subnet(self) -> str:
        idx = self.net_combo.currentIndex()
        if 0 <= idx < len(self.networks):
            return self.networks[idx].cidr
        return ""

    def _scan(self, mode: str):
        subnet = self._get_selected_subnet()
        if not subnet:
            QMessageBox.warning(self, "Нет сети", "Выберите сеть.")
            return
        if self.scanner and self.scanner.isRunning():
            QMessageBox.warning(self, "Занято", "Сканирование уже выполняется.")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Сканирование ({mode})...")
        self.log_text.clear()

        self.scanner = ScannerThread(mode, subnet)
        self.scanner.progress.connect(self._on_progress)
        self.scanner.device_found.connect(self.device_model.add_device)
        self.scanner.scan_done.connect(self._on_scan_done)
        self.scanner.scan_error.connect(self._on_scan_error)
        self.scanner.start()

    def _on_progress(self, msg: str, pct: int):
        self.status_label.setText(msg)
        self.progress_bar.setValue(pct)
        self._log(msg)

    def _on_scan_done(self, result: ScanResult):
        self.scanner = None
        self.current_result = result
        self.progress_bar.setVisible(False)
        self.device_model.set_devices(result.devices)
        self.status_label.setText(f"Готово: {len(result.devices)} устройств")
        self.count_label.setText(f"Устройств: {len(result.devices)}")
        self._show_json(result)

    def _on_scan_error(self, msg: str):
        self.scanner = None
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Ошибка: {msg}")
        QMessageBox.critical(self, "Ошибка", msg)

    def _toggle_monitor(self):
        pass  # TODO

    def _export_result(self):
        pass  # TODO

    def _show_json(self, result: ScanResult):
        from dataclasses import asdict
        import json
        data = asdict(result)
        self.json_text.setPlainText(json.dumps(data, indent=2, ensure_ascii=False, default=str))

    def _log(self, msg: str):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.appendPlainText(f"[{ts}] {msg}")


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("NetMap")
    window = NetMapWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
