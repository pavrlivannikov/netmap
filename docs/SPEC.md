# NetMap — Техническая спецификация v0.3.0

## 1. Обзор

NetMap — кроссплатформенный сетевой анализатор на Python. Версия v0.3.0 (май 2026).

### Стек

- **Язык**: Python 3.12+
- **Зависимости**: netifaces, pysnmp, paramiko, fastapi, uvicorn
- **Сборка**: PyInstaller → `.exe` (Windows)
- **Без Rust, Tauri, Svelte, TypeScript** — проект полностью на Python

### Принципы

- **Лёгкость**: чистый Python, минимум зависимостей, бинарник < 30 МБ
- **Скорость**: ARP мгновенно, asyncio даёт ускорение 5–8× против ThreadPoolExecutor
- **Автономность**: работает без интернета, OUI-база встроена (39 000 записей)
- **Изолированные сети**: не требует онлайн-зависимостей
- **Кроссплатформенность**: Linux и Windows, platform-specific код через ctypes

### Способы использования

| Интерфейс | Файл | Описание |
|-----------|------|----------|
| CLI | через `netmap_scanner.py` | Прямой вызов функций из кода |
| tkinter GUI | `netmap_gui.py` | Быстрый десктопный интерфейс, встроен в сборку |
| PyQt6 GUI | `pyqt6/main_window.py` | Продвинутый GUI с QGraphicsView-топологией |
| Web UI | `netmap_web.py` | FastAPI + статический HTML/JS/Canvas |

---

## 2. Архитектура

### 2.1. Модули

```
python/
├── netmap_device.py     # Dataclass'ы: Device, Port, Edge, ScanResult, NetworkInfo
├── netmap_utils.py      # Утилиты: OUI, парсинг ARP, TCP scan, OS detection, сервис-мап
├── netmap_discovery.py  # Обнаружение сетей: Win32 API, ARP, ICMP, ping sweep
├── netmap_scanner.py    # Высокоуровневые сценарии: quick, discover, deep, topology
├── netmap_snmp.py       # SNMP v2c через pysnmp: sysName, LLDP, FDB, walk
├── netmap_ssh.py        # SSH через paramiko: FDB с Cisco, TP-Link, MikroTik
├── netmap_async.py      # Асинхронное сканирование на asyncio (5–8× быстрее)
├── netmap_db.py         # SQLite: история сканов, diff, статистика, миграция JSON→SQLite
├── netmap_alerts.py     # Алерты: Telegram, Webhook, Console. Детекция: новый, пропал, порты, MAC
├── netmap_config.py     # Конфигурация: ~/.netmap_config.json, автосоздание
├── netmap_monitor.py    # Diff-движок и сериализация ScanResult ↔ JSON
├── netmap_gui.py        # tkinter GUI (десктоп)
├── netmap_web.py        # Web UI: FastAPI API + статика
├── oui_data.py          # OUI-база: 39 000 записей MAC→вендор
├── netmap_diag.py       # Диагностика окружения
├── bump_version.py      # Утилита версионирования
└── test_netmap.py       # Unit-тесты (unittest)
```

### 2.2. Слои архитектуры

```
┌─────────────────────────────────────────────────────────────┐
│                   Интерфейсы                                 │
│    CLI (netmap_scanner)  │  tkinter GUI  │  PyQt6  │  Web   │
├─────────────────────────────────────────────────────────────┤
│                   Сценарии (netmap_scanner)                  │
│    quick  │  discover  │  deep  │  topology  │  monitor     │
├─────────────────────────────────────────────────────────────┤
│               Discovery Layer (netmap_discovery)             │
│    Win32 API (ARP + адаптеры)  │  ARP scan  │  ICMP sweep  │
│    PowerShell Get-NetNeighbor  │  arp -a     │  ip neigh    │
├─────────────────────────────────────────────────────────────┤
│              Identification Layer                            │
│    SNMP sysName/sysDescr  │  OUI lookup (39K)  │  nmap OS  │
│    TCP port scan  │  TTL-based OS guess  │  Reverse DNS    │
├─────────────────────────────────────────────────────────────┤
│               Topology Layer                                 │
│    SNMP LLDP walk  │  SNMP FDB (dot1qFdbTable)             │
│    SSH FDB (Cisco/TP-Link/MikroTik)                        │
├─────────────────────────────────────────────────────────────┤
│              Monitoring Layer                                │
│    Diff engine  │  SQLite history  │  Alerts (Telegram)    │
├─────────────────────────────────────────────────────────────┤
│              Persistence Layer                               │
│    JSON (save_result/load_result)  │  SQLite (ScanDB)      │
└─────────────────────────────────────────────────────────────┘
```

### 2.3. Поток данных при сканировании

```
discover_networks()          → список NetworkInfo
       │
       ▼
arp_scan(subnet)             → list[Device] (IP + MAC + vendor)
       │
       ▼
ping_sweep(remaining_ips)    → list[Device] (оставшиеся хосты)
       │
       ▼
scan_ports(ip, COMMON_PORTS) → list[Port] (31 TCP-порт)
       │
       ▼
SNMP discover / LLDP / FDB   → hostname, интерфейсы, связи
       │
       ▼
ScanResult                   → JSON / SQLite / Web API
```

---

## 3. Режимы сканирования

### 3.1. Сводка

| Режим | Функция | Протоколы | Типовое время (/24) | Результат |
|-------|---------|-----------|---------------------|-----------|
| **quick** | `scan_quick()` | ARP | < 1 с | IP + MAC + vendor |
| **discover** | `scan_discover()` | ARP + ICMP + TCP | ~2 мин | + hostname + порты + OS guess |
| **deep** | `scan_deep()` | всё + nmap OS | ~10 мин | + детальная ОС + все порты |
| **topology** | `scan_topology()` | + SNMP LLDP + FDB | ~5 мин | + связи между устройствами |
| **monitor** | `monitor_diff()` | diff + алерты | периодически | изменения: появился/пропал/порты/MAC |

### 3.2. Quick — `scan_quick(subnet, callbacks)`

1. `arp_scan_subnet()` — ARP-таблица системы (Win32 API → PowerShell → arp -a)
2. Связи: все устройства → gateway (предположительный)

```
Результат: ScanResult с IP, MAC, vendor для всех ARP-видимых хостов
```

### 3.3. Discover — `scan_discover(subnet, callbacks)`

1. ARP scan (как в quick)
2. `ping_sweep()` — ICMP для IP, не найденных через ARP (ThreadPool, 5 workers)
3. `scan_ports()` — 31 TCP-порт (22, 80, 443, 3389, ...) для каждого хоста
4. `guess_os_by_ttl()` — определение ОС по TTL пинга (≤64 → Linux, ≤128 → Windows)
5. `guess_device_type()` — эвристика по hostname + открытым портам

```
Результат: IP, MAC, vendor, hostname, OS, device_type, ports[]
```

### 3.4. Deep — `scan_deep(subnet, callbacks)`

1. Полный `scan_discover()`
2. `_nmap_scan()` — nmap `-O -sV --top-ports 20 -T4` (если nmap установлен)
3. Мерж результатов nmap в Device (OS + порты)

```
Результат: всё из discover + детальная ОС + расширенный список портов
```

### 3.5. Topology — `scan_topology(subnet, callbacks, community)`

1. ARP scan (как в quick)
2. Для каждого хоста:
   - `SnmpClient.probe()` — проверка доступности SNMP
   - `SnmpClient.discover()` — sysName, sysDescr, интерфейсы (IF-MIB)
   - `SnmpClient.get_lldp_neighbors()` — LLDP-соседи (LLDP-MIB)
   - `SnmpClient.get_fdb()` — MAC-таблица (Q-BRIDGE-MIB dot1qFdbTable)
3. Резолвинг FDB MAC → IP через ARP-таблицу
4. Fallback: если SNMP недоступен — TCP port scan

```
Результат: devices с интерфейсами + edges с LLDP/FDB-связями
```

### 3.6. Асинхронный режим — `netmap_async.py`

Полный эквивалент discover на asyncio:

| Операция | ThreadPool (5 workers) | asyncio (100 concurrent) | Ускорение |
|----------|----------------------|------------------------|-----------|
| Ping sweep /24 (256 IP) | ~50 с | ~6 с | **~8×** |
| Port scan (31 порт) | ~3 с/хост | ~0.8 с/хост | **~3.7×** |
| Полный скан /24 | ~80–120 с | ~12–20 с | **~5–6×** |

Функции: `scan_network_async()`, `ping_sweep_async()`, `scan_ports_async()`, `scan_host_async()`.

---

## 4. Протоколы и OID'ы

### 4.1. ARP

| Платформа | Метод |
|-----------|-------|
| Windows | 1) Win32 `GetIpNetTable` (ctypes) — локаль-независимо |
| | 2) PowerShell `Get-NetNeighbor -State Reachable,Stale,...` → JSON |
| | 3) `arp -a` с regex-парсером |
| Linux | 1) `ip -4 neigh` |
| | 2) `arp -a` |

### 4.2. ICMP (ping)

Системный `ping` через `subprocess` (Windows: `-n 1 -w`, Linux: `-c 1 -W`).
Asyncio-версия: `asyncio.create_subprocess_exec`.

### 4.3. TCP Port Scan

- Синхронный: `socket.connect_ex()` через `ThreadPoolExecutor` (10 workers)
- Асинхронный: `asyncio.open_connection()` с `Semaphore` (50–100 concurrent)
- 31 порт по умолчанию: `COMMON_PORTS` (22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554, 993, 995, 1080, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9090, 9100, 9200, 27017)
- Сервис-мап: `SERVICE_MAP` — ассоциация порт → название сервиса

### 4.4. SNMP v2c (pysnmp)

```
SnmpClient(community="public", timeout=2.0)

.probe(target)              → bool (sysDescr GET)
.discover(target)           → SnmpDevice (sysName, sysDescr, sysLocation, интерфейсы IF-MIB)
.walk(target, base_oid)     → list[(oid, value)] (через nextCmd)
.get_lldp_neighbors(target) → list[(local_port, remote_name, remote_port)]
.get_fdb(target)            → list[(vlan, mac, port)] (Q-BRIDGE-MIB dot1qFdbTable)
.discover_topology(target)  → SnmpTopology (всё сразу)
```

Используемые OID'ы:

| OID | Описание |
|-----|----------|
| `1.3.6.1.2.1.1.1.0` | sysDescr |
| `1.3.6.1.2.1.1.5.0` | sysName |
| `1.3.6.1.2.1.1.6.0` | sysLocation |
| `1.3.6.1.2.1.2.2.1.2.{i}` | ifDescr |
| `1.3.6.1.2.1.2.2.1.8.{i}` | ifOperStatus (1=up) |
| `1.0.8802.1.1.2.1.4.1.1.*` | LLDP-MIB (lldpRemTable) |
| `1.3.6.1.2.1.17.7.1.2.2.1.*` | Q-BRIDGE-MIB (dot1qFdbTable) |

### 4.5. SSH (paramiko)

Используется как fallback для получения MAC-таблиц с коммутаторов:

| Вендор | Команда | Парсер |
|--------|---------|--------|
| Cisco IOS | `show mac address-table` | `_parse_cisco_style()` |
| TP-Link JetStream | `show mac-address` | `_parse_tplink()` |
| MikroTik RouterOS | `/interface bridge host print` | `_parse_mikrotik()` |

`SshClient` — тонкая обёртка над paramiko: `connect()`, `exec_command()`, `close()`.
`get_fdb_ssh()` автоматически перебирает команды, пока не получит результат.

---

## 5. Модель данных

### 5.1. Device

```python
@dataclass
class Device:
    ip: str                          # "192.168.1.1"
    mac: str = ""                    # "aa:bb:cc:dd:ee:ff"
    hostname: Optional[str] = None   # "router.local"
    vendor: Optional[str] = None     # "MikroTik" (из OUI)
    os: Optional[str] = None         # "Linux/Unix" | "Windows" | ...
    device_type: str = "unknown"     # router | switch | server | workstation | printer | ...
    status: str = "online"           # online | offline
    ports: list[Port] = []           # открытые порты
    first_seen: Optional[str] = None # ISO timestamp
    last_seen: Optional[str] = None

    @property
    def id(self) -> str:             # mac если есть, иначе ip
```

### 5.2. Port

```python
@dataclass
class Port:
    port: int                  # 22
    protocol: str = "tcp"     # tcp | udp | snmp
    service: Optional[str] = None  # "SSH", "HTTP", ...
    state: str = "open"       # open | closed | filtered
```

### 5.3. Edge (связь)

```python
@dataclass
class Edge:
    source: str                    # device.id источника
    target: str                    # device.id цели
    edge_type: str = "direct"      # direct | LLDP port X | FDB port Y vlan Z
    latency_ms: Optional[float] = None
```

### 5.4. ScanResult

```python
@dataclass
class ScanResult:
    scan_time: str       # ISO timestamp
    network: str         # "192.168.1.0/24"
    devices: list[Device]
    edges: list[Edge]
```

### 5.5. NetworkInfo

```python
@dataclass
class NetworkInfo:
    interface: str       # "eth0" | "Ethernet"
    ip: str              # "192.168.1.100"
    prefix: int          # 24
    gateway: str         # "192.168.1.1"
    cidr: str            # "192.168.1.0/24"
    description: str     # человекочитаемое имя интерфейса
```

### 5.6. SNMP-специфичные dataclass'ы

```python
SnmpDevice    # sysName, sysDescr, sysLocation, interfaces[]
SnmpInterface # index, name, status ("up"/"down")
LldpNeighbor  # local_port, remote_name, remote_port
MacEntry      # mac, port, vlan
SnmpTopology  # device + lldp_neighbors + mac_table
```

### 5.7. ScanCallbacks (интерфейс)

```python
class ScanCallbacks:
    def on_device_found(self, device: Device): ...
    def on_progress(self, msg: str, pct: int): ...
    def on_complete(self, result: ScanResult): ...
    def on_error(self, msg: str): ...
```

Используется GUI и Web API для получения прогресса в реальном времени.

---

## 6. Web API (FastAPI)

Сервер: `python netmap_web.py --port 8080 --host 0.0.0.0`

### Endpoint'ы

| Метод | Путь | Описание |
|-------|------|----------|
| `GET` | `/` | Статический index.html |
| `GET` | `/static/*` | Статические файлы (CSS, JS) |
| `POST` | `/api/scan` | Запуск сканирования: `?subnet=&scan_type=quick&community=` |
| `GET` | `/api/scan/status` | Прогресс: `running, progress_msg, progress_pct` |
| `GET` | `/api/devices` | Список устройств последнего скана |
| `GET` | `/api/topology` | Граф: устройства + связи |
| `GET` | `/api/networks` | Обнаруженные сети на хосте |
| `GET` | `/api/fdb` | MAC-таблица: `?device_ip=&community=` |
| `GET` | `/api/config` | Текущая конфигурация (токен замаскирован) |
| `POST` | `/api/config` | Сохранение: `{"config": {"telegram_token": "...", ...}}` |
| `POST` | `/api/config/test-telegram` | Тестовое сообщение в Telegram |

### Параметры `/api/scan`

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `subnet` | string | `192.168.1.0/24` | Подсеть в CIDR |
| `scan_type` | string | `quick` | `quick` / `discover` / `deep` / `topology` |
| `community` | string | `public` | SNMP community (для topology) |

Сканирование выполняется в фоне через `BackgroundTasks` + `run_in_executor`.

---

## 7. Алерты и мониторинг

### 7.1. Типы алертов

| Тип | Enum | Важность | Триггер |
|-----|------|----------|---------|
| Новое устройство | `NEW_DEVICE` | INFO 🟢 | IP появился в текущем скане |
| Устройство пропало | `DEVICE_GONE` | WARNING 🔴 | IP исчез из текущего скана |
| Изменение портов | `PORT_CHANGE` | WARNING 🟡 | Набор открытых портов изменился |
| Смена MAC | `MAC_CHANGE` | CRITICAL 🚨 | MAC-адрес изменился (возможен ARP-spoofing) |

### 7.2. Каналы доставки

| Канал | Класс | Назначение |
|-------|-------|------------|
| Console | `ConsoleChannel` | stdout, отладка |
| Telegram | `TelegramChannel` | HTML-сообщения через Bot API |
| Webhook | `WebhookChannel` | POST JSON на HTTP-эндпоинт |

### 7.3. AlertManager

```python
mgr = AlertManager({
    "telegram_token": "...",
    "telegram_chat_id": "...",
    "webhook_url": "https://hooks.example.com/alerts",
    "alert_cooldown_seconds": 300,
    "min_importance": "warning",
})

alerts = mgr.check_and_alert(prev_scan, curr_scan)
```

- Фильтрация по важности (`min_importance`)
- Кулдаун на пару `(тип, IP)` — предотвращает спам
- Все каналы получают алерт параллельно
- `ConsoleChannel` активен всегда

### 7.4. Diff-мониторинг

`monitor_diff(previous, current) → dict`:

```python
{
    "appeared": [...],       # новые устройства
    "disappeared": [...],    # пропавшие
    "changed": [             # изменившиеся (порты)
        {"ip": "10.0.0.1", "prev": [22, 80], "curr": [22, 443]}
    ],
    "previous_count": N,
    "current_count": M,
}
```

### 7.5. SQLite-история (`ScanDB`)

```python
db = ScanDB("netmap.db")

scan_id = db.save_scan(result)           # сохранить скан
db.list_scans(limit=20)                  # список сканов
db.get_scan(scan_id)                     # загрузить скан
db.get_device_history("192.168.1.1")     # история устройства
db.diff_scans(id1, id2)                  # сравнить два скана
db.get_stats()                           # агрегатная статистика
db.delete_scan(scan_id)                  # удалить
db.vacuum()                              # рекламировать место

migrate_json_to_sqlite("scans/")         # миграция JSON → SQLite
```

Схема: `scans`, `devices`, `ports`, `edges` с индексами по IP, MAC, scan_id, scan_time. WAL-режим, внешние ключи, CASCADE-удаление.

### 7.6. Конфигурация (`NetMapConfig`)

```python
from netmap_config import config

config.load()                             # загрузить (кэшируется)
config["telegram_token"]                  # доступ как к словарю
config.update({"snmp_community": "public"})
config.save()                             # сохранить на диск
```

Файл: `~/.netmap_config.json` (или `NETMAP_CONFIG` env var). Автосоздаётся с дефолтами при первом обращении.

Параметры:
- `telegram_token`, `telegram_chat_id` — Telegram Bot API
- `snmp_community` — community string (по умолчанию "public")
- `scan_timeout` — таймаут операций (по умолчанию 5.0 с)
- `alert_cooldown` — кулдаун алертов (по умолчанию 300 с)
- `default_subnet` — подсеть по умолчанию

---

## 8. Платформенные особенности

### 8.1. Обнаружение сетей

| | Linux | Windows |
|---|-------|---------|
| Основной метод | `ip -4 -o addr show` | Win32 `GetAdaptersAddresses` (ctypes) |
| Fallback 1 | — | `netifaces` |
| Fallback 2 | — | `netsh interface ip show addresses` |
| Fallback 3 | — | `ipconfig` |
| Шлюз | `ip -4 route show dev <iface>` | `route print -4` + Win32 GatewayAddress |

### 8.2. ARP

| Linux | Windows |
|-------|---------|
| `ip -4 neigh` | 1) Win32 `GetIpNetTable` |
| `arp -a` | 2) PowerShell `Get-NetNeighbor` → JSON |
| | 3) `arp -a` regex |

### 8.3. Производительность

- **Windows**: субпроцессы ping медленнее из-за overhead создания процессов. Asyncio ускорение ~3–4× против ~8× на Linux.
- **Сборка**: PyInstaller в один `.exe` (включая Python-рантайм, все зависимости, OUI-базу).
- **Консольные окна**: все subprocess-вызовы используют `CREATE_NO_WINDOW` для подавления чёрных окон на Windows.

### 8.4. Ограничения

- **ARP**: только IPv4. IPv6 — через `ip -6 neigh` (Linux), Windows — не реализовано.
- **ICMP**: только через системный `ping` (нет асинхронного ICMP в Python stdlib).
- **SNMP**: только v2c (v3 не реализован).
- **SSH**: только password auth (ключи не поддерживаются).

---

## 9. Зависимости

```
netifaces>=0.11.0    # Определение сетевых интерфейсов
pysnmp>=5.0.0        # SNMP v2c (walk, get, LLDP, FDB)
paramiko>=3.0.0      # SSH (FDB с коммутаторов)
fastapi>=0.100.0     # Web API
uvicorn>=0.20.0      # ASGI сервер
```

Опционально:
- `nmap` — для режима deep (OS detection)
- `PyQt6` — для продвинутого GUI

---

## 10. Сборка и версионирование

```bash
# Windows: PyInstaller в один .exe
python/build_exe.bat
# → python/dist/netmap-v{VERSION}.exe

# Версия хранится в python/VERSION
python bump_version.py {major|minor|patch}
```

Текущая версия: **v0.3.0**.
