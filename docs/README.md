# NetMap 🦊

Универсальный кроссплатформенный сетевой анализатор.

## Возможности

| Режим | Команда | Описание |
|-------|---------|----------|
| 🔍 Quick | `--quick` | ARP — все устройства в L2 (< 1 сек) |
| 📡 Discover | `--discover` | + UDP + SNMP имена |
| 🔬 Deep | `--deep` | + порты + nmap OS |
| 🗺️ Topology | `--topology` | + LLDP + MAC table |
| 📊 Monitor | `--monitor` | мониторинг изменений |

## Установка

### Linux
```bash
cargo build --release
./target/release/netmap --discover
```

### Windows (PowerShell)
```powershell
powershell -File scripts/netmap-auto.ps1
```

## Стек

| Слой | Linux | Windows |
|------|-------|---------|
| Язык | Rust | PowerShell |
| SNMP | snmp2 library | Raw UDP |
| GUI | Tauri + Svelte | Tauri (WebView2) |
| Графы | Cytoscape.js | JSON export |

## Пример

```bash
$ netmap --discover
NetMap v0.3
Network: 192.168.99.0/21
ARP: 235 devices
UDP: 106 alive
SNMP: 48 devices
  T2600G-52TS @ DESNA3
  MikroTik NikNik, otd kad, Arch...
```

## Структура

```
netmap/
├── src/              # Svelte UI
├── src-tauri/        # Rust backend
│   └── src/
│       ├── scanner.rs   # ARP/ICMP/TCP/UDP
│       ├── snmp.rs      # SNMP v2c + LLDP
│       ├── lib.rs       # Tauri API
│       └── main.rs      # CLI entry
├── scripts/          # PowerShell (Windows)
├── docs/             # Документация
└── release/          # Сборки
```

## Лицензия

MIT
