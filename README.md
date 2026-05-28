# NetMap — кросс-платформенный сетевой анализатор

Сканирование сети, мониторинг изменений, построение топологии. Три режима работы: CLI, GUI, Web.

---

## Возможности

| Протокол | Что делает |
|----------|------------|
| **ARP** | Обнаружение устройств в локальной сети (IP → MAC) |
| **ICMP (ping)** | Проверка доступности, параллельный свип до 256 хостов |
| **SNMP v2c** | sysName, sysDescr, LLDP-соседи, FDB/MAC-таблица коммутаторов |
| **SSH FDB** | MAC-таблица через CLI: Cisco IOS, TP-Link JetStream, MikroTik RouterOS |
| **TCP-порты** | Сканирование 31 порта на хост, определение сервисов |
| **OUI** | Определение производителя по MAC (39 461 запись IEEE) |
| **Diff / Monitor** | Кто появился, кто пропал, что изменилось |

---

## Быстрый старт

```bash
# Установка зависимостей
pip install -r requirements.txt

# Web-интерфейс (рекомендуется)
python netmap_web.py --port 8080
# → Открыть http://localhost:8080

# CLI: быстрый скан
python netmap_scanner.py --quick

# GUI (tkinter)
python netmap_gui.py
```

**Зависимости:** `netifaces`, `pysnmp`, `paramiko`, `fastapi`, `uvicorn`

---

## Три способа использования

### 1. CLI (`netmap_scanner.py`)
```
--quick         ARP-скан (< 5 сек)
--discover      ARP + ping sweep + TCP-порты (1-3 мин)
--deep          Всё + nmap OS detection (5-15 мин)
--topology      SNMP LLDP + FDB (1-5 мин)
--monitor       Авто-повтор с diff и алертами
--output FILE   Сохранить в JSON
```

### 2. GUI (`netmap_gui.py`)
- Десктопное приложение на tkinter
- Граф топологии с drag/zoom/pan
- Контекстное меню на устройствах
- Авто-мониторинг с алертами
- Экспорт/импорт JSON

### 3. Web (`netmap_web.py`)
- FastAPI + HTML/JS/Canvas (встроенный Web UI)
- REST API: `/api/scan`, `/api/devices`, `/api/topology`
- Интерактивный граф в браузере
- Работает на Linux, Windows, macOS

---

## Архитектура

Проект на Python, 11 модулей:

| Модуль | Назначение |
|--------|------------|
| `netmap_device.py` | Dataclass'ы: Device, Port, Edge, ScanResult |
| `netmap_utils.py` | Хелперы: подсети, hostname, OUI, ping, шлюз |
| `netmap_discovery.py` | Обнаружение сетей, ARP-скан, ping-свип |
| `netmap_async.py` | Asyncio-сканер (в 5-8× быстрее потоков) |
| `netmap_snmp.py` | SNMP v2c: sysName, sysDescr, LLDP, FDB |
| `netmap_ssh.py` | SSH FDB: Cisco, TP-Link, MikroTik |
| `netmap_scanner.py` | Фасад: quick, discover, deep, topology, monitor |
| `netmap_monitor.py` | Diff-движок, сравнение снапшотов |
| `netmap_gui.py` | Tkinter GUI |
| `netmap_web.py` | FastAPI + Web UI |
| `oui_data.py` | OUI-база: 39K+ записей IEEE |

Веб-фронтенд: чистый HTML/JS/Canvas (один файл `static/index.html`, без node_modules).

---

## SNMP

- **Версия:** SNMP v2c
- **Community:** настраиваемый (по умолчанию `public`)
- **Таймаут:** 0.5 сек на устройство

**Собираемые данные:**
- `sysName` (.1.3.6.1.2.1.1.5) — hostname
- `sysDescr` (.1.3.6.1.2.1.1.1) — описание / ОС
- **LLDP** (1.0.8802.1.1.2.1.4.1.1) — прямые связи между устройствами
- **FDB** (Q-BRIDGE-MIB + BRIDGE-MIB) — MAC-таблица коммутатора

---

## SSH FDB

Резервный метод получения MAC-таблицы для устройств без BRIDGE-MIB:

| Вендор | Команда |
|--------|---------|
| Cisco IOS | `show mac address-table` |
| TP-Link JetStream | `show mac-address` |
| MikroTik RouterOS | `/interface bridge host print` |

---

## Мониторинг и Diff

```python
from netmap_monitor import monitor_diff
diff = monitor_diff(previous_scan, current_scan)
# diff['appeared']  — новые устройства
# diff['disappeared'] — пропавшие
# diff['changed']   — изменившиеся (MAC, порты, статус)
```

---

## Планы

- [ ] **Cable Health** — диагностика кабелей (TDR, SFP DOM, CRC-ошибки)
- [ ] **LLDP-топология** — автоматическое построение графа связей
- [ ] **SNMP v3** — аутентификация и шифрование
- [ ] **nmap-интеграция** — OS detection через nmap
- [ ] **Wi-Fi survey** — беспроводные сети
- [ ] **Пакеты:** Windows (.msi), Linux (.deb/.AppImage), macOS
- [ ] **SQLite** — история сканов

Подробнее: [docs/ROADMAP.md](docs/ROADMAP.md)

---

## Версия

**v0.3.0** — май 2026
