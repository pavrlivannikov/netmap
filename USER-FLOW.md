# NetMap — Архитектура и UX (v2, пересмотрено с учётом Qwen)

## Стек

Rust (scanner, SNMP, topology, FDB, diff) + Svelte/Tauri (UI) + SQLite (история)

## Ключевые решения

- **SNMP-community — спрашивать, не брутфорсить.** Поле ввода + чекбокс «Try public, private» (выключен по умолчанию). Импорт из Ansible/Zabbix/CSV.
- **Граф >100 узлов — WebGL/Canvas** (pixi.js или regl), не SVG.
- **Хранение — SQLite** через rusqlite. История сканов, diff, офлайн-first.
- **Svelte stores** — единый источник правды, Tauri events обновляют реактивно.

---

## First-Run Experience

1. Авто-определение интерфейса с default gateway
2. Если интерфейсов >1 — карточки выбора (IP, маска, имя адаптера)
3. Пока админ смотрит — фоновый Quick Scan (ARP + Ping) уже идёт
4. Поле SNMP community + чекбокс «Try common» (выключен)
5. Импорт из CSV/Ansible/Zabbix

---

## Режимы сканирования

| Режим | Время | Сценарий | Что делает |
|-------|-------|----------|-----------|
| **Quick** | 10–30 сек | «Кто в сети?» | ARP + Ping |
| **Standard** | 1–3 мин | Ежедневная инвентаризация | ARP + SNMP (system, interfaces) + LLDP |
| **Deep Audit** | 5–15 мин | Документирование | Полный SNMP walk + FDB + VLAN mapping + Port status |
| **Monitor** | Непрерывно | Дежурный | Периодический опрос ключевых OID |

⚠️ Deep Audit: прогресс-бар с **Pause/Resume**.

---

## Визуализация

### Topology View (LLDP)
- Иерархический граф: коммутаторы = крупные узлы, хосты = кластеры вокруг порта
- Цвета: зелёный=up, оранжевый=high load, красный=down/error
- Drag, zoom, click→details

### FDB Matrix View
- Где этот MAC? Таблица: VLAN | MAC | IP | Switch | Port | Last Seen
- Фильтрация и поиск в реальном времени (Svelte stores)

### Subnet Cards
- Карточки подсетей с мини-графиком заполненности
- Список неизвестных устройств

### Device Detail Slide-over
- Выезжающая панель справа (не модальное окно!)
- hostname, vendor (OUI), open ports, SNMP sysDescr, история изменений
- Топология остаётся видимой

---

## Diff и изменения

### Timeline Slider
- Внизу экрана — временная шкала сканов
- Перетаскивание ползунка переключает топологию между сканами
- Мощнее статичной таблицы diff

### Цветовая семантика
- 🟢 Зелёная обводка/пульсация: новое устройство
- 🔴 Красная обводка: исчезнувшее
- 🟡 Жёлтая подсветка: изменился параметр (IP, порт, VLAN)

### Change Feed
- Боковая панель/тост: «[+10:32] New: 192.168.1.55 (HP Printer) on SW-Core:Gi1/0/24»
- Кликабельно — ведёт к устройству
- Экспорт diff между сканами в CSV/JSON

---

## Горячие клавиши (keyboard-first)

| Клавиша | Действие |
|---------|----------|
| `Ctrl+K` | Command Palette (устройства, команды, настройки) |
| `Space` | Quick Rescan выделенного узла/подсети |
| `F` | Фокус в поиск |
| `D` | Toggle Diff Mode |
| `1-4` | Переключение: Discover / Topology / FDB / Monitor |
| `Esc` | Закрыть панель / отменить скан |
| `Ctrl+Shift+C` | Копировать IP/MAC/Port в буфер |

---

## Сценарии использования

### 🚀 Первый запуск
1. Открыл → видит eth0 (192.168.1.0/24) авто-определён
2. Ввёл community `netmon2024`, галочка «Also try public», Start Discovery
3. Через 15 сек: 47 устройств, 3 свитча по LLDP, хосты сгруппированы
4. Клик по свитчу → панель: модель, uptime, CPU
5. Неизвестное устройство → Space → рескан → IP-камера по OUI

### 📅 Ежедневно
1. Утром Change Feed: «2 new, 1 offline»
2. Клик по offline → принтер в бухгалтерии, порт SW-Access-3:Fa0/12
3. FDB View (клавиша 4), фильтр по VLAN 20, проверка MAC
4. Deep Audit перед работами, пауза в обед
5. Экспорт топологии в SVG для отчёта

### 🔍 Инцидент
1. Жалоба на медленную сеть → Monitor View
2. Gi1/0/48 мигает жёлтым (high errors)
3. Timeline Slider → отмотка на 2 часа назад → ошибка после нового AP
4. Ctrl+Shift+C → копировать инфо → идти к стойке

---

## Архитектура Rust

```
scanner/       ARP, Ping sweep, SNMP walk
topology/      LLDP BFS, graph algorithms
fdb/           MAC table (SNMP + SSH fallback)
diff/          State comparison между сканами
storage/       SQLite через rusqlite
api/           Tauri commands → Svelte frontend
```

- tokio для асинхронного сканирования
- Параллельный ping sweep с семафором
- SSH-fallback для свитчей без SNMP MIB (russh/ssh2)

---

## Выбор сети (адаптация к 5+ интерфейсам)

При множестве интерфейсов — компактные карточки:

```
┌──────────────────┐  ┌─────────────────┐  ┌──────────────┐
│ Ethernet0        │  │ Wi-Fi           │  │ VPN           │
│ 192.168.96.222   │  │ 192.168.1.5     │  │ 10.8.0.10     │
│ /21  ▸ default   │  │ /24             │  │ /24           │
│ Realtek PCIe     │  │ Intel AX200     │  │ TAP-Windows   │
└──────────────────┘  └─────────────────┘  └──────────────┘
```

- Карточка с default gateway подсвечена
- Клик по карточке = выбрать для сканирования
- Кнопка «Scan All» = последовательно все интерфейсы
- Ручной ввод CIDR через поле ввода
