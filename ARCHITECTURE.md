# NetMap — Информационная архитектура

## Принцип: 4 зоны, не одна куча

| Зона | Ответ на вопрос |
|------|----------------|
| **Discover** | Что существует? |
| **Monitor** | Что изменилось? |
| **Topology** | Как связано? |
| **FDB** | Где именно воткнуто? |

## Sidebar

```
OVERVIEW
 🏠 Dashboard
 📡 Activity Feed

DISCOVERY
 🔍 Discover
 🖧 Inventory

TOPOLOGY
 🌐 Topology Map
 🔀 FDB Mapping

MONITORING
 📈 Monitor (Diff)
 📶 Ping Monitor
 🔌 Port Monitor
 🚨 Alerts

OPERATIONS
 ⏱ Scheduled Jobs
 ⬆⬇ Import / Export
 🧬 Baselines

CONFIGURATION (свёрнуто)
 🧪 Scan Profiles
 🔐 SNMP Credentials
 📲 Notifications
 🛠 Settings
```

## Topbar
```
[NetMap] | 10.0.0.0/16 | [Поиск...] | [Discover] [Export] | ●●●
```

## Горячие клавиши
`g d` Discover | `g t` Topology | `g m` Monitor | `g a` Alerts | `/` Поиск

## Приоритет реализации
1. FDB Mapping (MAC→Port→Switch)
2. Auto-discovery (Scheduled Jobs)
3. Export Draw.io
4. CSV Import
5. SNMP v3
6. Telegram Alerts
7. Ping/Port Monitor
