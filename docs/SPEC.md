# NetMap — Техническая спецификация v0.3

## 1. Обзор

NetMap — кроссплатформенный сетевой анализатор. Режимы: quick, discover, deep, topology, monitor.

### Принципы
- **Лёгкость**: бинарник < 20 МБ, RAM < 100 МБ
- **Скорость**: ARP мгновенно, UDP sweep /21 за < 5 мин
- **Автономность**: работает БЕЗ интернета, всё локально
- **Изолированные сети**: не требует онлайн-зависимостей (WebView2 встроен, OUI база embedded)
- **Кроссплатформенность**: Linux (Rust), Windows (PowerShell)

## 2. Архитектура

```
┌──────────────────────────────────────────────────────┐
│                    CLI / GUI                          │
│  --quick  --discover  --deep  --topology  --monitor  │
├──────────────────────────────────────────────────────┤
│              Discovery Layer                          │
│  ARP │ UDP(53,137,161) │ ICMP │ TCP │ mDNS/LLMNR     │
├──────────────────────────────────────────────────────┤
│             Identification Layer                      │
│  SNMP sysName │ MAC OUI │ nmap OS │ NetBIOS name    │
├──────────────────────────────────────────────────────┤
│               Topology Layer                          │
│  LLDP walk │ SNMP MAC table │ Traceroute │ STP root  │
├──────────────────────────────────────────────────────┤
│              Monitoring Layer                         │
│  Diff scan │ Interface counters │ Latency │ Alerts   │
├──────────────────────────────────────────────────────┤
│                Export Layer                           │
│  JSON │ CSV │ Graphviz DOT │ PNG/SVG │ Markdown      │
└──────────────────────────────────────────────────────┘
```

## 3. Режимы сканирования

| Режим | Флаг | Протоколы | Время | Результат |
|-------|------|-----------|-------|-----------|
| Quick | `--quick` | ARP | < 1 сек | IP + MAC |
| Discover | `--discover` | ARP + UDP + SNMP | ~2 мин | + sysName + порты |
| Deep | `--deep` | всё + nmap OS | ~10 мин | + ОС + все порты |
| Topology | `--topology` | + LLDP + MAC table | ~5 мин | + связи |
| Monitor | `--monitor` | diff + alert | периодически | изменения |

## 4. SNMP v2c через библиотеку snmp2

```rust
SnmpClient::new("public")
    .discover(ip)           // sysName + sysDescr + ports
    .walk_lldp(ip)          // lldpRemTable → соседи
    .walk_mac_table(ip)     // dot1qFdbTable → MAC → порт
```

## 5. PowerShell (Windows fallback)

Скрипты в `scripts/`:
- `netmap-auto.ps1` — автоопределение + ARP + порты + SNMP
- `netmap-udp-scan.ps1` — UDP параллельный скан /21
- `netmon.ps1` — мониторинг изменений
- `snmp-discover.ps1` — детальный SNMP опрос

## 6. Модель данных

```typescript
interface Device {
  ip: string; mac: string;
  name?: string; descr?: string; location?: string;
  type: "router"|"switch"|"server"|"workstation"|"printer"|"iot"|"unknown";
  ports?: number[]; os?: string;
}

interface Edge {
  source: string; target: string;
  type: "lldp"|"mac_table"|"traceroute"|"arp";
  src_port?: number; dst_port?: number;
}
```

## 7. Платформенные особенности

| | Linux | Windows |
|---|-------|---------|
| Основной код | Rust CLI (native) | PowerShell + Rust cross |
| SNMP | snmp2 library | Raw UDP + snmp2 |
| GUI | Tauri (Xvfb) | Tauri (WebView2) |
| Мониторинг | systemd timer | Task Scheduler |
