# NetMap — Roadmap (обновлён 25 мая)

## ✅ Готово

- [x] **Rust CLI** — --quick, --ping, --fdb, --topology, --deep (Linux ✅)
- [x] **FDB модуль** — SNMP walk Q-BRIDGE + BRIDGE-MIB
- [x] **Ping sweep** — параллельный (до 64 хостов)
- [x] **C# прототип** — ARP + SNMP + веб-сервер, один .exe (15 КБ)
- [x] **Python прототип** — stdlib, ARP + SNMP + Web (7 КБ)
- [x] **Документация** — AUDIT, USER-FLOW, ROADMAP, ARCHITECTURE
- [x] **Rust на Linux** — работает идеально (den-PC, 3 устройства)
- [x] **VS 2022** установлен, Rust toolchain есть (MSVC и GNU)

## 🔴 Блокеры

- [ ] **Сборка Rust на Windows** — GNU нет dlltool, MSVC link.exe краш (нужен repair VS)
- [ ] **Python на Windows** — установщик скачан, ждёт ручной установки

## 🟡 Основные фичи

- [ ] **LLDP topology** — протестировать BFS на живом свитче, отрисовать SVG-граф
- [ ] **SSH-fallback для FDB** — для свитчей без BRIDGE-MIB (T2600G)
- [ ] **FDB в C#/Python прототипах** — сейчас только в Rust
- [ ] **OUI-база** — MAC → Vendor офлайн

## 🟢 Интерфейс

- [ ] **Tauri/Svelte** — нативный десктоп вместо прототипов
- [ ] **Граф топологии** — SVG сейчас, WebGL для 100+ узлов
- [ ] **Command Palette, Timeline Slider, Slide-over**

## 🔵 Данные

- [ ] **SQLite** — история сканов
- [ ] **Diff** — сравнение снапшотов
- [ ] **Экспорт** — CSV, JSON, Draw.io
