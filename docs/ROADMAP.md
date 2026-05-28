# NetMap — Roadmap (май 2026)

## v0.1 — Прототип ✅ DONE
- [x] Документация и спецификация
- [x] Структура проекта
- [x] SVG-иконки (8 типов устройств)
- [x] ARP-скан, ICMP ping, TCP port check
- [x] OUI-парсер (производитель по MAC)
- [x] PowerShell CLI (Windows)

## v0.2 — Сетевые протоколы ✅ DONE
- [x] SNMP v2c discovery (sysName, sysDescr)
- [x] ARP + TCP/UDP + SNMP сканирование
- [x] Автоопределение сети
- [x] Сохранение результатов в JSON
- [x] SSH FDB: Cisco IOS, TP-Link, MikroTik
- [x] Asyncio-сканер (5-8× быстрее потоков)

## v0.3 — Мониторинг и топология 🟡 В ПРОЦЕССЕ
- [x] Мониторинг изменений (diff: появился/пропал/изменился)
- [x] Сохранение истории состояний
- [x] Web-интерфейс (FastAPI + HTML/JS/Canvas)
- [x] GUI-граф (tkinter canvas: drag, zoom, pan)
- [x] Интерактивный граф в Web (Canvas)
- [ ] SNMP LLDP-топология (BFS-обход соседей) — 🟡 код написан, не тестирован
- [ ] SNMP FDB/MAC-таблица → карта портов (сейчас только SSH)
- [ ] SQLite вместо JSON (история сканов)
- [ ] Периодический авто-запуск (cron/systemd)
- [ ] Алерты при изменениях (Telegram/email)
- [ ] Автоматическое построение топологии
- [ ] Группировка устройств по локациям

## v0.5 — Продвинутые возможности
- [ ] SNMP v3 (аутентификация и шифрование)
- [ ] nmap интеграция (OS detection)
- [ ] Wi-Fi survey (беспроводные сети)
- [ ] Экспорт топологии (PNG, SVG, draw.io)
- [ ] Cable Health:
  - [ ] Cable diagnostics через SNMP/SSH (MikroTik, Cisco, TP-Link)
  - [ ] TDR-тест: длина кабеля, обрыв, КЗ
  - [ ] SFP DOM: температура, напряжение, RX/TX power
  - [ ] CRC-ошибки и коллизии (IF-MIB + dot3 MIB)
  - [ ] Дуплекс-mismatch детектор
  - [ ] Port Health Score (0-100)

## v1.0 — Релиз
- [ ] Кроссплатформенный CLI (Python, упакованный в exe/bin)
- [ ] Web-интерфейс (HTML/JS/Canvas)
- [ ] Пакеты: Windows (.msi), Linux (.deb/.AppImage), macOS
- [ ] Автообновление
- [ ] Документация и справка
