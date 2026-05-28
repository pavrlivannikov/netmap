# NetMap Monitor — авто-мониторинг сети

Автоматический периодический мониторинг сети: сканирование ARP → сравнение с предыдущим состоянием → алерты при изменениях.

## Состав

| Файл | Назначение |
|------|-----------|
| `netmap-monitor.sh` | Скрипт-обёртка (Linux/macOS) |
| `netmap-monitor.service` | systemd user-сервис |
| `netmap-monitor.timer` | systemd таймер (каждые 5 мин) |
| `netmap-monitor.ps1` | PowerShell-скрипт (Windows) |

## Логика работы

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│ scan_quick() │ ──▶ │ save JSON    │ ──▶ │ monitor_diff │
│ (ARP-скан)   │     │ scan_TS.json │     │ prev ↔ curr  │
└─────────────┘     └──────────────┘     └──────┬───────┘
                                          есть изменения?
                                         /              \
                                       ДА                НЕТ
                                      /                    \
                            ┌──────────────┐         ┌──────────┐
                            │ AlertManager │         │  OK, log │
                            │ → Telegram   │         └──────────┘
                            │ → Console    │
                            └──────────────┘
                                    │
                            ┌──────────────┐
                            │ Rotate JSON  │
                            │ (keep 10)    │
                            └──────────────┘
```

## Установка (Linux / systemd)

### 1. Копируем файлы

```bash
# Сервис и таймер — в пользовательский systemd
mkdir -p ~/.config/systemd/user
cp deploy/netmap-monitor.service ~/.config/systemd/user/
cp deploy/netmap-monitor.timer   ~/.config/systemd/user/

# Скрипт остаётся в проекте (путь прописан в .service)
# Убедись, что он исполняемый:
chmod +x deploy/netmap-monitor.sh
```

### 2. Проверяем конфиг

Убедись, что `~/.netmap_config.json` содержит нужные параметры:

```json
{
  "default_subnet": "192.168.1.0/24",
  "telegram_token": "123456:ABC-DEF",
  "telegram_chat_id": "-1003555063823",
  "alert_cooldown": 300
}
```

Если файла нет — он создастся автоматически при первом запуске с дефолтными значениями.

### 3. Включаем и запускаем

```bash
systemctl --user daemon-reload
systemctl --user enable netmap-monitor.timer
systemctl --user start  netmap-monitor.timer
```

### 4. Проверяем

```bash
# Статус таймера
systemctl --user status netmap-monitor.timer

# Когда следующий запуск
systemctl --user list-timers netmap-monitor.timer

# Лог последнего запуска
journalctl --user -u netmap-monitor.service -n 40

# Ручной запуск (для отладки)
systemctl --user start netmap-monitor.service
```

### 5. Логи мониторинга

Логи пишутся в:
- `journalctl` — systemd journal
- `data/monitor.log` — текстовый лог в проекте

Сканы сохраняются в `data/scan_YYYYMMDD_HHMMSS.json` (последние 10).

### 6. Остановка

```bash
systemctl --user stop    netmap-monitor.timer
systemctl --user disable netmap-monitor.timer
```

### 7. Lingering (чтобы таймер работал без логина)

Если нужно, чтобы мониторинг работал даже когда пользователь не в системе:

```bash
sudo loginctl enable-linger $USER
```

## Установка (Windows / Task Scheduler)

### 1. Требования

- Python 3.10+ с установленными зависимостями (`pip install -r python/requirements.txt`)
- Либо используйте скомпилированный `.exe` из `python/dist/`

### 2. Импорт задачи через PowerShell (от администратора)

```powershell
$Action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"C:\Users\paveladmin\projects\netmap\deploy\netmap-monitor.ps1`""

$Trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration ([TimeSpan]::MaxValue)

$Principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive `
    -RunLevel Limited

$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName "NetMap Monitor" `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description "NetMap network change monitor — every 5 minutes"
```

### 3. Проверка

```powershell
# Статус задачи
Get-ScheduledTask -TaskName "NetMap Monitor" | Format-List *

# Ручной запуск
Start-ScheduledTask -TaskName "NetMap Monitor"

# История запусков
Get-ScheduledTaskInfo -TaskName "NetMap Monitor"

# Логи
Get-Content C:\Users\paveladmin\projects\netmap\data\monitor.log -Tail 30
```

### 4. Удаление

```powershell
Unregister-ScheduledTask -TaskName "NetMap Monitor" -Confirm:$false
```

## Переменные окружения

| Переменная | Назначение | По умолчанию |
|-----------|-----------|-------------|
| `NETMAP_DATA_DIR` | Директория для JSON-сканов и логов | `$PROJECT/data` |
| `NETMAP_CONFIG` | Путь к конфигурационному JSON | `~/.netmap_config.json` |
| `NETMAP_LOG_FILE` | Путь к лог-файлу | `$DATA_DIR/monitor.log` |

## Типы детектируемых изменений

| Тип | Важность | Описание |
|-----|---------|----------|
| 🟢 NEW_DEVICE | info | Новое устройство в сети |
| 🔴 DEVICE_GONE | warning | Устройство пропало из сети |
| 🟡 PORT_CHANGE | warning | Изменились открытые порты |
| 🚨 MAC_CHANGE | critical | Сменился MAC-адрес (возможен ARP-spoofing) |

## Отладка

```bash
# Локальный запуск без systemd
cd ~/projects/netmap
./deploy/netmap-monitor.sh

# С указанием своего subnet
NETMAP_DATA_DIR=/tmp/netmap-test ./deploy/netmap-monitor.sh

# Посмотреть сканы
ls -la data/scan_*.json
cat data/scan_$(date +%Y%m%d)*.json | python3 -m json.tool | head -30
```
