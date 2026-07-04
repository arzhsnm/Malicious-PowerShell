# 🔍 Malicious PowerShell — Forensics Linear Quest: Task 3

> DFIR-расследование компрометации хоста **RD01** в домене **shieldbase.com**.
> Полный разбор: 25 вопросов, PowerShell-команды, найденные артефакты.

[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)]()
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE?logo=powershell&logoColor=white)]()
[![Status](https://img.shields.io/badge/status-completed-brightgreen)]()

---

## 📑 Оглавление

- [Часть 0. Подготовка среды](#часть-0-подготовка-среды)
- [Часть 1. PowerShell Operational Log (Q1–Q9)](#часть-1-powershell-operational-log)
- [Часть 2. PowerShell-транскрипты (Q10–Q12)](#часть-2-powershell-транскрипты)
- [Часть 3. Microsoft Defender (Q13–Q19)](#часть-3-microsoft-defender)
- [Часть 4. Суперталайм-лайн (Q20–Q25)](#часть-4-суперталайм-лайн)
- [Итоговая реконструкция](#итоговая-реконструкция-инцидента)

---

## Часть 0. Подготовка среды

### Распаковка архива

```powershell
tar -xzvf rteam_task.tar.gz
```

Появляются: `rd01-triage.vhdx` (образ диска, ~5.9 ГБ) и `host-full-timeline.csv` (суперталайм-лайн, ~100 МБ).

### Монтирование VHDX (без Hyper-V, через diskpart)

```powershell
diskpart
```
```
select vdisk file="C:\triage\rd01-triage.vhdx"
attach vdisk readonly
list volume
exit
```

> ⚠️ **Проблема с кириллицей:** `diskpart` не находит файл, если путь содержит кириллические символы (например, `C:\Users\Аружан\...`). Решение — скопировать образ в путь без кириллицы:
> ```powershell
> New-Item -ItemType Directory -Path "C:\triage" -Force
> Copy-Item "C:\Users\<имя>\Downloads\...\rd01-triage.vhdx" -Destination "C:\triage\rd01-triage.vhdx"
> ```

Образу присвоена буква **D:**. Проверка структуры:

```powershell
Get-ChildItem D:\
```

Корень образа содержит вложенную папку `C\`, все пути далее начинаются с `D:\C\...` (например `D:\C\Windows\System32\...`).

---

## Часть 1. PowerShell Operational Log

Журнал: `D:\C\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`

```powershell
$log = "D:\C\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
```

### Q1 — Даты Warning-событий с "encoded" (false positive)

```powershell
$events = Get-WinEvent -Path $log |
    Where-Object { $_.Message -match "encoded" -and $_.LevelDisplayName -eq "Warning" }

$events | Select-Object TimeCreated, Id, LevelDisplayName | Sort-Object TimeCreated | Format-Table -AutoSize
$events | Group-Object { $_.TimeCreated.Date } | Select-Object Name, Count | Sort-Object Name

# проверка источника шума
$events | ForEach-Object {
    [PSCustomObject]@{ Date = $_.TimeCreated; IsChocolatey = $_.Message -match "chocolatey" }
} | Format-Table -AutoSize
```

**Ответ:** 02.10.2022, 12.10.2022, 14.10.2022, 20.10.2022, 21.10.2022, 12.11.2022 — все являются шумом от **Chocolatey Package Manager** (легитимный менеджер пакетов, использует `-EncodedCommand` в служебных целях).

---

### Q2 — Что дают Information-события с "encoded"

```powershell
$infoEvents = Get-WinEvent -Path $log |
    Where-Object { $_.Message -match "encoded" -and $_.LevelDisplayName -eq "Information" }
$infoEvents.Count   # -> 4

$infoEvents | ForEach-Object { $_.Message }
```

**Ответ:** раскрывают полный контекст выполнения — Host Application (командная строка с `-EncodedCommand`), User, Engine Version, Runspace ID.

---

### Q3 — Пользователь и дата закодированных команд

```powershell
$infoEvents | Select-Object TimeCreated, @{N='SID';E={$_.UserId}}
```

**Ответ:** `shieldbase\tdungan`, дата **25.01.2023**, ~19:57:22.

---

### Q4 — Декодирование Base64

```powershell
[System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String("ZwBlAHQALQBkAGEAdABlAA==")
)
```

**Ответ:** `get-date` — тестовый запуск механизма EncodedCommand.

---

### Q5 — Фильтр "invoke" + дата после 2023-01-01

```powershell
$invokeEvents = Get-WinEvent -Path $log |
    Where-Object { $_.Message -match "invoke" -and $_.TimeCreated -gt (Get-Date "2023-01-01") }

$invokeEvents.Count   # -> 906
$invokeEvents | Measure-Object -Property TimeCreated -Minimum -Maximum

$invokeEvents | Group-Object { $_.UserId } | Sort-Object Count -Descending
$invokeEvents | Group-Object { $_.TimeCreated.Date } | Sort-Object Count -Descending | Select-Object -First 10
```

**Найдено:** явный выброс — 18.01.2023, 870 из 906 событий, SID `S-1-5-21-2838623409-1327563992-2591358621-1220`.

---

### Q6 — Пользователь, связанный с большинством событий

Попытки резолва SID через реестр и NTFS ACL **не сработали**:

```powershell
# Попытка 1: reg load (куст повреждён при копировании)
Copy-Item "D:\C\Windows\System32\config\SOFTWARE" -Destination "C:\triage\SOFTWARE_copy"
reg load HKLM\OfflineSAM "C:\triage\SOFTWARE_copy"
# ERROR: The configuration registry database is corrupt.

# Попытка 2: Get-Acl (показывает встроенную группу Administrators образа, а не SID пользователя)
Get-Acl "D:\C\Users\rsydow-a" | Select-Object -ExpandProperty Owner
Get-Acl "D:\C\Users\tdungan" | Select-Object -ExpandProperty Owner
# -> O:S-1-5-21-159748157-2665083705-1129654168-500 (одинаково для всех папок)
```

**Рабочий метод** — напрямую из текста события (поле `User = domain\username`):

```powershell
$cluster = $invokeEvents | Where-Object {
    $_.UserId -eq "S-1-5-21-2838623409-1327563992-2591358621-1220" -and
    $_.TimeCreated.Date -eq (Get-Date "2023-01-18").Date
}
$cluster | Where-Object { $_.Message -match "User = " } |
    Select-Object -First 1 -ExpandProperty Message
```

**Ответ:** `shieldbase\wacsvc`.

---

### Q7 — Временной диапазон и его значение

```powershell
$cluster.Count
$cluster | Measure-Object -Property TimeCreated -Minimum -Maximum
```

**Ответ:** ~870 событий сжаты в окно ~11 секунд на каждом хосте — признак **автоматизированного скрипта/фреймворка**, а не ручного ввода.

---

### Q8 — Атакующие команды

```powershell
$cluster | Where-Object { $_.Message -match "CommandInvocation" } | Select-Object -First 10 -ExpandProperty Message
```

**Найдено (recon через Invoke-Command):**
- `net localgroup administrators`
- `net user`
- `net share`
- `ipconfig /all`, `netstat -nao`
- `tasklist /v`, `systeminfo`, `quser`
- `cmd.exe /c where /r C:\Users *.xls*` (а также `*.doc*`, `*.ppt*`, `*.pdf`, `*.lnk`, `*.url`)

---

### Q9 — Разведка на удалённых системах (-ComputerName)

```powershell
$cluster | Where-Object { $_.Message -match "-ComputerName" } | Select-Object -ExpandProperty Message
```

**Ответ:** разведка проводилась минимум на **четырёх** хостах домена:

| Хост | Роль |
|---|---|
| `exchange01.shieldbase.com` | Почтовый сервер |
| `file01.shieldbase.com` | Файловый сервер |
| `dc01.shieldbase.com` | Контроллер домена |
| `wac01.shieldbase.com` | *(обнаружен дополнительно)* |

```powershell
# доп. проверка по wac01
$cluster | Where-Object { $_.Message -match "wac01" } | Select-Object -ExpandProperty Message
Get-ChildItem "D:\C\Windows\Update" -Recurse -Filter "*wac01*"
```

На `dc01` дополнительно получен полный список пользователей домена, включая `krbtgt` и `SRLAdmin` (Domain/Enterprise Admins).

---

## Часть 2. PowerShell-транскрипты

### Q10 — Транскрипты wacsvc

```powershell
Get-ChildItem "D:\C\Users\wacsvc\Documents" -Directory
$wacsvcTranscripts = Get-ChildItem "D:\C\Users\wacsvc\Documents" -Filter "PowerShell_transcript*" -Recurse
$wacsvcTranscripts.Count
```

**Ответ:** 1 день — **17.01.2023**, всего **113 файлов**.

---

### Q11 — Транскрипты tdungan

```powershell
Get-ChildItem "D:\C\Users\tdungan\Documents" -Directory
$tdunganTranscripts = Get-ChildItem "D:\C\Users\tdungan\Documents" -Filter "PowerShell_transcript*" -Recurse
$tdunganTranscripts.Count
$tdunganTranscripts | Select-Object Name, LastWriteTime | Sort-Object LastWriteTime
```

**Ответ:** 2 файла, за 2 дня — **23.01.2023** и **25.01.2023**.

---

### Q12 — Содержимое транскриптов tdungan ("Access is denied")

```powershell
Get-Content "D:\C\Users\tdungan\Documents\20230123\PowerShell_transcript.RD01.bi2wuUVL.20230123101935.txt"
Get-Content "D:\C\Users\tdungan\Documents\20230125\PowerShell_transcript.RD01.2vQx+75A.20230125095722.txt"
```

**23.01.2023** (через Microsoft Edge): `Invoke-Command {cmd.exe /c netsh winhttp show proxy} -ComputerName wkstn01.shieldbase.com` → **"Access is denied"** (PSRemotingTransportException).

**25.01.2023**: сессия с `-EncodedCommand`, выполняющая только `get-date` (см. Q4).

---

## Часть 3. Microsoft Defender

```powershell
$defenderLog = "D:\C\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx"
$threats = Get-WinEvent -Path $defenderLog | Where-Object { $_.Id -in 1116,1117,1118,1119 }
$threats.Count   # -> 23
```

### Q13 — Преобладающее семейство вредоносного ПО

```powershell
$threats | ForEach-Object { $_.Message } | Select-String "Behavior:\S+" -AllMatches |
    ForEach-Object { $_.Matches.Value } | Group-Object | Sort-Object Count -Descending
```

**Ответ:** `Behavior:Win32/CobaltStrike.E!sms` (14/23). Также `VirTool:Win32/Kekeo.B` и `Trojan:Win32/PowerRunner.A` (оба через AMSI в `msedge.exe`).

---

### Q14 — Пути вредоносных процессов (мин. 4)

```powershell
$threats | ForEach-Object {
    $msg = $_.Message
    [PSCustomObject]@{
        Time = $_.TimeCreated
        ThreatName = ($msg | Select-String "Name:\s*(.+)").Matches[0].Groups[1].Value
        Path = ($msg | Select-String "Path:\s*(.+)").Matches[0].Groups[1].Value
        Process = ($msg | Select-String "Process Name:\s*(.+)").Matches[0].Groups[1].Value
    }
} | Format-Table -Wrap
```

- `C:\Windows\System32\SRLUpdate.exe` — маячок Cobalt Strike, персистентность через задачу "SRL User Maintenance"
- `C:\Windows\explorer.exe` — process injection
- `C:\Windows\System32\svchost.exe` — process injection (самое раннее, 24.01.2023)
- `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` — AMSI-детект

---

### Q15 — MPDetection log (4 записи DETECTION)

```powershell
$mpDetectionPath = "D:\C\ProgramData\Microsoft\Windows Defender\Support\MPDetection-20230123-095120.log"
Get-Content $mpDetectionPath | Select-String "DETECTION" -Context 2,2
```

| Дата/время UTC | DETECTION |
|---|---|
| 2023-01-24T00:51:58.218Z | CobaltStrike.E!sms — svchost.exe, pid:2376 |
| 2023-01-25T00:41:10.327Z | CobaltStrike.E!sms — explorer.exe, pid:8544 |
| 2023-01-25T00:41:16.599Z | CobaltStrike.E!sms — SRLUpdate.exe, pid:6976 |
| 2023-01-25T00:41:57.075Z | CobaltStrike.E!sms — taskscheduler: SRL User Maintenance |

---

### Q16 — STUN.exe в MPLog

```powershell
Get-ChildItem "D:\C\ProgramData\Microsoft\Windows Defender\Support" -Filter "MPLog*"
Select-String -Path "...\MPLog-20230121-192504.log" -Pattern "STUN.exe" | Select-Object -First 5
```

**Ответ:** самая ранняя запись — `2023-01-22T02:25:04.260Z`.

---

### Q17 — Два пути werfault.exe

```powershell
Get-ChildItem "D:\C" -Filter "werfault.exe" -Recurse -Force
Select-String -Path "...\MPLog-20230121-192504.log" -Pattern "werfault" -SimpleMatch
```

- `\\dev01.shieldbase.com\c$\windows\services\werfault.exe`
- `c:\windows\update\werfault.exe`

---

### Q18 — Оригинальное имя werfault.exe

```powershell
# из MPLog:
# Engine:Setting original file name "sdelete.exe" for "...\werfault.exe", hr=0x0
```

**Ответ:** `sdelete.exe`

---

### Q19 — Описание sdelete.exe

Файл, замаскированный под `werfault.exe`, на самом деле — переименованная копия **SDelete** (Sysinternals/Microsoft), утилиты безвозвратного удаления файлов путём многократной перезаписи. Используется атакующими как **анти-форензик инструмент** для уничтожения улик. Расположение в `C:\Windows\Update` указывает, что именно там зачищались следы собранной разведки.

---

## Часть 4. Суперталайм-лайн

```powershell
$timeline = Import-Csv "host-full-timeline.csv"
$timeline.Count   # -> 104009
$updateEvents = $timeline | Where-Object { $_.short -match "windows\\update" }
$updateEvents.Count   # -> 195
```

### Q20 — Фильтр "windows\update"

**Ответ:** 195 событий — директория оказалась **staging area** атакующего.

---

### Q21 — Кто открыл C:\Windows\Update

```powershell
$updateEvents | Where-Object { $_.sourcetype -match "Windows Shortcut" } | Format-List *
```

**Ответ:** все LNK/jump-list записи ссылаются на профиль **wacsvc**.

---

### Q22 — Ранее существовавшие подпапки

- `rd01, rd02, rd03, rd04, rd09` — скомпрометированные рабочие станции
- `rec` — папка результатов разведки

---

### Q23 — Файлы в C:\Windows\Update\rec

- `dc01.shieldbase.com.txt` (1 194 264 байт)
- `dev01.shieldbase.com.txt` (874 531 байт)

---

### Q24 — Последняя модификация + связанный ключ реестра

```powershell
$bodyfileUpdate = $timeline | Where-Object { $_.sourcetype -eq "Bodyfile" -and $_.short -match "windows\\update$" }
$bodyfileUpdate | Select-Object date, time, MACB, short, desc | Format-List

$targetTime = [datetime]"2023-01-23 18:54:54"
$nearby30 = $timeline | Where-Object {
    $eventTime = [datetime]"$($_.date) $($_.time)"
    [Math]::Abs(($eventTime - $targetTime).TotalMinutes) -le 30
}
$nearby30 | Where-Object { $_.source -eq "REG" } | Select-Object date, time, short, desc | Format-List
```

**Найдено:** `[\Software\Sysinternals\SDelete] EulaAccepted: 1` (18:45:50) — за ~9 минут до финальной модификации папки (18:54:54). Подтверждает: SDelete был запущен именно в `C:\Windows\Update` для зачистки следов.

---

### Q25 — Создание профиля wacsvc + вход по RDP

```powershell
$wacsvcProfile = $timeline | Where-Object { $_.short -match "Users\\wacsvc$" -and $_.sourcetype -eq "Bodyfile" }
$wacsvcProfile | Select-Object date, time, MACB, short, desc | Format-List
# -> Birth (B): 01/17/2023 14:43:03

$profileTime = [datetime]"2023-01-17 14:43:03"
$logonNearby = $timeline | Where-Object {
    $eventTime = [datetime]"$($_.date) $($_.time)"
    [Math]::Abs(($eventTime - $profileTime).TotalMinutes) -le 5 -and $_.source -eq "EVT"
}
$logonNearby | Where-Object { $_.short -match "4624" } | Format-List *
```

| Параметр | Значение |
|---|---|
| Дата/время | 17.01.2023 14:43:03 UTC |
| Пользователь | `shieldbase\wacsvc` |
| Logon Type | **10** (RemoteInteractive / RDP) |
| IP-адрес источника | **172.16.6.18** |
| Пакет аутентификации | Kerberos / Negotiate |

---

## Итоговая реконструкция инцидента

```
17.01.2023 14:43  →  RDP-вход wacsvc с внутреннего IP 172.16.6.18 (Logon Type 10)
17.01.2023 14:57  →  Создание C:\Windows\Update (staging area)
17.01.2023 14:43–19:00  →  Массовая разведка (Invoke-Command) на
                            exchange01 / file01 / dc01 / wac01.shieldbase.com
21–25.01.2023      →  Закрепление Cobalt Strike (SRLUpdate.exe, задача
                       планировщика "SRL User Maintenance")
23.01.2023         →  Неудачная попытка RDP на wkstn01 (tdungan) +
                       anti-forensics: SDelete под видом werfault.exe
25.01.2023         →  PowerRunner (загрузчик) + Kekeo (кража Kerberos-тикетов)
```

**Тип инцидента:** целенаправленная компрометация домена с элементами APT / red-team операции, использующая типичный набор пост-эксплуатационных инструментов (Cobalt Strike, Kekeo, SDelete).

---

## ⚠️ Дисклеймер

Учебный CTF/DFIR-квест (rteam), выполнен в образовательных целях. Все IP-адреса и домен `shieldbase.com` принадлежат смоделированной лабораторной среде.
