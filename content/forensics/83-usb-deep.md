---
id: forensics-usb-deep
title: "Форензика USB и устройств глубоко"
category: forensics
parent: forensics-usb-devices
difficulty: hard
order: 1
tags: [usb, usbstor, mountdevices, setupapi, usbforensics, windows, dfir]
prerequisites: [forensics-usb-devices, forensics-registry-hives]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Корпоративные расследования"
estimated_minutes: 50
summary: "Глубокий анализ подключений USB: USBSTOR, MountedDevices, setupapi.dev.log, Volume Serial, связь устройства с LNK/Shellbags и восстановление истории использования носителей."
---
Глубокий анализ USB-подключений отвечает на ключевые вопросы расследования: какое устройство подключалось, когда, к какому порту и какие файлы с него копировались. Windows фиксирует это в нескольких независимых источниках, и их корреляция даёт доказуемую картину. Этот урок — про USBSTOR, MountedDevices, setupapi.dev.log, Volume Serial и связь с LNK/Shellbags.

## USBSTOR и Enum

`SYSTEM\CurrentControlSet\Enum\USBSTOR` — главный источник по накопителям: вендор, модель, **серийный номер**, время первого/последнего подключения.

```bash
$ rip.pl -r SYSTEM -p usb
USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00
  S/N: 4C530001120523116345
  First Install: 2024-02-10 09:00:00
  Last Connected: 2024-03-01 12:00:00
```

Различайте `Enum\USB` (само устройство/интерфейс) и `Enum\USBSTOR` (накопители). MTP-устройства (телефоны) — в `WpdBusEnumRoot`.

```bash
$ rip.pl -r SYSTEM -p usbdevices
$ hivexregedit --export SYSTEM '\ControlSet001\Enum\USBSTOR' usbstor.reg
```

## MountedDevices и Volume Serial

`SYSTEM\MountedDevices` сопоставляет букву диска с идентификатором тома, содержащим **Volume Serial Number** — ключ к связыванию буквы с конкретным USB.

```bash
$ rip.pl -r SYSTEM -p mountdev
\DosDevices\E: -> dmio:ID... Serial: 4C53-0001
\??\Volume{...} -> ...
```

Volume Serial уникален для тома и совпадает с тем, что хранится в LNK/Jump Lists — по нему связывают файл с носителем.

## setupapi.dev.log

`C:\Windows\INF\setupapi.dev.log` — текстовый лог установки драйверов с точным временем (до секунды), серийным номером и устройством.

```bash
$ grep -iA5 'USBSTOR' setupapi.dev.log | head -30
>>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_SanDisk...]
>>>  Section start 2024/03/01 12:00:03.123
```

Логи ротируются (`.log`, `.log1`); старые записи могут быть в предыдущих файлах.

## События EVTX

| Event ID | Лог | Смысл |
|----------|-----|-------|
| 20001 | DriverFrameworks-UserMode | подключение PnP |
| 20003 | DriverFrameworks-UserMode | отключение |
| 6416 | Security | новое устройство |
| 2100/2102 | PnP | установка драйвера |

```bash
$ evtx_dump -o json System.evtx | jq 'select(.Event.System.EventID==20001) | .Event.EventData'
$ EvtxECmd.exe -f System.evtx --csv out --csvf system.csv && grep -i usbstor out/system.csv
```

## Связь с LNK и Shellbags

**LNK** хранит путь целевого файла, Volume Serial и Drive Type — доказывает открытие файла с носителя. **Shellbags** (`UsrClass.dat`) — просмотр папок носителя. **Jump Lists** — недавние документы приложения.

```bash
$ LECmd.exe -d Recent --csv out --csvf lnk.csv
$ grep -i 'E:\\' out/lnk.csv
secret.docx, E:\backup\secret.docx, Volume Serial: 4C53-0001, Drive: Removable
$ SBECmd.exe -d . --csv out --csvf sb.csv && grep -i 'E:' out/sb.csv
$ JLECmd.exe -d AutomaticDestinations --csv out --csvf jl.csv
```

Совпадение Volume Serial в LNK и MountedDevices — прямое доказательство связи файла с конкретной флешкой.

## Первый/последний раз и уникальность

USBSTOR хранит время первого и последнего подключения; setupapi — точные моменты; EVTX — каждое подключение/отключение. Сопоставляя, восстанавливают полную историю использования. Серийник USBSTOR генерируется драйвером и может быть подделан прошивкой (дешёвые флешки с одинаковым S/N) — учитывайте это.

## Разобранный пример

Нужно доказать копирование данных на флешку.

```bash
# 1. Устройство
$ rip.pl -r SYSTEM -p usb | grep -A3 USBSTOR
USBSTOR\Disk&Ven_SanDisk... S/N 4C530001120523116345
  Last Connected: 2024-03-01 12:00:00
# 2. Буква и серийник
$ rip.pl -r SYSTEM -p mountdev | grep 'DosDevices\\E:'
\DosDevices\E: ... Serial 4C53-0001
# 3. Точное время
$ grep -iA3 'USBSTOR' setupapi.dev.log | grep 'Section start'
>>>  Section start 2024/03/01 12:00:03.123
# 4. Файлы с носителя
$ LECmd.exe -d Recent --csv out --csvf lnk.csv && grep -i 'E:\\' out/lnk.csv
secret.docx, E:\backup\secret.docx, Volume Serial: 4C53-0001
# 5. Навигация
$ SBECmd.exe -d . --csv out --csvf sb.csv | grep -i 'E:'
```

Итог: флешка SanDisk подключена в 12:00:03, буква E: (Serial 4C53-0001), с неё открыт `secret.docx` — доказано.

## Справочная таблица

| Артефакт | Расположение | Даёт |
|----------|-------------|------|
| USBSTOR | `Enum\USBSTOR` | модель+серийник+время |
| USB | `Enum\USB` | интерфейс |
| MountedDevices | SYSTEM | буква↔серийник |
| setupapi.dev.log | INF | точное время |
| LNK | Recent | файл+серийник |
| Shellbags | UsrClass.dat | просмотр папок |
| EVTX | System | события |

## Частые ошибки

- **Путать USB и USBSTOR** — накопители только в USBSTOR.
- **Не связывать букву с серийником** — нужен MountedDevices.
- **Игнорировать setupapi** — точное время только там.
- **Забывать про LNK/Shellbags** — доказательство использования.
- **Считать серийник USBSTOR серийником тома** — это разные вещи.
- **Не учитывать несколько подключений** — времена разные.

## Что дальше / решение

Конвейер: `rip.pl -p usb` (USBSTOR) → `mountdev` (буква↔серийник) → `setupapi.dev.log` (время) → `LECmd`/`SBECmd` (использование) → EVTX (события). Связка: `forensics-usb-devices` (основы), `forensics-registry-hives` (кусты), `forensics-lnk` (ярлыки), `forensics-shellbags`.

## Сложные случаи и восстановление

- **Виртуальные USB** (RDP-проброс, `usbip`) — нет «физического» серийника; ищите артефакты в `TerminalServices`.
- **MTP-устройства** (телефоны) — в `WpdBusEnumRoot`, а не USBSTOR.
- **Внешние HDD/SSD** — могут попадать в `Enum\SCSI` вместо USBSTOR.
- **Удалённые ключи USBSTOR** — восстанавливаются из unallocated/теневых копий.
- **Подделанный серийник** — дешёвые флешки с одинаковым S/N; коррелируйте с временем.

```bash
# восстановить удалённый USBSTOR из теневой копии
$ vshadowmount disk.img /mnt/vss
$ hivexregedit --export /mnt/vss/.../SYSTEM '\ControlSet001\Enum\USBSTOR' old_usb.reg
$ grep -i USBSTOR old_usb.reg
# поиск в unallocated
$ blkls -o 2048 disk.img | strings | grep -i 'USBSTOR\\Disk'
```

## Полная цепочка доказательства

1. **Устройство**: USBSTOR — модель, серийник, первое/последнее подключение.
2. **Буква**: MountedDevices — Volume Serial.
3. **Время**: setupapi.dev.log + EVTX 20001/6416.
4. **Использование**: LNK (файл+серийник), Shellbags (папки), Jump Lists (документы).
5. **Копирование**: если файлы копировались на диск — MFT/USN; если с диска — LNK/Recent.
6. **Связь**: совпадение Volume Serial во всех источниках.

## Сводный чек-лист

1. `rip.pl -p usb` — USBSTOR (модель+серийник+время).
2. `rip.pl -p mountdev` — буква↔Volume Serial.
3. `setupapi.dev.log` — точное время.
4. EVTX 20001/6416 — события подключения.
5. `LECmd` — файлы с носителя.
6. `SBECmd` — просмотр папок.
7. Восстановить удалённые ключи (теневые копии).
8. Свести в единую цепочку.

## Ограничения

- **Серийник может быть подделан** прошивкой.
- **setupapi ротируется** — старые записи утеряны.
- **Win10+** пишет меньше в USBSTOR.
- **Буквы переиспользуются** — одна `E:` = разные носители в разное время.
- **MTP/виртуальные** — иные артефакты.

## Краткое резюме

USB-форензика строится на корреляции независимых источников: USBSTOR (модель и серийник), MountedDevices (буква ↔ Volume Serial), setupapi.dev.log (точное время), EVTX (события подключения), LNK/Jump Lists/Shellbags (какие файлы и папки использовались). Совпадение Volume Serial во всех источниках доказывает связь файла с конкретной флешкой. Учитывайте подделку серийников и ротацию логов; удалённые ключи восстанавливайте из теневых копий и unallocated.

## Квиз

```quiz
- question: "Какой реестровый ключ хранит модели и серийники USB-накопителей?"
  options:
    - "SAM"
    - "SYSTEM\\...\\Enum\\USBSTOR"
    - "SECURITY"
    - "SOFTWARE"
  answer: 1
- question: "Что связывает флешку с открытыми на ней файлами?"
  options:
    - "PID"
    - "Volume Serial Number (VSN)"
    - "VID"
    - "буква диска"
  answer: 1
- question: "Какой лог даёт точное время первого подключения устройства?"
  options:
    - "setupapi.dev.log"
    - "auth.log"
    - "EVTX Security"
    - "prefetch"
  answer: 0
- question: "Где хранятся буквы дисков, к которым обращался пользователь?"
  options:
    - "MountedDevices"
    - "MountPoints2 (NTUSER.DAT)"
    - "SAM"
    - "USBSTOR"
  answer: 1
- question: "Чем серийный номер устройства отличается от Volume Serial?"
  options:
    - "это одно и то же"
    - "серийник — у устройства, VSN — у тома (при форматировании)"
    - "VSN у USB, серийник у диска"
    - "оба не существуют"
  answer: 1
```

## Где пригодится

- **CTF:** задачи «с какой флешки скопировали данные».
- **DFIR:** доказательство подключения и использования носителей.
- **Корпоративные расследования:** выявление утечек через USB.
- **Threat Hunting:** аномальные подключения устройств.
- **Судебная экспертиза:** связка USB ↔ файлы через VSN.
