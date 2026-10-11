---
id: forensics-usb-devices
title: "USB и device forensics: следы подключений устройств"
category: forensics
parent: forensics-win-registry
difficulty: medium
order: 4
tags: [usb, usbstor, setupapi, lnk, devices, registry, dfir]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Криминалистика (утечки на носители)"
estimated_minutes: 40
summary: "Как восстановить историю подключения USB-устройств: реестр USBSTOR, SetupAPI, LNK-файлы, MountPoints и привязка файлов к конкретной флешке."
---
История подключения USB-устройств — один из самых востребованных артефактов: она доказывает, что конкретная флешка подключалась к системе, и позволяет связать с ней скопированные файлы. Windows фиксирует это в нескольких местах реестра и в логах. Этот урок — про USBSTOR, SetupAPI, MountedDevices, LNK-файлы и привязку файлов к конкретному носителю.

## USBSTOR: реестр подключений

Главный источник — ключ `SYSTEM\CurrentControlSet\Enum\USBSTOR`. Для каждого USB-накопителя там есть запись с производителем, моделью и **серийным номером**, а также время первого и последнего подключения.

```bash
$ rip.pl -r SYSTEM -p usb
USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00
  S/N: 4C530001120523116345
  First Install: 2024-02-10 09:00:00
  Last Connected: 2024-03-01 12:00:00
```

Структура ключа: `USBSTOR\Disk&Ven_<Vendor>&Prod_<Product>&Rev_<Rev>\<Serial>`. Серийный номер уникален — по нему связывают все последующие артефакты.

## USB и USBSTOR vs USB

- `Enum\USB` — само устройство (интерфейс USB).
- `Enum\USBSTOR` — именно **накопители** (mass storage).
- `Enum\SCSI` — внешние диски, подключённые иначе.
- `Enum\WpdBusEnumRoot` — MTP-устройства (телефоны).

```bash
$ rip.pl -r SYSTEM -p usbdevices
$ hivexregedit --export SYSTEM '\ControlSet001\Enum\USBSTOR' usbstor.reg
```

## MountedDevices и Volume Serial

`MountedDevices` (`SYSTEM\MountedDevices`) сопоставляет букву диска (`\DosDevices\E:`) с бинарным идентификатором тома, содержащим **Volume Serial Number**. Это связывает букву с конкретным USB-накопителем.

```bash
$ rip.pl -r SYSTEM -p mountdev
\DosDevices\E: -> dmio:ID... Serial: 4C53-0001
```

## setupapi.dev.log

`C:\Windows\INF\setupapi.dev.log` — текстовый лог установки драйверов устройств. Содержит точное время подключения, серийный номер и имя устройства, часто с точностью до секунды.

```bash
$ grep -iA5 'USBSTOR' setupapi.dev.log | head -30
>>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer...]
>>>  Section start 2024/03/01 12:00:03.123
```

Этот лог — отличное подтверждение времени подключения.

## LNK и привязка файлов

Ярлыки (`.lnk`) в `Recent` содержат не только путь целевого файла, но и **серийный номер тома** и MAC-времена — по ним видно, что файл был на съёмном носителе и когда открывался. Jump Lists аналогичны.

```bash
$ LECmd.exe -d Recent --csv out --csvf lnk.csv
$ grep -i 'E:\\' out/lnk.csv
```

Поле `Volume Serial Number` в LNK-записи связывает файл с конкретным USB (из `MountedDevices`/`USBSTOR`).

## Shellbags и папки на носителе

Shellbags (`UsrClass.dat`) фиксируют просмотр папок, включая удалённые и на съёмных носителях, с временем доступа. Вместе с LNK они доказывают навигацию по флешке.

```bash
$ SBECmd.exe -d . --csv out --csvf sb.csv
```

## Сводная таблица артефактов

| Артефакт | Расположение | Что даёт |
|----------|-------------|----------|
| USBSTOR | `Enum\USBSTOR` | модель + серийник + время |
| USB | `Enum\USB` | интерфейс устройства |
| MountedDevices | `SYSTEM` | буква ↔ серийник тома |
| setupapi.dev.log | `INF\` | точное время установки |
| LNK | `Recent` | файл на носителе + серийник |
| Jump Lists | `AutomaticDestinations` | недавние файлы |
| Shellbags | `UsrClass.dat` | просмотр папок |
| EVTX | System | события подключения (20001/20003) |

## Разобранный пример

Нужно доказать, что злоумышленник скопировал данные на флешку.

```bash
# 1. Найти подключённый USB
$ rip.pl -r SYSTEM -p usb
USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer ... S/N 4C530001120523116345
  Last Connected: 2024-03-01 12:00:00
# 2. Буква диска и серийник тома
$ rip.pl -r SYSTEM -p mountdev | grep -i dosdevices
\DosDevices\E: ... Serial 4C53-0001
# 3. Точное время из setupapi
$ grep -iA3 'USBSTOR' setupapi.dev.log | grep 'Section start'
>>>  Section start 2024/03/01 12:00:03.123
# 4. Файлы, открытые с E:
$ LECmd.exe -d Recent --csv out --csvf lnk.csv
$ grep -i 'E:\\' out/lnk.csv
secret.docx, E:\backup\secret.docx, Volume Serial: 4C53-0001
# 5. Навигация по папкам
$ SBECmd.exe -d . --csv out --csvf sb.csv | grep -i 'E:'
```

Итог: флешка SanDisk подключена в 12:00:00, буква E:, с неё открыт `secret.docx` — привязка файла к носителю доказана.

## Частые ошибки

- **Путать USB и USBSTOR** — накопители только в USBSTOR.
- **Не проверять MountedDevices** — без него не связать букву с серийником.
- **Игнорировать setupapi.dev.log** — самое точное время подключения.
- **Забывать про LNK/Shellbags** — они доказывают использование носителя.
- **Считать серийник USBSTOR серийником тома** — это разные идентификаторы.
- **Не учитывать несколько подключений** — серийник повторяется, а времена — нет.

## Что дальше / решение

Конвейер: `rip.pl -p usb` (USBSTOR) → `mountdev` (буква↔серийник) → `setupapi.dev.log` (время) → `LECmd`/`SBECmd` (использование файлов). Связка: `forensics-usb-deep` (глубоко), `forensics-registry-hives` (кусты), `forensics-lnk` (ярлыки), `forensics-shellbags` (папки).

## События EVTX о подключении

Кроме реестра, подключения устройств фиксируются в журналах событий:

| Event ID | Лог | Смысл |
|----------|-----|-------|
| 20001 | Microsoft-Windows-DriverFrameworks-UserMode | подключение PnP-устройства |
| 20003 | DriverFrameworks-UserMode | отключение |
| 6416 | Security | новое устройство распознано |
| 2100/2102 | PnP | установка драйвера |

```bash
$ evtx_dump -o json System.evtx | jq 'select(.Event.System.EventID==20001)' | head
$ EvtxECmd.exe -f System.evtx --csv out --csvf system.csv
$ grep -i usbstor out/system.csv
```

Событие 20001 содержит `InstanceId` вида `USBSTOR\Disk&Ven_...&Serial`, что связывает его с записью в реестре и даёт точное время.

## Привязка файлов к носителю в деталях

Ключевой вопрос — «какие файлы скопированы на эту флешку». Ответ собирается из нескольких источников:

1. **LNK в `Recent`** — файлы, открытые с носителя, с Volume Serial.
2. **Jump Lists** — недавние документы приложения (например, Word).
3. **Shellbags** — навигация по каталогам носителя.
4. **MFT/USN** — если файлы копировались на диск с флешки, остаются следы.
5. **Prefetch** — «Files referenced» может содержать пути с буквой съёмного диска.

```bash
# LNK: файлы с E: и серийником
$ LECmd.exe -d Recent --csv out --csvf lnk.csv
$ grep -i 'E:\\' out/lnk.csv
# Jump Lists
$ JLECmd.exe -d AutomaticDestinations --csv out
# Shellbags
$ SBECmd.exe -d . --csv out --csvf sb.csv
$ grep -i 'E:' out/sb.csv
```

Volume Serial Number из LNK (`4C53-0001`) совпадает с `MountedDevices`, что доказывает связь файла именно с этим USB-накопителем, а не с любым диском.

## Практические ограничения

- **Серийник USBSTOR** генерируется драйвером и может быть подделан прошивкой (дешёвые флешки с одинаковым S/N).
- **setupapi.dev.log** ротируется (`.log`, `.log1`…); старые записи могут быть утеряны.
- **Windows 10+** меньше пишет в USBSTOR (использует `USB` и `WpdBusEnumRoot`).
- **Буквы дисков** переиспользуются; одна буква `E:` может соответствовать разным носителям в разное время.
- **Виртуальные USB** (RDP-проброс, `usbip`) не оставляют «физического» серийника.
- **MTP-устройства** (телефоны) фиксируются иначе, чем mass-storage.

## Пример полного отчёта

Итоговая реконструкция: «2024-03-01 12:00:03 устройство SanDisk Cruzer (S/N 4C530001120523116345) подключено (setupapi + USBSTOR + Event 20001), получило букву E: (MountedDevices, Volume Serial 4C53-0001); с него открыт `E:\backup\secret.docx` (LNK, Volume Serial совпадает); пользователь просматривал каталог `E:\backup` (Shellbags)». Такая связка из независимых источников — стандарт доказывания в DFIR.

## Квиз

```quiz
- question: "Какой ключ хранит вендора/продукт/серийник USB-носителя?"
  options:
    - "`MountedDevices`"
    - "`Enum\USBSTOR`"
    - "`SAM`"
    - "`Run`"
  answer: 1
- question: "Где фиксируется время ПЕРВОГО подключения USB?"
  options:
    - "в `setupapi.dev.log`"
    - "в `SAM`"
    - "в Prefetch"
    - "в SRUM"
  answer: 0
- question: "Что связывает букву диска с устройством?"
  options:
    - "`USBSTOR`"
    - "`MountedDevices`"
    - "`NTUSER.DAT`"
    - "`EVTX`"
  answer: 1
- question: "Какие артефакты доказывают работу с файлами на флешке?"
  options:
    - "только Prefetch"
    - "LNK и Shellbags"
    - "SAM"
    - "MFT"
  answer: 1
- question: "Зачем нужен серийный номер USB-устройства?"
  options:
    - "для сжатия"
    - "для привязки файлов/действий к конкретному носителю"
    - "для шифрования"
    - "для удаления"
  answer: 1
```

## Где пригодится

- **CTF:** задачи «следы флешки».
- **DFIR:** расследование утечек данных на носители.
- **Криминалистика:** доказательство подключения устройства.
- **Корпоративная безопасность:** контроль неавторизованных носителей.
- **Threat Hunting:** выявление перемещения данных.
