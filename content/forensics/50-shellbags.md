---
id: forensics-shellbags
title: "Shellbags, UserAssist, RecentDocs: доказательство работы с папками"
category: forensics
parent: forensics-win-execution
difficulty: hard
order: 3
tags: [shellbags, userassist, recentdocs, registry, windows, dfir, usrclass]
prerequisites: [forensics-windows-artifacts, forensics-registry-hives]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 45
summary: "Как по кустам NTUSER.DAT и UsrClass.dat доказать, что пользователь открывал папки, включая удалённые и съёмные носители, и как читать Shellbags/UserAssist/RecentDocs."
---
Shellbags — один из самых недооценённых артефактов Windows. Они фиксируют, какие папки пользователь открывал в проводнике, даже если папка удалена или находилась на съёмном носителе. Вместе с UserAssist и RecentDocs они доказывают работу с конкретными каталогами и файлами. Этот урок — про кусты NTUSER.DAT и UsrClass.dat и разбор Shellbags/UserAssist/RecentDocs.

## Где живут Shellbags

Shellbags хранятся в кусте **`UsrClass.dat`** (не в NTUSER.DAT!) по пути `Local Settings\Software\Microsoft\Windows\Shell\Bags` и `BagMRU`. Ключи `BagMRU` содержат бинарные **Shell Item ID Lists**, описывающие путь к папке (включая сетевые и съёмные).

```bash
$ ls "$USERPROFILE\AppData\Local\Microsoft\Windows\UsrClass.dat"
# RegRipper: shellbags
$ rip.pl -r UsrClass.dat -p shellbags
```

## Формат Shell Item ID List

Каждый элемент пути — «shell item» с типом: файловая система, MTP-устройство, сетевое расположение, корзина. Для файловых элементов хранятся имя, размер, а часто и MAC-времена целевого объекта.

```bash
# SBECmd (Eric Zimmerman) — удобный парсер
$ SBECmd.exe -d . --csv out --csvf sb.csv
# колонки: Path, LastModified, Created, Accessed, ...
$ grep -i 'removable\|E:\\' out/sb.csv
```

Поле `LastModified`/`LastWrite` ключа даёт время, когда папка просматривалась в последний раз.

## UserAssist

UserAssist (`NTUSER.DAT\...\Explorer\UserAssist`) фиксирует программы и документы, запущенные **через GUI** (двойной клик, меню «Пуск»). Имена ROT13-закодированы, есть счётчик запусков и время последнего.

```bash
$ rip.pl -r NTUSER.DAT -p userassist
UEME_RUNPATH: C:\Tools\mimikatz.exe (3)
UEME_RUNPIDL: C:\Users\bob\Documents\secret.docx (1)
# декодировать ROT13 вручную
$ echo 'P:\GbbY\zvzvxngm.rkr' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
C:\Tools\mimikatz.exe
```

UserAssist не зависит от Prefetch — работает, даже если Prefetch отключён, и остаётся в профиле.

## RecentDocs

`RecentDocs` (`NTUSER.DAT\...\Explorer\RecentDocs`) — последние открытые документы, сгруппированные по расширению, с MRUListEx (порядок) и именами (часто в hex/Unicode).

```bash
$ rip.pl -r NTUSER.DAT -p recentdocs
.doc: secret.docx
.xlsx: budget.xlsx
# + подразделы по расширениям
```

## Другие MRU-артефакты

| Артефакт | Что фиксирует |
|----------|---------------|
| `RecentDocs` | последние документы |
| `TypedPaths` | пути, введённые в адресную строку |
| `TypedURLs` | URL, введённые в IE/Edge |
| `RunMRU` | команды из Win+R |
| `MUICache` | имена запущенных приложений |
| `LastVisitedPidlMRU` | последние папки |
| `ComDlg32` | пути из диалогов «Открыть/Сохранить» |
| `OpenSavePidlMRU` | файлы из диалогов |

```bash
$ rip.pl -r NTUSER.DAT -p typedurls -p typedpaths -p runmru
$ rip.pl -r NTUSER.DAT -p comdlg32
```

## Разобранный пример

Нужно доказать, что пользователь просматривал папку на флешке и запускал программу.

```bash
# 1. Shellbags: папки на E:
$ SBECmd.exe -d . --csv out --csvf sb.csv
$ grep -i 'E:\\' out/sb.csv
E:\backup, LastModified=2024-03-01 12:05:00
E:\backup\secret, LastModified=2024-03-01 12:06:00
# 2. UserAssist: запущенные программы
$ rip.pl -r NTUSER.DAT -p userassist | grep -i evil
UEME_RUNPATH: E:\tools\dump.exe (1)
# 3. RecentDocs: открытые документы
$ rip.pl -r NTUSER.DAT -p recentdocs | grep -i secret
.docx: E:\backup\secret\report.docx
# 4. RunMRU: команды Win+R
$ rip.pl -r NTUSER.DAT -p runmru
powershell -w hidden -c ...
```

Итог: Shellbags (просмотр `E:\backup`), UserAssist (запуск `E:\tools\dump.exe`), RecentDocs (`report.docx`), RunMRU (подозрительная команда) — согласованная картина использования флешки.

## Справочная таблица

| Артефакт | Куст | Инструмент |
|----------|------|-----------|
| Shellbags | `UsrClass.dat` | `SBECmd`, `rip.pl -p shellbags` |
| UserAssist | `NTUSER.DAT` | `rip.pl -p userassist` |
| RecentDocs | `NTUSER.DAT` | `rip.pl -p recentdocs` |
| TypedPaths/URLs | `NTUSER.DAT` | `rip.pl` |
| RunMRU | `NTUSER.DAT` | `rip.pl -p runmru` |
| ComDlg32 | `NTUSER.DAT` | `rip.pl -p comdlg32` |

## Частые ошибки

- **Искать Shellbags в NTUSER.DAT** — они в `UsrClass.dat`.
- **Не декодировать ROT13** в UserAssist.
- **Игнорировать Shellbags** — они доказывают доступ к удалённым/съёмным папкам.
- **Забывать про ComDlg32** — пути из диалогов сохранения файлов.
- **Не учитывать MRUListEx** — он задаёт порядок (что было последним).
- **Считать `UsrClass.dat` «грязным»** — применяйте транзакционный журнал.

## Что дальше / решение

Конвейер: `SBECmd` (Shellbags) → `rip.pl -p userassist` → `rip.pl -p recentdocs` → ComDlg32/RunMRU → сведение с LNK/USB-артефактами. Связка: `forensics-registry-hives` (кусты), `forensics-usb-devices` (USB), `forensics-lnk` (ярлыки), `forensics-windows-execution` (запуск).

## Сведение Shellbags с другими артефактами

Shellbags сами по себе доказывают лишь «просмотр папки». Силу им придаёт корреляция:

- **С USB-артефактами**: путь `E:\backup` + `MountedDevices` (Volume Serial) + LNK → доказательство использования конкретной флешки.
- **С LNK**: Shellbags показывает навигацию, LNK — открытие файла; вместе — полная картина.
- **С UserAssist/RecentDocs**: что запускалось/открывалось в найденных папках.
- **С MFT/USN**: если файл копировался на диск, остаются следы.

```bash
# путь из Shellbags + серийник тома из MountedDevices
$ SBECmd.exe -d . --csv out --csvf sb.csv
$ grep -i 'E:\\' out/sb.csv
$ rip.pl -r SYSTEM -p mountdev | grep -i 'DosDevices\\E:'
# сопоставить время просмотра папки с LNK-записью файла
$ LECmd.exe -d Recent --csv out --csvf lnk.csv
$ grep -i 'E:\\backup' out/lnk.csv
```

## Разбор `UsrClass.dat` и «грязных» кустов

`UsrClass.dat` часто остаётся «грязным» (не сброшен на диск), особенно при снятии с живой системы или из снапшота. Тогда транзакционные журналы (`UsrClass.dat.LOG1`/`.LOG2`) содержат незакоммиченные изменения, включая свежие Shellbags.

```bash
$ ls UsrClass.dat*
UsrClass.dat  UsrClass.dat.LOG1  UsrClass.dat.LOG2
# применить журналы (yarp/hivex) или взять куст из теневой копии
$ python3 yarp.py UsrClass.dat
```

Если Shellbags «пусты», проверьте теневые копии (`System Volume Information`) — там старые версии кустов с историей.

## Справочная таблица путей

| Артефакт | Точный путь в кусте |
|----------|---------------------|
| BagMRU | `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` |
| Bags | `Local Settings\Software\Microsoft\Windows\Shell\Bags` |
| UserAssist | `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` |
| RecentDocs | `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` |
| TypedPaths | `...\Explorer\TypedPaths` |
| RunMRU | `...\Explorer\RunMRU` |
| ComDlg32 | `...\Explorer\ComDlg32\OpenSavePidlMRU` |

## Ограничения

- **Shellbags — это «просмотр», а не «открытие»** файла; не путайте с LNK.
- **Сетевые пути** (UNC) хранятся иначе, чем локальные.
- **Несколько SID** — если в системе несколько пользователей, разбирайте `UsrClass.dat` каждого профиля.
- **Время `LastWrite`** ключа — момент последнего изменения, а не обязательно «последнего просмотра».
- **Win10+** структура Bags изменилась — используйте свежие версии парсеров.

## Практическое замечание по инструментам

`SBECmd` (Eric Zimmerman) — самый удобный и поддерживаемый парсер Shellbags: он выдаёт CSV с путями, временами и флагами (удалённый/съёмный). Для быстрого разбора одного куста используйте `rip.pl -r UsrClass.dat -p shellbags`, а для глубокого — комбинацию `SBECmd` + `ShellBagsExplorer` (GUI). Всегда разбирайте Shellbags **вместе** с UserAssist и RecentDocs: первые доказывают просмотр папок, вторые — запуск программ и открытие файлов, и только совместно они дают полную картину действий пользователя.

## Краткое резюме

Shellbags — это «карта навигации» пользователя: какие папки он открывал, включая удалённые и на съёмных носителях, с временем последнего просмотра. UserAssist показывает запущенные через GUI программы, RecentDocs — открытые документы, а TypedPaths/RunMRU/ComDlg32 добавляют введённые пути и команды. Вместе с LNK и USB-артефактами они позволяют доказать доступ к конкретным данным на конкретном носителе в конкретное время — фундамент доказательной базы в DFIR.

## Квиз

```quiz
- question: "В каком кусте реестра лежит основная часть Shellbags?"
  options:
    - "NTUSER.DAT"
    - "UsrClass.dat (Software\\Classes\\Local Settings)"
    - "SYSTEM"
    - "SAM"
  answer: 1
  explanation: "Основной путь начинается с Software\\Classes\\Local Settings, а он относится к UsrClass.dat."
- question: "Каким преобразованием закодированы имена в UserAssist?"
  options:
    - "Base64"
    - "ROT13"
    - "XOR"
    - "Hex"
  answer: 1
- question: "Что доказывают Shellbags, если папка уже удалена?"
  options:
    - "что папка существовала, но не что её открывали"
    - "что пользователь открывал эту папку в проводнике"
    - "что папка была на USB"
    - "пароль пользователя"
  answer: 1
- question: "Какой артефакт хранит пути, введённые вручную в адресную строку проводника?"
  options:
    - "RecentDocs"
    - "TypedPaths"
    - "RunMRU"
    - "UserAssist"
  answer: 1
- question: "Почему отсутствие записи в Shellbags НЕ доказывает, что папку не открывали?"
  options:
    - "запись всегда удаляется антифорензикой"
    - "Shellbags кэшируется только для GUI-навигации, а не для cd в консоли"
    - "Shellbags хранится в памяти"
    - "запись шифруется"
  answer: 1
```

## Где пригодится

- **CTF:** задачи, где нужно доказать работу с удалённой папкой или подключённым USB.
- **DFIR:** восстановление навигации злоумышленника по файловой системе.
- **Threat Hunting:** поиск обращения к сетевым шарам и админ-каталогам.
- **Судебная экспертиза:** доказательство доступа к конфиденциальным каталогам.
- **Криминалистика носителей:** связь папки с конкретным съёмным диском по GUID тома.
