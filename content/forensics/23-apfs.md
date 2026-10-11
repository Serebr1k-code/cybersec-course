---
id: forensics-apfs
title: "APFS и артефакты macOS"
category: forensics
parent: forensics-fs-internals
difficulty: hard
order: 4
tags: [apfs, macos, hfs, plist, time-machine, apfs-fuse]
prerequisites: [forensics-filesystems]
useful_for:
  - "CTF Forensics категория"
  - "Анализ macOS-хостов"
  - "DFIR / Incident Response"
estimated_minutes: 40
summary: "Устройство APFS и HFS+, монтирование образов macOS, артефакты системы (plist, Unified Logs, Spotlight, quarantine) и особенности восстановления."
---
APFS (Apple File System) заменила HFS+ на всех современных устройствах Apple — от iPhone до Mac. Для форензика macOS и iOS понимание APFS критично: это контейнер с несколькими томами, снапшотами, шифрованием и копированием при записи (COW), из-за чего «удалённые» данные живут дольше, а структура сложнее классических ФС. Этот урок — про устройство APFS и HFS+, монтирование образов и ключевые артефакты macOS.

## APFS: контейнер, а не том

Ключевое отличие: APFS — это **контейнер** (container) с пулом блоков, внутри которого лежат несколько **томов** (volumes). Тома делят пространство контейнера динамически. В одном контейнере обычно живут тома: системный, `Data`, `Preboot`, `Recovery`, `VM`. Это объясняет, почему «раздел» macOS выглядит странно в `fdisk`.

Структуры: суперблок `NXSB` (container superblock) указывает на checkpoint-карту и объектную карту (`OMAP`), которая сопоставляет виртуальные адреса томов с физическими блоками. Каждый том имеет суперблок `APSB`.

```bash
$ xxd -l 32 disk.img | head
00000000: 4e58 5342 0000 0000 ...   NXSB....
```

## COW, снапшоты и восстановление

APFS использует copy-on-write: изменение блока создаёт новую версию, старая остаётся в старых checkpoint. **Снапшоты** (Time Machine, локальные) фиксируют состояние тома — из них можно восстановить файлы, удалённые после снапшота. Это мощный источник в расследовании: даже если файл удалён, его версия может сохраниться в снапшоте.

```bash
# список снапшотов (macOS)
$ tmutil listlocalsnapshots /
# монтирование снапшота (через diskutil или APFS-инструменты)
$ diskutil apfs listSnapshots /dev/disk1s1
```

Для офлайн-образа снапшоты видны через `apfs-fuse`/`apfs-analyzer`, которые умеют перечислять и монтировать их.

## Монтирование APFS на Linux

```bash
# apfs-fuse (FUSE, read-only)
$ sudo apt install apfs-fuse
$ sudo apfs-fuse disk.img /mnt/apfs
$ ls /mnt/apfs
# apfs-fuse монтирует все тома контейнера; снапшоты — через опции
$ sudo apfs-fuse -o vol=1 disk.img /mnt/apfs
```

Альтернативы: `libfsapfs` (python/pytsk), коммерческие `Cellebrite`/`Magnet AXIOM`. Для HFS+ — `hfsutils`/`hfsplus` (`hmount`, `hls`).

## HFS+ и её артефакты

HFS+ (предшественник APFS) хранит данные в **extents overflow file** и **catalog file** (B-tree с записями файлов/каталогов). Каталог содержит HFS+ **dates** (create/modify/backup/access), а `HFSPlus` поддерживает расширенные атрибуты.

```bash
$ hfsutils
hfs> mount disk.img
hfs> ls
hfs> get file.txt
```

HFS+ славится восстановлением: удалённые записи остаются в B-tree до переиспользования.

## Ключевые артефакты macOS

| Артефакт | Путь | Что даёт |
|----------|------|----------|
| Unified Log | `/var/db/diagnostics/*.tracev3` | системные события, процессы |
| FSEvents | `.fseventsd/` | журнал изменений файлов |
| Spotlight | `.Spotlight-V100/` | метаданные, история |
| Quarantine | xattr `com.apple.quarantine` | откуда скачан файл |
| plist | `~/Library/Preferences/*.plist` | настройки, история приложений |
| LaunchAgents/Daemons | `/Library/Launch*`, `~/Library/LaunchAgents` | автозапуск (персистентность) |
| Keychain | `~/Library/Keychains/login.keychain-db` | пароли, сертификаты |
| Time Machine | `.TimeMachine` / снапшоты | версии файлов |

```bash
# plist в читаемый вид
$ plutil -p Info.plist
$ plistutil -i Info.plist -o out.xml
# Unified Log из образа — инструменты: macos-unifiedlogs (Mandiant), UnifiedLogReader
$ unifiedlog_parser /path/*.tracev3
```

## Шифрование

FileVault шифрует том целиком. APFS поддерживает шифрование на уровне контейнера/тома/файла. Без ключа (или recovery key) данные недоступны. Ключи могут храниться в Secure Enclave (не извлекаются), но recovery key иногда лежит в конфигах, iCloud-бэкапах или памяти.

## Разобранный пример

Дан образ `mac.dd`. Нужно найти скачанный файл и автозапуск.

```bash
# 1. Смонтировать
$ sudo apfs-fuse mac.dd /mnt/apfs
# 2. Quarantine-атрибут показывает источник загрузки
$ getfattr -d /mnt/apfs/Users/bob/Downloads/malware.app 2>/dev/null
user.com.apple.quarantine="0083;5f8a1b2c;Safari;..."
# 3. Автозапуск
$ ls /mnt/apfs/Users/bob/Library/LaunchAgents/
com.evil.updater.plist
$ plutil -p /mnt/apfs/Users/bob/Library/LaunchAgents/com.evil.updater.plist
{ "ProgramArguments" => [ "/Users/bob/Library/evil/run.sh" ] }
# 4. Unified Log: запуск процесса
$ unifiedlog_parser /mnt/apfs/var/db/diagnostics/*.tracev3 | grep -i evil | head
```

Итог: файл скачан Safari (quarantine), закреплён через LaunchAgent, запуск подтверждён Unified Log.

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| Монтировать APFS | `apfs-fuse`, `libfsapfs` |
| Монтировать HFS+ | `hfsutils`, `hfsplus` |
| Снапшоты | `tmutil`, `diskutil apfs listSnapshots` |
| plist | `plutil`, `plistutil` |
| Unified Log | `unifiedlog_parser` |
| FSEvents | `fseventsparse`, `FSEventsParser` |
| Keychain | `security` (на macOS), `chainbreaker` |

## Частые ошибки

- **Путать контейнер и том** — APFS-тома делят один пул; монтируйте нужный.
- **Монтировать rw** — COW создаст новые версии блоков, изменив образ.
- **Игнорировать снапшоты** — удалённые файлы часто есть в старых снапшотах.
- **Забывать про Unified Log** — основной источник событий на macOS.
- **Не проверять xattr** — quarantine/`com.apple.metadata` дают ценную атрибуцию.
- **Считать FileVault непроходимым** — ищите recovery key в бэкапах/конфигах.

## Что дальше / решение

Смонтируйте образ (`apfs-fuse`), определите тома, проверьте снапшоты, затем разбирайте артефакты: plist (настройки), Unified Log (события), FSEvents (изменения файлов), LaunchAgents (персистентность), quarantine (источник файлов). Связка: `forensics-macos-artifacts` (глубоко), `forensics-filesystems` (структуры), `forensics-timeline` (хронология).

## Разбор томов и объектной карты

APFS-контейнер хранит `OMAP` (object map) — таблицу соответствия виртуальных адресов томов физическим блокам. Каждый том имеет собственный набор: суперблок `APSB`, `B-tree` для файловой системы (records: inode, directory, extent, xattr). Понимание этой схемы важно для ручного разбора повреждённых образов, когда `apfs-fuse` не справляется.

```bash
# libfsapfs: список томов и файлов
$ fsapfsinfo disk.img
$ fsapfsmount disk.img /mnt/apfs -X allow_other
# перечисление снапшотов контейнера
$ fsapfsinfo -H disk.img | grep -i snapshot
```

Инструменты `apfs-analyzer`/`libfsapfs` показывают `nx_superblock`, `omap` и список томов с их UUID. Если образ повреждён, ручной парсинг checkpoint-карты позволяет найти последний валидный суперблок.

## Time Machine и версии файлов

Time Machine на APFS хранит не отдельные копии, а **локальные снапшоты** тома `Data`. Это значит, что версии файлов лежат в старых снапшотах и доступны офлайн. В расследовании это золотая жила: удалённый файл может существовать в снапшоте, снятом до удаления.

```bash
# macOS: список и монтирование локального снапшота
$ tmutil listlocalsnapshots /
com.apple.TimeMachine.2024-03-01-120000.local
$ mkdir /tmp/snap && mount_apfs -s com.apple.TimeMachine.2024-03-01-120000.local / /tmp/snap
$ ls /tmp/snap/Users/bob/Documents/
```

Для офлайн-образа снапшоты извлекают через `apfs-fuse`/`libfsapfs` (указав том и снапшот) и сравнивают содержимое с текущим томом, чтобы найти удалённое.

## Ключи и шифрование APFS

APFS поддерживает шифрование на трёх уровнях: контейнера, тома и отдельного файла. Ключи хранятся в `keybag` — структуре в начале контейнера, защищённой паролем пользователя или ключом Secure Enclave (на устройствах с чипом). Для образов Mac без Secure Enclave ключ можно извлечь, зная пароль/`keybag`-пароль.

```bash
# проверка шифрования тома
$ diskutil apfs list | grep -i encrypted
# apfs-fuse с паролем
$ apfs-fuse -o pass=SECRET disk.img /mnt/apfs
```

Если том не зашифрован, данные доступны напрямую. Если зашифрован FileVault, ищите recovery key в `~/Library`, iCloud-бэкапах или в памяти — иначе данные нечитаемы.

## Сравнение с HFS+ и восстановление

| Свойство | HFS+ | APFS |
|----------|------|------|
| Структура | B-tree (catalog/extents) | OMAP + B-tree на том |
| Снапшоты | ограниченные | встроены (Time Machine) |
| Шифрование | FileVault 2 (CoreStorage) | многоуровневое |
| Удаление | запись в B-tree | COW, старая версия в checkpoint |
| Инструмент | `hfsutils`, `hfsplus` | `apfs-fuse`, `libfsapfs` |

COW означает, что «удалённые» данные APFS живут дольше — старые версии блоков остаются в предыдущих checkpoint, пока не будут перезаписаны. Это увеличивает шансы восстановления, но усложняет навигацию: нужно уметь читать checkpoint-карту.

## Квиз

```quiz
- question: "Какая сигнатура у APFS-контейнера?"
  options:
    - "`NXSB`"
    - "`APSB`"
    - "`H+`"
    - "`EFI PART`"
  answer: 0
- question: "Что такое Cocoa epoch?"
  options:
    - "Unix-время"
    - "секунды с 2001-01-01"
    - "с 1970-01-01"
    - "Windows FILETIME"
  answer: 1
- question: "Где macOS хранит URL скачанных файлов?"
  options:
    - "в Safari History"
    - "в `QuarantineEventsV2`"
    - "в `Keychain`"
    - "в Unified Logs"
  answer: 1
- question: "Чем монтируют APFS-образ на Linux?"
  options:
    - "`apfs-fuse`"
    - "`ntfs-3g`"
    - "`mount -t ext4`"
    - "`unrar`"
  answer: 0
- question: "Почему снапшоты APFS важны для форензика?"
  options:
    - "ускоряют анализ"
    - "содержат старые версии ФС с удалёнными/изменёнными файлами"
    - "это логи"
    - "это шифрование"
  answer: 1
```

## Где пригодится

- **CTF:** образы macOS и APFS — отдельная категория задач.
- **DFIR:** анализ MacBook в корпоративной среде.
- **Мобильная форензика:** iPhone использует APFS (см. mobile-forensics).
- **Криминалистика:** артефакты пользователя и история.
- **IT-поддержка:** понимание структуры macOS-дисков.
