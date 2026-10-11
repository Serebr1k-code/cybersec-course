---
id: forensics-exfat
title: "exFAT: структура, directory entries и recovery"
category: forensics
parent: forensics-fs-family
difficulty: medium
order: 2
tags: [exfat, sdcard, boot-sector, recovery, directory-entries]
prerequisites: [forensics-fat]
useful_for:
  - "CTF Forensics категория"
  - "Data recovery (SDXC, флешки)"
  - "Анализ камер и дронов"
estimated_minutes: 48
summary: "Устройство exFAT: boot sector, allocation bitmap, таблицы FAT, наборы записей каталога (File/Directory/Stream/Name), восстановление удалённых файлов и типичные подводные камни."
---

exFAT (Extended File Allocation Table) — файловая система Microsoft, созданная для больших съёмных носителей: карт SDXC, USB-флешек на десятки и сотни гигабайт, карт памяти камер и дронов. Она убрала ограничения FAT32 (файл ≤ 4 ГБ, том ≤ 2 ТБ), но осталась «простой»: нет журнала, метаданные лежат в предсказуемых местах. Для форензика это означает, что **удалённые видео и фото с карт камер часто восстанавливаются** прямо из структуры ФС.

## Загрузочный сектор exFAT

Первый сектор тома начинается с `EB 76 90` и метки `EXFAT   ` по offset 3. Структура boot sector:

| Смещение | Размер | Поле |
|---------:|-------:|------|
| 0x00 | 3 | jump (`EB 76 90`) |
| 0x03 | 8 | файловая система (`EXFAT   `) |
| 0x40 | 8 | partition offset (секторы) |
| 0x48 | 8 | volume length (секторы) |
| 0x50 | 4 | FAT offset (сектор) |
| 0x54 | 4 | FAT length (сектор) |
| 0x58 | 4 | cluster heap offset (сектор) |
| 0x5C | 4 | cluster count |
| 0x60 | 4 | root dir first cluster |
| 0x64 | 4 | volume serial |
| 0x6C | 1 | bytes per sector shift (обычно 9 → 512) |
| 0x6D | 1 | sectors per cluster shift (напр. 3 → 8 секторов) |
| 0x6F | 1 | number of FATs (обычно 1 или 2) |
| 0x1FE | 2 | signature `55 AA` |

Смещения считаются в **секторах** от начала тома. `cluster_heap_offset` — где начинаются кластеры; корневой каталог — цепочка кластеров, начинающаяся с `root dir first cluster`.

## Allocation bitmap и таблица FAT

В exFAT два механизма учёта:

- **Allocation Bitmap** — по одному биту на кластер (1 = занят). Служебный файл `$Bitmap` (в root directory, entry с именем `$Bitmap`). Быстро показывает занятость.
- **FAT** — необязательная цепочка кластеров (для фрагментированных файлов). Часто FAT «пустая» (все нули), а файлы не фрагментированы и описываются как contiguous-экстенты в **Stream Extension**.

Ключевое отличие от FAT32: **имя файла и его метаданные разделены на несколько записей каталога**, идущих подряд и образующих **набор (entry set)**.

## Наборы записей каталога

Каждая запись — 32 байта. Первый байт — тип: `0x85` — File, `0xC0` — Stream Extension, `0xC1` — File Name, `0x81` — Allocation Bitmap, `0x82` — Up-case Table, `0x83` — Volume Label.

| Тип | Запись | Что хранит |
|-----|--------|-----------|
| 0x85 | File | атрибуты, таймстампы (create/modify/access) |
| 0xC0 | Stream Extension | first cluster, data length, valid data length, флаги (NoFatChain = contiguous) |
| 0xC1 | File Name | до 15 символов UTF-16 на запись, продолжения при длинных именах |

Набор идёт: File → Stream Extension → Name[0] → Name[1]… Флаг `NoFatChain` в Stream Extension означает, что данные лежат **непрерывно** от first cluster и длину берут из data length — тогда FAT не нужна.

```bash
# Дамп корневого каталога exFAT (после вычисления offset heap + root cluster)
xxd -s <root_dir_offset> -l 256 sdcard.img
# ищем 0x85 0xC0 0xC1 ... наборы
```

## Инструменты и флаги

```bash
# Параметры ФС
fsstat -o <offset> sdcard.img | head -30    # cluster size, FAT/heap offsets

# Листинг и удалённые
fls -o <offset> -r sdcard.img
fls -o <offset> -r -d sdcard.img            # удалённые записи
icat -o <offset> sdcard.img <inode> > out.bin

# Монтирование (read-only!)
sudo mount -o ro,loop,offset=<bytes> sdcard.img /mnt/exfat

# Каринг медиа (когда метаданные потеряны)
photorec sdcard.img
foremost -i sdcard.img -o out/ -t jpg,mp4,mov
```

## Разобранный пример: удалённое видео с карты

```bash
$ fsstat -o 8192 card.img | sed -n '1,18p'
FILE SYSTEM INFORMATION
File System Type: EXFAT
Cluster Size: 32768
FAT Offset (sectors): 128
FAT Length (sectors): 256
Cluster Heap Offset (sectors): 512
Root Directory Cluster: 4
$ fls -o 8192 -r -d card.img
r/r * 42: DCIM/100VIDEO/VID_0007.MP4
$ icat -o 8192 card.img 42 > vid0007.mp4
$ ls -l vid0007.mp4
-rw-r--r-- 1 user user 104857600 vid0007.mp4
$ ffprobe -v error -show_entries format=duration -of csv=p=0 vid0007.mp4
10.0
```

Файл восстановлен целиком, потому что его кластеры (contiguous) не были перезаписаны, а запись Stream Extension сохранила first cluster и data length.

## Краевые случаи и подводные камни

- **NoFatChain.** Если флаг установлен, цепочку в FAT искать бессмысленно — читайте непрерывный диапазон кластеров от first cluster.
- **Valid Data Length (VDL).** Может быть меньше data length — часть файла «не инициализирована»; для форензики это отдельный интерес (остатки прежних данных).
- **Несколько Name-записей.** Длинное имя собирается из нескольких 0xC1; последняя запись помечается битом `0x40`. Не путайте с одиночным именем.
- **Две FAT (number of FATs = 2).** Иногда FAT дублируется; allocation bitmap — единственный источник правды о занятости.
- **Кластеры ≥ 2.** Кластер 0/1 зарезервированы; root directory cluster обычно 4.
- **Байты на кластер.** `sectors per cluster shift` — степень двойки; для видео часто 32–128 КБ на кластер.
- **Смещение раздела.** `partition offset` в boot sector может отличаться от реального offset раздела в образе — проверяйте `mmls`.
- **Удаление.** Запись File помечается «не in-use» (сбрасывается бит 0x80 типа → 0x05), но Stream/Name могут остаться — по ним и восстанавливают.

## Почему появился exFAT и где он встречается

FAT32 уперлась в два жёстких предела: максимальный размер файла — 4 ГиБ и максимальный размер тома — 2 ТиБ (по факту 32 ГиБ для форматирования штатными средствами Windows). Для карт SDXC (от 64 ГиБ) и современных камер этого мало: одно видео 4K легко переваливает за 4 ГиБ, а карта — за 2 ТиБ. Microsoft ответила exFAT, сохранив простоту FAT (нет журнала, нет транзакций) и добавив 64-битные размеры.

Практические следствия для форензика:

- **Нет журнала** — значит, после аварийного отключения камеры метаданные могут быть неполными, но зато нет и «отката» к консистентному состоянию, который уничтожил бы следы удаления.
- **Большие кластеры** — на видео-картах часто 64–256 КиБ на кластер; это ускоряет чтение, но увеличивает объём «хвоста» после последнего файла (данные в нераспределённом пространстве).
- **OEM-параметры** — камеры и телефоны форматируют карты по-своему (cluster size, число FAT); не полагайтесь на значения по умолчанию, всегда читайте boot sector.

Типичные носители: SD/SDHC/SDXC, microSD в телефонах, USB-флешки >32 ГиБ, карты дронов (DJI и др.), а также некоторые встраиваемые устройства.

## Ручной разбор Stream Extension по байтам

Покажем, как вручную прочитать метаданные файла, если sleuthkit недоступен. Возьмём набор записей каталога и разберём Stream Extension (тип `0xC0`).

| Смещение | Размер | Поле |
|---------:|-------:|------|
| 0x00 | 1 | тип записи (`0xC0`) |
| 0x01 | 1 | general secondary flags (0x00 — allocation possible) |
| 0x02 | 1 | reserved |
| 0x03 | 1 | name length (число символов UTF-16) |
| 0x04 | 2 | name hash |
| 0x06 | 2 | reserved |
| 0x08 | 8 | valid data length (VDL) |
| 0x10 | 4 | reserved |
| 0x14 | 4 | first cluster |
| 0x18 | 8 | data length |
| 0x20 | 4 | general secondary flags (NoFatChain и др.) |

Порядок чтения:

```bash
# 1) boot sector -> heap offset, cluster size
xxd -s <part_off> -l 128 sdcard.img
# 2) root directory cluster (offset 0x60 boot) -> адрес корня
# 3) в корне ищем наборы 0x85/0xC0/0xC1
xxd -s <root_dir_off> -l 512 sdcard.img
# 4) для Stream Extension: first cluster по 0x14, data length по 0x18
# 5) данные = heap_offset + (first_cluster - 2) * cluster_size
```

Если выставлен `NoFatChain` (бит 0x02 в байте general secondary flags по offset 0x01, либо флаг по offset 0x20 — зависит от реализации), данные непрерывны: `data_offset = heap_start + (first_cluster-2)*cluster_size`, длина = `data_length`. Если нет — идём по цепочке FAT от `first_cluster`.

## Восстановление без метаданных

Когда запись каталога переиспользована или занулена, остаётся carving. exFAT-носители — это чаще всего медиа, поэтому сигнатурный поиск особенно эффективен:

```bash
# Поиск JPEG/PNG/MP4 по сигнатурам, независимо от ФС
photorec sdcard.img
foremost -i sdcard.img -o out/ -t jpg,png,mp4,mov,avi
# Скан по сигнатурам вручную
binwalk sdcard.img
# Проверить, есть ли exFAT-записи (0x85) в нераспределённом
xxd sdcard.img | grep -c '8580\|8500\|85 00'
```

Важно: carving не восстанавливает имена, время и цепочку — только содержимое. Если задача требует доказать, что файл существовал, метаданные важнее; если нужно просто извлечь флаг — carving достаточен.

## Проверка целостности и подозрительные признаки

- **volume serial** в boot sector — сверяйте с эталоном, если сравниваете два образа.
- **partition offset** — если он не совпадает с реальным положением раздела, карта могла быть переразмечена.
- **Аномально большие data length** при нулевом first cluster — признак повреждения или антифорензики.
- **Наборы без парной Name-записи** — «осиротевшие» Stream Extension, часто остаток удалённых файлов.
- **Файлы `$Bitmap`, `$UpCase`, `$Volume`** — системные; их наличие нормально, отсутствие — признак урезанного/подделанного образа.

## Что дальше / решение

Алгоритм:

1. `fsstat` — cluster size, heap offset, root cluster.
2. `fls -r -d` — найти удалённые записи и inode.
3. `icat` — прочитать содержимое (для NoFatChain — непрерывный диапазон).
4. Проверить VDL на остаточные данные.
5. Не вышло — `photorec` по сигнатурам видео/фото.

Дальше переходите к `forensics-carving` для восстановления без метаданных и к `forensics-xfs`/`forensics-hfsplus` для серверных и macOS-носителей.

## Квиз

```quiz
- question: "Какая метка указывает на exFAT в boot sector?"
  options:
    - "FAT32"
    - "EXFAT"
    - "NTFS"
    - "XFSB"
  answer: 1
  explanation: "exFAT помечает тип ФС строкой EXFAT по offset 3."
- question: "Что означает флаг NoFatChain в Stream Extension?"
  options:
    - "файл зашифрован"
    - "данные лежат непрерывно, цепочка в FAT не используется"
    - "файл удалён"
    - "это каталог"
  answer: 1
  explanation: "NoFatChain = contiguous allocation: first cluster + data length задают весь файл."
- question: "Из каких записей состоит набор метаданных файла exFAT?"
  options:
    - "только File"
    - "File + Stream Extension + одна или несколько File Name"
    - "только File Name"
    - "MFT + bitmap"
  answer: 1
  explanation: "Набор: File (0x85), Stream Extension (0xC0) и Name (0xC1), возможно несколько для длинных имён."
- question: "Где в exFAT хранится учёт занятости кластеров?"
  options:
    - "в MFT"
    - "в Allocation Bitmap ($Bitmap)"
    - "в $LogFile"
    - "в B-дереве"
  answer: 1
  explanation: "Allocation Bitmap — по биту на кластер; служебный файл $Bitmap в корне."
```

## Где пригодится

- **CTF:** образы SD-карт камер/дронов, большие флешки.
- **DFIR:** разбор носителей с видео и фото.
- **Data recovery:** восстановление удалённых медиафайлов.
- **Пентест:** анализ извлечённых съёмных носителей.
