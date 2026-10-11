---
id: forensics-recyclebin
title: "Корзина и Thumbcache: удалённые файлы и превью"
category: forensics
parent: forensics-win-registry
difficulty: medium
order: 3
tags: [recyclebin, thumbcache, windows, dfir, deleted, thumbnails]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Криминалистика"
estimated_minutes: 35
summary: "Как восстановить удалённые в Корзину файлы, получить оригинальные пути и время удаления из $I-файлов, и вытащить превью изображений/документов из Thumbcache."
---

## Корзина Windows ($Recycle.Bin)

Когда файл удаляют в Корзину, Windows **перемещает** его в `C:\$Recycle.Bin\<SID>\` и создаёт **два** файла:

- **`$I<id>`** — метаданные: оригинальный путь, размер, время удаления.
- **`$R<id>`** — сами данные файла (переименованные).

`$I`-файл имеет структуру: 8 байт заголовка, 8 байт размера, 8 байт времени удаления (FILETIME), затем путь (для Win10 — Unicode UTF-16). Разбор даёт **точный** оригинальный путь и время удаления — мощное доказательство.

```bash
# Инструменты: RBCmd, rifiuti2, python
python3 - <<'EOF'
import struct, datetime
def parse_I(path):
    d = open(path, "rb").read()
    version = struct.unpack("<Q", d[0:8])[0]
    size = struct.unpack("<Q", d[8:16])[0]
    ft = struct.unpack("<Q", d[16:24])[0]
    # FILETIME -> datetime
    ts = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ft/10)
    path_str = d[24:].decode("utf-16-le", "ignore").rstrip("\x00")
    return version, size, ts, path_str
print(parse_I("$IABCDEF"))
EOF
```

`$R`-файл — это содержимое; его можно проанализировать как обычный файл.

## Что доказывает Корзина

- **Оригинальный путь** — откуда удалён файл.
- **Время удаления** — точная хронология.
- **Содержимое** (`$R`) — что было удалено.
- **SID** — какой пользователь удалил.

Если Корзина «пуста», но `$I`/`$R` остались (после восстановления или частичного удаления) — данные всё равно есть.

## Thumbcache

Windows кэширует **превью** изображений/документов в `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db`. Даже если оригинал удалён, превью может остаться.

Формат: `CMMM` — заголовок, затем записи с миниатюрами (BMP/JPEG/PNG). Инструменты: **ThumbsViewer**, **thumbcache_viewer**, **RustyThumbs**.

```bash
# thumbcache_viewer.py (Python)
python thumbcache_viewer.py -i thumbcache_256.db -o out/
ls out/    # извлечённые превью
```

Также существуют `iconcache_*.db`, `thumbcache_idx.db` (индексы).

## Другие «превью»-артефакты

- **`~$` временные файлы Office** — остаются после редактирования.
- **Recent files (LNK, Jump Lists)** — см. `forensics-lnk`.
- **`Windows.edb`** (Windows Search) — индекс содержимого.
- **Prefetch/Amcache** — запуски.
- **`swapfile.sys`/`pagefile.sys`** — могут содержать фрагменты данных.

## Практический пример: восстановление

```bash
# 1. Смонтировать образ (только чтение)
sudo mount -o ro,loop,offset=$((2048*512)) disk.img /mnt
# 2. Найти Корзину
ls /mnt/'$Recycle.Bin'/
# 3. Разобрать $I-файлы
for f in /mnt/'$Recycle.Bin'/*/\$I*; do python parse_I.py "$f"; done
# 4. Скопировать $R-файлы
cp /mnt/'$Recycle.Bin'/*/\$R* /evidence/
# 5. Извлечь thumbcache
python thumbcache_viewer.py -i /mnt/Users/*/AppData/Local/Microsoft/Windows/Explorer/thumbcache_256.db -o out/
```

## Инструменты и команды

```bash
# rifiuti2 (Linux) — разбор $I
rifiuti2 '$Recycle.Bin/'
# RBCmd (Zimmerman)
RBCmd.exe -d C:\$Recycle.Bin -o out.csv
# thumbcache_viewer
python thumbcache_viewer.py -i thumbcache_96.db -o out/
```

## Формат thumbcache детально

Файл `thumbcache_<size>.db` начинается с сигнатуры `CMMM` (0x434D4D4D), версии, числа записей. Каждая запись: хэш, размер, offset, timestamp (FILETIME), затем данные — миниатюра в формате BMP/JPEG/PNG. Размеры: 16, 32, 48, 96, 256, 1024 (пикселей).

```bash
# Извлечение через thumbcache_viewer
python thumbcache_viewer.py -i thumbcache_256.db -o out/
# Или вручную: найти "CMMM" и парсить записи
```

Даже если оригинал удалён, превью **остаётся** в кэше до перезаписи. `thumbcache_idx.db` — индексы (соответствие хэша и метаданных).

## Восстановление и корреляция

- **`$I` → оригинальный путь** → ищите файл в других артефактах (MFT, USN).
- **`$R` → содержимое** → восстановите файл целиком.
- **thumbcache → превью** → визуальное доказательство.
- **Коррелируйте** с LNK/Jump Lists (что открывалось), Prefetch (что запускалось).

```bash
# Проверить, есть ли файл ещё в MFT (по имени)
MFTECmd.exe -f '$MFT' --csv out/
grep -i 'deleted_file' out/*.csv
```

## Практический чек-лист

1. **Смонтируйте образ** только для чтения.
2. **Найдите Корзину** по всем SID (`/mnt/$Recycle.Bin/*/`).
3. **Разберите `$I`** (rifiuti2/RBCmd) → пути и время удаления.
4. **Скопируйте `$R`** → содержимое.
5. **Извлеките thumbcache** → превью.
6. **Коррелируйте** с MFT/USN/LNK/Jump Lists.
7. **Восстановите** удалённое (photorec/testdisk при необходимости).

## Инструменты и команды

```bash
# rifiuti2 (Linux)
rifiuti2 /mnt/\$Recycle.Bin/
# RBCmd (Zimmerman)
RBCmd.exe -d C:\$Recycle.Bin -o out.csv
# thumbcache_viewer
python thumbcache_viewer.py -i thumbcache_256.db -o out/
# Монтирование образа
sudo mount -o ro,loop,offset=$((2048*512)) disk.img /mnt
# Разбор $I вручную
python3 parse_I.py '$I...'
```

## Восстановление удалённых файлов: методы

Если файл удалён **мимо** Корзины (Shift+Delete) или Корзина очищена, данные всё ещё могут быть на диске:

- **Carving** (photorec, foremost) — поиск по сигнатурам в unallocated.
- **MFT-записи** — `$MFT` хранит метаданные (имя, размер, времена) даже для удалённых файлов (пока запись не переиспользована).
- **USN Journal** — журнал изменений (создание/удаление/переименование).
- **Slack space** — «хвосты» кластеров, содержащие остатки данных.
- **Volume Shadow Copies** — снапшоты тома (если есть).

```bash
# MFT-анализ (Zimmerman)
MFTECmd.exe -f '$MFT' --csv out/
# USN
MFTECmd.exe -f '$J' --csv out/
# Carving
photorec /dev/sdX
foremost -i disk.img -o out/
# Теневые копии
vssadmin list shadows
```

**Корзина** — лишь один из источников; комбинируйте с MFT/USN/carving для полной картины.

## Формат $I-файла и парсинг

Структура `$I<id>` (Windows 10/11, версия 2):

| Offset | Размер | Поле |
|---|---|---|
| 0 | 8 | Header/version (обычно 2) |
| 8 | 8 | Размер файла |
| 16 | 8 | Время удаления (FILETIME) |
| 24 | 4 | Длина пути (символы) |
| 28 | var | Путь (UTF-16LE, без завершающего NUL) |

Для Windows Vista/7 (версия 1) путь — ASCII, смещение 24, длина 4. Определите версию по первым 8 байтам. Конвертация FILETIME: секунды с 1601-01-01.

```python
import struct, datetime
def parse(path):
    d = open(path,'rb').read()
    ver = struct.unpack('<Q', d[:8])[0]
    ft = struct.unpack('<Q', d[16:24])[0]
    ts = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ft/10)
    if ver == 2:
        plen = struct.unpack('<I', d[24:28])[0]
        name = d[28:28+plen*2].decode('utf-16-le','ignore')
    else:
        plen = struct.unpack('<I', d[24:28])[0]
        name = d[28:28+plen].decode('latin1','ignore')
    return ver, ts, name
```

## Итог

Корзина и Thumbcache — простые, но мощные артефакты. `$I`-файлы дают оригинальные пути и точное время удаления, `$R` — содержимое, thumbcache — превью. Даже «пустая» Корзина может содержать остатки. Комбинируйте с MFT/USN/LNK и carving для полного восстановления. `rifiuti2`/`RBCmd`/`thumbcache_viewer` — базовые инструменты.

## Резюме

`$I` → путь/время; `$R` → содержимое; thumbcache → превью. Комбинируйте с MFT/USN/carving. rifiuti2/RBCmd/thumbcache_viewer — базовый набор инструментов для быстрого разбора Корзины и кэша превью. Даже «пустая» Корзина часто содержит остатки, а thumbcache хранит превью удалённых изображений и документов.

## Частые ошибки

- **Считать Корзину «пустой» = нет данных.** Проверьте `$I`/`$R`.
- **Путать `$I` и `$R`.** `$I` — метаданные, `$R` — содержимое.
- **Не учитывать per-user Корзину** (по SID).
- **Игнорировать thumbcache.** Часто единственное превью удалённого.
- **Не парсить FILETIME корректно.** Формат 100-нс с 1601 года.
- **Писать на образ.** Только чтение.

## Как не застрять

- **`$I`** → путь и время удаления.
- **`$R`** → содержимое.
- **thumbcache** → превью.
- **RBCmd/rifiuti2** → автоматизация.
- **Проверьте все SID.**
- **Сопоставьте** с LNK/Jump Lists.

## Квиз

```quiz
- question: "Что содержит $I-файл в Корзине?"
  options:
    - "содержимое файла"
    - "метаданные: оригинальный путь, размер, время удаления"
    - "пароль"
    - "ничего"
  answer: 1
- question: "Что такое $R-файл?"
  options:
    - "метаданные"
    - "содержимое удалённого файла"
    - "индекс"
    - "лог"
  answer: 1
- question: "Где Windows хранит кэш превью?"
  options:
    - "thumbcache_*.db"
    - "SAM"
    - "MFT"
    - "Prefetch"
  answer: 0
- question: "В каком формате время удаления в $I?"
  options:
    - "Unix time"
    - "FILETIME (100-нс с 1601)"
    - "строка"
    - "DOS time"
  answer: 1
- question: "Какой инструмент разбирает Корзину?"
  options:
    - "RBCmd"
    - "nmap"
    - "hashcat"
    - "zeek"
  answer: 0
```

## Где пригодится

- **CTF Forensics** — задачи с образами Windows.
- **DFIR** — восстановление удалённых данных.
- **Криминалистика** — доказательство удаления.
- **Threat Hunting** — поиск удалённых инструментов.
- **Recovery** — восстановление файлов.
