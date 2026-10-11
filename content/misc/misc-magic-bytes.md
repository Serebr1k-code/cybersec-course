---
id: misc-magic-bytes
title: "Magic bytes и определение форматов"
category: misc
parent: misc-fileformats
difficulty: easy
order: 1
tags: [fileformat, magic-bytes, binwalk, xxd, carving, ctf]
prerequisites: [misc-fileformats]
useful_for:
  - "CTF Misc/Forensics категория"
  - "Анализ файлов"
  - "Карвинг данных"
estimated_minutes: 25
summary: "Сигнатуры форматов, file/binwalk/xxd, карвинг встроенных файлов, ложные расширения и ручное определение типа по первым байтам."
---

Первое, что делает опытный игрок в misc, получив неизвестный файл, — не открывает его в любимом редакторе, а смотрит на **первые байты**. Расширение файла в CTF и в реальном мире обманывает постоянно: `image.png`, внутри которого ZIP; `document.pdf`, внутри которого PNG; файл без расширения, который на самом деле tar. Умение определить реальный формат по сигнатуре — базовый навык, на котором держатся forensics, стего и file-format-задачи.

## Почему расширение — ненадёжный источник

Операционная система определяет тип файла двумя способами: по расширению (для ассоциаций) и по **magic bytes** (для `file` и приложений). Расширение — это просто часть имени; его можно переименовать одной командой. Поэтому в задачах вас специально путают: `flag.txt` может быть PNG, а `image.jpg` — на самом деле base64. Правило номер один: **никогда не доверяй расширению**.

Есть и обратный случай: файл без расширения. Тогда единственный способ понять, что это, — сигнатура. И третий случай: **полиглот** — файл, который одновременно валиден как два формата (например, ZIP + PNG). Такие файлы создают, дописывая один формат в конец другого.

## Команда file

`file` — самый быстрый способ получить вердикт:

```bash
file mystery.bin
# mystery.bin: PNG image data, 800 x 600, 8-bit/color RGBA, non-interlaced
file --mime-type mystery.bin
# mystery.bin: image/png
file -k mystery.bin
# mystery.bin: PNG image data ... \012- Zip archive data, at least v2.0
```

`-k` (keep going) полезен для полиглотов: `file` выведет все совпадения, а не только первое. `--mime-type` даёт MIME для скриптов. Если `file` говорит `data`, значит сигнатура неизвестна — переходим к `xxd`.

## xxd и hexdump

Смотрим первые байты в hex:

```bash
xxd mystery.bin | head -4
# 00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
# 00000010: 0000 0320 0000 0258 0806 0000 00ab 5f34  ... ...X......_4
```

`8950 4e47` = `\x89PNG` — сигнатура PNG. Для сравнения: `504b 0304` = `PK\x03\x04` (ZIP), `2550 4446` = `%PDF`, `7f45 4c46` = `\x7fELF`, `ffd8 ffe0` = JPEG, `1f8b 08` = gzip, `425a 68` = bzip2, `377a bcaf` = 7z, `5249 4646` = RIFF (WAV/AVI).

`hexdump -C` — аналог с другим форматированием:

```bash
hexdump -C mystery.bin | head -2
# 00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|
```

## Таблица сигнатур

| Hex | Формат | Расширение |
|-----|--------|-----------|
| `89 50 4E 47 0D 0A 1A 0A` | PNG | .png |
| `FF D8 FF` | JPEG | .jpg |
| `47 49 46 38` | GIF | .gif |
| `42 4D` | BMP | .bmp |
| `25 50 44 46` | PDF | .pdf |
| `50 4B 03 04` | ZIP (и docx/xlsx/apk/jar) | .zip |
| `1F 8B 08` | gzip | .gz |
| `42 5A 68` | bzip2 | .bz2 |
| `FD 37 7A 58 5A` | xz | .xz |
| `37 7A BC AF 27 1C` | 7z | .7z |
| `52 61 72 21 1A 07` | RAR | .rar |
| `7F 45 4C 46` | ELF | (linux exe) |
| `4D 5A` | PE/EXE | .exe/.dll |
| `52 49 46 46` | RIFF (WAV/AVI) | .wav/.avi |
| `1A 45 DF A3` | Matroska/WebM | .mkv |
| `CA FE BA BE` | Java class | .class |
| `75 73 74 61 72` | tar (offset 257) | .tar |

Обратите внимание: ZIP-сигнатура совпадает у docx, xlsx, pptx, apk, jar, epub — все это ZIP-контейнеры. И tar имеет «магию» не в начале, а по смещению 257 (`ustar`).

## binwalk и карвинг

`binwalk` находит **встроенные** файлы внутри других:

```bash
binwalk firmware.bin
# DECIMAL       HEXADECIMAL     DESCRIPTION
# 0             0x0             PNG image, 800 x 600
# 12345         0x3039          Zip archive data
# 987654        0xF1206         gzip compressed data
```

Извлечь всё:

```bash
binwalk -e firmware.bin
# создаёт _firmware.bin.extracted/ со всеми найденными файлами
binwalk --dd='.*' firmware.bin   # агрессивный режим
```

Если `binwalk` не установлен, ручной карвинг через `dd`:

```bash
# найти смещение PNG и вырезать от него до конца
grep -abo $'\x89PNG' firmware.bin
# 0:mystery.bin
dd if=firmware.bin of=carved.png bs=1 skip=0
```

`foremost` и `scalpel` делают то же по сигнатурам из конфига.

## Практический workflow

1. `file mystery` — быстрый вердикт.
2. `xxd mystery | head` — подтвердить сигнатуру глазами.
3. `binwalk mystery` — найти встроенные файлы.
4. Если встроенные — `binwalk -e` или ручной `dd`.
5. Если формат неизвестен — искать сигнатуры в бинаре, сверять с таблицей, пробовать `strings`.
6. Если это полиглот — открывать по частям разными инструментами.

## Разобранный пример: PNG внутри PDF

Дано: `challenge.pdf`, при открытии — пустая страница.

```bash
file challenge.pdf
# challenge.pdf: PDF document, version 1.4, 1 pages

binwalk challenge.pdf
# DECIMAL   HEXADECIMAL   DESCRIPTION
# 0         0x0           PDF document
# 4096      0x1000        PNG image, 400 x 100
```

```bash
dd if=challenge.pdf of=hidden.png bs=1 skip=4096
file hidden.png
# hidden.png: PNG image data, 400 x 100
```

Внутри PNG, вероятно, ещё и текст — открываем или идём в `zsteg`/`exiftool`. Вот так одна команда `binwalk` превращает «пустой PDF» в находку.

## Частые ошибки и подводные камни

- Открывать файл в графическом просмотрщике и удивляться, что «не работает».
- Искать сигнатуру только в начале: tar-магия в середине, ZIP может начинаться после префикса (SFX/полиглот).
- Забывать, что `binwalk` может давать ложные срабатывания на случайных данных — проверяйте смещения.
- Путать `grep -a` (binary-safe) и обычный grep — без `-a` текстовый файл может «не находиться».
- Игнорировать порядок байт в сигнатуре: `\x89PNG` — ровно эти байты, регистр важен.
- Резать через `dd bs=1` огромные файлы — это медленно; используйте `skip` с большим `bs` или `tail -c +N`.

## Что дальше / решение

Освоив определение формата, переходите к `misc-json-yaml-xml` (текстовые структуры), затем `misc-archive-tricks` (архивы и полиглоты) и `misc-document-formats` (офисные контейнеры). Параллельно посмотрите forensics-ветку: карвинг из образов — та же техника.

## Контрольный список

- [ ] Проверил `file`, `file -k`, `--mime-type`.
- [ ] Посмотрел первые байты через `xxd`/`hexdump`.
- [ ] Прогнал `binwalk` (и `-e` при находках).
- [ ] Сверил сигнатуру с таблицей.
- [ ] Проверил хвост файла (несколько форматов подряд).
- [ ] Учёл возможность полиглота.

## Практический разбор: файл без расширения

Дано: файл `mystery` без расширения, размер 4 МБ.

```bash
file mystery
# mystery: data
xxd mystery | head -2
# 00000000: 1f8b 0808 ...  — это gzip!
```

Первые байты `1f 8b 08` — gzip. Распаковываем:

```bash
mv mystery mystery.gz && gunzip mystery.gz
file mystery
# mystery: POSIX tar archive
tar tvf mystery
# внутри: image.png, readme.txt, secret.zip
```

Дальше — по слоям: `binwalk -e` извлечёт всё сразу. Если внутри PNG, а задача про картинку — идём в стего. Если внутри ELF — в реверс. Ключевой навык: **не гадать по имени**, а смотреть байты и рекурсивно определять формат. Ведите журнал слоёв (gzip → tar → png → zip → flag.txt), чтобы не запутаться. Этот приём («матryoshka») — основа многих misc-задач, и `file`/`xxd`/`binwalk` покрывают 90% случаев.

## Квиз

```quiz
- question: "Какие байты соответствуют сигнатуре PNG?"
  options:
    - "89 50 4E 47 0D 0A 1A 0A"
    - "25 50 44 46"
    - "50 4B 03 04"
    - "FF D8 FF"
  answer: 0
  explanation: "\\x89PNG\\r\\n\\x1a\\n — классическая сигнатура PNG."
- question: "Что делает `file -k`?"
  options:
    - "Продолжает проверку и печатает все совпавшие форматы (полезно для полиглотов)"
    - "Удаляет файл"
    - "Сжимает файл"
    - "Меняет расширение"
  answer: 0
  explanation: "keep going — не останавливается на первом совпадении."
- question: "Зачем нужен binwalk?"
  options:
    - "Находит встроенные файлы и структуры внутри бинаря"
    - "Считает хэш"
    - "Открывает порты"
    - "Компилирует код"
  answer: 0
  explanation: "binwalk сканирует по сигнатурам и может извлекать."
- question: "Где у tar-архива находится сигнатура `ustar`?"
  options:
    - "По смещению 257"
    - "В первом байте"
    - "В конце файла"
    - "В имени файла"
  answer: 0
  explanation: "Поэтому tar не определяется по началу так же просто, как ZIP."
- question: "docx, xlsx и apk объединяет то, что все они:"
  options:
    - "ZIP-контейнеры (сигнатура PK\\x03\\x04)"
    - "Текстовые файлы"
    - "ELF-бинари"
    - "PDF-документы"
  answer: 0
  explanation: "Это Open Packaging Convention поверх ZIP."
```

## Где пригодится

- **CTF:** misc/forensics — определение и карвинг файлов.
- **Forensics:** восстановление данных из образов и дампов.
- **Malware analysis:** определение вложенных форматов.
- **Работа:** безопасная обработка загрузок, валидация по сигнатуре.
