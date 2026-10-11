---
id: forensics-carving
title: "Carving и binwalk: извлечение встроенных данных"
category: forensics
parent: forensics-file-magic
difficulty: easy
order: 1
tags: [binwalk, foremost, carving, extraction, ctf]
prerequisites: [forensics-file-magic]
useful_for:
  - "CTF Forensics категория"
  - "Восстановление данных"
  - "Malware analysis (dropper-контейнеры)"
estimated_minutes: 35
summary: "Как находить и извлекать данные, спрятанные внутри файлов и образов: binwalk, foremost, dd, сигнатуры."
---
Carving (вырезание) — это восстановление файлов из сырого потока данных по сигнатурам, без опоры на файловую систему. Когда метаданные повреждены, том отформатирован или данные спрятаны внутри другого файла, carving остаётся единственным способом достать содержимое. В этом уроке — полный арсенал `binwalk`, `foremost`, `scalpel`, `dd` и вспомогательных утилит, а также разобранный пример извлечения флага из образа.

## Когда carving необходим

Carving применяют в трёх случаях: (1) **образ диска без ФС** или с разрушенной ФС — таблица разделов и inode потеряны; (2) **вложенные данные** — ZIP/PNG/PDF внутри другого файла; (3) **CTF-задачи**, где флаг спрятан в нераспределённом пространстве, slack-пространстве или за концевым маркером формата. Carving не восстанавливает имена и структуру каталогов — только содержимое по сигнатурам, поэтому его всегда дополняют анализом метаданных.

## binwalk

`binwalk` — главный инструмент для поиска и извлечения встроенных данных. Он сканирует файл на сигнатуры и, что важно, умеет рекурсивно распаковывать найденное.

| Флаг | Назначение |
|------|-----------|
| `-e` / `--extract` | извлечь распознанные образы |
| `-M` / `--matryoshka` | рекурсивно спускаться во вложенные образы |
| `-d N` | ограничить глубину рекурсии |
| `-C DIR` | каталог для извлечения |
| `-r` | удалить распакованные файлы после извлечения |
| `-A` | только сигнатуры (быстро, без энтропии) |
| `-B` | только энтропийный анализ |
| `-E` | вычислить энтропию (найти сжатые/шифрованные области) |
| `-v` | подробно |
| `-l` | только список сигнатур, без извлечения |

```bash
$ binwalk firmware.bin
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             uImage header, header size: 64 bytes
64            0x40            LZMA compressed data
1048576       0x100000        Squashfs filesystem, little endian, version 4.0
2097152       0x200000        JFFS2 filesystem
$ binwalk -e -M firmware.bin
```

Энтропийный режим помогает найти зашифрованные или сжатые блобы, у которых нет знакомой сигнатуры:

```bash
$ binwalk -E -N firmware.bin | head
DECIMAL       HEXADECIMAL     ENTROPY
0             0x0             0.95
```

Высокая энтропия (~7.9–8.0) — признак шифрования или сжатия; резкие скачки указывают на границу разделов.

## foremost и scalpel

`foremost` восстанавливает файлы по встроенной базе сигнатур (по умолчанию JPEG, PNG, GIF, PDF, ZIP, RAR, Office, HTML и др.). Он читает образ и вырезает всё, что совпало.

```bash
# /etc/foremost.conf — список расширений, сигнатур, max size
$ foremost -i disk.img -o out/ -v
$ foremost -t jpg,png,pdf -i disk.img -o out/   # только указанные типы
$ foremost -i disk.img -o out/ -q               # тихий режим
```

`scalpel` — форк foremost с более гибким конфигом (`/etc/scalpel/scalpel.conf`), где раскомментированием строк включают нужные типы и задают `maxsize`:

```bash
$ scalpel -c /etc/scalpel/scalpel.conf -o out/ disk.img
```

Разница: `foremost` работает «из коробки» и быстр, `scalpel` точнее настраивается под конкретный тип, но требует правки конфига.

## dd и ручное вырезание

Когда `binwalk` даёт точное смещение и длину, точнее всего вырезать вручную через `dd`.

```bash
# вырезать 1 МБ начиная со смещения 0x100000
$ dd if=firmware.bin of=part.sqsh bs=1 skip=$((0x100000)) count=$((1024*1024)) status=none

# bs=1 медленно на больших объёмах — используйте skip в блоках
$ dd if=firmware.bin of=part.sqsh bs=4096 skip=1024 count=256 status=none
```

Важные флаги `dd`: `skip`/`seek` — смещение в блоках, `bs` — размер блока, `count` — число блоков, `status=none` — убрать статистику, `conv=notrunc` — не обрезать выход. Для разделов `dd` часто заменяют на `ddrescue` (устойчив к ошибкам чтения).

## Поиск по сигнатурам вручную

Когда автоматика не срабатывает, сигнатуры ищут `grep -aboP` и режут по смещению:

```bash
# найти все смещения ZIP-заголовков
$ grep -aboP 'PK\x03\x04' disk.img
1048576
5242880
# найти все JPEG (SOI) и их конец (EOI)
$ grep -aboP '\xff\xd8\xff' disk.img | head
$ grep -aboP '\xff\xd9' disk.img | head
```

Для форматов с длиной (RIFF, PNG-чанки) вырезание по паре сигнатур неточно — лучше парсить структуру или использовать `foremost`.

## Энтропия и сжатые данные

Перед carving полезно оценить, есть ли вообще что извлекать. `ent` (или `binwalk -E`) считает энтропию Шеннона по блокам: случайные/сжатые данные дают ~7.9–8.0 бит/байт, текст — 4–5, нули — 0. Резкий рост энтропии — вероятная граница встроенного сжатого блоба.

```bash
$ ent disk.img
Entropy = 7.987654 bits per byte.
```

## Разобранный пример

Дан образ `chal.img`. Нужно найти флаг.

```bash
# 1. Что внутри
$ binwalk chal.img
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             JPEG image data, JFIF standard 1.01
20480         0x5000          PNG image, 512 x 512, 8-bit/color RGBA
65536         0x10000         Zip archive data, at least v2.0

# 2. Извлекаем всё рекурсивно
$ binwalk -e -M chal.img -C out/
$ find out/ -type f
out/_chal.img.extracted/0
out/_chal.img.extracted/5000.png
out/_chal.img.extracted/10000.zip

# 3. ZIP запаролен — ломаем (см. урок forensics-archives)
$ unzip -o out/_chal.img.extracted/10000.zip
[...] flag.txt  (password protected)
$ zip2john out/_chal.img.extracted/10000.zip > h.txt
$ john h.txt --wordlist=/usr/share/wordlists/rockyou.txt
$ unzip -P secret out/_chal.img.extracted/10000.zip -d z/
$ cat z/flag.txt
CTF{c4rv1ng_w0rks}
```

## Таблица «инструмент → задача»

| Задача | Инструмент | Команда |
|--------|-----------|---------|
| Найти вложенные данные | binwalk | `binwalk -e -M file` |
| Найти зашифрованное | binwalk/ent | `binwalk -E file` |
| Восстановить много типов | foremost | `foremost -i img -o out` |
| Точный тип/настройка | scalpel | `scalpel -c conf -o out img` |
| Вырезать по смещению | dd | `dd if=img of=o bs=1 skip=N count=M` |
| Устойчивое чтение битых | ddrescue | `ddrescue img out map` |
| Найти сигнатуру вручную | grep | `grep -aboP 'PK\x03\x04' img` |

## Частые ошибки

- **Путать hex и десятичное смещение.** `binwalk` даёт и то, и другое; `dd skip` — десятичное.
- **`bs=1` на гигабайтном образе** — часы ожидания; пересчитывайте в блоки.
- **Забыть `-M` у binwalk** — не увидите вложенное во вложенном.
- **Извлекать в тот же каталог**, где лежит образ, и перезаписывать исходник.
- **Игнорировать энтропию** — там, где всё зашифровано, carving бесполезен без ключа.
- **Верить только binwalk** — он пропускает форматы без сигнатуры (например, сжатый LZMA-поток без заголовка).
- **Не фиксировать хеш оригинала** — после carving важно доказать неизменность улики.

## Что дальше / решение

После извлечения классифицируйте каждый файл (`file -k`), проверьте метаданные (`exiftool`) и, если внутри снова контейнер, повторите carving. Связка уроков: `forensics-file-magic` (тип) → `forensics-carving` (извлечение) → `forensics-archives` (пароли) → `forensics-metadata` (скрытое в метаданных). Готовый конвейер: `binwalk -e -M` → `file -k` по результату → `foremost` на остатках → ручной `grep -aboP` для нестандартных сигнатур.

## Квиз

```quiz
- question: "Что делает `binwalk -eM`?"
  options:
    - "только сканирует"
    - "извлекает встроенные данные рекурсивно"
    - "шифрует файл"
    - "удаляет метаданные"
  answer: 1
- question: "В выводе binwalk колонка `DECIMAL 10240`. Как извлечь ZIP с этого места?"
  options:
    - "`dd if=f of=o.zip bs=1 skip=10240`"
    - "`dd if=f of=o.zip bs=10240 skip=1`"
    - "`cat f > o.zip`"
    - "`unzip f`"
  answer: 0
- question: "Какой инструмент является carver'ом по сигнатурам?"
  options:
    - "`nmap`"
    - "`foremost`"
    - "`jq`"
    - "`gzip`"
  answer: 1
- question: "Где в JPEG искать appended data?"
  options:
    - "в начале файла"
    - "после маркера `FF D9`"
    - "в EXIF только"
    - "внутри комментария `COM`"
  answer: 1
- question: "Почему `binwalk -e` иногда «не извлекает» ничего?"
  options:
    - "файл зашифрован"
    - "не установлены extract-модули / p7zip"
    - "нужен root"
    - "binwalk не поддерживает ZIP"
  answer: 1
```

## Где пригодится

- **CTF:** основной инструмент для задач «файл в файле».
- **Data recovery:** восстановление файлов с повреждённых носителей.
- **Malware analysis:** извлечение встроенных полезных нагрузок из дропперов.
- **Forensic triage:** быстрый разбор подозрительных вложений.
- **Bug bounty:** анализ загруженных на сервер полиглотов.
