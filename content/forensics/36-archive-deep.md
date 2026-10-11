---
id: forensics-archive-deep
title: "Продвинутые архивы и потоки сжатия"
category: forensics
parent: forensics-archives
difficulty: medium
order: 2
tags: [archive, gzip, zstd, lzma, bzip2, tar, 7z, compression, streams]
prerequisites: [forensics-archives]
useful_for:
  - "CTF Forensics категория"
  - "Malware analysis (dropper-контейнеры)"
  - "Восстановление данных"
estimated_minutes: 40
summary: "Разбор всех основных форматов сжатия и контейнеров: gzip/zstd/lzma/bzip2, tar, 7z, вложенность, encrypted headers, потоки без каталога и восстановление битых архивов."
---
Сжатие и контейнеры — повседневный инструмент атакующих и источник головной боли для аналитика: данные прячут в многослойных архивах, используют потоковые форматы без каталога и повреждённые контейнеры. Этот урок — про все основные форматы сжатия (gzip, zstd, lzma/xz, bzip2), tar, 7z, вложенность, encrypted headers, потоки без каталога и восстановление битых архивов.

## Форматы сжатия и их сигнатуры

| Формат | Расширение | Сигнатура | Утилита |
|--------|-----------|-----------|---------|
| gzip | `.gz` | `1F 8B 08` | `gzip`, `zcat` |
| bzip2 | `.bz2` | `42 5A 68` (`BZh`) | `bzip2`, `bzcat` |
| xz/lzma | `.xz` | `FD 37 7A 58 5A 00` | `xz`, `unxz` |
| zstd | `.zst` | `28 B5 2F FD` | `zstd` |
| lz4 | `.lz4` | `04 22 4D 18` | `lz4` |
| compress | `.Z` | `1F 9D` | `uncompress` |
| zip | `.zip` | `50 4B 03 04` | `unzip` |
| 7z | `.7z` | `37 7A BC AF 27 1C` | `7z` |
| rar | `.rar` | `52 61 72 21 1A 07` | `unrar` |
| tar | `.tar` | (нет; `ustar` на 257) | `tar` |

```bash
$ file archive.*
$ xxd -l 8 archive.zst
00000000: 28b5 2ffd ...
```

## gzip/zstd/xz/bzip2

Потоковые форматы сжимают один файл (или поток) и не хранят имена каталогов — имя берётся из заголовка или задаётся вручную.

```bash
$ gzip -d file.gz                 # распаковать (удалит .gz)
$ gzip -dk file.gz                # сохранить оригинал
$ zcat file.gz | head
$ bzip2 -dk file.bz2
$ xz -dk file.xz
$ zstd -d file.zst -o out
# определить формат без расширения
$ file -z mystery.bin
```

Многослойность: `file.gz` может быть tar.gz, где внутри ещё один архив.

```bash
$ zcat file.gz | tar -tvf -          # список содержимого tar.gz
$ tar -xzf file.tar.gz -C out/
```

## tar и его варианты

`tar` — контейнер без сжатия; сигнатуры нет, но на смещении 257 лежит `ustar`. Сжатие применяется снаружи (`tar.gz`, `tar.bz2`, `tar.xz`, `tar.zst`).

```bash
$ tar -tf file.tar                     # список
$ tar -tvf file.tar                    # подробно
$ tar -xf file.tar -C out/
$ tar -xzf file.tar.gz -C out/
$ tar -xJf file.tar.xz -C out/         # xz
$ tar --zstd -xf file.tar.zst -C out/
# если формат не распознан — определить и распаковать вручную
$ file file.bin
$ zstd -dc file.bin | tar -xf - -C out/
```

## 7z и encrypted headers

7z поддерживает AES-256 и опционально шифрование имён (**encrypted header**, `-mhe=on`). Тогда даже листинг требует пароля.

```bash
$ 7z l archive.7z                  # список (без пароля — если заголовок не шифрован)
$ 7z l -slt archive.7z | grep -i encrypted
$ 7z x archive.7z -oout/ -pPASS
$ 7z x archive.7z -so file.bin > out.bin   # поток в stdout
# извлечь хеш для офлайн-брута
$ 7z2john.pl archive.7z > h.txt
$ hashcat -m 11600 h.txt rockyou.txt
```

## Вложенность и рекурсивная распаковка

```bash
# binwalk распакует все слои
$ binwalk -e -M nested.bin
# цикл по всем архивам
$ find . -name '*.gz' -exec gunzip -k {} \;
$ find . -name '*.tar' -exec tar -xf {} -C out/ \;
# atool: единый интерфейс
$ aunpack archive.7z -X out/
```

Пароль верхнего слоя часто повторяется на вложенных — применяйте найденный пароль повторно.

## Потоки без каталога и битые архивы

Иногда данные — это «сырой» сжатый поток без заголовка (например, после XOR или в теле другого файла). Тогда:

```bash
# определить и распаковать по сигнатуре
$ binwalk file.bin            # покажет смещение gzip/xz/zstd
$ dd if=file.bin of=blob.bin bs=1 skip=<offset> status=none
$ zstd -d blob.bin -o out     # или xz -d, gzip -d
# если заголовок повреждён — попробовать сжатие по энтропии
$ binwalk -E file.bin
```

**Битые архивы**:
- ZIP: `zip -FF broken.zip --out fixed.zip` (перестроить центральный каталог), `7z x` иногда игнорирует хвост.
- gzip: `gzip -dc` игнорирует CRC-ошибку и выдаёт данные до повреждения; `zcat` + `tail`.
- tar: `tar -xf` с `--ignore-zeros`, `--ignore-failed-read`.
- 7z/RAR: пробуйте `7z x`/`unrar x` с `-y`; при частичном повреждении извлекаются первые файлы.

```bash
$ zip -FF broken.zip --out fixed.zip && unzip -o fixed.zip
$ gzip -dc broken.gz > out 2>/dev/null || true
$ tar -xf broken.tar --ignore-zeros -C out/
```

## Разобранный пример

Дан `data.bin` неизвестного формата.

```bash
$ file data.bin
data.bin: gzip compressed data
$ zcat data.bin | file -
/dev/stdin: POSIX tar archive
$ zcat data.bin | tar -xf - -C out/
$ ls out/
payload.7z
$ 7z l out/payload.7z
   ... flag.txt  (Encrypted)
$ 7z2john.pl out/payload.7z > h
$ hashcat -m 11600 h rockyou.txt
$ 7z x out/payload.7z -oout2/ -psecret
$ cat out2/flag.txt
CTF{nested_archives}
```

Три слоя: gzip → tar → 7z с паролем.

## Справочная таблица

| Задача | Команда |
|--------|---------|
| Определить формат | `file -z`, `xxd` |
| gzip | `zcat`/`gzip -dk` |
| xz | `xz -dk`/`unxz` |
| zstd | `zstd -d` |
| tar | `tar -xf`/`-tvf` |
| 7z | `7z x -pPASS` |
| Рекурсивно | `binwalk -e -M` |
| Битый ZIP | `zip -FF` |
| Хеш 7z | `7z2john` + `hashcat -m 11600` |

## Частые ошибки

- **Забыть `-k`** у gzip/xz — оригинал удалится.
- **Путать tar.gz и gz** — сначала распаковать, потом `tar`.
- **Не проверять encrypted header 7z** — листинг не покажет имена.
- **Считать битый архив мёртвым** — `zip -FF`/`gzip -dc` часто спасают.
- **Не распаковывать рекурсивно** — пропустите внутренние слои.
- **Онлайн-брут 7z** вместо офлайн (`hashcat -m 11600`).

## Краткое резюме

Сжатие и контейнеры встречаются повсюду: потоковые форматы (gzip/bzip2/xz/zstd) без каталога, контейнеры (tar/7z) и вложенность. Ключевые приёмы — определить формат (`file -z`), распаковать по сигнатуре/смещению (`binwalk`, `dd`), пройти вложенные слои (`binwalk -e -M`) и восстановить битые архивы (`zip -FF`, `gzip -dc`). Для 7z с encrypted header работайте офлайн-брутом по извлечённому хешу. Связка «`file` → распаковка → `binwalk -M` → пароль → повтор» покрывает почти любой случай.

## Что дальше / решение

Конвейер: `file -z` (формат) → распаковать (`zcat`/`xz`/`zstd`) → `tar` (контейнер) → 7z (пароль → `hashcat`) → `binwalk -e -M` (рекурсия). Связка: `forensics-archives` (ZIP/RAR и пароли), `forensics-carving` (поиск потоков), `forensics-file-magic` (сигнатуры).

## Квиз

```quiz
- question: "Какой magic у zstd?"
  options:
    - "`1F 8B`"
    - "`28 B5 2F FD`"
    - "`42 5A 68`"
    - "`FD 37 7A 58 5A 00`"
  answer: 1
- question: "Где в tar можно спрятать данные?"
  options:
    - "только в именах"
    - "в padding между/после файлов"
    - "в magic"
    - "нельзя"
  answer: 1
- question: "Как починить ZIP с битым EOCD?"
  options:
    - "`zip -FF broken.zip --out fixed.zip`"
    - "`unrar`"
    - "`gunzip`"
    - "`7z x`"
  answer: 0
- question: "Что такое encrypted headers в 7z?"
  options:
    - "шифрование имён файлов — список тоже требует пароль"
    - "сжатие"
    - "CRC"
    - "комментарий"
  answer: 0
- question: "Как распаковать обрезанный gzip-поток?"
  options:
    - "`gzip -t` покажет ошибку, но `zcat ... 2>/dev/null` даст часть"
    - "нельзя"
    - "`unzip`"
    - "`tar`"
  answer: 0
```

## Где пригодится

- **CTF:** матрешки из архивов и битые контейнеры.
- **Malware analysis:** распаковка дропперов (nested gzip/cab).
- **Data recovery:** восстановление повреждённых архивов.
- **Linux-администрирование:** понимание форматов пакетов.
- **Криминалистика:** извлечение данных из вложенных контейнеров.
