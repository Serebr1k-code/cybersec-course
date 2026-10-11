---
id: stego-archive-nested
title: "Рекурсивная вложенность: архивы в архивах и матрёшки"
category: stego
parent: stego-module-container-adv
difficulty: medium
order: 4
tags: [stego, archive, nested, recursive, carving, matryoshka]
prerequisites: [stego-archives, stego-appended]
useful_for:
  - "CTF Stego/Forensics: многоуровневые вложенные данные"
  - "Автоматизация извлечения «до дна»"
estimated_minutes: 32
summary: "Рекурсивная вложенность контейнеров: архивы в архивах, конкатенация форматов, полиглоты, пароли на вложенных уровнях; автоматизация через binwalk -e, foremost, 7z и собственный скрипт."
---

Один уровень сокрытия — это редкость для CTF. Гораздо чаще данные лежат «матрёшкой»: ZIP внутри PNG внутри PDF, а на дне — base64 с флагом. Ручное извлечение быстро надоедает и легко пропускает уровень, поэтому ключевой навык — автоматизированная рекурсивная распаковка «до дна». Этот урок — про вложенность, конкатенацию контейнеров и то, как не потерять ни одного слоя.

## Вложенность и матрёшки

Схема «матрёшка»: файл A содержит файл B, B содержит C, и так далее. Каждый слой может быть любым: архив, изображение, текст, base64. Задача — распаковать все слои и не зациклиться (вложенность бывает и бесконечной — «zip bomb»). Признаки вложенности: сигнатуры внутри файла (`PK\x03\x04`, `\x89PNG`, `%PDF`), несоответствие расширения содержимому.

```bash
file mystery.bin
# mystery.bin: PNG image data, 1024 x 768
# но binwalk показывает внутри ещё один файл
binwalk mystery.bin
```

## Конкатенация контейнеров

Многие форматы допускают «дописанные» данные после конца: PNG читается до `IEND`, но файл может продолжаться; ZIP читается до `End of Central Directory`, но за ним могут быть другие файлы; JPEG читается до `FFD9`. Это позволяет склеивать несколько файлов в один — «полиглот», который открывается и как один формат, и как другой.

Пример: PNG + ZIP.

```bash
cat image.png secret.zip > polyglot.png
file polyglot.png          # PNG image data
unzip -l polyglot.png      # видит ZIP!
binwalk polyglot.png       # покажет оба
```

## Инструменты и команды

- **`binwalk -e`** — рекурсивное извлечение сигнатур (по умолчанию в `_extracted`).
- **`binwalk -Me`** — глубокая рекурсия (matryoshka).
- **`foremost`/`scalpel`** — carving по сигнатурам.
- **`7z x -y`** — универсальная распаковка многих форматов.
- **`unzip -l`/`-P pass`** — список и пароль для ZIP.
- **`unzip -o`, `bsdtar`** — перезапись/универсальный tar.
- **`base64 -d`** — декодирование текстового слоя.
- **Свой Python-скрипт** — рекурсивный обход с проверкой сигнатур.

Рекурсивное извлечение:

```bash
binwalk -Me stego.png
ls _stego.png.extracted/
# 0.zip  400.bin  ...
cd _stego.png.extracted && binwalk -Me 400.bin
```

## Разобранный пример: скрипт рекурсивной распаковки

Автоматизируем «до дна»:

```python
import os, subprocess, zipfile, io

SIGS = {b"\x89PNG":".png", b"PK\x03\x04":".zip", b"%PDF":".pdf",
        b"\xff\xd8\xff":".jpg", b"7z\xbc\xaf":".7z", b"Rar!":".rar"}

def carve(data):
    out = []
    for sig, ext in SIGS.items():
        i = data.find(sig)
        if i != -1:
            out.append((i, ext))
    return sorted(out)

def recurse(path, depth=0, maxdepth=12):
    if depth > maxdepth:
        return
    data = open(path, "rb").read()
    hits = carve(data)
    if not hits:
        print("  "*depth, "leaf:", path, len(data), "bytes")
        return
    for off, ext in hits:
        blob = data[off:]
        sub = path + f"_{depth}{ext}"
        open(sub, "wb").write(blob)
        print("  "*depth, "->", sub)
        if ext == ".zip":
            try:
                with zipfile.ZipFile(io.BytesIO(blob)) as z:
                    for n in z.namelist():
                        z.extract(n, path + f"_{depth}_zip")
                        recurse(os.path.join(path+f"_{depth}_zip", n), depth+1, maxdepth)
            except Exception as e:
                print("  "*depth, "zip err", e)
        else:
            recurse(sub, depth+1, maxdepth)

recurse("mystery.bin")
```

Вывод (пример):

```
 -> mystery.bin_0.png
   -> mystery.bin_0.png_1.zip
     -> ..._zip/secret.txt
       leaf: .../secret.txt 24 bytes
```

Дальше читаем `secret.txt` — там может быть base64 или ещё один слой.

## Полиглоты и двойные расширения

- **Двойное расширение.** `file` смотрит на содержимое, а не на имя; `photo.jpg` может быть ZIP.
- **Polyglot.** Файл, валидный одновременно как два формата (PNG+ZIP, PDF+ZIP, GIF+JS).
- **Магические байты.** Всегда начинайте с `file` и `xxd | head`, а не с расширения.

```bash
xxd mystery.bin | head -3
# 00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
```

## Пароли на вложенных архивах

Вложенный ZIP/RAR/7z может быть под паролем. Инструменты: `unzip -P pass`, `7z x -pPASS`, `john`/`hashcat` для offline-брута (`zip2john` → `john`). Не тратьте на онлайн-брут — сначала проверьте «очевидные» пароли (имя файла, `password`, пусто).

```bash
zip2john secret.zip > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

## Крайние случаи и подводные камни

- **Zip bomb.** Вложенность может раскрываться экспоненциально — ограничьте `maxdepth` и общий размер.
- **Несколько сигнатур.** Файл может содержать и PNG, и ZIP — обрабатывайте все, а не первую.
- **Обрезанные файлы.** Carving может дать «битый» хвост; иногда данные всё равно читаются частично.
- **Кодировки.** Текстовый слой бывает hex/base64/ROT13 — декодируйте по цепочке.
- **Ложные сигнатуры.** `PK` может встретиться случайно; проверяйте валидность (`unzip -l`).
- **`binwalk -e` зависит от внешних тулов.** Без них он извлечёт не всё — проверяйте `_extracted`.

## Что дальше / решение

- Файл «не тот», чем кажется, — `file`, `binwalk`, `xxd`.
- Нашли сигнатуру — режьте и распаковывайте рекурсивно (`binwalk -Me`).
- ZIP под паролем — `zip2john` + `john`, но сначала «очевидные» пароли.
- Дошли до текста — прогоните через цепочку декодирований (base64/hex/URL/ROT).
- Зациклилось — ставьте лимит глубины и размера.

## Справочная таблица

| Сигнатура | Формат | Инструмент |
|---|---|---|
| `PK\x03\x04` | ZIP | unzip, 7z |
| `\x89PNG` | PNG | binwalk, PIL |
| `%PDF` | PDF | qpdf, mutool |
| `7z\xbc\xaf` | 7z | 7z |
| `Rar!` | RAR | unrar |
| `\x1f\x8b` | gzip | gunzip |

## Автоматизация рекурсивной распаковки: практические ограничения

Скрипт из основного примера работает, но у него есть слабые места, о которых стоит знать. Во-первых, он берёт *первую* найденную сигнатуру каждого типа, а файл может содержать несколько ZIP. Во-вторых, он не проверяет валидность «вырезанного» файла — `PK` может встретиться случайно. В-третьих, вложенные архивы могут быть зашифрованы, и скрипт молча упадёт. Улучшенная стратегия:

```python
import zipfile, io, re

def find_all(data, sig):
    return [m.start() for m in re.finditer(re.escape(sig), data)]

def try_zip(blob, base):
    # пробуем все смещения, где может начинаться валидный ZIP
    for off in [0] + [m for m in range(1, min(len(blob), 4096))]:
        try:
            z = zipfile.ZipFile(io.BytesIO(blob[off:]))
            z.testzip()      # проверка CRC — валидный архив
            return z
        except Exception:
            continue
    return None
```

`testzip()` возвращает `None`, если все CRC сошлись — это надёжная проверка, что архив настоящий, а не случайные байты.

## Работа с 7z, RAR и tar

Не всё сводится к ZIP. Универсальный инструмент — `7z`, который понимает десятки форматов:

```bash
7z l mystery.bin          # список содержимого (по сигнатуре)
7z x mystery.bin -oout/   # распаковать
7z x -pPASS secret.7z     # с паролем
7z x nested.rar
```

Для tar-семейства: `tar tf`, `tar xf`, а для сжатых — `tar xzf`/`xjf`. Универсальный `bsdtar` определяет формат автоматически:

```bash
bsdtar -tf mystery.bin    # libarchive сам разберёт gzip/zip/7z/tar
```

## Кодировочные цепочки на дне

Дойдя до текстового слоя, вы почти всегда встречаете *цепочку* кодирований: base64 → gzip → hex → base64 → флаг. Распознавайте по алфавиту:

| Признак | Кодировка |
|---|---|
| `[A-Za-z0-9+/=]`, длина %4 | Base64 |
| только `[0-9a-f]`, чётная длина | Hex |
| `%XX` | URL-encode |
| буквы+цифры без символов, алфавит 62 | Base62 |
| `\uXXXX` | Unicode escape |

Автоматизируйте перебор цепочек:

```python
import base64, binascii, codecs
def try_decode(s):
    outs = []
    try: outs.append(("b64", base64.b64decode(s).decode('latin1')))
    except Exception: pass
    try: outs.append(("hex", binascii.unhexlify(s).decode('latin1')))
    except Exception: pass
    return outs
```

Практика: применяйте декодеры рекурсивно, пока результат меняется, и ищите подстроку `flag`/`ctf`.

## Защита от «бомб» и бесконечных циклов

Вложенность бывает злонамеренной: ZIP-бомба (42.zip), рекурсивные симлинки, архив, содержащий сам себя. Всегда ограничивайте:

- глубину рекурсии (`maxdepth`),
- суммарный распакованный размер,
- число файлов,
- таймаут на уровень.

Инструмент `7z` имеет флаг `-xr!` и лимиты; для скриптов задайте счётчик и общий бюджет байт. Иначе «матрёшка» съест диск и время.

## Инструменты carving и их различия

Carving — восстановление файлов по сигнатурам без метаданных. Три инструмента с разной логикой:

- **`binwalk`** — сканирует сигнатуры, умеет рекурсию (`-Me`), зависит от внешних распаковщиков.
- **`foremost`** — конфигурируемый carving по типам (`-t`), работает по заголовку и подошве.
- **`scalpel`** — форк foremost, быстрее, с гибким конфигом.

```bash
foremost -t zip,png,pdf -i mystery.bin -o out/
scalpel -c /etc/scalpel/scalpel.conf -o out2/ mystery.bin
```

`foremost` не рекурсивен по умолчанию — после извлечения прогоняйте снова по каждому файлу. `binwalk -Me` рекурсивен, но может «застрять» на больших вложенных данных — ограничивайте время.

## Полиглоты на практике

Полиглот — файл, валидный как несколько форматов. Классика: PNG+ZIP, PDF+ZIP, GIF+JS. Создать:

```bash
cat image.png secret.zip > polyglot.png
file polyglot.png        # PNG
unzip -l polyglot.png    # видит ZIP
```

Анализ: `binwalk` покажет обе сигнатуры; `file` — «первую» (по сигнатуре в начале). Не доверяйте одному инструменту: проверяйте и как изображение, и как архив, и как текст.

## Итоговый алгоритм

1. `file` — реальный формат.
2. `binwalk`/`grep -aboP` — сигнатуры вложенных файлов.
3. Carving (`binwalk -e`, `foremost`, `dd` по смещению).
4. Рекурсия по каждому извлечённому файлу (с лимитами).
5. Пароли — `zip2john`+`john`/`7z -p`.
6. Текстовый слой — цепочки декодирований.
7. Проверка на полиглот (валидность в нескольких форматах).

Вложенность — мета-техника: она комбинируется с любым носителем, поэтому автоматизация и лимиты обязательны.

## Квиз

```quiz
- question: "Какая команда binwalk рекурсивно распаковывает «матрёшку»?"
  options:
    - "binwalk -Me"
    - "binwalk -a"
    - "binwalk -l"
    - "binwalk -q"
  answer: 0
- question: "Что такое полиглот-файл?"
  options:
    - "Файл, валидный одновременно как несколько форматов"
    - "Файл с двойным паролем"
    - "Зашифрованный архив"
    - "Файл нулевого размера"
  answer: 0
- question: "Как проверить, под паролем ли вложенный ZIP offline?"
  options:
    - "zip2john + john/hashcat"
    - "unzip без пароля"
    - "zsteg -a"
    - "exiftool"
  answer: 0
- question: "Чем опасна глубокая вложенность?"
  options:
    - "Zip bomb — экспоненциальный рост размера"
    - "Потеря цвета"
    - "Смена разрешения"
    - "Замена палитры"
  answer: 0
```

## Где пригодится

- **CTF:** Stego/Forensics — многоуровневые задачи, полиглоты, матрёшки.
- **Forensics:** carving и восстановление вложенных артефактов.
- **Работа:** анализ подозрительных вложений (фишинг, малварь).
