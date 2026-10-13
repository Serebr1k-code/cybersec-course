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

lab:
  kind: shell
  title: "Практика: раскрутить вложенные архивы"
  toolset: [core, unzip, python, hex]
  workdir: /home/student/task
  files: [task.md, notes.txt, outer.zip, unwrap.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Проверь формат: `file outer.zip`."
    - "Список: `unzip -l outer.zip`."
    - "Слои хранятся без сжатия — `strings outer.zip`."
    - "Сохрани флаг: `strings outer.zip | grep nto > found.txt`."

---

## Вопрос, с которого всё начинается

В задаче дан `mystery.bin`. Ты открываешь его — PNG-картинка, ничего особенного. `zsteg` пусто, `strings` пусто. Ты уже собираешься двигаться дальше, но `binwalk` внезапно показывает внутри файла **ещё один файл**. И это только первый слой.

Один уровень сокрытия в CTF — редкость. Гораздо чаще данные лежат «матрёшкой»: ZIP внутри PNG внутри PDF, а на дне — base64 с флагом. Разберём, как распутать такую вложенность и ничего не потерять.

## Наш пример: mystery.bin

Начнём с самого главного правила: **доверяй содержимому, а не расширению**. `file` смотрит на «магические» байты в начале файла, а не на имя.

```bash
$ file mystery.bin
mystery.bin: PNG image data, 1024 x 768, 8-bit/color RGB
$ xxd mystery.bin | head -1
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
```

Первые байты `89 50 4e 47` — сигнатура PNG. Но `binwalk` видит больше:

```bash
$ binwalk mystery.bin
DECIMAL   HEXADECIMAL  DESCRIPTION
0         0x0          PNG image, 1024 x 768
1048321   0xFFF01      Zip archive data, at offset 0xFFF01
```

После конца PNG (а PNG «заканчивается» на маркере `IEND`) дописан **ZIP**. Это **concatenation** — приём, при котором после корректного файла дописывают второй.

## Шаг 1: почему это работает — appended-данные

Многие форматы читаются до определённого маркера и игнорируют всё, что дальше:

- PNG читается до `IEND`;
- JPEG — до `FFD9`;
- ZIP — до `End of Central Directory`.

Значит, за «концом» можно спрятать другой файл, и оба будут валидны. Файл, который открывается как два формата одновременно, называют **полиглотом**. Классика — PNG+ZIP, PDF+ZIP, GIF+JS.

```bash
$ unzip -l mystery.bin
Archive:  mystery.bin
  Length      Name
      480    layer2.zip
$ binwalk mystery.bin
# покажет обе сигнатуры
```

## Шаг 2: рекурсивная распаковка

`binwalk -e` извлекает все найденные сигнатуры, а `-Me` делает это рекурсивно — «матрёшку до дна»:

```bash
$ binwalk -Me mystery.bin
$ ls _mystery.bin.extracted/
0.zip   FFF01.zip
$ cd _mystery.bin.extracted && binwalk -Me FFF01.zip
```

Но `binwalk` зависит от внешних распаковщиков и иногда пропускает слои. Надёжнее — свой скрипт, который обходит вложенность с проверкой сигнатур:

```python
import os, zipfile, io, re

SIGS = {b"\x89PNG":".png", b"PK\x03\x04":".zip", b"%PDF":".pdf",
        b"\xff\xd8\xff":".jpg", b"7z\xbc\xaf":".7z", b"Rar!":".rar"}

def carve(data):
    hits = []
    for sig, ext in SIGS.items():
        for m in re.finditer(re.escape(sig), data):
            hits.append((m.start(), ext))
    return sorted(hits)

def recurse(path, depth=0, maxdepth=12):
    if depth > maxdepth:
        return
    data = open(path, "rb").read()
    for off, ext in carve(data):
        blob = data[off:]
        sub = f"{path}_{depth}{ext}"
        open(sub, "wb").write(blob)
        print("  "*depth, "->", sub)
        if ext == ".zip":
            try:
                with zipfile.ZipFile(io.BytesIO(blob)) as z:
                    z.testzip()                 # проверка CRC — архив настоящий
                    z.extractall(f"{path}_{depth}_zip")
            except Exception as e:
                print("  "*depth, "zip err", e)
        else:
            recurse(sub, depth+1, maxdepth)

recurse("mystery.bin")
```

```bash
$ python3 unpack.py
 -> mystery.bin_0.png
   -> mystery.bin_0.png_1.zip
     -> ..._zip/secret.txt
```

`testzip()` возвращает `None`, если все контрольные суммы сошлись, — это надёжная проверка, что перед нами настоящий архив, а не случайные байты.

## Шаг 3: пароль на вложенном архиве

Вложенный ZIP может быть под паролем. Не трать время на онлайн-перебор — сначала проверь «очевидные» пароли (имя файла, `password`, пустой), затем ломай офлайн:

```bash
$ zip2john secret.zip > hash.txt
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
$ unzip -P найденный_пароль secret.zip
```

## Шаг 4: кодировочные цепочки на дне

Дойдя до текста, ты почти всегда видишь **цепочку** кодирований: base64 → gzip → hex → флаг. Распознавай по алфавиту:

| Признак | Кодировка |
|---|---|
| `[A-Za-z0-9+/=]`, длина кратна 4 | Base64 |
| только `[0-9a-f]`, чётная длина | Hex |
| `%XX` | URL-encode |
| `\uXXXX` | Unicode escape |

```bash
$ cat secret.txt
ZmxhZ3tuZXN0ZWRfbWF0cnlvc2hrYX0=
$ base64 -d secret.txt
flag{nested_matryoshka}
```

## Шаг 5: защита от «бомб»

Вложенность бывает злонамеренной: **ZIP-бомба** (архив, который при распаковке растёт экспоненциально), рекурсивные симлинки, архив, содержащий сам себя. Всегда ограничивай:

- глубину рекурсии (`maxdepth`);
- суммарный распакованный размер;
- число файлов;
- таймаут на уровень.

Иначе «матрёшка» съест диск и время. `7z` и `binwalk` тоже стоит ограничивать.

## Если не сработало

- **Несколько сигнатур.** Файл может содержать и PNG, и ZIP — обрабатывай все, а не первую.
- **Ложные сигнатуры.** `PK` может встретиться случайно; проверяй валидность (`unzip -l`, `testzip`).
- **Обрезанные файлы.** Carving может дать «битый» хвост; иногда данные читаются частично.
- **`binwalk -e` без внешних тулов** извлечёт не всё — проверяй `_extracted`.
- **Зациклилось** — ставь лимит глубины и размера.

## Carving-инструменты

**Carving** — восстановление файлов по сигнатурам без метаданных. Три инструмента с разной логикой:

- **`binwalk`** — сканирует сигнатуры, умеет рекурсию (`-Me`), зависит от внешних распаковщиков;
- **`foremost`** — конфигурируемый carving по типам (`-t`), работает по заголовку и «подошве»;
- **`scalpel`** — форк foremost, быстрее, с гибким конфигом.

```bash
foremost -t zip,png,pdf -i mystery.bin -o out/
```

`foremost` не рекурсивен по умолчанию — после извлечения прогоняй его снова по каждому файлу.

## Работа с 7z, RAR и tar

Не всё сводится к ZIP. Универсальный `7z` понимает десятки форматов:

```bash
7z l mystery.bin          # список содержимого по сигнатуре
7z x mystery.bin -oout/   # распаковать
7z x -pPASS secret.7z     # с паролем
```

Для tar-семейства: `tar tf`, `tar xf`, а для сжатых — `tar xzf`. Универсальный `bsdtar` определяет формат автоматически.

## Практика: распаковываем матрёшку

Проверим вложенность на живом примере. Соберём ZIP, внутри которого лежит ещё один ZIP:

```python
import zipfile, io
inner = io.BytesIO()
with zipfile.ZipFile(inner, "w") as z:
    z.writestr("flag.txt", "flag{nested}")
with zipfile.ZipFile("outer.zip", "w") as z:
    z.writestr("inner.zip", inner.getvalue())
o = zipfile.ZipFile("outer.zip")
print("outer:", o.namelist())
i = zipfile.ZipFile(io.BytesIO(o.read("inner.zip")))
print("inner:", i.namelist(), i.read("flag.txt"))
```

```bash
$ python3 nested.py
outer: ['inner.zip']
inner: ['flag.txt'] b'flag{nested}'
```

На реальной задаче такую матрёшку удобнее вскрывать циклом: пока `file` на очередном слое говорит «Zip archive», распаковывай и повторяй. `7z` делает это рекурсивно, а `binwalk -e` вытаскивает все вложенные образы сразу — но осторожно с **zip-бомбами**: проверяй заявленный размер перед распаковкой.

## Что мы теперь знаем

1. Данные прячут **слоями**: архив в изображении в архиве.
2. Доверяй **содержимому** (`file`, `xxd`), а не расширению.
3. Многие форматы допускают **appended**-данные за своим маркером конца.
4. `binwalk -Me` и свой скрипт распаковывают «матрёшку» рекурсивно.
5. Ограничивай глубину и размер — защита от **zip-бомб**.

## Квиз

Проверь себя.

```quiz
- question: "Какая команда binwalk рекурсивно распаковывает «матрёшку»?"
  options:
    - "binwalk -Me"
    - "binwalk -a"
    - "binwalk -l"
    - "binwalk -q"
  answer: 0
  explanation: "-M включает рекурсию (matryoshka), -e — извлечение."
- question: "Что такое полиглот-файл?"
  options:
    - "Файл, валидный одновременно как несколько форматов"
    - "Файл с двойным паролем"
    - "Зашифрованный архив"
    - "Файл нулевого размера"
  answer: 0
  explanation: "Полиглот открывается как два и более форматов."
- question: "Как проверить, под паролем ли вложенный ZIP offline?"
  options:
    - "zip2john + john/hashcat"
    - "unzip без пароля"
    - "zsteg -a"
    - "exiftool"
  answer: 0
  explanation: "zip2john извлекает хэш, john/hashcat подбирает пароль."
- question: "Чем опасна глубокая вложенность?"
  options:
    - "Zip bomb — экспоненциальный рост размера"
    - "Потеря цвета"
    - "Смена разрешения"
    - "Замена палитры"
  answer: 0
  explanation: "Рекурсивная распаковка без лимитов может забить диск."
- question: "Что проверяет `zipfile.testzip()`?"
  options:
    - "Контрольные суммы (CRC) всех файлов архива"
    - "Пароль архива"
    - "Размер архива"
    - "Имя архива"
  answer: 0
  explanation: "testzip сверяет CRC — признак валидного архива."
```

## Куда дальше

Мы научились распутывать «матрёшки». Дальше — про **архивы как носители** сами по себе: склеенные потоки, пароли, скрытые тома. А пока запомни: файл «не тот, чем кажется» — начинай с `file`, `binwalk`, `xxd`.

## Где пригодится

- **CTF:** Stego/Forensics — многоуровневые задачи, полиглоты, матрёшки.
- **Forensics:** carving и восстановление вложенных артефактов.
- **Работа:** анализ подозрительных вложений (фишинг, малварь).
