---
id: stego-flac-alac
title: "Стеганография в FLAC и ALAC: блоки метаданных, APPLICATION и PADDING"
category: stego
parent: stego-module-codecs-audio
difficulty: medium
order: 2
tags: [stego, flac, alac, metadata-block, application, padding, vorbis-comment]
prerequisites: [stego-midi]
useful_for:
  - "CTF Stego: задачи на lossless-аудио"
  - "Работа: аудиоархивы и плееры"
  - "Форензика: скрытые данные в метаданных"
estimated_minutes: 17
summary: "Разбираем FLAC как поток блоков метаданных: STREAMINFO, APPLICATION, PADDING, VORBIS_COMMENT, PICTURE. Показываем, как PADDING/APPLICATION-блоки и Vorbis-комментарии становятся носителем, и как читать их вручную."
lab:
  kind: shell
  title: "Практика: APPLICATION-блок во FLAC"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, song.flac, flac.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "FLAC начинается с ASCII `fLaC`."
    - "Блок: `1 байт (last-flag + тип) + 3 байта длины (big-endian) + данные`."
    - "Тип `2` — APPLICATION."
    - "`python3 flac.py | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается

`song.flac` — lossless-аудио. В отличие от MP3, здесь звук сохранён без потерь, а
сверху лежат **блоки метаданных**. Эти блоки никто не «слушает». С них и начнём: в
FLAC закладка чаще всего лежит не в сэмплах, а в одном из таких блоков.

## Наш пример: файл song.flac

```bash
file song.flac
xxd -l 80 song.flac
```

```text
song.flac: FLAC audio bitstream data, 16 bit, stereo, 44.1 kHz
00000000: 664c 6143 0000 2200 0000 0000 0000 0000  fLaC..".........
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0082 0000 136e  ...............n
00000040: 746f 7b66 6c34 635f 3470 705f 626c 3063  to{fl4c_4pp_bl0c
```

Первые 4 байта — `fLaC`. Дальше идут блоки метаданных. Видим ASCII `nto{...}` — значит,
закладка в блоке. Разберём структуру.

## Шаг 1: заголовок блока метаданных

FLAC-файл после `fLaC` состоит из цепочки блоков. Каждый блок начинается с 4-байтного
**заголовка**:

```
[ 1 байт: последний? (бит 7) + тип (биты 0..6) ]
[ 3 байта: длина данных, big-endian ]
```

Типы блоков:

- `0` — **STREAMINFO** (обязательный, всегда первый; 34 байта: частота, каналы,
  разрядность, общее число сэмплов).
- `1` — **PADDING** (пустое место для будущих тегов).
- `2` — **APPLICATION** (данные конкретного приложения; первые 4 байта — ID).
- `3` — **SEEKTABLE** (таблица точек перемотки).
- `4` — **VORBIS_COMMENT** (теги: исполнитель, альбом и т.п.).
- `5` — **CUESHEET** (разметка CD).
- `6` — **PICTURE** (обложка).

В нашем файле первый блок: байт `00` → последний=0, тип=0 (STREAMINFO), длина
`00 00 22` = 34. Затем 34 байта данных. Следующий блок: байт `82` → бит 7=1
(последний), тип=2 (**APPLICATION**), длина `00 00 13` = 19. Дальше — `nto{...}`.

## Шаг 2: почему APPLICATION/PADDING — идеальное место

Спецификация FLAC разрешает приложению хранить в `APPLICATION`-блоке любые данные,
помеченные 4-байтным ID. Плееры их не показывают. `PADDING` — вообще «пустое место»:
некоторые инструменты добавляют его, чтобы потом дописывать теги без перезаписи всего
файла. Оба блока — легальная «серая зона» для закладок.

## Шаг 3: читаем блоки вручную

```bash
python3 - <<'PY'
d = open('song.flac','rb').read()
assert d[:4] == b'fLaC'
i = 4
while i < len(d):
    hdr = d[i]
    last = hdr >> 7
    typ = hdr & 0x7f
    ln = int.from_bytes(d[i+1:i+4], 'big')
    body = d[i+4:i+4+ln]
    print(typ, ln, body[:24])
    i += 4 + ln
    if last:
        break
PY
```

```text
0 34 b'\x00\x00...'
2 19 b'nto{fl4c_4pp_bl0ck}'
```

Тип `2`, длина 19, тело — флаг. Достали.

## Шаг 4: VORBIS_COMMENT — тоже носитель

Теги FLAC — это блок `VORBIS_COMMENT`: vendor-строка и список пар `КЛЮЧ=значение`.
Можно спрятать флаг в поле вроде `DESCRIPTION`, `COMMENT` или в vendor:

```bash
metaflac --list song.flac | grep -iE 'comment|description'
python3 - <<'PY'
# парсинг VORBIS_COMMENT: little-endian длины!
import struct
d=open('song.flac','rb').read()
# ... найти блок типа 4 и распарсить LE-строки
PY
```

Важно: внутри `VORBIS_COMMENT` длины **little-endian**, в отличие от заголовков
блоков (big-endian). Это классическая ловушка.

## Шаг 5: инструменты и ALAC

```bash
metaflac --list song.flac        # все блоки и теги
flac -t song.flac                # проверка целостности
exiftool song.flac
binwalk song.flac
```

**ALAC** — это lossless-кодек Apple, обычно в контейнере MP4 (`.m4a`). Блоков
метаданных, как во FLAC, там нет; вместо них — ISOBMFF-боксы `moov`/`meta`/`ilst`.
Разбирать ALAC надо как MP4 (см. урок про AVIF).

## Шаг 6: PADDING-блок глубоко

`PADDING` — это блок, который содержит только нули. Его добавляют, чтобы потом
дописывать теги без полной перезаписи файла: место уже зарезервировано. Для
стеганографии это идеальный носитель: если внутри padding-блока вместо нулей лежат
осмысленные байты, это сразу заметно — и это явная закладка.

```bash
python3 - <<'PY'
d = open('song.flac','rb').read()
i = 4
while i < len(d):
    typ = d[i] & 0x7f
    ln = int.from_bytes(d[i+1:i+4],'big')
    if typ == 1:
        body = d[i+4:i+4+ln]
        nonzero = bytes(b for b in body if b != 0)
        print('padding non-zero:', nonzero[:64])
    i += 4 + ln
PY
```

Если `padding non-zero` непустой — внутри спрятано сообщение.

## Шаг 7: VORBIS_COMMENT по шагам

Разберём блок `4` подробно, потому что в нём чаще всего лежит флаг. Формат:

```
vendor_length(4, LE)
vendor_string(vendor_length)
comment_count(4, LE)
[ comment_length(4, LE) + comment ] * comment_count
```

Комментарий — `КЛЮЧ=значение`, ключ без пробелов, значение произвольное. `metaflac
--list --block-type=VORBIS_COMMENT` покажет их человекочитаемо. Но если ключ
нестандартный, `metaflac` может его просто вывести как есть — поэтому ручной парсер
надёжнее для CTF.

## Шаг 8: PICTURE-блок как контейнер

Блок `6` (`PICTURE`) содержит обложку: MIME-тип, описание, размеры и сами байты
картинки. Внутрь картинки можно встроить ещё один файл (polyglot), а в поле
`description` — текст. Это двухуровневая закладка: сначала смотришь `PICTURE`, потом
разбираешь вложенное изображение.

## Шаг 9: сравнение lossless-форматов

| Формат | Контейнер | Метаданные | Где искать |
|---|---|---|---|
| FLAC | блоки после `fLaC` | `VORBIS_COMMENT`/`APPLICATION` | блоки, padding, appended |
| ALAC | ISOBMFF/MP4 | `moov`/`ilst` | боксы, `free` |
| WAV | RIFF | `LIST`/`INFO` | чанки, сэмплы |
| AIFF | IFF-чанки | `NAME`/`ANNO` | чанки |

Общий принцип один: **lossless-формат почти всегда даёт «пустые» служебные области**,
и именно там живёт закладка. Сэмпловый LSB оставь на случай, когда контейнер чист.

## Второй пример: флаг в VORBIS_COMMENT

Разберём блок комментариев на конкретном файле. Допустим, `metaflac --list` показал
нестандартный тег. Вытащим его вручную, помня про little-endian.

```bash
python3 - <<'PY'
import struct
d = open('song.flac','rb').read()
i = 4
while i < len(d):
    hdr = d[i]; typ = hdr & 0x7f
    ln = int.from_bytes(d[i+1:i+4], 'big')
    body = d[i+4:i+4+ln]
    if typ == 4:  # VORBIS_COMMENT
        p = 0
        vl = struct.unpack('<I', body[p:p+4])[0]; p += 4
        vendor = body[p:p+vl]; p += vl
        n = struct.unpack('<I', body[p:p+4])[0]; p += 4
        print('vendor:', vendor)
        for _ in range(n):
            cl = struct.unpack('<I', body[p:p+4])[0]; p += 4
            print(body[p:p+cl].decode('utf-8')); p += cl
    i += 4 + ln
PY
```

Обрати внимание: заголовок блока — big-endian, а строки внутри комментария —
little-endian. Это самая частая ошибка при разборе FLAC. Если значения «съезжают»
или длины выглядят абсурдно большими — ты перепутал порядок байтов.

## Частые ошибки при разборе FLAC

Первая ошибка — путать порядок байтов. Заголовок блока и его длина — big-endian, а
внутренние строки Vorbis-комментария — little-endian. Это не случайность: FLAC
унаследовал Vorbis-комментарии из формата Ogg, а заголовки — из собственной
спецификации. Запомни это правило и не путайся.

Вторая ошибка — считать, что `STREAMINFO` всегда 34 байта «как есть». Это правда по
длине, но внутри поля упакованы битами: частота (20 бит), каналы (3 бита), разрядность
(5 бит) и общее число сэмплов (36 бит) лежат в одних и тех же байтах. Разбирать их
наивно нельзя — нужна битовая распаковка.

Третья ошибка — останавливаться, когда `metaflac` ничего не показал. `metaflac`
отображает штатные теги; нестандартный `APPLICATION`-блок он может показать как
«application data» без деталей. Ручной парсер нужен всегда.

## Почему lossless важен для стеганографии

В lossy-формате (MP3, AAC) данные теряются при сжатии: если встроить биты в сэмплы,
кодек их «съест». В lossless (FLAC, ALAC, WAV) такого нет — байты сохраняются точно.
Поэтому в lossless-форматах сэмпловое встраивание возможно, а в lossy — нет. Именно
поэтому в FLAC стоит проверять и блоки метаданных, и сами сэмплы, а в MP3 — только
контейнер (теги) и структуру кадров.

## Итоговая стратегия поиска во FLAC

Порядок для `.flac`: прочитай `fLaC`, пройди по всем блокам и выпиши их типы и длины.
Отдельно посмотри `APPLICATION` (тип 2), `PADDING` (тип 1), `VORBIS_COMMENT` (тип 4)
и `PICTURE` (тип 6). Проверь, нет ли ненулевых байтов в padding и нет ли в application
осмысленного текста. Затем — `metaflac --list` для перекрёстной проверки и `binwalk`
для вложенных файлов.

Для `.m4a` (ALAC) тот же файл может быть ISOBMFF-контейнером — тогда обходи боксы
`moov`/`ilst`. Всегда смотри на первые байты: `fLaC` — это FLAC, `00 00 00 .. 66 74 79 70`
— это MP4-обёртка.

## Что мы теперь знаем

- FLAC — поток блоков после `fLaC`; заголовок = тип + 3-байтная длина (big-endian).
- `STREAMINFO` обязателен и первый; `APPLICATION`/`PADDING` — удобные «пустые» блоки.
- `VORBIS_COMMENT` хранит теги, но его длины little-endian.
- ALAC живёт в MP4-контейнере и разбирается как ISOBMFF.
- `metaflac --list` показывает блоки, но не заменяет ручной парсер.

## Квиз

Проверь себя.

```quiz
- question: Какие 4 байта открывают FLAC-файл?
  options:
    - "fLaC"
    - "MThd"
    - "OggS"
    - "ID3"
  answer: 0
  explanation: "FLAC начинается с ASCII fLaC, затем идут блоки метаданных."
- question: Какой тип блока FLAC хранит данные приложения?
  options:
    - "0 (STREAMINFO)"
    - "1 (PADDING)"
    - "2 (APPLICATION)"
    - "4 (VORBIS_COMMENT)"
  answer: 2
  explanation: "Тип 2 — APPLICATION, первые 4 байта данных — ID приложения."
- question: Как закодирован тип блока в первом байте его заголовка?
  options:
    - "Все 8 бит — тип"
    - "Бит 7 — последний блок, биты 0..6 — тип"
    - "Биты 0..6 — длина"
    - "Это ASCII-символ"
  answer: 1
  explanation: "Старший бит отмечает последний блок, остальные 7 — тип."
- question: В каком порядке байтов длины внутри VORBIS_COMMENT?
  options:
    - "Big-endian"
    - "Little-endian"
    - "Syncsafe"
    - "Переменная длина"
  answer: 1
  explanation: "Vorbis-комментарии используют little-endian; заголовки блоков FLAC — big-endian."
- question: Как разбирается ALAC-аудио?
  options:
    - "Как поток блоков FLAC"
    - "Как ISOBMFF/MP4-контейнер"
    - "Как MIDI-события"
    - "Как Ogg-страницы"
  answer: 1
  explanation: "ALAC обычно лежит в MP4-контейнере (.m4a) и разбирается как ISOBMFF."
```

## Куда дальше

Дальше возьмём Ogg/Opus — там не блоки, а страницы с собственным CRC, и комментарии
`OpusTags`. Пока запомни: **во FLAC сначала смотри блоки метаданных, а не сэмплы**.

## Где пригодится

- CTF Stego: задачи на `*.flac`, `APPLICATION`/`PADDING`-блоки.
- Форензика: скрытые теги и данные приложений в аудио.
- Работа: корректная запись/чтение метаданных FLAC.
