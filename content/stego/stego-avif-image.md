---
id: stego-avif-image
title: "Стеганография в AVIF глубоко: ISOBMFF-боксы, AV1-интра и mdat"
category: stego
parent: stego-module-codecs-image
difficulty: medium
order: 3
tags: [stego, avif, isobmff, av1, mdat, meta, box]
prerequisites: [stego-heic-avif, stego-jpegxl]
useful_for:
  - "CTF Stego: задачи на AVIF/HEIF"
  - "Работа: современные веб-изображения"
  - "Форензика: анализ MP4-подобных контейнеров"
estimated_minutes: 18
summary: "Углублённый разбор AVIF как ISOBMFF-контейнера: боксы ftyp/meta/mdat/iloc, AV1-интра-кодирование и типичные места сокрытия — произвольные боксы, свободные области и appended data."
lab:
  kind: shell
  title: "Практика: нестандартный бокс в AVIF"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, image.avif, avif.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "AVIF — это ISOBMFF: те же боксы, что в MP4."
    - "Бокс: `размер(4, big-endian) + тип(4) + данные`."
    - "Ищи бокс с типом `FLG `."
    - "`python3 avif.py | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается

`image.avif` — современное изображение. AVIF сегодня хвалят за качество при малом
размере, и он основан на **AV1** — том же кодеке, что и видео. Значит, его контейнер
устроен как видеофайл. Посмотрим, что это даёт для стеганографии: в MP4-подобных
контейнерах мест для «лишних» данных едва ли не больше, чем в PNG.

## Наш пример: файл image.avif

```bash
file image.avif
xxd -l 64 image.avif
```

```text
image.avif: ISO Media, AVIF Image
00000000: 0000 0018 6674 7970 6176 6966 0000 0000  ....ftypavif....
00000010: 6176 6966 6d69 6631 0000 000c 6d65 7461  avifmif1....meta
00000020: 0000 0000 0000 001e 464c 4720 6e74 6f7b  ........FLG nto{
00000030: 3476 3166 5f31 736f 626d 6666 5f66 6c34  4v1f_1s0bmff_fl4
```

Первые байты — `ftyp` (file type), как в MP4. Дальше `meta`, потом — бокс `FLG `,
которого в спецификации AVIF нет.

## Шаг 1: AVIF — это ISOBMFF, а не «картинка»

**ISOBMFF** (ISO Base Media File Format) — это контейнер, в котором живут MP4, HEIF,
AVIF, 3GP. Всё внутри — **боксы** одинакового вида:

```
[ размер(4, big-endian) ][ тип(4) ][ данные ]
```

Есть «контейнерные» боксы (`meta`, `moov`), внутри которых лежат другие боксы, и
«листовые» (`mdat`, `iloc`). Понимая ISOBMFF один раз, ты читаешь и MP4, и HEIC, и
AVIF.

## Шаг 2: ключевые боксы AVIF

- **`ftyp`** — тип файла: `avif` (основной бренд) и список совместимых (`mif1`, `miaf`).
- **`meta`** — метаданные: `hdlr` (тип), `iloc` (где лежат данные), `iinf`/`infe`
  (описания элементов), `iprp`/`ipco` (свойства: размер, цвет), `pitm` (главный элемент).
- **`mdat`** — «media data»: сами сжатые AV1-кадры. Именно сюда указывает `iloc`.
- **`free`/`skip`** — «свободные» области; спецификация разрешает их, и они идеальны
  для закладок: ничего не ломают.

В нашем файле есть `meta`, а `FLG ` — явно самодельный бокс. Читаем его.

## Шаг 3: парсер боксов и извлечение

```bash
python3 - <<'PY'
import struct
d = open('image.avif','rb').read()
i = 0
while i + 8 <= len(d):
    size = struct.unpack('>I', d[i:i+4])[0]
    typ = d[i+4:i+8]
    print(f'{i:>6}  {size:>6}  {typ}')
    if size == 0:
        break
    i += size
PY
```

```text
     0      24  b'ftyp'
    24      12  b'meta'
    36      30  b'FLG '
```

Три бокса. `FLG ` не из спецификации — достаём данные:

```bash
python3 - <<'PY'
import struct
d = open('image.avif','rb').read()
i = 36
size = struct.unpack('>I', d[i:i+4])[0]
print(d[i+8:i+size].decode())
PY
```

```text
nto{4v1f_1s0bmff_fl4g}
```

## Шаг 4: где ещё прячут в AVIF

- **`free` / `skip`** — штатные пустые боксы. Данные в них никто не проверяет.
- **`uuid`** — частное расширение, как в JP2.
- **`Exif` / `XMP`** — в `meta` могут быть `iinf`-элементы типа Exif/XMP.
  `exiftool -a -G1 image.avif` их покажет.
- **appended data** — хвост после последнего бокса.
- **внутри `mdat`** — LSB в декодированных AV1-кадрах или в остаточных коэффициентах
  (сложно, требует декодера).

## Шаг 5: инструменты

```bash
exiftool -a -G1 image.avif | grep -iE 'Comment|XML|Exif|Item'
mp4box -info image.avif 2>/dev/null | head
binwalk image.avif
```

`mp4box` (GPAC) показывает дерево ISOBMFF-боксов и очень помогает: он перечислит
`meta`, `iloc`, `mdat` и заметит незнакомый бокс. `ffprobe image.avif` покажет
потоковые параметры.

## Что мы теперь знаем

- AVIF — это ISOBMFF-контейнер (`ftyp`, `meta`, `mdat`) с AV1-интра внутри.
- Боксы — `размер(4, big-endian) + тип(4) + данные`.
- `free`/`skip`/`uuid`/`Exif` и appended data — типовые места закладок.
- Один парсер ISOBMFF работает и для MP4/HEIC/AVIF.
- `mp4box`/`exiftool`/`binwalk` ускоряют разбор, но не заменяют ручной парсер.

## Квиз

Проверь себя.

```quiz
- question: На каком формате-контейнере основан AVIF?
  options:
    - "RIFF"
    - "ISOBMFF"
    - "PNG chunks"
    - "EBML"
  answer: 1
  explanation: "AVIF — это ISOBMFF (ISO Base Media File Format), как MP4/HEIF."
- question: Какой бокс содержит сами сжатые AV1-данные?
  options:
    - "ftyp"
    - "meta"
    - "mdat"
    - "iloc"
  answer: 2
  explanation: "mdat — media data; iloc лишь указывает, где внутри него лежат данные."
- question: Какой штатный бокс специально предназначен для «пустых» областей и удобен для закладок?
  options:
    - "free"
    - "mdat"
    - "ftyp"
    - "hdlr"
  answer: 0
  explanation: "free/skip — свободные области; их содержимое не проверяется."
- question: В каком порядке байтов записан размер бокса в ISOBMFF?
  options:
    - "Little-endian"
    - "Big-endian"
    - "ASCII"
    - "Зависит от бренда"
  answer: 1
  explanation: "ISOBMFF использует big-endian для всех целочисленных полей."
- question: Какой инструмент покажет дерево ISOBMFF-боксов?
  options:
    - "zsteg"
    - "steghide"
    - "mp4box -info"
    - "pngcheck"
  answer: 2
  explanation: "GPAC mp4box разбирает ISOBMFF; zsteg/steghide под AVIF не заточены."
```

## Куда дальше

Следующий урок — про AV1-видео: там та же интра-кодировка, но появляются межкадровые
предсказания и motion vectors, а это уже новый носитель. Пока запомни: **AVIF — это
MP4-контейнер, и приёмы для MP4 применимы к нему один в один**.

## Где пригодится

- CTF Stego: задачи на `*.avif`, `*.heic`, нестандартные ISOBMFF-боксы.
- Работа: анализ современных веб-изображений и их метаданных.
- Форензика: разбор MP4/HEIF/AVIF одним и тем же парсером.
