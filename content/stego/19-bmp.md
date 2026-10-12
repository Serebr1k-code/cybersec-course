---
id: stego-bmp
title: "Стеганография в BMP: заголовки, padding и палитра"
category: stego
parent: stego-container-formats
difficulty: easy
order: 4
tags: [stego, bmp, header, padding, palette, raw]
prerequisites: [stego-image-tools, stego-lsb]
useful_for:
  - "CTF Stego — простые BMP-задачи"
  - "Понимание несжатых форматов"
  - "Быстрое извлечение из «сырых» картинок"
estimated_minutes: 30
summary: "Специфика BMP: несжатые пиксели, поля заголовка как канал, padding до 4 байт, палитра и простые LSB-приёмы, которые работают только на BMP."
---

## Вопрос, с которого всё начинается

Ты уже знаешь про LSB в пикселях. Но когда дело доходит до BMP, всё и проще, и хитрее одновременно. Проще — потому что BMP **несжатый**, и данные лежат прямо в байтах. Хитрее — потому что у BMP есть свои особенности: выравнивание строк и поля заголовка, которые автоинструменты пропускают.

Разберём один BMP-файл и пройдём по всем каналам.

## Наш пример: image.bmp

Сначала — что это за файл.

```
$ file image.bmp
image.bmp: PC bitmap, Windows 3.x format, 100 x 100 x 24
```

Читаем: BMP, 100×100, 24 бита на пиксель (то есть 3 байта: B, G, R). Первым делом пробуем автоматический перебор LSB — `zsteg` умеет BMP:

```
$ zsteg image.bmp
[?] b1,r,lsb,xy .. text: "flag{bmp_lsb}"
```

`zsteg` нашёл текст в младших битах канала R. Готово. Но давай разберёмся, что делать, если бы он молчал.

## Шаг 1: как устроен BMP

BMP прост настолько, что любой байт можно посчитать вручную:

| Поле | Смещение | Размер | Что несёт |
|---|---|---|---|
| Signature | 0x00 | 2 | `BM` |
| File size | 0x02 | 4 | размер файла (аномалия = хвост) |
| Reserved 1/2 | 0x06 | 4 | **резерв — частый канал** |
| Data offset | 0x0A | 4 | где начинаются пиксели |
| DIB header size | 0x0E | 4 | 40/108/124 |
| Width / Height | 0x12/0x16 | 4+4 | размеры |
| Planes / BPP | 0x1A/0x1C | 2+2 | 1/4/8/24/32 бита |
| Compression | 0x1E | 4 | 0=BI_RGB |
| Image size | 0x22 | 4 | размер пиксельных данных |
| DPI X/Y | 0x26/0x2A | 4+4 | **аномальный DPI = канал** |

Проверим заголовок и хвост:

```
$ xxd image.bmp | head -4
00000000: 424d 3670 0300 0000 0000 3600 0000 2800  BM6p......6...(.
$ xxd image.bmp | tail -4
```

Байты `BM` в начале — подпись BMP. А в полях `Reserved` и `DPI` может лежать что угодно: их никто не проверяет.

## Шаг 2: главная ловушка — выравнивание строк

BMP хранит строки пикселей **выровненными до 4 байт**. Если ширина строки не кратна 4, добавляются **padding**-байты (1–3 штуки). Их LSB — отличный канал, который автоинструменты часто не трогают.

Ещё одна особенность: строки хранятся **снизу вверх**. При прямом чтении файла картинка «перевёрнута».

Ручное извлечение LSB через Pillow (Pillow сам учитывает padding и порядок строк):

```python
from PIL import Image
im = Image.open('image.bmp').convert('RGB')
bits = ''.join(str(p[0] & 1) for p in im.getdata())   # LSB красного
data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8))
print(data[:200])
```

А если данные именно в **padding-байтах** (а не в пикселях), нужен сырой разбор:

```python
raw = open('image.bmp', 'rb').read()
off = int.from_bytes(raw[0x0A:0x0E], 'little')   # data offset
W = int.from_bytes(raw[0x12:0x16], 'little')
H = int.from_bytes(raw[0x16:0x1A], 'little')
bpp = int.from_bytes(raw[0x1C:0x1E], 'little')
stride = ((W * bpp // 8) + 3) & ~3               # строка с padding
pad = [raw[off + y*stride + (W*bpp//8) : off + (y+1)*stride] for y in range(H)]
bits = ''.join(str(b & 1) for row in pad for b in row)
```

## Шаг 3: палитра у 8-битного BMP

Для 1/4/8-бит BMP пиксели — **индексы** палитры. LSB индексов — отдельный канал, который `zsteg` может не трогать.

```python
from PIL import Image
im = Image.open('image.bmp')
if im.mode == 'P':
    idx = list(im.getdata())
    bits = ''.join(str(i & 1) for i in idx)
    print(bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8)))
    pal = im.getpalette()
    print(bytes(c & 1 for c in pal))    # LSB самой палитры
```

## Шаг 4: битовые плоскости

Иногда данные видны глазом, если отрисовать одну битовую плоскость. Плоскости 0–7 каждого канала — 24 картинки, в одной из них часто «проступает» текст или QR.

```python
from PIL import Image
im = Image.open('image.bmp').convert('RGB')
W, H = im.size
out = Image.new('L', (W, H))
out.putdata([(p[0] & 1) * 255 for p in im.getdata()])   # плоскость 0 красного
out.save('plane_r0.png')
```

Открой `plane_r0.png` — если вместо шума видна надпись, данные точно есть.

## Шаг 5: дописанное и поля заголовка

Как и в других форматах, после конца пиксельных данных можно дописать файл:

```
$ binwalk image.bmp
$ strings -a image.bmp | grep -iE 'flag|PK|http'
```

А аномальные значения полей `Reserved`/`DPI`/`File size` — отдельный канал: собери байты этих полей в нужном порядке и декодируй.

## Если не сработало

- Учти **padding** и **порядок снизу вверх** — иначе LSB-поток сдвинется.
- Пробуй не только канал R, но и G/B, и все биты 0–7.
- Для 8-битного BMP проверь палитру и индексы.
- Не забудь про хвост: сравни `File size` из заголовка с реальным размером файла.

## Что мы теперь знаем

1. BMP несжатый, поэтому LSB-приёмы работают «как есть».
2. Строки выровнены до 4 байт (padding) и хранятся снизу вверх.
3. Padding-байты и поля заголовка (`Reserved`, `DPI`) — каналы.
4. В 8-битном BMP данные могут быть в индексах палитры.
5. `zsteg` поддерживает BMP, но ручной разбор ловит то, что он пропускает.

## Шаг 6: ручной разбор заголовка и padding

Главная ловушка BMP — **выравнивание строк до 4 байт**: между строками есть 1–3 «пустых» байта. Если их не пропускать, LSB-поток сдвинется. Для **сырого** разбора (когда данные в padding, а не в пикселях):

```python
raw = open('image.bmp', 'rb').read()
off = int.from_bytes(raw[0x0A:0x0E], 'little')   # data offset
W = int.from_bytes(raw[0x12:0x16], 'little')
H = int.from_bytes(raw[0x16:0x1A], 'little')
bpp = int.from_bytes(raw[0x1C:0x1E], 'little')
stride = ((W * bpp // 8) + 3) & ~3               # строка с padding
pad = [raw[off + y*stride + (W*bpp//8): off + (y+1)*stride] for y in range(H)]
bits = ''.join(str(b & 1) for row in pad for b in row)
```

Порядок строк — **снизу вверх**: при прямом чтении файла данные «перевёрнуты».

## Шаг 7: битовые плоскости

Иногда данные видны глазом, если отрисовать одну битовую плоскость:

```python
from PIL import Image
im = Image.open('image.bmp').convert('RGB')
W, H = im.size
out = Image.new('L', (W, H))
out.putdata([(p[0] & 1) * 255 for p in im.getdata()])   # плоскость 0 красного
out.save('plane_r0.png')
```

Плоскости 0–7 каждого канала — 24 картинки; в одной из них часто «проступает» текст или QR.

## Шаг 8: инструменты

| Инструмент | Назначение | Пример |
|---|---|---|
| `zsteg` | авто-перебор LSB/каналов | `zsteg image.bmp` |
| `stegsolve` | битовые плоскости (GUI) | — |
| `binwalk` | дописанные данные | `binwalk image.bmp` |
| `xxd` | ручной разбор заголовка | `xxd image.bmp | head` |
| `strings` | текст в хвосте/полях | `strings -a image.bmp` |
| Pillow | свои скрипты | см. выше |

## Квиз

Проверь себя.

```quiz
- question: "Чем BMP отличается от PNG для стего?"
  options:
    - "BMP несжатый, LSB-приёмы работают напрямую"
    - "BMP сжимает с потерями"
    - "BMP не содержит пикселей"
    - "BMP шифрован"
  answer: 0
  explanation: "Отсутствие сжатия делает LSB тривиальным."
- question: "До скольких байт выравниваются строки BMP?"
  options:
    - "4 байта"
    - "1 байт"
    - "8 байт"
    - "16 байт"
  answer: 0
  explanation: "Каждая строка добивается до кратного 4 байтам."
- question: "В каком порядке хранятся строки пикселей BMP?"
  options:
    - "Снизу вверх"
    - "Сверху вниз"
    - "Слева направо по столбцам"
    - "Случайно"
  answer: 0
  explanation: "По умолчанию BMP хранит строки снизу вверх."
- question: "Что может нести данные кроме пикселей?"
  options:
    - "Padding, поля заголовка, палитра"
    - "Только имя файла"
    - "Только DPI"
    - "Только комментарий ОС"
  answer: 0
  explanation: "Неиспользуемые байты — удобный канал."
- question: "Какая команда покажет hex заголовка BMP?"
  options:
    - "`xxd image.bmp | head`"
    - "`jadx image.bmp`"
    - "`mmls image.bmp`"
    - "`nm image.bmp`"
  answer: 0
  explanation: "xxd выводит hex-дамп для анализа структуры."
```

## Куда дальше

Дальше — **стегоанализ**: как по статистике понять, есть ли вообще данные, ещё до извлечения. А пока запомни: в BMP LSB работает напрямую, но не забывай про padding, порядок строк снизу вверх и поля заголовка.

## Где пригодится

- **CTF (Stego):** простые BMP-задачи — быстрый способ «размяться».
- **Forensics:** «сырые» изображения и дампы.
- **Blue team:** нестандартные каналы в несжатых форматах.
- **Работа:** анализ структуры файлов.
