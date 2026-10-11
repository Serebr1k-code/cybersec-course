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

BMP — простой несжатый формат: заголовок (14 + 40 байт) и пиксельные данные построчно, снизу вверх, с выравниванием строк до 4 байт. Из-за отсутствия сжатия LSB-приёмы работают «как есть», а специфичные каналы — поля заголовка, padding-байты, палитра (для 8-бит BMP) и порядок строк.

## Структура

- **BITMAPFILEHEADER (14 байт):** сигнатура `BM`, размер файла, смещение данных.
- **BITMAPINFOHEADER (40 байт):** ширина, высота, бит на пиксель, сжатие.
- **Пиксели:** BGR(A), строки выровнены до 4 байт, порядок снизу вверх.
- **Палитра:** для 1/4/8-бит — таблица цветов.

## Извлечение

```bash
# базовая инфа
file image.bmp
identify -verbose image.bmp | head -30
# LSB через zsteg (поддерживает BMP)
zsteg image.bmp
# hex-анализ заголовка/padding
xxd image.bmp | head -20
xxd image.bmp | tail -20
```

```python
from PIL import Image
im = Image.open('image.bmp').convert('RGB')
bits = ''.join(str(p[0] & 1) for p in im.getdata())   # LSB красного
print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-7,8)))
```

## BMP-специфичные каналы

- **Padding:** до 3 байт на строку — часто несут данные.
- **Поля заголовка:** «неиспользуемые»/резервные поля, аномальные значения.
- **Порядок строк:** данные в порядке снизу-вверх.
- **Палитра:** LSB индексов или порядок цветов (8-бит).
- **Дописанные данные:** после конца пикселей (`binwalk`).

## Разобранный пример

CTF: BMP-файл. Пентестер:
1. `zsteg image.bmp` → LSB текст.
2. Если нет — `xxd` → аномальные поля/padding.
3. Или `binwalk` → дописанный архив.

## Частые ошибки

- Забыть про выравнивание строк (padding) — смещение LSB.
- Не учитывать порядок снизу вверх.
- Игнорировать поля заголовка.
- Пропускать дописанные данные.

## Что делать дальше

- **LSB** → zsteg/скрипт.
- **Padding/заголовок** → hex-анализ.
- **Палитра** → анализ индексов.
- **Пусто** → binwalk, дописанные данные.

## Полная структура BMP (byte-level)

BMP прост настолько, что любой байт можно посчитать вручную — а значит, найти канал, который автоинструмент пропустил.

| Поле | Смещение | Размер | Что несёт |
|------|----------|--------|-----------|
| Signature | 0x00 | 2 | `BM` |
| File size | 0x02 | 4 | размер файла (аномалия = хвост) |
| Reserved 1/2 | 0x06 | 4 | **резерв — частый канал** |
| Data offset | 0x0A | 4 | где начинаются пиксели |
| DIB header size | 0x0E | 4 | 40/108/124 (BITMAPINFOHEADER/V4/V5) |
| Width / Height | 0x12/0x16 | 4+4 | размеры |
| Planes / BPP | 0x1A/0x1C | 2+2 | 1/4/8/24/32 бита |
| Compression | 0x1E | 4 | 0=BI_RGB, 3=bitfields |
| Image size | 0x22 | 4 | размер пиксельных данных |
| DPI X/Y | 0x26/0x2A | 4+4 | **аномальный DPI = канал** |
| Colors used | 0x2E | 4 | размер палитры |

```bash
xxd image.bmp | head -4          # заголовок
xxd image.bmp | tail -4          # хвост/хвостовые байты
file image.bmp                   # базовая идентификация
identify -verbose image.bmp      # ImageMagick-метаданные
```

## Извлечение LSB с учётом padding

Главная ловушка BMP — **выравнивание строк до 4 байт**: между строками есть 1–3 «пустых» байта. Если их не пропускать, LSB-поток сдвинется и текст не прочитается.

```python
from PIL import Image
im = Image.open('image.bmp').convert('RGB')
W, H = im.size
row_bytes = W * 3
pad = (-row_bytes) % 4            # 0..3 байта padding на строку
bits = []
for y in range(H):
    for x in range(W):
        r, g, b = im.getpixel((x, y))
        bits.append(r & 1)        # канал красного; пробуйте g, b
# padding уже отброшен, т.к. работаем через пиксели, а не сырой файл
bits = ''.join(map(str, bits))
data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8))
print(data[:200])
```

Если нужен **сырой** разбор (данные в padding, а не в пикселях):

```python
raw = open('image.bmp', 'rb').read()
off = int.from_bytes(raw[0x0A:0x0E], 'little')   # data offset
W = int.from_bytes(raw[0x12:0x16], 'little')
H = int.from_bytes(raw[0x16:0x1A], 'little')
bpp = int.from_bytes(raw[0x1C:0x1E], 'little')
stride = ((W * bpp // 8) + 3) & ~3               # строка с padding
pad_bytes = [raw[off + y*stride + (W*bpp//8) : off + (y+1)*stride] for y in range(H)]
bits = ''.join(str(b & 1) for row in pad_bytes for b in row)   # LSB padding-байтов
```

## Палитра 8-бит BMP: индексы как канал

Для 1/4/8-бит BMP пиксели — индексы палитры. LSB **индексов** (а не цветов) — отдельный канал, который zsteg может не трогать.

```python
from PIL import Image
im = Image.open('image.bmp')
if im.mode == 'P':
    idx = list(im.getdata())
    bits = ''.join(str(i & 1) for i in idx)
    print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-7,8)))
    pal = im.getpalette()
    print(bytes(c & 1 for c in pal))   # LSB самой палитры
```

Каналы палитры: перестановка цветов, «мусорные» записи за пределами `colors used`, дубликаты с разными LSB.

## Битовые плоскости и визуализация

Иногда данные видны глазом, если отрисовать одну битовую плоскость.

```bash
# stegsolve — Bit Plane Slicer по каналам R/G/B/A (GUI)
# Или скриптом:
```

```python
from PIL import Image
im = Image.open('image.bmp').convert('RGB')
W, H = im.size
out = Image.new('L', (W, H))
out.putdata([(p[0] & 1) * 255 for p in im.getdata()])   # плоскость 0 красного
out.save('plane_r0.png')
```

Плоскости 0–7 каждого канала — 24 (или 32) картинки; в одной из них часто «проступает» текст/QR.

## Инструменты (полный набор)

| Инструмент | Назначение | Пример |
|------------|-----------|--------|
| `zsteg` | авто-перебор LSB/каналов (BMP поддерживается) | `zsteg image.bmp` |
| `stegsolve` | битовые плоскости, каналы, XOR (GUI) | — |
| `binwalk` | дописанные данные, встроенные файлы | `binwalk image.bmp` |
| `xxd`/`hexdump` | ручной разбор заголовка/padding | `xxd image.bmp \| head` |
| `strings` | текст в хвосте/полях | `strings -a image.bmp` |
| PIL/NumPy | свои скрипты извлечения | см. выше |

## Разобранные примеры (три сценария)

**1. Чистый LSB.** `zsteg image.bmp` находит `b1,r,lsb,xy .. text: "flag{...}"`. Готово.

**2. Padding-канал.** zsteg молчит. Ручной разбор сырого файла показывает, что padding-байты не нулевые, а их LSB дают текст.

**3. Поля заголовка.** «Reserved»/DPI аномальны; байты этих полей в нужном порядке → флаг.

## Частые ошибки и отладка

- **Забыть про padding** при ручном разборе — сдвиг потока.
- **Порядок строк снизу вверх** — при прямом чтении файла данные «перевёрнуты».
- **Проверять только канал R** — пробуйте G/B и все биты 0–7.
- **Игнорировать палитру** у 8-бит.
- **Не смотреть хвост** после пиксельных данных (`file size` vs реальный размер).
- **Отладка:** печатайте первые байты при разных offset (0–7) и каналах — правильная комбинация даёт `flag{`/`PK`/`BM` в выводе.

## Что делать дальше / дерево решений

1. `zsteg image.bmp` → текст? → готово.
2. Нет → `xxd` заголовок: аномальные reserved/DPI/размер? → декодируйте эти байты.
3. Нет → ручной LSB по всем каналам/битам/offset (см. скрипт).
4. Нет → 8-бит? проверьте LSB индексов и палитру.
5. Нет → `binwalk`/`strings` — хвост и дописанные файлы.

## Квиз

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
    - "xxd image.bmp | head"
    - "jadx image.bmp"
    - "mmls image.bmp"
    - "nm image.bmp"
  answer: 0
  explanation: "xxd выводит hex-дамп для анализа структуры."
```

## Где пригодится

- **CTF Stego:** простые BMP-задачи.
- **Forensics:** «сырые» изображения.
- **Bug bounty:** нестандартные каналы.
- **Работа:** анализ изображений.
