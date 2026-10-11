---
id: stego-gif
title: "Стеганография в GIF: кадры, тайминги и палитры"
category: stego
parent: stego-container-formats
difficulty: easy
order: 3
tags: [stego, gif, frames, timing, palette, animation]
prerequisites: [stego-image-tools, stego-palette]
useful_for:
  - "CTF Stego — GIF-анимации"
  - "Анализ покадровых различий"
  - "Forensics: скрытые данные в анимации"
estimated_minutes: 35
summary: "Каналы сокрытия в GIF: скрытые кадры, задержки между кадрами, палитры отдельных кадров, различия между кадрами и восстановление из повреждённых файлов."
---

GIF — палитровый формат с поддержкой анимации. Каждый кадр имеет свою палитру (до 256 цветов) и задержку. Каналы: скрытые/лишние кадры, тайминги (задержки кодируют биты), палитры (порядок/значения), различия между кадрами, дописанные данные после конца GIF, а также LSB в индексах палитры.

## Разбор кадров

```bash
# все кадры
convert animation.gif frames/frame_%03d.png
# или
ffmpeg -i animation.gif frames/%03d.png
# информация о кадрах/задержках
identify -verbose animation.gif | grep -iE "delay|scene|colors"
gifsicle --info animation.gif
```

## Тайминги как канал

Задержка кадра (в сотых долях секунды) может кодировать биты (например, 10=0, 20=1).

```bash
# извлечь задержки
identify -format "%s %T\n" animation.gif
# → последовательность задержек → биты
```

## Палитры и кадры

- **Скрытый кадр:** последний/лишний кадр с данными.
- **Палитра:** порядок цветов или LSB индексов несут данные (для палитровых форматов LSB пикселей = индексы).
- **Различия кадров:** XOR соседних кадров выявляет скрытое.
- **Дописанные данные:** `binwalk`, `grep -abo GIF89a`.

## Повреждённые GIF

Иногда файл «битый» намеренно: восстановите кадры (`convert`/`gifsicle`), проверьте обрезанные данные.

## Разобранный пример

CTF: GIF-анимация. Пентестер:
1. `identify -format "%s %T\n"` → задержки двух значений → биты → флаг.
2. Или `convert` → последний кадр содержит текст.

## Частые ошибки

- Смотреть анимацию, не разбирая на кадры.
- Не проверять задержки (частый канал).
- Игнорировать палитру каждого кадра.
- Забывать про дописанные данные после GIF.

## Что делать дальше

- **Задержки двух значений** → биты → декодируйте.
- **Лишний кадр** → посмотрите его.
- **Палитра** → LSB индексов/порядок.
- **Повреждён** → восстановите и проверьте хвост.

## Полная структура GIF (byte-level)

GIF — это поток блоков, и каждый блок — потенциальный канал. Знание точной структуры позволяет вручную вырезать данные там, где автоинструменты слепы.

| Блок | Байт-маркер | Что внутри | Стего-канал |
|------|-------------|------------|-------------|
| Header | `GIF87a`/`GIF89a` | версия | — |
| Logical Screen Descriptor | — | ширина, высота, флаг GCT, фон, aspect | aspect/фон как канал |
| Global Color Table | — | до 256 цветов (3 байта/цвет) | порядок/LSB цветов |
| Application Extension | `0x21 0xFF` | NETSCAPE loop count | счётчик циклов как канал |
| Comment Extension | `0x21 0xFE` | произвольный текст | **текст-флаг напрямую** |
| Graphic Control Extension | `0x21 0xF9` | задержка, прозрачность, disposal | **задержка как канал** |
| Image Descriptor | `0x2C` | позиция, размер кадра, флаг LCT | локальная палитра |
| Local Color Table | — | палитра кадра | порядок/LSB |
| Image Data | LZW min code size + sub-blocks | сжатые пиксели | LSB индексов |
| Trailer | `0x3B` | конец | **данные после него** |

```bash
# Найти все блоки вручную
xxd animation.gif | grep -iE '21 f9|21 fe|21 ff|2c|3b'
# Прочитать комментарий (частый канал)
strings -a animation.gif | head
# Посмотреть application extension (NETSCAPE loop)
xxd animation.gif | grep -i '21 ff'
```

## Разбор кадров: полный набор инструментов

```bash
# ImageMagick — кадры + метаданные
convert animation.gif frames/frame_%03d.png
identify -verbose animation.gif | grep -iE "delay|scene|colors|dispose"
# gifsicle — точный разбор, ре-тайминг, сборка
gifsicle --info animation.gif
gifsicle --explode animation.gif          # каждый кадр в отдельный .gif
gifsicle -b -d 10 animation.gif           # установить задержку 10 (100ms)
# ffmpeg — кадры и анализ
ffmpeg -i animation.gif frames/%04d.png
ffmpeg -i animation.gif -vf "fps=25" out.mp4
# GIMP / ezgif.com — визуальный покадровый просмотр
```

Ключевой приём: посмотреть **все** кадры, включая те, что «не успевают» показаться (задержка 0), и последний кадр — там часто текст или QR.

## Тайминги как канал: полный декодер

Задержка в Graphic Control Extension — 2 байта, в сотых долях секунды. Схема: 10 → 0, 20 → 1 (или порог).

```bash
# Список задержек всех кадров
identify -format "%s %T\n" animation.gif
```

```python
from PIL import Image, ImageSequence
im = Image.open('animation.gif')
delays = [f.info.get('duration', 0) for f in ImageSequence.Iterator(im)]
# порог: медиана; выше — 1, ниже — 0
import statistics
med = statistics.median(delays)
bits = ''.join('1' if d > med else '0' for d in delays)
# попробовать оба порядка бит и сгруппировать по 8
for order in (bits, bits[::-1]):
    out = bytes(int(order[i:i+8], 2) for i in range(0, len(order) - 7, 8))
    print(repr(out))
```

Варианты: задержки могут кодировать Морзе (короткая/длинная пауза), или несколько бит на кадр при более чем двух значениях задержки (тогда — база-N).

## Палитры: индексы, LSB и ремаппинг

В GIF пиксель хранится как **индекс** в палитре (0..255). Поэтому LSB «пикселей» = LSB индексов — а не цветов. Часто этим и объясняется, почему обычный RGB-LSB ничего не даёт.

```python
from PIL import Image
im = Image.open('animation.gif')
pal = im.getpalette()                      # [r,g,b, r,g,b, ...]
idx = list(im.convert('P').getdata())      # индексы
bits = ''.join(str(i & 1) for i in idx)
print(bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8)))
# LSB каналов самой палитры
pbits = ''.join(str(c & 1) for c in pal)
print(bytes(int(pbits[i:i+8], 2) for i in range(0, len(pbits) - 7, 8)))
```

Каналы палитры: порядок цветов (перестановка кодирует данные), «неиспользуемые» записи палитры за пределами числа цветов, дубликаты цветов с разными LSB.

## Скрытые и лишние кадры

- **Кадр с задержкой 0** — визуально не появляется, но данные в нём есть.
- **Кадр «за» видимым** — последний кадр может быть полным флагом/QR.
- **Смещённый кадр** — Image Descriptor задаёт позицию; кадр может быть нарисован за пределами экрана.
- **Disposal method** — способ очистки кадра (0..3) тоже может кодировать биты.

```bash
gifsicle --explode animation.gif && ls frame*
# затем каждый кадр прогнать через zsteg/binwalk
for f in frame*; do zsteg "$f"; done
```

## Дописанные данные и polyglot-хвосты

После трейлера `0x3B` может лежать ZIP/PNG/текст. Это классический «appended data»-канал.

```bash
binwalk animation.gif
grep -abo $'\x3b' animation.gif         # найти трейлер
tail -c +N animation.gif > tail.bin     # вырезать хвост после N
file tail.bin && binwalk tail.bin
# Polyglot: GIF+ZIP, GIF+PDF
unzip -l animation.gif 2>/dev/null
```

## Разобранные примеры (три сценария)

**Сценарий 1 — тайминги.** `identify -format "%s %T\n"` даёт две задержки (10 и 20). Медианный порог → биты → ASCII-строка → флаг.

**Сценарий 2 — скрытый кадр.** Анимация из 2 видимых кадров, но `gifsicle --info` показывает 3. `--explode` → третий кадр содержит текст-флаг.

**Сценарий 3 — палитра.** Обычный RGB-LSB молчит, а LSB индексов (`convert('P').getdata()`) даёт текст. Причина — палитровый формат.

## Частые ошибки и отладка

- **Смотреть анимацию глазами** — кадры/тайминги не видны.
- **Искать LSB в RGB** — в GIF данные в индексах палитры.
- **Не проверять задержки** — самый частый канал.
- **Игнорировать хвост** после `0x3B`.
- **Не смотреть последний/нулевой кадр.**
- **Отладка:** если текст «съезжает» — попробуйте порядок бит (MSB↔LSB), выравнивание (offset 0..7), пропуск первых кадров.

## Что делать дальше / дерево решений

1. `identify -format "%s %T\n"` → две-три задержки? → декодируйте тайминги.
2. `gifsicle --info` → больше кадров, чем видно? → `--explode`, смотрите лишние.
3. `zsteg` молчит по RGB? → извлеките LSB **индексов** палитры.
4. Ничего? → `binwalk`/`strings` — комментарий и хвост.
5. Повреждён? → `gifsicle --repair`/`convert`, затем снова с п.1.

## Квиз

```quiz
- question: "Что может кодировать биты в GIF?"
  options:
    - "Задержки между кадрами"
    - "Расширение файла"
    - "Имя файла"
    - "DPI"
  answer: 0
  explanation: "Тайминги кадров — частый канал в анимации."
- question: "Как разложить GIF на кадры?"
  options:
    - "convert animation.gif frames/frame_%03d.png"
    - "jadx animation.gif"
    - "zsteg animation.gif"
    - "mmls animation.gif"
  answer: 0
  explanation: "ImageMagick извлекает кадры."
- question: "Что такое палитра GIF?"
  options:
    - "Набор до 256 цветов для кадра"
    - "Размер файла"
    - "Задержка"
    - "Метаданные"
  answer: 0
  explanation: "GIF палитровый; индексы могут нести данные."
- question: "Чем выявить различия между кадрами?"
  options:
    - "XOR/compare соседних кадров"
    - "Открыть в браузере"
    - "Сменить цвет"
    - "Переименовать"
  answer: 0
  explanation: "Попиксельная разница выявляет скрытое."
- question: "Где искать дописанные данные в GIF?"
  options:
    - "После конца GIF (binwalk)"
    - "В имени"
    - "В DPI"
    - "В комментарии ОС"
  answer: 0
  explanation: "Данные после конца файла — классический канал."
```

## Где пригодится

- **CTF Stego:** GIF-анимации.
- **Forensics:** скрытые данные в анимации.
- **Bug bounty:** нестандартные каналы.
- **Работа:** анализ медиа.
