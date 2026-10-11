---
id: stego-tga-dds
title: "Стеганография в TGA и DDS: заголовки, RLE и DXT-блоки"
category: stego
parent: stego-image-formats-exotic
difficulty: medium
order: 2
tags: [stego, tga, dds, textures, rle, dxt, bc, gamedev]
prerequisites: [stego-image-formats-exotic, stego-bitplane]
useful_for:
  - "CTF Stego: игровые текстуры"
  - "Анализ ассетов игр"
  - "Reverse engineering игровых ресурсов"
estimated_minutes: 45
summary: "TGA и DDS — низкоуровневые форматы текстур: разбираем заголовки, RLE-сжатие, DXT/BC-блоки, палитру и приёмы извлечения скрытых данных из игровых ассетов."
---

TGA (Truevision) и DDS (DirectDraw Surface) приходят из мира игр, 3D-графики и Windows-обоев. TGA предельно прост: 18-байтный заголовок и «сырые» или RLE-сжатые пиксели, поэтому LSB работает напрямую. DDS — контейнер текстур с четырьмяCC-кодом и поддержкой **DXT/BC-сжатия** (блочное сжатие), из-за которого классический LSB по пикселям неприменим, зато свободные биты в блоках и заголовке — отличный канал. Эти форматы часто игнорируют, поэтому данные в них «переживают» типовые проверки.

## TGA: простой заголовок

TGA — 18 байт заголовка, затем опциональный ID-блок, палитра (для индексированных), затем пиксельные данные.

| Смещение | Поле | Размер | Описание |
|---|---|---|---|
| 0x00 | ID length | 1 | длина ID-блока |
| 0x01 | ColorMapType | 1 | 0/1 |
| 0x02 | ImageType | 1 | 2=RGB, 3=gray, 10/11=RLE |
| 0x03 | ColorMap spec | 5 | палитра |
| 0x08 | X/Y origin | 4 | начало |
| 0x0C | Width/Height | 4 | размеры |
| 0x10 | BPP/Descriptor | 2 | бит/пиксель + origin |

```bash
file tex.tga
# tex.tga: Targa image data - RGB - 256 x 256
identify tex.tga
# ID-блок (первые ID length байт) — частый канал
python3 -c "d=open('tex.tga','rb').read();print('IDlen',d[0],'type',d[2],'bpp',d[16]);print(d[18:18+d[0]])"
```

ID-блок — произвольные байты, которые рендереры игнорируют; туда часто пишут строку/флаг.

## DDS: заголовок и DXT/BC

DDS начинается с magic `DDS `, затем 124-байтный заголовок, за которым идут данные (или, для DX10, расширенный заголовок).

| Поле | Смещение | Описание |
|---|---|---|
| Magic | 0x00 | `DDS ` |
| dwSize | 0x04 | 124 |
| dwFlags | 0x08 | флаги (caps, height, width, pixelformat…) |
| dwHeight/Width | 0x0C/0x10 | размеры |
| dwPitchOrLinearSize | 0x14 | размер строки/данных |
| ddspf (FourCC) | 0x4C.. | `DXT1`, `DXT5`, `DX10`, `ATI2`… |

```bash
file tex.dds
# tex.dds: Microsoft DirectDraw Surface (DDS), 512 x 512, DXT5
# FourCC
python3 -c "d=open('tex.dds','rb').read();print(d[:4], 'fmt', d[0x54:0x58])"
# конвертация для визуального анализа
convert tex.dds tex.png
```

## Каналы в TGA/DDS

- **TGA ID-блок:** произвольные байты после заголовка.
- **TGA descriptor:** 8 бит, из которых часть «неиспользуемые» — можно кодировать данные.
- **TGA RLE:** длина серий — данные в «мусорных» байтах после распаковки.
- **DDS заголовок:** неиспользуемые флаги и reserved-поля.
- **DDS DXT-блоки:** 8/16-байтные блоки; неиспользуемые биты в colour-индексах.
- **Дописанные данные:** после конца пиксельных данных (как overlay).
- **Mipmap-цепочка:** лишние уровни, которые редко смотрят.

```bash
# DDS: извлечь мипмапы и проверить
convert tex.dds[0] mip0.png
# DXT-декод вручную (пример для одного блока DXT1)
python3 - <<'PY'
import struct
d=open('tex.dds','rb').read()
off=128
c0,c1,bits=struct.unpack('<HHI', d[off:off+8])
print('color0=%04x color1=%04x idx=%08x'%(c0,c1,bits))
PY
```

## Разобранный пример

CTF: `skybox.dds`.

```bash
$ python3 -c "d=open('skybox.dds','rb').read();print(d[:4], d[0x54:0x58])"
b'DDS ' b'DXT1'

$ binwalk skybox.dds
DECIMAL  HEXADECIMAL  DESCRIPTION
0        0x0          Microsoft DirectDraw Surface
163968   0x28080      Zip archive data

$ dd if=skybox.dds bs=1 skip=163968 of=hidden.zip
$ unzip -o hidden.zip && cat flag.txt
flag{dds_overlay_zip}
```

Данные были дописаны после текстуры как ZIP. Если бы не было — проверяем ID-блок (TGA) или неиспользуемые биты DXT-блоков.

```bash
# TGA: ID-блок
python3 -c "d=open('tex.tga','rb').read();print(d[18:18+d[0]])"
# LSB по пикселям TGA (несжатый)
python3 - <<'PY'
from PIL import Image
im=Image.open('tex.tga').convert('RGB')
bits=''.join(str(p[0]&1) for p in im.getdata())
print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-7,8)))
PY
```

## Краевые случаи и подводные камни

- **TGA origin:** изображение может быть снизу вверх или сверху вниз (бит 5 дескриптора) — влияет на порядок пикселей при LSB.
- **RLE-типы 10/11:** данные упакованы; «сырой» LSB даст мусор без распаковки.
- **DDS DX10:** после заголовка идёт 20-байтный DX10-заголовок (`dxgiFormat`) — смещение данных сдвигается.
- **Cubemap/volume:** DDS может содержать 6 граней или 3D-объём — несколько изображений.
- **Игровые упаковщики:** файл может быть в proprietарном контейнере с переставленными байтами — проверь `file`.

## Что дальше / решение

Пайплайн: `file`/`identify` → для TGA проверить ID-блок и дескриптор, при RLE распаковать; для DDS определить FourCC и смещение данных (учесть DX10) → `binwalk`/`grep -aboP` для overlay → `convert` в PNG и `zsteg`/StegSolve → проверить мипмапы и грани cubemap. TGA/DDS — «нишевые» форматы, и именно поэтому данные в них часто не затираются при подготовке задачи.

## Справочные таблицы

| Формат | Magic | Сжатие | LSB? |
|---|---|---|---|
| TGA (uncompressed) | (нет) | нет | да |
| TGA (RLE) | (нет) | RLE | после распаковки |
| DDS DXT1 | `DDS ` | BC1 | нет (блоки) |
| DDS DXT5 | `DDS ` | BC3 | нет |
| DDS DX10 | `DDS ` | разное | зависит |

| Инструмент | Команда | Назначение |
|---|---|---|
| file | `file x.tga` | определить тип |
| identify | `identify x.dds` | параметры |
| convert | `convert x.dds x.png` | декод |
| binwalk | `-e x.dds` | overlay/вложенные |
| grep | `-aboP` | поиск сигнатур |

## Cubemap и volume-текстуры

DDS поддерживает не только 2D-текстуры: флаги заголовка указывают на cubemap (6 граней), volume (3D) и mipmap-цепочку. Каждая грань/уровень — отдельное изображение, и данные могут быть в любой из них.

| Флаг (dwCaps2) | Значение |
|---|---|
| 0x00000200 | CUBEMAP (+X) |
| 0x00000400 | CUBEMAP (−X) |
| 0x00000800 | CUBEMAP (+Y) |
| 0x00001000 | CUBEMAP (−Y) |
| 0x00002000 | CUBEMAP (+Z) |
| 0x00004000 | CUBEMAP (−Z) |
| 0x00200000 | VOLUME |

```bash
# определить caps
python3 -c "import struct;d=open('tex.dds','rb').read();caps2=struct.unpack('<I',d[0x70:0x74])[0];print(hex(caps2))"
# извлечь все грани cubemap (ImageMagick понимает .dds[0..5])
for i in 0 1 2 3 4 5; do convert "tex.dds[$i]" "face_$i.png" 2>/dev/null; done
zsteg face_*.png
```

Практика: грани cubemap часто однотипны, и аномалия в одной из них сразу бросается в глаза при сравнении.

## DXT-декодер вручную

Понимание блочного формата помогает найти «неиспользуемые» биты. DXT1-блок — 8 байт: два 16-битных цвета (`c0`, `c1`) и 32 бита индексов (по 2 бита на пиксель). В DXT5 добавляется 8-байтный alpha-блок.

```python
import struct
def decode_dxt1_color(c):
    # RGB565 -> RGB888
    r=((c>>11)&0x1F)*255//31; g=((c>>5)&0x3F)*255//63; b=(c&0x1F)*255//31
    return r,g,b
d=open('tex.dds','rb').read(); off=128
c0,c1,bits=struct.unpack('<HHI', d[off:off+8])
print('c0',hex(c0),decode_dxt1_color(c0))
print('c1',hex(c1),decode_dxt1_color(c1))
print('idx',bin(bits))
```

Неиспользуемые/аномальные индексы (например, все нули там, где ожидается шум) — признак встроенных данных.

## Игровые упаковщики ресурсов

В играх текстуры часто лежат не «голыми» DDS/TGA, а внутри proprietарного контейнера (Unity `.assets`, Unreal `.pak`, кастомные паки). Формат контейнера нужно определить по сигнатуре.

```bash
file resource.bin
# Unity
python3 -c "print('используйте AssetStudio/UnityPy для .assets')"
# Unreal .pak
python3 -c "print('используйте UnrealPak/repak для .pak')"
# общий поиск вложенных сигнатур
binwalk resource.bin
grep -aboP 'DDS |\x00\x00\x02\x00|\x1f\x8b' resource.bin | head
```

После извлечения текстур — стандартный пайплайн: `convert`, `zsteg`, `binwalk`. Ключевой навык — распознать контейнер и достать из него носители.

## Итоговый чек-лист по TGA/DDS

1. `file`/`identify` — определить формат и сжатие.
2. TGA: проверить ID-блок и дескриптор; при RLE распаковать.
3. DDS: определить FourCC и смещение данных (учесть DX10-заголовок).
4. Проверить caps: cubemap/volume/mipmap — извлечь все уровни.
5. `binwalk`/`grep -aboP` — дописанные данные и вложенные файлы.
6. `convert` в PNG и `zsteg`/StegSolve по каждому изображению.
7. При упаковщике — распаковать контейнер и повторить с шага 1.

## Разобранный пример 2: cubemap

Задача: `env.dds` — текстура окружения (cubemap из 6 граней).

```bash
$ python3 -c "import struct;d=open('env.dds','rb').read();print(hex(struct.unpack('<I',d[0x70:0x74])[0]))"
0xfe00    # биты CUBEMAP +X..-Z

$ for i in 0 1 2 3 4 5; do convert "env.dds[$i]" "face_$i.png"; done
$ ls face_*.png
face_0.png face_1.png face_2.png face_3.png face_4.png face_5.png
$ zsteg face_2.png
b1,r,lsb,xy .. text: "flag{cubemap_face_2}"
```

Данные были только в одной грани (+Y, index 2). Такой приём коварен: если смотреть только «первую» грань, флаг пропускается. Всегда извлекайте **все** грани и mip-уровни. Дополнительно проверьте `dwCaps2` на volume-флаг (3D-текстура) и число mip-уровней в `dwMipMapCount` — там тоже могут быть данные. Помните про порядок данных: DXT-блоки идут подряд, и грани могут быть «перемешаны» при нестандартной упаковке — сверяйтесь со спецификацией и `identify`.

## Итоговый чек-лист по TGA/DDS

1. `file`/`identify` — формат и тип сжатия.
2. TGA: проверить ID-блок, дескриптор; при RLE — распаковать.
3. DDS: FourCC, смещение данных (учесть DX10-заголовок).
4. Проверить caps: cubemap/volume/mipmap — извлечь **все** уровни.
5. `binwalk`/`grep -aboP` — дописанные данные и вложенные файлы.
6. `convert` в PNG и `zsteg`/StegSolve по каждому изображению.
7. При игровом упаковщике — распаковать контейнер и повторить с шага 1.

## Квиз

```quiz
- question: "Какой канал особенно характерен для TGA?"
  options:
    - "ID-блок сразу после заголовка"
    - "PLTE-палитра"
    - "DCT-коэффициенты"
    - "iinf/iloc items"
  answer: 0
- question: "Почему в DXT-текстурах не работает обычный LSB по пикселям?"
  options:
    - "Пиксели хранятся в блочно-сжатом виде (DXT/BC)"
    - "Там нет пикселей вообще"
    - "Файл всегда зашифрован"
    - "Там нет заголовка"
  answer: 0
- question: "Как называется magic DDS?"
  options:
    - "DDS "
    - "RIFF"
    - "8BPS"
    - "WEBP"
  answer: 0
- question: "Что делать с RLE-сжатым TGA перед LSB-анализом?"
  options:
    - "Распаковать пиксели"
    - "Удалить заголовок"
    - "Сменить расширение"
    - "Добавить CRC"
  answer: 0
```

## Где пригодится

- **CTF Stego:** игровые текстуры и ассеты.
- **Reverse engineering:** разбор игровых ресурсов.
- **Работа:** пайплайн обработки текстур.
- **Форензика:** анализ графических ассетов.
