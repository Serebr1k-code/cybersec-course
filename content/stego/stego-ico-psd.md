---
id: stego-ico-psd
title: "Стеганография в ICO и PSD: слои, каналы и невидимые маски"
category: stego
parent: stego-image-formats-exotic
difficulty: medium
order: 2
tags: [stego, ico, psd, layers, channels, masks, photoshop]
prerequisites: [stego-image-formats-exotic]
useful_for:
  - "CTF Stego: PSD/ICO-задачи"
  - "Форензика графических редакторов"
  - "Анализ исходников дизайна"
estimated_minutes: 45
summary: "ICO хранит несколько вложенных изображений, PSD — слои, каналы и маски; разбираем, где прячут данные в этих форматах и как их извлекать."
---

ICO и PSD — два «многослойных» формата. ICO — это контейнер с несколькими растровыми изображениями разных размеров (16×16, 32×32, 256×256…), и любое из них может нести данные. PSD (Photoshop Document) — полноценный редакторский формат: слои, каналы, маски, смарт-объекты и «скрытые» слои. Для стеганографии здесь два ключевых приёма: спрятать данные в **невидимом/скрытом слое** и дописать их в **«сырые» данные канала** или после секции изображения. Формально PSD — это структура с сигнатурой `8BPS` и набором секций.

## ICO: контейнер нескольких изображений

ICO начинается с 6-байтного заголовка, за которым идёт директория записей (по 16 байт на изображение). Каждое изображение — либо BMP-данные (DIB), либо PNG (для размеров ≥256).

| Поле | Размер | Описание |
|---|---|---|
| Reserved | 2 | `0` |
| Type | 2 | `1` = ICO, `2` = CUR |
| Count | 2 | число изображений |
| Entry | 16 | width, height, colors, planes, bpp, size, offset |

```bash
file icon.ico
# icon.ico: MS Windows icon resource - 3 icons, 16x16, 32x32, 256x256
icotool -l icon.ico          # список изображений
icotool -x -i 2 icon.ico     # извлечь изображение №2
# или через ImageMagick
convert icon.ico -thumbnail 512x512 out_%d.png
```

Каждое вложенное изображение — отдельный носитель: прогони по всем `zsteg`/StegSolve, а «неиспользуемые» bpp/planes могут нести мусор.

## PSD: секции и слои

PSD имеет сигнатуру `8BPS`, версию, затем секции: Color Mode Data, Image Resources, Layer and Mask Information, Image Data. Слои описаны в Layer and Mask Information, а данные каждого слоя — в Image Data (сжатие RLE/ZIP).

| Смещение | Поле | Описание |
|---|---|---|
| 0x00 | `8BPS` | сигнатура |
| 0x04 | version | 1 = PSD, 2 = PSB (large) |
| 0x06 | reserved | 6 байт нулей |
| 0x0C | channels | число каналов |
| 0x0E | height/width/depth/color | параметры |

```bash
file image.psd
# image.psd: Adobe Photoshop Image, 800 x 600, RGB, 3 channels
exiftool -a -u -g1 image.psd
# список слоёв
psd-tools export image.psd out_dir/ 2>/dev/null   # или python-psd-tools
python3 -c "from psd_tools import PSDImage; p=PSDImage.open('image.psd'); print([(l.name,l.visible) for l in p])"
```

## Скрытые слои и маски

Самый частый приём в CTF: **слой с `visible=False`**, содержащий текст/картинку с флагом. Второй приём — данные в канале, который не отображается (например, лишний alpha-канал), или в маске слоя.

```bash
# экспортировать все слои, включая скрытые
python3 - <<'PY'
from psd_tools import PSDImage
psd=PSDImage.open('image.psd')
for i,layer in enumerate(psd):
    layer.visible = True          # принудительно включить
    try:
        layer.composite().save(f'layer_{i}_{layer.name}.png')
        print(i, layer.name, 'visible=', layer.visible)
    except Exception as e:
        print(i, layer.name, 'err', e)
PY
zsteg layer_*.png
```

## Разобранный пример

CTF: `poster.psd`.

```bash
$ python3 -c "from psd_tools import PSDImage; p=PSDImage.open('poster.psd'); print([(l.name,l.visible) for l in p])"
[('background', True), ('logo', True), ('hidden', False)]

$ python3 -c "from psd_tools import PSDImage; p=PSDImage.open('poster.psd'); p[2].composite().save('hidden.png')"
$ zsteg hidden.png
b1,rgb,lsb,xy .. text: "flag{psd_hidden_layer}"
```

Флаг был в скрытом слое `hidden`. Альтернатива — «невидимый» слой с alpha=0, который тоже нужно форсировать. Если слои пустые, проверь дописанные данные после Image Data.

```bash
# поиск дописанных данных после секции изображения
binwalk poster.psd
grep -aboP 'flag\{|PK\x03\x04' poster.psd
# ресурсы (Image Resources) — там бывают комментарии
exiftool -b -Photoshop:All poster.psd 2>/dev/null | strings | head
```

## Краевые случаи и подводные камни

- **PSB (version=2):** большие документы — те же структуры, но 64-битные размеры; часть парсеров не умеет.
- **RLE-сжатие слоёв:** «сырые» данные канала придётся распаковывать; данные могут быть в padding RLE.
- **Смарт-объекты:** внутри PSD может лежать встроенный файл (другой PSD/растр) — извлекай их отдельно.
- **ICO с PNG-записями:** для больших размеров внутри ICO лежит PNG — обрабатывай как PNG.
- **CUR:** тот же контейнер, type=2 — не пропусти.

## Что дальше / решение

Пайплайн для PSD: `file` (версия) → `psd-tools` для списка слоёв → форсировать `visible` и композитить **все** слои → `zsteg` по каждому → `binwalk`/`grep -aboP` по файлу → проверить Image Resources и встроенные смарт-объекты. Для ICO: `icotool -l`, извлечь все записи, `zsteg` по каждой. В обоих форматах ключ — не доверять «одной видимой картинке»: данных может быть в скрытом слое или вложенном изображении.

## Справочные таблицы

| Формат | Сигнатура | Ключевые структуры |
|---|---|---|
| ICO | `\x00\x00\x01\x00` | директория + DIB/PNG |
| CUR | `\x00\x00\x02\x00` | как ICO |
| PSD | `8BPS` | секции + слои/каналы |
| PSB | `8BPS` v2 | 64-битные размеры |

| Инструмент | Команда | Назначение |
|---|---|---|
| icotool | `-l` | список изображений ICO |
| icotool | `-x -i N` | извлечь запись N |
| psd-tools | `export` | экспорт слоёв |
| exiftool | `-b -Photoshop:All` | ресурсы PSD |

## PSB и большие документы

PSB (Photoshop Big) — версия формата с `version=2`, поддерживающая документы больше 30 000 пикселей. Структуры те же, но размеры 64-битные, и многие старые парсеры (включая часть версий ImageMagick) отказываются открывать PSB. Для стеганографии это означает «слепую зону»: инструмент не видит файл, а данные там есть.

```bash
xxd image.psb | head -2
# 3842 5053 0002 ...   -> '8BPS', version=2 (PSB)
exiftool -a -u -g1 image.psb        # exiftool понимает PSB
python3 -c "from psd_tools import PSDImage; print(PSDImage.open('image.psb').size)"
```

Если psd-tools не берёт PSB, обновите библиотеку или читайте секции вручную: сигнатура `8BPS`, затем 2 байта версии, 6 зарезервированных, 2 канала, 4 высота, 4 ширина, 2 глубина, 2 цветовой режим.

## Смарт-объекты и вложенные файлы

Слой-смарт-объект хранит внутри себя исходный файл (другой PSD, PNG или вектор). Это буквально «файл в файле»: извлеките его и прогоните по полному пайплайну.

```bash
# psd-tools умеет доставать smart object
python3 - <<'PY'
from psd_tools import PSDImage
psd=PSDImage.open('image.psd')
for layer in psd.descendants():
    if layer.kind == 'smartobject':
        print('smart object:', layer.name)
        with layer.smart_object.open() as f:
            open(f'so_{layer.name}.bin','wb').write(f.read())
PY
file so_*.bin
```

Вложенный файл может оказаться изображением с LSB-данными, архивом или другим PSD — рекурсивно применяйте инструменты.

## Пакетная обработка PSD

Когда слоёв много, ручной экспорт неэффективен. Скрипт ниже выгружает **все** слои (включая скрытые) и сразу прогоняет `zsteg` по каждому.

```python
import subprocess
from psd_tools import PSDImage
psd=PSDImage.open('image.psd')
for i,layer in enumerate(psd.descendants()):
    layer.visible = True
    try:
        img=layer.composite()
        p=f'L{i:02d}.png'; img.save(p)
        r=subprocess.run(['zsteg',p],capture_output=True,text=True)
        if 'text' in r.stdout or 'flag' in r.stdout.lower():
            print('HIT', p, r.stdout[:200])
    except Exception as e:
        print('skip', layer.name, e)
```

Так вы не пропустите ни один слой, а результат сразу отфильтрован.

## Чек-лист по PSD/ICO

1. `file` — PSD это или PSB (версия).
2. `psd-tools` — список слоёв и их `visible`.
3. Форсировать видимость и композитить **все** слои.
4. `zsteg`/StegSolve по каждому слою.
5. Извлечь смарт-объекты и обработать их рекурсивно.
6. `binwalk`/`grep -aboP` по файлу — дописанные данные и ресурсы.
7. Для ICO — `icotool -l`, извлечь все записи, повторить шаги 4–6.

Такой порядок покрывает и «очевидные» скрытые слои, и неочевидные вложенные файлы.

## Разобранный пример 2: ICO-записи

Задача: `app.ico`, обычная иконка.

```bash
$ icotool -l app.ico
--image 1: 16x16, 32 bpp
--image 2: 32x32, 32 bpp
--image 3: 48x48, 32 bpp
--image 4: 256x256, 32 bpp (PNG)

$ for i in 1 2 3 4; do icotool -x -i $i app.ico -o icon_$i.png 2>/dev/null; done
$ zsteg icon_4.png
b1,rgb,lsb,xy .. text: "flag{ico_png_entry}"
```

Флаг был в PNG-записи 256×256 — самой крупной. Заметьте: маленькие записи (16×16) слишком малы для полезной нагрузки, а большая PNG-запись — идеальный носитель. Если бы записей было больше, прогоняем все. Дополнительно проверяем «мусор» между записями (смещения в директории могут не покрывать весь файл) через `binwalk` и `grep -aboP`.

Второй типовой приём для ICO — использовать неиспользуемые биты `planes`/`bpp` в записи директории: рендереры их игнорируют, а данные живут. Проверяйте директорию `xxd`-ом: аномальные значения в этих полях — сигнал.

## Частые ошибки и как их избежать

- **Не форсировать видимость слоёв:** скрытый слой (`visible=False`) — самый частый канал; композитите все слои принудительно.
- **Пропустить смарт-объекты:** внутри PSD может лежать вложенный файл; извлекайте и обрабатывайте рекурсивно.
- **Игнорировать PSB:** `version=2` — те же структуры, но 64-битные размеры; часть парсеров падает.
- **RLE-паддинг:** «сырые» данные слоя могут содержать данные в padding после RLE; учитывайте при ручном разборе.
- **Смотреть только большую запись ICO:** данные бывают и в маленькой PNG-записи; прогоняйте все.
- **Не проверять хвост:** дописанные данные после Image Data (`binwalk`/`grep -aboP`) — частая находка.

Практический вывод: PSD/ICO — «многослойные» контейнеры. Пайплайн `psd-tools` (все слои, включая скрытые) → `zsteg` по каждому → смарт-объекты → `binwalk` → для ICO `icotool -l` и все записи. Не доверяйте одной видимой картинке: данные почти всегда в скрытом или вложенном элементе.

## Квиз

```quiz
- question: "Какой самый частый приём стего в PSD?"
  options:
    - "Скрытый (invisible) слой с данными"
    - "Изменение CRC"
    - "Палитра PLTE"
    - "DCT-коэффициенты"
  answer: 0
- question: "Что такое ICO по структуре?"
  options:
    - "Контейнер с несколькими вложенными изображениями (DIB/PNG)"
    - "Текстовый XML"
    - "Архив ZIP"
    - "Аудиофайл"
  answer: 0
- question: "Как принудительно показать скрытый слой в psd-tools?"
  options:
    - "Установить layer.visible = True и композитить"
    - "Удалить файл"
    - "Переименовать слой"
    - "Сменить формат"
  answer: 0
- question: "Какая сигнатура у PSD?"
  options:
    - "8BPS"
    - "RIFF"
    - "II*\\0"
    - "PK\\x03\\x04"
  answer: 0
```

## Где пригодится

- **CTF Stego:** PSD-слои и ICO-записи.
- **Форензика:** восстановление истории редактирования PSD.
- **Работа:** разбор дизайн-исходников и иконок.
- **Bug bounty:** анализ иконок и вложенных изображений.
