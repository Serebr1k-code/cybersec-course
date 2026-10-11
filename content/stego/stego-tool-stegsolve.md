---
id: stego-tool-stegsolve
title: "StegSolve, AperiSolve и StegOnline: каналы и битовые плоскости"
category: stego
parent: stego-tooling-advanced
difficulty: medium
order: 1
tags: [stego, stegsolve, aperisolve, stegonline, bitplane, channels, frames]
prerequisites: [stego-zsteg, stego-bitplane]
useful_for:
  - "CTF Stego: визуальный анализ"
  - "Быстрая проверка изображений"
  - "Онлайн-анализ без установки"
estimated_minutes: 40
summary: "Методология визуального стего-анализа: StegSolve (каналы, bit-planes, frame browser), AperiSolve и StegOnline — что смотреть, в каком порядке и как интерпретировать."
---

StegSolve, AperiSolve и StegOnline решают одну задачу: **показать то, что не видно глазом** — отдельные каналы, битовые плоскости, XOR-комбинации и кадры. Это первый инструмент, когда данные «спрятаны на виду»: текст на младшей битовой плоскости, картинка в альфа-канале или QR, проявившийся после XOR. Установка StegSolve — Java-приложение; AperiSolve и StegOnline — веб-версии того же набора операций. Уметь их использовать — базовый рефлекс в CTF Stego.

## StegSolve: интерфейс и операции

StegSolve открывает файл и предлагает меню операций. Ключевые:

| Операция | Что делает | Когда смотреть |
|---|---|---|
| Colour/Channel | R/G/B/A по отдельности | текст в одном канале |
| Bit Planes | битовые плоскости 0..7 | LSB/MSB-данные |
| Frame Browser | кадры GIF/анимации | данные в кадре |
| Image Combiner | XOR/ADD/SUB двух изображений | diff двух версий |
| Stereogram | анаглиф | редкие задачи |

```bash
# запуск (Java)
java -jar stegsolve.jar image.png
# если StegSolve нет — консольный аналог по bit-planes
python3 - <<'PY'
from PIL import Image
import numpy as np
im=np.array(Image.open('image.png').convert('RGB'))
for b in range(8):
    for c,name in enumerate('RGB'):
        plane=((im[:,:,c]>>b)&1)*255
        Image.fromarray(plane.astype('uint8')).save(f'plane_{name}_{b}.png')
print('saved 24 planes')
PY
```

## Порядок просмотра (методология)

1. **Alpha-канал:** часто пустой, но если там данные — видны сразу.
2. **Младшая битовая плоскость (bit 0)** каждого канала — классический LSB.
3. **Остальные плоскости** (1..7) — multibit-LSB и нестандартные схемы.
4. **XOR двух каналов/изображений** — проявляет скрытые слои.
5. **Frame browser** — для GIF/APNG/анимаций.

```bash
# XOR двух изображений (эквивалент Image Combiner)
python3 - <<'PY'
from PIL import Image
import numpy as np
a=np.array(Image.open('a.png').convert('RGB'))
b=np.array(Image.open('b.png').convert('RGB'))
Image.fromarray((a^b)).save('xor.png')
PY
```

## AperiSolve и StegOnline

Веб-сервисы автоматизируют рутину: AperiSolve (`aperisolve.fr`) прогоняет набор инструментов (zsteg, exiftool, binwalk, stegsolve-подобные плоскости) и показывает результат; StegOnline — браузерная реализация StegSolve (каналы, bit-planes, XOR). Полезны, когда нет локальной Java или нужно быстро.

```bash
# локальные аналоги того же набора
zsteg -a image.png                 # все каналы/комбинации
binwalk image.png                  # вложенные данные
exiftool image.png                 # метаданные
# StegOnline-подобный bit-plane через Pillow (см. выше)
```

## Frame browser: кадры

Для GIF/APNG данные часто лежат в одном кадре или в таймингах.

```bash
# разобрать GIF на кадры
convert animation.gif frame_%03d.png
# или через Pillow
python3 - <<'PY'
from PIL import Image
im=Image.open('animation.gif')
i=0
try:
    while True:
        im.seek(i); im.convert('RGB').save(f'f{i:03d}.png'); i+=1
except EOFError:
    pass
print('frames', i)
PY
zsteg f*.png
```

## Разобранный пример

CTF: `hidden.png`, на вид — градиент.

```bash
$ zsteg -a hidden.png
[!] nothing found in standard planes
$ python3 - <<'PY'
from PIL import Image; import numpy as np
im=np.array(Image.open('hidden.png').convert('RGB'))
Image.fromarray(((im[:,:,0]&1)*255).astype('uint8')).save('lsb_r.png')
PY
# lsb_r.png показывает читаемый текст -> флаг
```

Инструмент не нашёл, потому что данные были в нестандартной комбинации (например, только R-канал bit 0). StegSolve/ручной bit-plane это проявил.

## Краевые случаи и подводные камни

- **Lossy-форматы:** для JPEG битовые плоскости почти всегда шумны — не тратьте время, идите в DCT/метаданные.
- **Порядок каналов:** PIL даёт RGB, некоторые инструменты — BGR; путаница ломает XOR-анализ.
- **Масштаб:** StegSolve показывает 1:1; мелкий текст можно не заметить — увеличивай/смотри по плоскостям отдельно.
- **Онлайн-сервисы = утечка:** не заливайте чувствительные файлы на AperiSolve/StegOnline в реальном пентесте.
- **False positives:** XOR-шум похож на данные; ищи осмысленный текст, а не просто контраст.

## Что дальше / решение

Порядок: StegSolve/AperiSolve → alpha → bit-plane 0 по каналам → остальные плоскости → XOR → frame browser → при неудаче переходить к `zsteg -a`, `binwalk`, метаданным и частотным методам. Визуальный анализ — быстрый и дешёвый первый шаг, но он не заменяет форматный и частотный анализ: если картинка lossy, сразу переключайся.

## Справочные таблицы

| Инструмент | Тип | Ключевые функции |
|---|---|---|
| StegSolve | локальный (Java) | каналы, bit-planes, frames, combiner |
| AperiSolve | веб | авто-набор инструментов |
| StegOnline | веб | каналы, bit-planes, XOR |
| zsteg | CLI | перебор каналов/комбинаций |
| Pillow+numpy | скрипт | bit-planes, XOR |

| Операция | Что выявляет |
|---|---|
| Channel R/G/B/A | данные в одном канале |
| Bit plane 0 | классический LSB |
| Bit plane 7 | MSB-аномалии |
| XOR | diff двух изображений |
| Frame browser | данные в кадре |

## Stereogram и дополнительные режимы

Кроме каналов и битовых плоскостей, StegSolve умеет строить анаглифы/стереограммы и выполнять арифметику над каналами. Эти режимы реже нужны, но в «эзотерических» задачах именно они проявляют данные.

| Режим | Что делает |
|---|---|
| Stereogram | анаглиф (красно-синий) — данные в глубине |
| Image Combiner | XOR/ADD/SUB/OR/AND двух изображений |
| Channel offset | сдвиг канала на N пикселей |
| Random color map | случайная палитра — проявляет палитровые данные |

```python
# channel offset: сдвиг канала для проявления синхронизации
from PIL import Image
import numpy as np
im=np.array(Image.open('image.png').convert('RGB'))
im[:,:,2]=np.roll(im[:,:,2], shift=1, axis=1)
Image.fromarray(im).save('offset_b.png')
```

## Автоматизация bit-plane анализа

Ручной просмотр 24 плоскостей утомителен. Скрипт генерирует их и сразу ищет текстовые паттерны по каждой.

```python
from PIL import Image
import numpy as np, re
im=np.array(Image.open('image.png').convert('RGB'))
found=False
for b in range(8):
    for ci,name in enumerate('RGB'):
        plane=((im[:,:,ci]>>b)&1)*255
        # быстрый признак: горизонтальные «текстовые» полосы
        Image.fromarray(plane.astype('uint8')).save(f'p_{name}{b}.png')
        # эвристика: доля белых пикселей в узком диапазоне
        frac=plane.mean()/255
        if 0.1 < frac < 0.6:
            print('suspicious plane', name, b, 'white frac', round(frac,3))
            found=True
if not found:
    print('no obvious textual plane; try XOR/combiner')
```

## Сравнение онлайн-сервисов

| Сервис | Что делает | Плюсы | Минусы |
|---|---|---|---|
| AperiSolve | авто-набор (zsteg, exiftool, binwalk, planes) | быстро, всё сразу | утечка файла |
| StegOnline | StegSolve в браузере | без установки | ограниченный размер |
| Forensically | плоскости, магнитуда, клонирование | визуально удобно | не для бинарных каналов |
| StegSolve (local) | полный набор | приватность, скорость | требует Java |

Правило: для чувствительных файлов используйте **локальные** инструменты; онлайн-сервисы — только для публичных CTF-задач.

## Что делать, если визуальный анализ пуст

Если StegSolve/AperiSolve ничего не показали, не зацикливайтесь: переходите к систематике. Порядок: `zsteg -a` → `binwalk` → `exiftool` → форматный разбор (чанки/теги/боксы) → частотные методы (DCT/DWT) → стегоанализ (хи-квадрат/RS). Визуальный анализ — это быстрый первый шаг, а не единственный инструмент.

## Разобранный пример 2: XOR двух каналов

Задача: `noise.png`, обещано «скрыто на виду». Одиночные каналы и плоскости выглядят шумом.

```bash
$ zsteg -a noise.png
(пусто)
```

Попробуем XOR каналов — иногда данные в разнице между R и B:

```python
from PIL import Image
import numpy as np
im=np.array(Image.open('noise.png').convert('RGB')).astype(int)
xor=((im[:,:,0]^im[:,:,1])).astype('uint8')
Image.fromarray(xor).save('xor_rg.png')
# и R^B
Image.fromarray((im[:,:,0]^im[:,:,2]).astype('uint8')).save('xor_rb.png')
```

В `xor_rg.png` проявляется читаемый текст — флаг. Приём: данные встроены так, что видны только в разности каналов (например, в R записан шум, а в G — шум XOR данные). Это классический «нестандартный» канал, который не находят авто-инструменты. В StegSolve то же самое делается через Image Combiner (XOR). Порядок каналов (RGB vs BGR) критичен — если XOR не даёт результата, попробуйте перестановки и операции ADD/SUB.

## Частые ошибки и как их избежать

Визуальный анализ прост, но именно на нём чаще всего «застревают», потому что результат кажется пустым.

- **Смотрите каналы по отдельности, а не RGB вместе:** текст может быть виден только в одном канале (например, R). StegSolve/ручные плоскости это показывают.
- **Порядок каналов:** PIL — RGB, OpenCV — BGR. При XOR/combiner путаница даёт ложный результат; фиксируйте порядок явно.
- **Масштаб 1:1:** мелкий текст не виден при уменьшении; смотрите плоскости в натуральном размере и при увеличении.
- **Lossy-форматы:** для JPEG bit-planes почти всегда шумны — не тратьте время, переходите к метаданным/DCT.
- **Alpha-канал:** если он весь 255 (непрозрачный), данных там нет; если есть вариации — проверяйте в первую очередь.
- **Онлайн-сервисы:** не заливайте чувствительные файлы; для пентеста — только локальные инструменты.

Итог: визуальный анализ — быстрый фильтр, а не финальный вердикт. Если 5 минут просмотра не дали результата — переходите к `zsteg -a`, `binwalk`, метаданным и форматному разбору, иначе потеряете время на «красивом» пути.

## Итоговый чек-лист визуального анализа

1. Alpha-канал — есть ли вариации (не все 255).
2. Bit-plane 0 по каналам R/G/B — классический LSB.
3. Остальные плоскости (1..7) — multibit и нестандартные схемы.
4. XOR/ADD/SUB каналов и изображений — diff-анализ.
5. Frame browser — для GIF/APNG/анимаций.
6. Если пусто за 5 минут — перейти к `zsteg -a`, `binwalk`, метаданным, формату.
7. Lossy-форматы (JPEG) — сразу к DCT/метаданным, плоскости бесполезны.

## Квиз

```quiz
- question: "Что показывает операция Bit Planes в StegSolve?"
  options:
    - "Отдельные битовые плоскости каналов"
    - "EXIF-метаданные"
    - "CRC-суммы"
    - "Спектр аудио"
  answer: 0
- question: "Когда особенно полезен Frame Browser?"
  options:
    - "Для GIF/анимаций, где данные лежат в кадре"
    - "Для JPEG DCT"
    - "Для TIFF IFD"
    - "Для ZIP-комментариев"
  answer: 0
- question: "Почему для JPEG визуальный анализ bit-planes малоэффективен?"
  options:
    - "Артефакты сжатия делают плоскости шумными"
    - "Там нет пикселей"
    - "Файл всегда зашифрован"
    - "Там нет каналов"
  answer: 0
- question: "Чем опасны онлайн-сервисы типа AperiSolve в пентесте?"
  options:
    - "Заливка файла может быть утечкой данных"
    - "Они всегда платные"
    - "Они не работают с PNG"
    - "Они меняют файл"
  answer: 0
```

## Где пригодится

- **CTF Stego:** быстрый визуальный анализ.
- **Bug bounty:** проверка изображений на скрытый контент.
- **Форензика:** выявление аномалий в каналах.
- **Работа:** построение пайплайна анализа медиа.
