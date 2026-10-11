---
id: forensics-image-ela
title: "Image forensics: ELA, PRNU и обнаружение манипуляций"
category: forensics
parent: forensics-metadata
difficulty: medium
order: 2
tags: [image-forensics, ela, prnu, steganography, metadata, manipulation]
prerequisites: [forensics-metadata]
useful_for:
  - "CTF Forensics категория"
  - "OSINT / проверка подлинности"
  - "Журналистика / судебная экспертиза"
estimated_minutes: 50
summary: "Обнаружение подделок изображений: Error Level Analysis (ELA), PRNU (шум сенсора), анализ метаданных и квантования JPEG, геометрии теней и освещения."
---
Обнаружение подделок изображений — задача форензики медиа: манипуляции (вставки, клонирование, изменение) оставляют следы в сжатии, шуме и метаданных. Основные методы — Error Level Analysis (ELA), PRNU (шум сенсора), анализ метаданных и геометрии. Этот урок — про эти методы, их ограничения и инструменты.

## Error Level Analysis (ELA)

ELA повторно сжимает JPEG с известным качеством и вычисляет разницу. Области с разным «уровнем ошибки» могут указывать на вставки: изменённый фрагмент сжимался иначе и даёт другой остаток.

```bash
# ImageMagick: пересжать и вычислить разницу
$ convert original.jpg -quality 90 recompressed.jpg
$ compare -metric AE original.jpg recompressed.jpg ela.png 2>&1
# усилить разницу
$ convert original.jpg recompressed.jpg -compose difference -composite \
    -auto-level -evaluate multiply 10 ela.png
```

Ограничения: ELA **не доказательство** — высокий/низкий ELA бывает у легитимных областей (края, текст, однотонные зоны). Используйте как эвристику, а не вердикт. Инструменты: `Forensically` (веб), `FotoForensics`, `GIMP` с плагинами, `ImageMagick`.

## PRNU: шум сенсора

Каждая камера имеет уникальный **photo-response non-uniformity** (PRNU) — «отпечаток» сенсора. Он присутствует во всех снимках камеры и позволяет связать фото с устройством, а также выявить вставки (в подделанном фрагменте PRNU отсутствует/иной).

```bash
# оценка шума: разница с денойз-версией
$ convert img.jpg -wavelet-denoise 0.5 denoised.png
$ convert img.jpg denoised.png -compose difference -composite noise.png
# корреляция PRNU двух снимков (инструменты: PRNU-скрипты, MATLAB)
```

Инструменты PRNU-анализа: исследовательские реализации (Python/MATLAB), `PRNU extractor`. Требуют много снимков для надёжного отпечатка.

## JPEG: квантование и блоки

JPEG сжимает блоками 8×8 с квантованием. Повторное сохранение меняет коэффициенты; «несовпадение» блоков указывает на манипуляцию. Анализ DCT-коэффициентов и таблиц квантования (JPEG ghosts) — профессиональный метод.

```bash
# таблицы квантования
$ exiftool -jpegtables img.jpg
# «JPEG ghosts»: гистограммы DCT (исследовательские инструменты)
# определить двойное сжатие
$ jpegio img.jpg
```

## Метаданные

EXIF/XMP/IPTC содержат модель камеры, дату, GPS, ПО редактирования. Несоответствия (снимок «камерой A», но ПО «Photoshop», дата раньше модели) — индикаторы.

```bash
$ exiftool -a -u -g1 img.jpg
$ exiftool -Model -Software -DateTimeOriginal -CreateDate -ModifyDate img.jpg
$ exiftool -a -gps:all img.jpg
$ exiftool -xmp:all img.jpg
```

```bash
# проверить, не редактировалось ли
$ exiftool img.jpg | grep -iE 'Software|History|XMP'
```

Инструменты: `exiftool`, `mat2`, `exiv2`, `metadata-extractor`.

## Геометрия и освещение

Сложные подделки выдают несоответствия теней, перспективы, отражений, освещения. Это визуальный/полуавтоматический анализ: сравнение направления теней, точек схода, источников света.

```bash
# увеличение/осмотр деталей
$ convert img.jpg -crop 200x200+500+300 +repage -resize 400% zoom.png
```

## Сравнение методов

| Метод | Что выявляет | Ограничение |
|-------|--------------|-------------|
| ELA | вставки/пересохранение | много ложных |
| PRNU | связь с камерой, вставки | нужны снимки камеры |
| JPEG ghosts | двойное сжатие | сложно интерпретировать |
| Метаданные | ПО/дата/камера | легко подделать |
| Геометрия | тени/перспектива | экспертный |

## Разобранный пример

Дан `suspect.jpg`. Нужно оценить подлинность.

```bash
# 1. Метаданные
$ exiftool suspect.jpg | grep -iE 'Model|Software|DateTime|GPS'
Software: Adobe Photoshop 25.0
Model: Canon EOS 5D
# 2. ELA
$ convert suspect.jpg -quality 90 r.jpg && compare -metric AE suspect.jpg r.jpg ela.png 2>&1
$ convert suspect.jpg r.jpg -compose difference -composite -auto-level ela.png
# 3. Шум (PRNU-признаки)
$ convert suspect.jpg -wavelet-denoise 0.5 d.png && convert suspect.jpg d.png -compose difference -composite noise.png
# 4. Строки (скрытое)
$ strings -n 8 suspect.jpg | grep -iE 'flag|secret'
```

Итог: ПО Photoshop + ELA-аномалии в одной области → вероятная вставка; проверить PRNU для подтверждения.

## Частые ошибки

- **Считать ELA доказательством** — только эвристика.
- **Верить метаданным** — легко подделать/очистить.
- **Игнорировать многократное сжатие** — меняет все признаки.
- **Анализировать пересжатую копию** — работайте с оригиналом.
- **Забывать про PRNU** — самый надёжный (но требующий данных) метод.
- **Путать «необычный» артефакт с подделкой** — нужна корреляция.

## Что дальше / решение

Конвейер: `exiftool` (метаданные) → ELA (`convert`/Forensically) → PRNU (шум) → JPEG-анализ → визуальная геометрия. Связка: `forensics-metadata` (метаданные), `forensics-stego` (скрытое), `forensics-file-magic` (тип), `forensics-carving`.

## Clone detection и другие методы

**Copy-move (clone) detection** находит скопированные участки внутри одного изображения — классическая манипуляция. Метод — поиск похожих блоков (DCT/PCA-хеши).

```bash
# инструменты: image-match, исследовательские реализации copy-move
# простой признак: визуальный осмотр повторяющихся текстур
$ convert img.jpg -crop 100x100+300+200 +repage patch.png
# сравнение блоков (ImageMagick compare по патчам)
$ compare -metric RMSE patch1.png patch2.png diff.png 2>&1
```

Другие методы:
- **CFA (Color Filter Array) artifacts** — несоответствие интерполяции каналов.
- **Noise inconsistency** — разные уровни шума (вставка из другого источника).
- **Histogram analysis** — «ступеньки» от повторного сжатия.

## Инструменты и рабочий процесс

| Инструмент | Назначение |
|-----------|-----------|
| `Forensically` (веб) | ELA, clone, noise, метаданные |
| `FotoForensics` | ELA онлайн |
| `GIMP` | ручной анализ, плагины |
| `ImageMagick` | ELA/шум скриптами |
| `exiftool` | метаданные |
| `jpegio`/`jpegtran` | DCT/квантование |

```bash
# полный ELA-конвейер скриптом
$ convert in.jpg -quality 90 r.jpg
$ compare -metric AE in.jpg r.jpg null: 2>&1
$ convert in.jpg r.jpg -compose difference -composite -auto-level -evaluate multiply 8 ela.png
```

## Сводный чек-лист

1. `exiftool -a -u -g1` — метаданные, ПО, даты, GPS.
2. ELA — области с аномальным остатком.
3. PRNU/шум — несоответствие источника.
4. Clone detection — копированные фрагменты.
5. JPEG ghosts — двойное сжатие.
6. Геометрия — тени/перспектива.
7. Проверить оригинал (не пересжатую копию).

## Ограничения

- **ELA — эвристика**, не доказательство; нужна корреляция.
- **Соцсети пересжимают** изображения — все признаки меняются.
- **PRNU требует** снимков камеры для отпечатка.
- **Скриншоты/синтетика** — нет PRNU/EXIF.
- **Онлайн-инструменты** — загружают изображение на сторонний сервер (риск для чувствительных данных).

## Метаданные в деталях

EXIF содержит десятки полей: `Make`, `Model`, `Software`, `DateTimeOriginal`, `CreateDate`, `ModifyDate`, `GPS*`, `LensModel`, `ExposureTime`, `FNumber`, `ISOSpeedRatings`, `Orientation`. XMP и IPTC добавляют автора, заголовок, ключевые слова, историю редактирования.

```bash
$ exiftool -a -u -g1 img.jpg          # все группы
$ exiftool -Make -Model -Software -DateTimeOriginal -ModifyDate img.jpg
$ exiftool -a -gps:all img.jpg
$ exiftool -xmp:all img.jpg
$ exiv2 -pa img.jpg | head
```

Несоответствия: `Software` = редактор при «камерном» `Make`/`Model`; `ModifyDate` > `DateTimeOriginal`; отсутствие `Make`/`Model` (скриншот/синтетика); несовпадение `Orientation`.

## Инструменты: сводка

| Инструмент | Задача |
|-----------|--------|
| `exiftool` | метаданные (EXIF/XMP/IPTC) |
| `ImageMagick` (`convert`/`compare`) | ELA, шум, патчи |
| `Forensically` (веб) | ELA/clone/noise GUI |
| `jpegio`/`jpegtran` | DCT/квантование |
| `exiv2` | метаданные (альтернатива) |
| `mat2` | анализ/очистка метаданных |

## Судебная ценность и осторожность

Результаты ELA/PRNU/шума — **индикаторы**, а не доказательства подделки. В отчёте формулируйте осторожно: «обнаружены признаки, согласующиеся с манипуляцией», а не «изображение подделано». Для судебного заключения нужен комплексный анализ (несколько методов, экспертная интерпретация).

## Практические приёмы

- **Работайте с оригиналом**, не с пересжатой/соцсетевой копией.
- **Сравнивайте методы** — ELA + шум + метаданные вместе убедительнее.
- **Фиксируйте хеш** изображения до анализа.
- **Не загружайте чувствительные файлы** в онлайн-сервисы.
- **Учитывайте пересжатие** — оно искажает ELA/JPEG-признаки.
- **Проверяйте xattr/alternate** — данные могут быть вне EXIF.

## Квиз

```quiz
- question: "Что показывает Error Level Analysis (ELA)?"
  options:
    - "пароль к файлу"
    - "области с иным уровнем ошибки сжатия, вероятная правка"
    - "скрытый текст"
    - "шум сенсора"
  answer: 1
- question: "Что такое PRNU?"
  options:
    - "формат JPEG"
    - "уникальный шум сенсора камеры"
    - "тип сжатия"
    - "метаданные EXIF"
  answer: 1
- question: "Какой EXIF-тег часто выдаёт редактирование?"
  options:
    - "Software (например, Adobe Photoshop)"
    - "DateTimeOriginal"
    - "Make"
    - "Model"
  answer: 0
- question: "О чём говорит несовпадение таблиц квантования в одном JPEG?"
  options:
    - "файл сжат один раз"
    - "вероятная склейка/пересохранение частей"
    - "файл пуст"
    - "это PNG"
  answer: 1
- question: "Каким инструментом искать LSB-стего в PNG?"
  options:
    - "zsteg"
    - "exiftool"
    - "pdfinfo"
    - "readpst"
  answer: 0
```

## Где пригодится

- **CTF:** stego и задачи на подделку изображений.
- **OSINT:** проверка подлинности фото, геолокация.
- **Журналистика:** верификация пользовательских медиа.
- **Судебная экспертиза:** доказательство/опровержение подделки.
- **Анализ инцидентов:** проверка приложенных к фишингу изображений.
