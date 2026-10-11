---
id: stego-raw-photo
title: "Стеганография в RAW-фото: CR2/NEF/DNG, превью и MakerNote"
category: stego
parent: stego-image-formats
difficulty: medium
order: 4
tags: [stego, raw, cr2, nef, dng, tiff, makernote, preview]
prerequisites: [stego-tiff, stego-exif-xmp]
useful_for:
  - "CTF Forensics: RAW-задачи"
  - "Форензика фотографий камер"
  - "Анализ DNG и сенсорных данных"
estimated_minutes: 55
summary: "RAW-форматы (CR2/NEF/DNG) — это TIFF-контейнеры: разбираем встроенные JPEG-превью, MakerNote, сенсорные данные и приёмы извлечения скрытых сообщений."
---

RAW-фото — это «негатив» камеры: сырые сенсорные данные плюс обширные метаданные. Формально почти все RAW (Canon CR2/CR3, Nikon NEF, Adobe DNG, Sony ARW) — это **TIFF-контейнеры** со специфичными тегами и, что важно для стеганографии, со **встроенными JPEG-превью** разных размеров. Превью — это полноценная картинка внутри файла: её можно извлечь, в неё можно спрятать данные, и она часто остаётся нетронутой даже после правки основного изображения. Плюс MakerNote и «дыры» между сенсорными данными — ещё два канала.

## RAW как TIFF-контейнер

CR2/NEF/DNG начинаются как TIFF (`II*\0` или `MM\0*`), но с расширениями:

| Формат | Сигнатура | Основа |
|---|---|---|
| CR2 | `II*\0` + `CR\2\0` | TIFF с magic-маркером |
| CR3 | `ftypcrx ` | ISOBMFF (новый Canon) |
| NEF | `MM\0*` | TIFF |
| DNG | `II*\0` | TIFF + DNG-теги |
| ARW | `II*\0` | TIFF |

```bash
file photo.cr2 photo.nef photo.dng
# photo.cr2: TIFF image data, little-endian
# photo.nef: TIFF image data, big-endian
# photo.dng: TIFF image data, little-endian, DNG version 1.4

exiftool -a -u -g1 photo.nef | head -40
```

## Встроенные превью

Каждое RAW обычно содержит 1–3 JPEG-превью: маленькое (thumbnail), среднее и полноразмерное. Это готовые носители.

| Тег | Имя | Что это |
|---|---|---|
| 256/257 | ImageWidth/Height | размер основного |
| 273/279 | StripOffsets/ByteCounts | где лежат превью (часто) |
| 513/514 | JpgFromRaw / JpgFromRawLength | полный JPEG |
| 0x0201/0x0202 | ThumbnailOffset/Length | миниатюра |
| 330 | SubIFDs | поддиректории с превью |
| 50706 | DNGVersion | версия DNG |

```bash
# извлечь все встроенные JPEG-превью
exiftool -b -JpgFromRaw photo.nef > full.jpg
exiftool -b -PreviewImage photo.cr2 > preview.jpg
exiftool -b -ThumbnailImage photo.dng > thumb.jpg

# или разом все JPEG-потоки
binwalk -e photo.nef        # вытащит все JPEG-сигнатуры
grep -aboP '\xff\xd8\xff' photo.nef   # смещения всех JPEG SOI
```

## MakerNote и «дыры»

MakerNote — приватный блок производителя, часто с вложенной структурой и своими тегами. Внутри бывают серийники, счётчик затвора и просто свободное место. Сенсорные данные (основной item) тоже часто содержат padding-байты.

```bash
# вытащить MakerNote целиком и поискать строки
exiftool -b -MakerNoteCanon photo.cr2 > mn.bin
strings -n 6 mn.bin | head
# счётчик затвора, серийник
exiftool -ShutterCount -SerialNumber photo.nef
```

## Разобранный пример

CTF: `holiday.nef`, задача — найти флаг.

```bash
$ file holiday.nef
holiday.nef: TIFF image data, big-endian

$ exiftool -b -JpgFromRaw holiday.nef > raw_preview.jpg
$ zsteg raw_preview.jpg
b1,r,lsb,xy .. text: "flag{raw_embedded_preview}"
```

Флаг был в LSB **встроенного превью**: основная картинка при этом выглядела безобидно. Если превью пустое — идём дальше:

```bash
# проверить все превью и миниатюры
for t in JpgFromRaw PreviewImage ThumbnailImage; do
  exiftool -b -$t holiday.nef > "$t.jpg" 2>/dev/null && zsteg "$t.jpg";
done
# поиск дописанных данных в хвосте
binwalk holiday.nef
grep -aboP 'PK\x03\x04|flag\{' holiday.nef
```

## Краевые случаи и подводные камни

- **Порядок байт отличается по бренду:** NEF часто big-endian, CR2/DNG — little-endian. Проверяй первые байты.
- **CR3 — это ISOBMFF**, не TIFF: для него работают инструменты из урока по HEIF/AVIF, а не `tiffdump`.
- **Несколько JPEG-превью:** маленькое может быть пустым, а полноразмерное — с данными; проверяй все.
- **Огромные файлы:** RAW бывают 20–80 МБ; `strings` по всему файлу шумный — фильтруй по длине (`-n 6`) и сигнатурам.
- **ExifTool предупреждения:** `[minor] Bad format` часто означает ручную модификацию — это сигнал, что файл «трогали».

## Что дальше / решение

Пайплайн: `file` (TIFF/ISOBMFF и порядок байт) → `exiftool -a -u -g1` (все теги, включая MakerNote) → извлечь **все** встроенные JPEG (`JpgFromRaw`, `PreviewImage`, `ThumbnailImage`) → `zsteg`/StegSolve по каждому → `binwalk`/`grep -aboP` по всему файлу → при пустом результате смотреть «дыры» в сенсорных данных. RAW почти всегда отдаёт данные через превью или MakerNote, а не через LSB основной картинки.

## Справочные таблицы

| Тег | Имя | Назначение |
|---|---|---|
| 513/514 | JpgFromRaw(+Length) | полный JPEG внутри |
| 0x0201/0x0202 | ThumbnailOffset/Length | миниатюра |
| 330 | SubIFDs | поддиректории превью |
| 50706 | DNGVersion | версия DNG |
| 37500 | MakerNote | приватный блок бренда |
| 0x0111 | StripOffsets | где данные стрипа |

| Бренд | Формат | Основа | Порядок байт |
|---|---|---|---|
| Canon | CR2 | TIFF | LE |
| Canon | CR3 | ISOBMFF | BE |
| Nikon | NEF | TIFF | BE |
| Adobe | DNG | TIFF | LE |
| Sony | ARW | TIFF | LE |

## DNG-специфика и конвертация

DNG (Digital Negative) — открытый формат Adobe, тоже TIFF-контейнер, но с собственными тегами `DNGVersion` (50706), `DNGBackwardVersion`, `UniqueCameraModel`, `ColorMatrix1/2` и другими. Он удобен тем, что конвертируется стандартными инструментами, а встроенное превью описано предсказуемо.

```bash
# список DNG-тегов
exiftool -a -u -g1 -DNG:all photo.dng
# конвертировать в TIFF/PNG для визуального анализа
dcraw -T photo.dng            # создаст photo.tiff
convert photo.tiff photo.png
# или через exiftool извлечь превью
exiftool -b -PreviewImage photo.dng > preview.jpg
```

DNG часто содержит несколько IFD: основное изображение, уменьшенное превью и иногда «флэт»-кадр. Проходите всю цепочку, а не только первый IFD.

## Сравнение превью и основного изображения

Превью внутри RAW — это отдельный JPEG, который мог остаться от момента съёмки, тогда как основное изображение (или его метаданные) правили позже. Расхождение между ними — сильный сигнал.

```bash
# извлечь все версии
exiftool -b -JpgFromRaw photo.nef > full.jpg
exiftool -b -ThumbnailImage photo.nef > thumb.jpg
# сравнить по метаданным и визуально
exiftool full.jpg | grep -iE "datetime|software"
exiftool thumb.jpg | grep -iE "datetime|software"
compare full.jpg thumb.jpg diff.png 2>/dev/null
```

Если превью содержит строку/флаг, а основное — нет (или наоборот), задача решена. Иногда в превью прячут LSB-данные, а основное изображение оставляют чистым «на вид».

## Инструменты RAW-пайплайна

| Инструмент | Команда | Назначение |
|---|---|---|
| exiftool | `-b -JpgFromRaw` | извлечь полноразмерное превью |
| dcraw | `-T` | конвертировать RAW в TIFF |
| rawtherapee-cli | `-o out.jpg -j90` | пакетная конвертация |
| binwalk | `-e` | найти все JPEG-потоки |
| strings | `-n 6` | поиск строк в MakerNote |

## Практический чек-лист по RAW

1. `file` — определить TIFF это или ISOBMFF (CR3).
2. `exiftool -a -u -g1` — все теги, включая MakerNote и SubIFDs.
3. Извлечь **все** встроенные JPEG (`JpgFromRaw`, `PreviewImage`, `ThumbnailImage`).
4. Каждый JPEG прогнать через `zsteg`/StegSolve.
5. `binwalk -e` и `grep -aboP` — поиск дописанных данных.
6. Сравнить превью и основное изображение на расхождения.
7. При пустом результате — проверить «дыры» в сенсорных данных и SubIFD.

Такой чек-лист закрывает практически все RAW-задачи: данные почти всегда в превью или MakerNote.

## Практика: разбор реального NEF

Разберём типовую задачу на файл `photo.nef` от Nikon. Сначала определяем порядок байт и структуру, затем извлекаем все превью и прогоняем их.

```bash
$ file photo.nef
photo.nef: TIFF image data, big-endian

$ exiftool -b -JpgFromRaw photo.nef > full.jpg
$ exiftool -b -ThumbnailImage photo.nef > thumb.jpg
$ ls -l full.jpg thumb.jpg
-rw-r--r-- 1 user user 2456789 full.jpg
-rw-r--r-- 1 user user   12345 thumb.jpg

$ zsteg thumb.jpg
b1,b,lsb,xy .. text: "flag{nef_thumbnail_lsb}"

$ exiftool -ShutterCount -SerialNumber photo.nef
Shutter Count : 8421
Serial Number : 6012345
```

Флаг был в LSB миниатюры. Если бы миниатюра была чистой, следующий шаг — проверить `full.jpg` (полноразмерное превью), затем MakerNote и «дыры». Важный момент: у Nikon порядок байт big-endian, поэтому ручной разбор требует учёта endianness — многие скрипты этого не делают и «не находят» данные. Для Canon CR2 — little-endian, для CR3 — вообще ISOBMFF. Всегда проверяйте первые байты перед тем, как доверять результату «пусто».

## Частые ошибки и как их избежать

- **Игнорировать порядок байт:** NEF часто big-endian, CR2/DNG — little-endian; неверное чтение сдвигает смещения и даёт «пусто».
- **Считать RAW «одним изображением»:** внутри несколько IFD и 1–3 JPEG-превью; проверяйте все.
- **Не извлекать превью:** флаг часто именно в LSB встроенного JPEG, а не в основном изображении.
- **Пропустить MakerNote:** приватный блок содержит свободное место и кастомные теги; используйте `exiftool -b -MakerNote*`.
- **Обрабатывать CR3 как TIFF:** CR3 — это ISOBMFF; нужны инструменты из урока по HEIF/AVIF.
- **Шумный `strings`:** файлы 20–80 МБ; фильтруйте по длине (`-n 6`) и сигнатурам, иначе утонете в выводе.

Практический порядок: `file` → `exiftool -a -u -g1` → извлечь **все** встроенные JPEG → `zsteg`/StegSolve по каждому → `binwalk`/`grep -aboP` по файлу → сравнить превью и основное изображение. Такой проход закрывает и «очевидные», и неочевидные RAW-задачи.

## Квиз

```quiz
- question: "На чём основано большинство RAW-форматов?"
  options:
    - "На TIFF-контейнере"
    - "На RIFF"
    - "На ZIP"
    - "На ELF"
  answer: 0
- question: "Что такое JpgFromRaw?"
  options:
    - "Встроенное полноразмерное JPEG-превью внутри RAW"
    - "Пароль камеры"
    - "CRC-сумма"
    - "Тип сжатия"
  answer: 0
- question: "Почему CR3 обрабатывают иначе, чем CR2?"
  options:
    - "CR3 основан на ISOBMFF, а CR2 — на TIFF"
    - "CR3 не содержит изображения"
    - "CR3 всегда зашифрован"
    - "CR3 — это аудиоформат"
  answer: 0
- question: "Где часто прячут данные в RAW-задаче?"
  options:
    - "В LSB встроенного превью"
    - "В имени файла"
    - "В расширении"
    - "В размере файла"
  answer: 0
```

## Где пригодится

- **CTF Forensics:** задачи на RAW-фото и встроенные превью.
- **Форензика:** восстановление изображения и следов редактирования.
- **Bug bounty:** анализ загружаемых RAW на скрытый контент.
- **Работа:** обработка фото-пайплайнов и каталогизация.
