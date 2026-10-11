---
id: forensics-stego
title: "Стеганография и стегоанализ файлов"
category: forensics
parent: forensics-metadata
difficulty: medium
order: 1
tags: [stego, lsb, zsteg, steghide, stegseek, audio, png, jpg]
prerequisites: [forensics-metadata]
useful_for:
  - "CTF Forensics категория"
  - "Анализ медиафайлов"
  - "Threat Hunting (скрытые каналы)"
estimated_minutes: 40
summary: "Как прячут данные в изображениях, аудио и документах, и как их извлекать: LSB, steghide, zsteg, stegseek, спектрограммы, appended data."
---
Стеганография — это сокрытие самого факта передачи данных, в отличие от криптографии, которая скрывает лишь содержание. В форензике стегоанализ позволяет находить данные, спрятанные в изображениях, аудио, видео и документах. Этот урок — про основные методы (LSB, steghide, appended data, спектрограммы) и инструменты их извлечения: `zsteg`, `steghide`, `stegseek`, `binwalk`, `exiftool`, `ffmpeg`.

## Классификация методов

| Метод | Где | Инструмент |
|-------|-----|-----------|
| LSB (младшие биты) | PNG/BMP/WAV | `zsteg`, `stegsolve`, `stegoveritas` |
| Встраивание в JPEG (DCT) | JPEG | `outguess`, `jsteg`, `steghide` |
| Appended data | любой файл | `binwalk`, `dd`, `tail` |
| Метаданные | все | `exiftool` |
| Стегоконтейнер с паролем | JPEG/WAV/AU | `steghide`/`stegseek` |
| Спектрограмма | аудио | `sox`, `audacity`, `ffmpeg` |
| Палитра/структура | GIF/PNG | `stegsolve`, `zsteg` |

## zsteg: LSB в PNG/BMP

`zsteg` перебирает все возможные каналы и битовые плоскости, извлекая спрятанные данные без пароля.

```bash
$ zsteg image.png
[+] 1 b1,rgb,lsb,xy       .. text: "CTF{lsb_is_easy}"
[+] 1 b2,r,msb,xy         .. text: "..."
# только текст, только указанный метод
$ zsteg -a image.png              # все методы
$ zsteg -E 'b1,bgr,lsb,xy' image.png > out.bin   # извлечь конкретный
```

Флаги: `-a` (все), `-l` (список методов), `-E` (extract по маске), `-s` (пропустить «шум»), `--limit N` (ограничить длину).

## steghide и stegseek

`steghide` встраивает данные в JPEG/BMP/WAV/AU с паролем и **шифрованием**. Без пароля извлечь нельзя — но `stegseek` делает быстрый брут по словарю.

```bash
# извлечь (спросит пароль)
$ steghide extract -sf image.jpg
# без пароля — не выйдет; брут словарём
$ stegseek image.jpg /usr/share/wordlists/rockyou.txt
[i] Found passphrase: "sunshine"
[i] Extracting to "image.jpg.out"
# встроить (для тренировки)
$ steghide embed -cf cover.jpg -ef secret.txt -p pass
```

`stegseek` проверяет миллионы паролей в секунду (использует оптимизированное ядро) — это замена медленному `stegcracker`.

## Appended data: binwalk и dd

Самый простой приём — дописать данные после конца изображения. `binwalk` найдёт вторую сигнатуру, `dd` вырежет.

```bash
$ binwalk image.jpg
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             JPEG image data
54321         0xD431          Zip archive data, at least v2.0
$ dd if=image.jpg of=hidden.zip bs=1 skip=54321 status=none
$ unzip -o hidden.zip
# или просто посмотреть хвост
$ tail -c 200 image.jpg | strings
```

## Метаданные и комментарии

Данные часто прячут в EXIF, комментариях PNG (`tEXt`, `zTXt`), XMP. `exiftool` покажет всё.

```bash
$ exiftool image.jpg | grep -iE 'comment|description|title|author'
$ exiftool -b -Comment image.jpg
$ strings -n 6 image.png | head
$ pngcheck -v image.png          # покажет чанки, включая tEXt/zTXt
```

`zTXt`/`iTXt` — сжатые текстовые чанки PNG, популярный контейнер для флага.

## Аудио: спектрограммы

Аудиостего часто прячет текст как «картинку» в спектре. Постройте спектрограмму (`sox`, `ffmpeg`, `Audacity`) и посмотрите на неё.

```bash
# спектрограмма в PNG
$ sox audio.wav -n spectrogram -o spec.png
$ ffmpeg -i audio.wav -lavfi showspectrumpic=s=1024x512 spec.png
# LSB в WAV
$ python3 -c "import wave,struct; w=wave.open('a.wav'); ..."   # или stegoveritas
$ stegoveritas audio.wav
```

`stegoveritas` — мета-инструмент, прогоняющий десятки тестов (LSB, палитры, appended, метаданные) и складывающий результаты.

## Разобранный пример

Дан `stego.png`. Нужно достать флаг.

```bash
# 1. Метаданные и чанки
$ exiftool stego.png | grep -i comment
Comment: not here
$ pngcheck -v stego.png
tEXt chunk: "Comment"
# 2. Appended?
$ binwalk stego.png
0  0x0  PNG image, 800 x 600
# (ничего после IEND)
# 3. LSB
$ zsteg stego.png
[+] 1 b1,rgb,lsb,xy .. text: "CTF{lsb_in_png}"
# 4. Если бы был пароль — stegseek
$ stegseek stego.png rockyou.txt
```

Флаг найден в младших битах RGB.

## Справочная таблица

| Формат | Типичный метод | Инструмент |
|--------|----------------|-----------|
| PNG | LSB, tEXt/zTXt | zsteg, pngcheck |
| JPEG | DCT, steghide, appended | steghide, stegseek, binwalk |
| GIF | палитра, LSB | stegsolve, zsteg |
| WAV | LSB, спектр | sox, stegoveritas |
| MP3 | appended, ID3 | binwalk, exiftool |
| Документы | метаданные, скрытый текст | exiftool, oletools |

## Частые ошибки

- **Искать только LSB в JPEG** — там чаще DCT/steghide.
- **Забывать `binwalk`** — данные часто просто дописаны.
- **Не проверять метаданные** — EXIF/комментарии элементарно прячут текст.
- **Не строить спектрограмму** для аудио — текст может быть «виден» в спектре.
- **Считать steghide без пароля непроходимым** — `stegseek` ломает словарём за секунды.
- **Игнорировать порядок каналов** — `zsteg` перебирает их, ручной скрипт может ошибиться.

## Что дальше / решение

Конвейер: `exiftool` (метаданные) → `binwalk` (appended) → `zsteg` (LSB) → `stegseek` (пароль) → `stegoveritas` (мета-тесты). Связка: `forensics-metadata` (метаданные), `forensics-image-ela` (подделки), `forensics-carving` (извлечение), `forensics-file-magic` (тип).

## Дополнительные инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `stegsolve` | визуальный перебор битовых плоскостей и каналов |
| `stegoveritas` | мета-инструмент: десятки тестов разом |
| `outguess` | стего в JPEG (DCT), требует пароль |
| `jsteg`/`jphide` | стего в JPEG |
| `stegdetect` | детект наличия стего в JPEG (статистика) |
| `pngcheck` | разбор чанков PNG (tEXt/zTXt/iTXt) |
| `exiftool` | метаданные (EXIF/XMP/IPTC) |
| `Audacity`/`sox` | спектрограммы аудио |
| `mat2` | очистка/анализ метаданных |
| `zsteg` | LSB в PNG/BMP |

```bash
# stegoveritas прогоняет всё сразу
$ stegoveritas image.png
$ ls stegoveritas_image.png/     # извлечённые файлы и отчёты
# stegdetect: есть ли стего в JPEG
$ stegdetect image.jpg
image.jpg: jphide(***)
```

`stegoveritas` удобен как «первый проход»: он прогоняет метаданные, LSB, палитры, appended data, zsteg и складывает результаты в каталог.

## Стегоанализ в документах и архивах

Данные прячут не только в медиа. Документы Office (OLE/OOXML), PDF и архивы — тоже контейнеры:

- **Office**: скрытый текст белым цветом, макросы, встроенные OLE-объекты, кастомные XML-части.
- **PDF**: невидимый текст, слои, JavaScript, вложения, объекты после `%%EOF`.
- **ZIP**: дополнительные файлы, комментарии, «лишние» байты между записями.

```bash
# Office: распаковать OOXML и поискать скрытое
$ unzip -o doc.docx -d docx_unz/
$ grep -ri 'flag\|secret' docx_unz/ | head
$ python3 oletools/olevba.py doc.docm       # макросы
# PDF: объекты и потоки
$ pdf-parser.py --search flag doc.pdf
$ pdftotext -layout doc.pdf - | grep -i flag
# ZIP: посмотреть, что внутри и после
$ unzip -l a.zip && tail -c 64 a.zip | strings
```

## Методика: как не пропустить

Стеганография коварна тем, что метод заранее неизвестен. Работайте по чек-листу:

1. **Определите истинный тип** (`file -k`) — расширение врёт.
2. **Метаданные** — `exiftool -a -u -g1`, комментарии, чанки PNG.
3. **Appended data** — `binwalk`, `tail`, поиск сигнатур после конца формата.
4. **LSB** — `zsteg -a`, `stegsolve` (перебор плоскостей).
5. **Парольная стего** — `stegseek` со словарём.
6. **Аудио** — спектрограмма (`sox`), LSB в WAV.
7. **Документы** — olevba, pdf-parser, распаковка OOXML.
8. **Мета-инструмент** — `stegoveritas` как «всё сразу».
9. **Палитра/структура** — GIF/PNG аномалии (`pngcheck`, `gifsicle`).
10. **Сравнение с оригиналом** — если есть «чистая» версия, `cmp`/diff покажет изменения.

## Типовые ошибки стегоанализа

- **Пропустить appended data**, увлёкшись LSB.
- **Искать LSB в JPEG** — там скорее DCT/steghide.
- **Не строить спектрограмму** для аудио.
- **Забыть про метаданные** — самый простой контейнер.
- **Не проверять несколько каналов/битовых плоскостей** — флаг может быть в одном канале.
- **Игнорировать пароль** — steghide всегда шифрует; `stegseek` обязателен.
- **Смотреть только «картинку»**, не анализируя байты (`xxd`, `binwalk`).

## Квиз

```quiz
- question: "Какой инструмент автоматически ищет LSB-стего в PNG?"
  options:
    - "`zsteg`"
    - "`tshark`"
    - "`nmap`"
    - "`unzip`"
  answer: 0
- question: "Как извлечь скрытое в аудио, видимое только на частотах?"
  options:
    - "`strings`"
    - "спектрограмма (sox/Audacity)"
    - "`binwalk`"
    - "`exiftool`"
  answer: 1
- question: "Чем `stegseek` отличается от `steghide`?"
  options:
    - "ничем"
    - "`stegseek` брутит пароли для steghide"
    - "`stegseek` шифрует"
    - "`steghide` — это GUI"
  answer: 1
- question: "Где в PNG чаще всего лежат appended data?"
  options:
    - "до IHDR"
    - "после маркера IEND"
    - "в IDAT"
    - "в палитре"
  answer: 1
- question: "Что указывает на возможную LSB-стего?"
  options:
    - "маленький размер"
    - "аномально большой размер / аномалия энтропии"
    - "EXIF с GPS"
    - "низкая энтропия"
  answer: 1
```

## Где пригодится

- **CTF:** категории Forensics и Stego.
- **Threat Hunting:** скрытые каналы передачи данных.
- **Malware analysis:** встраивание полезной нагрузки в медиа.
- **OSINT:** скрытые сообщения в публичных файлах.
- **DLP:** обнаружение утечек через стего.
