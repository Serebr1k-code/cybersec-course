---
id: stego-image-tools
title: "Инструменты для изображений: exiftool, steghide, outguess, stegseek"
category: stego
parent: stego-media-basics
difficulty: easy
order: 3
tags: [stego, image, exiftool, steghide, outguess, stegseek, metadata]
prerequisites: [stego-intro]
useful_for:
  - "Быстрое извлечение данных без написания кода"
  - "Парольная стеганография (steghide/outguess) и брут словарём"
  - "Аудит метаданных изображений и документов"
estimated_minutes: 33
summary: "Практический обзор инструментов: exiftool для метаданных, steghide и outguess для парольной стеганографии, stegseek для быстрого брута, а также stegoveritas и статический анализ."
---

## Обзор: базовый набор инструментов для изображений

Изображения — самый частый носитель в стего-задачах, поэтому набор инструментов должен быть отработан до автоматизма. Условно их делят на четыре группы: **метаданные** (`exiftool`), **парольная стеганография** (`steghide`, `outguess`, `stegseek`), **перебор каналов** (`zsteg`, `stegsolve`, `stegoveritas`) и **структурный анализ** (`binwalk`, `pngcheck`, `file`, `strings`). Правильный порядок применения экономит время: сначала дешёвые проверки, потом парольные, потом битовые.

## exiftool: метаданные всех форматов

`exiftool` читает EXIF, IPTC, XMP, комментарии, ID3 и десятки других форматов. Это первый инструмент для любого файла.

```bash
exiftool image.jpg                  # все метаданные
exiftool -a -u -g1 image.jpg        # все, включая дубликаты, сгруппировано
exiftool -b -ThumbnailImage image.jpg > thumb.jpg   # извлечь превью
exiftool -Comment image.jpg
exiftool -all= image.jpg            # УДАЛИТЬ все метаданные (не для разбора!)
```

Полезные флаги: `-a` (все теги), `-u` (неизвестные), `-g1` (группировка), `-b` (бинарный вывод тега), `-s` (короткие имена). Флаг/пароль часто лежит в `Comment`, `ImageDescription`, `UserComment`, `XP Comment`.

## steghide: парольная стеганография в JPEG/BMP/WAV

`steghide` прячет данные в JPEG, BMP, WAV, AU, используя статистику коэффициентов/сэмплов. Требует пароль (может быть пустым).

```bash
steghide info image.jpg             # есть ли встроенные данные
steghide extract -sf image.jpg      # извлечь (спросит пароль)
steghide extract -sf image.jpg -p '' # пустой пароль
steghide embed -cf cover.jpg -ef secret.txt -p pass   # встроить (для практики)
```

`steghide info` покажет, встроены ли данные и их примерный размер — это сразу подсказывает, стоит ли брутить пароль.

## outguess: ещё один JPEG-метод

`outguess` — старый, но встречающийся инструмент для JPEG. Важно: он поддерживает только JPEG (не PNG/BMP) и иногда требует ключ.

```bash
outguess -r image.jpg out.txt       # извлечь без ключа
outguess -k "key" -r image.jpg out.txt   # с ключом
outguess -k "key" -d hidden.txt -t cover.jpg out.jpg   # встроить
```

Если `steghide` не срабатывает, а файл — JPEG, попробуйте `outguess`.

## stegseek: быстрый брут пароля steghide

`stegseek` перебирает пароли к `steghide`-контейнеру со скоростью десятков тысяч в секунду (против сотен у оригинала). Незаменим, когда `steghide info` показывает наличие данных, а пароля нет.

```bash
stegseek image.jpg rockyou.txt      # брут по словарю
stegseek image.jpg                  # встроенный словарь по умолчанию
stegseek --seed image.jpg           # оценка энтропии, без брута
```

Найденный пароль и путь к извлечённому файлу печатаются в конце.

## stegoveritas и binwalk

- **`stegoveritas`** — «всё-в-одном»: метаданные, LSB, битовые плоскости, дописанное, автоматический отчёт.
- **`binwalk`** — поиск встроенных/дописанных файлов по сигнатурам; `-e` извлекает.

```bash
stegoveritas image.png              # комплексный анализ, пишет результаты в каталог
binwalk image.png
binwalk -e image.png
```

`stegoveritas` удобен как «второй проход» после ручных проверок: он может найти то, что вы пропустили.

## Сравнительная таблица

| Инструмент | Форматы | Что делает | Пароль |
|---|---|---|---|
| `exiftool` | все | метаданные | нет |
| `steghide` | JPEG/BMP/WAV | парольная стего | да |
| `outguess` | JPEG | парольная стего | иногда |
| `stegseek` | JPEG/BMP/WAV | брут `steghide` | перебор |
| `zsteg` | PNG/BMP | перебор LSB | нет |
| `stegoveritas` | многие | комплексный | нет |
| `binwalk` | все | встроенное | нет |

## Порядок применения

1. `file` + `strings` — быстрые подсказки.
2. `exiftool` — метаданные.
3. `binwalk` — встроенное/дописанное.
4. `steghide info` — есть ли парольная стего.
5. `zsteg -a` — LSB (PNG/BMP).
6. `stegseek` — брут, если есть парольная стего.
7. `stegoveritas` — комплексный добор.

## Разобранный пример

```bash
$ exiftool cat.jpg | grep -i comment
Comment : password is hunter2
$ steghide info cat.jpg
"cat.jpg": contains embedded data
$ steghide extract -sf cat.jpg -p hunter2
wrote extracted data to "secret.txt"
$ cat secret.txt
flag{steghide_with_pass}
```

Маршрут: `exiftool` дал пароль → `steghide info` подтвердил наличие данных → `steghide extract` с паролем. Без пароля здесь бы сработал `stegseek cat.jpg rockyou.txt`.

## Установка

```bash
sudo apt install -y exiftool steghide outguess binwalk pngcheck foremost
sudo gem install zsteg
pip install stegoveritas
# stegseek — из релизов на GitHub (готовый бинарь)
```

## Частые ошибки и подводные камни

- **Брутить `steghide` без `info`** — сначала проверьте, есть ли данные вообще.
- **Применять `steghide` к PNG** — он не поддерживает PNG; для PNG нужен `zsteg`/`stegsolve`.
- **Путать `steghide` и `outguess`** — разные алгоритмы, разные форматы.
- **Забыть про пустой пароль** — иногда данные встроены без пароля.
- **Открыть и пересохранить файл** — данные погибнут.
- **Не смотреть метаданные** — пароль часто прямо там.

## Итог

Правильный набор инструментов и порядок их применения важнее, чем знание экзотических методов. В 80 % задач достаточно `file`/`strings`/`exiftool`/`binwalk`/`zsteg`/`steghide`. Остальные 20 % — это нестандартные каналы, где пригодятся скрипты и понимание формата.

## Расширенные флаги exiftool и полезные трюки

`exiftool` — не только «показать метаданные». Полезные режимы:

```bash
exiftool -a -u -g1 image.jpg        # все теги, включая неизвестные, сгруппировано
exiftool -s image.jpg               # короткие (машинные) имена тегов
exiftool -json image.jpg            # вывод в JSON (удобно парсить)
exiftool -b -ThumbnailImage i.jpg > t.jpg   # извлечь превью в файл
exiftool -b -Comment i.jpg          # сырое значение тега (без интерпретации)
exiftool -trailer image.jpg         # показать данные после конца файла
exiftool -X image.jpg               # RDF/XML-представление (XMP)
exiftool -r -ext jpg .              # рекурсивно по каталогу
```

Особенно полезен `-trailer`: он показывает «дописанные» данные после конца изображения — частая стего-закладка. А `-b -ThumbnailImage` извлекает превью, которое иногда содержит флаг, отсутствующий в основном изображении.

## stegoveritas подробно

`stegoveritas` — комбайн: прогоняет десятки проверок и складывает результаты в каталог.

```bash
stegoveritas image.png
# создаёт stegoveritas_image/ с подкаталогами:
#   metadata/  — exiftool, строки
#   bmp/       — битовые плоскости
#   lsb/       — результаты zsteg и подобных
#   extracted/ — найденные вложенные файлы
```

Удобство в том, что он может найти канал, который вы не догадались проверить вручную. Минус — много ложных срабатываний; просматривайте результаты критически. Используйте как «второй проход» после ручных проверок.

## Расширенные режимы steghide и stegseek

```bash
steghide info -v image.jpg          # подробно: размер данных, метод
steghide extract -sf image.jpg -p '' -f   # пустой пароль, перезаписать выход
stegseek -sf image.jpg -wl my.txt   # свой словарь
stegseek --crack image.jpg /usr/share/wordlists/rockyou.txt
```

Если `steghide info` показывает данные, но размер маленький, пароль может быть коротким/пустым — попробуйте `-p ''` до брута.

## Практический чек-лист по инструментам

1. `file`, `strings -n 6`, `xxd | tail` — быстрые подсказки.
2. `exiftool -a -u -g1` и `-trailer` — метаданные и хвост.
3. `binwalk` / `binwalk -e` — встроенное.
4. `steghide info` → `extract`/`stegseek`.
5. `outguess -r` (JPEG).
6. `zsteg -a` (PNG/BMP).
7. `stegoveritas` — добор.

## Автоматизация: единый скрипт-оркестратор разбора изображения

Когда инструментов много, удобно собрать оркестратор, который прогоняет их по очереди и складывает результаты:

```bash
#!/bin/bash
f="$1"; out="analysis_$(basename "$f")"; mkdir -p "$out"
file "$f"                          > "$out/00_file.txt"
strings -n 6 "$f"                  > "$out/01_strings.txt"
exiftool -a -u -g1 "$f"            > "$out/02_exif.txt"
exiftool -trailer "$f"             > "$out/03_trailer.txt"
binwalk "$f"                       > "$out/04_binwalk.txt"
pngcheck -v "$f" 2>/dev/null       > "$out/05_pngcheck.txt"
zsteg -a "$f" 2>/dev/null          > "$out/06_zsteg.txt"
steghide info "$f" 2>/dev/null     > "$out/07_steghide.txt"
grep -riE 'flag|http|base64|password' "$out" | head
```

Такой прогон за один вызов закрывает «дешёвые» каналы и сразу показывает, где копать дальше. Это особенно полезно в задачах, где файлов несколько.

## Выбор инструмента по формату

- **PNG/BMP** → `zsteg`, `stegsolve`, Pillow; `steghide` НЕ работает.
- **JPEG** → `steghide`, `outguess`, `stegseek`, `stegdetect`.
- **WAV/AU** → `steghide`, DeepSound, `sox`, LSB-скрипт.
- **PDF/DOCX** → `exiftool`, `pdfdetach`/`unzip`, `binwalk`.
- **GIF** → покадровый разбор + палитры.

Ошибка новичка — применять инструмент «не по формату» и делать вывод «данных нет». Формат определяет набор инструментов.

## Тонкости паролей и ключей

Если `steghide info` показывает данные, а пароля нет, порядок попыток: (1) пустой пароль `-p ''`; (2) пароль из метаданных/условия/имени файла; (3) `stegseek` с rockyou; (4) тематический словарь по подсказке. Для `outguess` аналогично: пустой ключ → ключ из условия → короткие ключи. Не начинайте с мега-словаря: это трата времени.

## Итог по инструментам для изображений

Мощь приходит не от экзотических инструментов, а от **правильного порядка** и дисциплины: дешёвые проверки сначала, затем по формату, затем парольные, затем комплексный добор. Оркестратор-скрипт делает этот порядок воспроизводимым и экономит время в каждой задаче.

## Что делать дальше / решение

- Всегда начинайте с `file`, `strings`, `exiftool`, `binwalk`.
- `steghide info` → `steghide extract` или `stegseek` (если пароля нет).
- PNG/BMP → `zsteg -a`, при необходимости `stegsolve`.
- JPEG → `steghide`/`outguess`/`stegseek`.
- Добор — `stegoveritas`.

## Квиз

```quiz
- question: "Какой инструмент покажет встроенное в JPEG содержимое и его размер, но потребует пароль для извлечения?"
  options:
    - "`exiftool`"
    - "`steghide info`"
    - "`binwalk`"
    - "`nmap`"
  answer: 1
  explanation: "`steghide info file.jpg` сообщит `embedded file ...` и размер; извлечение требует пароль."
- question: "Чем `stegseek` отличается от `steghide`?"
  options:
    - "Работает только с PNG"
    - "Это быстрый брут-инструмент для steghide-контейнеров (миллионы попыток/сек)"
    - "Он расшифровывает RSA"
    - "Он умеет только встраивать данные"
  answer: 1
  explanation: "`stegseek` перебирает словарь против steghide-контейнера на порядки быстрее."
- question: "`steghide info` молчит, но файл явно «не пустой». Что попробовать?"
  options:
    - "Сразу бросить задачу"
    - "`outguess -r` — другой алгоритм встраивания в JPEG"
    - "Запустить `nmap`"
    - "Открыть в браузере"
  answer: 1
  explanation: "`outguess` использует несовместимый с steghide алгоритм и иногда находит то, что steghide не видит."
- question: "Где в первую очередь искать пароль к steghide-контейнеру?"
  options:
    - "В метаданных (`exiftool`) и строках файла (`strings`)"
    - "В `/etc/passwd`"
    - "В DNS"
    - "Нигде, пароль нельзя найти"
  answer: 0
  explanation: "Пароль часто лежит в `Comment`/EXIF или в подсказке внутри строк файла; словарь — второй шаг."
- question: "Какой тег EXIF может содержать скрытую другую картинку?"
  options:
    - "`Make`"
    - "`ThumbnailImage`"
    - "`ExposureTime`"
    - "`Orientation`"
  answer: 1
  explanation: "Встроенная миниатюра (`ThumbnailImage`) может отличаться от основного изображения — извлекай через `exiftool -b`."
```

## Где пригодится

- `exiftool` нужен почти в каждой задаче — не только Stego, но и Forensics/OSINT.
- `steghide`+`stegseek` — обязательная связка для JPEG/BMP/WAV с паролем.
- `outguess` — альтернативный алгоритм, который ловит то, что пропустил steghide.
- Дальше: урок про дописанные данные и контейнеры, затем про полиглоты.
