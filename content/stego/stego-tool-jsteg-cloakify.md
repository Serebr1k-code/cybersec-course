---
id: stego-tool-jsteg-cloakify
title: "jsteg, cloakify и StegHide: встраивание и извлечение со всеми флагами"
category: stego
parent: stego-tooling-advanced
difficulty: medium
order: 3
tags: [stego, jsteg, cloakify, camouflage, steghide, hide, extract]
prerequisites: [stego-tooling-advanced, stego-jpeg-dct]
useful_for:
  - "CTF Stego: извлечение целевыми инструментами"
  - "Красная команда: скрытая передача данных"
  - "Понимание алгоритмов jsteg/steghide"
estimated_minutes: 50
summary: "jsteg, cloakify/camouflage и StegHide со всеми флагами: как встраивать и извлекать данные, где искать пароли и как диагностировать типовые ошибки."
---

## Вопрос, с которого всё начинается

В CTF дали файл `cat.jpg` — обычная фотография кота. Подсказка: «используй правильный инструмент». Пробуешь `zsteg` — ничего, потому что он для PNG. Открываешь в hex — тоже без толку. Как понять, каким инструментом извлекать данные и с какими флагами?

Этот урок — про три конкретных инструмента, которые в CTF «угадываются» чаще всего: **jsteg**, **cloakify/camouflage** и **StegHide**. У каждого свой формат, свои флаги и свои правила. Разберём их на одном файле.

## Наш пример: cat.jpg

Первым делом определяем формат — от него зависит выбор инструмента:

```bash
$ file cat.jpg
cat.jpg: JPEG image data, JFIF standard 1.01, 1920x1080
```

JPEG — значит, `zsteg` (для PNG) отпадает, а вот `steghide` подходит: он работает с JPEG, BMP, WAV и AU. Начинаем с проверки — есть ли вообще встроенные данные, ещё без пароля:

```bash
$ steghide info cat.jpg
cat.jpg:
  format: jpeg
  capacity: 2.3 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase:
  embedded file "flag.txt":
    size: 20.0 Byte
```

`steghide info` сообщает, что внутри лежит файл `flag.txt` размером 20 байт. Он не покажет содержимое без пароля, но сам факт наличия — огромная подсказка: инструмент угадан, осталось достать пароль.

## Шаг 1: извлекаем данные StegHide

Извлекаем с паролем из подсказки задачи:

```bash
$ steghide extract -sf cat.jpg -p 'password123' -xf flag.txt
wrote extracted data to "flag.txt".
$ cat flag.txt
flag{steghide_with_password}
```

Разберём флаги, потому что их легко перепутать:

| Флаг | Назначение |
|---|---|
| `embed` | встроить данные |
| `extract` | извлечь данные |
| `info` | показать, есть ли данные |
| `-cf FILE` | cover-файл (обложка), куда прячем |
| `-ef FILE` | файл, который прячем |
| `-sf FILE` | stego-файл (носитель), откуда достаём |
| `-xf FILE` | куда записать извлечённое |
| `-p PASS` | пароль |
| `-e ALG` | алгоритм шифрования (aes128/aes256) |
| `-f` | force — перезаписать выходной файл |

Встраивание выглядит зеркально:

```bash
$ steghide embed -cf cover.jpg -ef secret.txt -p 's3cr3t' -e aes256
```

## Шаг 2: читаем ошибки StegHide

StegHide пишет лаконично, и сообщения надо уметь читать:

| Сообщение | Причина | Решение |
|---|---|---|
| `could not extract any data with that passphrase` | неверный пароль | перебрать (`stegseek`) |
| `is not a supported file type` | PNG/GIF | другой инструмент |
| `error while processing the cover file` | файл повреждён или мало ёмкости | взять больший cover |
| `already exists. Use -f to overwrite` | выходной файл существует | добавить `-f` |
| `no valid steghide file` | данных нет | искать другими инструментами |

Две частые «немые» ошибки: забыть `-f` при существующем выходном файле и пытаться скормить PNG (StegHide его не поддерживает). При неизвестном пароле брут делает специализированный инструмент:

```bash
$ stegseek cat.jpg /usr/share/wordlists/rockyou.txt
```

## Шаг 3: если StegHide молчит — jsteg

Допустим, у нас второй файл, `sunset.jpg`, и `steghide info` по нему ничего не находит. Значит, данные могли встроить **другим** алгоритмом. **jsteg** прячет биты в младших разрядах DCT-коэффициентов JPEG (DCT — дискретно-косинусное преобразование, которым JPEG сжимает блоки пикселей), пропуская значения 0 и 1. Метод хрупкий, но обнаруживаемый утилитой `stegdetect`:

```bash
$ stegdetect sunset.jpg
sunset.jpg: jsteg(**)
```

Две звёздочки — уверенное указание на jsteg. Извлекаем:

```bash
$ jsteg reveal sunset.jpg out.bin
$ file out.bin
out.bin: ASCII text
$ cat out.bin
flag{jsteg_dct_lsb}
```

Синтаксис jsteg простой:

| Операция | Команда |
|---|---|
| hide | `jsteg hide cover.jpg secret.txt out.jpg` |
| reveal | `jsteg reveal out.jpg extracted.txt` |
| info | `jsteg` без аргументов |

Важно: jsteg работает **только с оригинальным** JPEG. Любая перекодировка (сохранение через редактор, отправка в мессенджере) меняет DCT-коэффициенты и разрушает данные. Поэтому бери файл прямо из условия задачи.

## Шаг 4: текст в тексте — cloakify и camouflage

Третий инструмент — для текстовых задач. **cloakify** прячет сообщение в «лингвистически правдоподобный» текст, подмешивая невидимые маркеры, а **camouflage** восстанавливает:

```bash
$ cloakify -p key123 "flag{text_stego}" -o cloaked.txt
$ camouflage -p key123 cloaked.txt
flag{text_stego}
```

Из файла — в файл:

```bash
$ cloakify -p secret -i message.txt -o cloaked.txt
$ camouflage -p secret cloaked.txt -o recovered.txt
```

Пароль здесь — не шифрование, а «ключ выбора символов»: один и тот же текст с разными паролями даёт разный выход, а неверный пароль — «случайный» текст. Забудешь пароль — данные не восстановить, бэкдора нет. И осторожно: при копировании через «умные» редакторы невидимые маркеры могут теряться — работай с исходным файлом.

## Шаг 5: единый пайплайн по инструментам

Чтобы не перебирать вслепую, держи порядок:

1. `file` — формат (для StegHide это JPEG/BMP/WAV/AU).
2. `steghide info` — есть ли встроенные данные.
3. `steghide extract -sf ... -p ...` — пароль из подсказки.
4. Пароль неизвестен → `stegseek`/`stegcracker` по словарю (это **офлайн**-брут, он дешёв и эффективен).
5. Не StegHide → `stegdetect` → `jsteg reveal` / `jpseek` / `outguess -r`.
6. Текстовый носитель → `camouflage -p`.
7. Пусто → вернуться к общему пайплайну (метаданные, LSB, частотные методы).

Сводка соответствий «инструмент → извлекатель»:

| Инструмент | Встраивание | Извлечение | Пароль |
|---|---|---|---|
| jsteg | `jsteg hide` | `jsteg reveal` | нет |
| cloakify | `cloakify` | `camouflage` | да |
| StegHide | `embed` | `extract` | да |
| outguess | `outguess -d` | `outguess -r` | ключ |
| stegseek | — | `stegseek` (брут) | брут |

Не зацикливайся на одном инструменте: одна неудачная попытка — повод проверить соседнюю гипотезу из таблицы.

## Что мы теперь знаем

1. Выбор инструмента зависит от формата: StegHide — JPEG/BMP/WAV/AU, не PNG/GIF.
2. `steghide info` показывает наличие данных без пароля; `extract` достаёт их.
3. Точные флаги критичны: `-sf`, `-ef`, `-xf`, `-p`, `-e`, `-f`.
4. Неизвестный пароль к StegHide перебирает `stegseek`/`stegcracker` (офлайн-брут).
5. jsteg прячет данные в младших битах DCT-коэффициентов; его выдаёт `stegdetect`, а извлекает `jsteg reveal`.
6. cloakify/camouflage прячут текст в тексте; пароль — ключ выбора символов.

## Квиз

Проверь себя.

```quiz
- question: "В чём встраивает данные jsteg?"
  options:
    - "В младшие биты DCT-коэффициентов JPEG"
    - "В палитру PNG"
    - "В пробелы текста"
    - "В RIFF-чанки"
  answer: 0
  explanation: "jsteg меняет LSB квантованных DCT-коэффициентов."
- question: "Какой подкомандой StegHide извлекают данные?"
  options:
    - "extract"
    - "embed"
    - "info"
    - "hide"
  answer: 0
  explanation: "extract извлекает, embed встраивает."
- question: "Что делает camouflage?"
  options:
    - "Декодирует текст, закодированный cloakify"
    - "Сжимает JPEG"
    - "Читает EXIF"
    - "Брутит пароль"
  answer: 0
  explanation: "camouflage — обратная операция к cloakify."
- question: "С какими форматами НЕ работает StegHide?"
  options:
    - "PNG и GIF"
    - "JPEG"
    - "BMP"
    - "WAV"
  answer: 0
  explanation: "StegHide поддерживает только JPEG/BMP/WAV/AU."
- question: "Какой инструмент перебирает пароль StegHide по словарю?"
  options:
    - "stegseek"
    - "zsteg"
    - "binwalk"
    - "camouflage"
  answer: 0
  explanation: "stegseek делает быстрый офлайн-брут пароля StegHide."
```

## Куда дальше

Эти три инструмента покрывают «целевые» задачи, где в подсказке звучит название. В следующем уроке разберём **stegdetect** и родственные утилиты (`jphide/jpseek`, аудио-инструменты) подробнее. А пока запомни: сначала определи формат и запусти `steghide info`, а инструмент подбирай по формату и подсказке.

## Где пригодится

- **CTF Stego:** извлечение целевыми инструментами.
- **Красная команда:** скрытая передача данных через медиа.
- **Форензика:** извлечение данных из подозрительных файлов.
- **Работа:** понимание алгоритмов парольной стеганографии.
