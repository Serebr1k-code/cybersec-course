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

Этот урок — про три конкретных инструмента, которые чаще всего «угадываются» в CTF. **jsteg** прячет данные в JPEG через замену LSB DCT-коэффициентов (и совместим с `stegdetect`-детекцией jsteg). **cloakify/camouflage** прячут текст в текст: сообщение превращается в набор «незаметных» символов/пробелов, а camouflage возвращает его обратно. **StegHide** — классический парольный инструмент для JPEG/BMP/WAV/AU с чистой архитектурой и удобным CLI. Знание точных флагов критично: `steghide` без пароля или с неверным форматом просто вернёт «nothing to extract».

## jsteg: LSB в DCT

jsteg встраивает биты в JPEG, заменяя младшие биты квантованных DCT-коэффициентов (пропуская 0 и 1). Это хрупкий, но быстрый метод, обнаруживаемый stegdetect.

```bash
# встраивание
jsteg hide cover.jpg message.txt out.jpg
# извлечение
jsteg reveal out.jpg extracted.txt
# проверка ёмкости
jsteg --help
```

| Операция | Команда |
|---|---|
| hide | `jsteg hide cover.jpg secret.txt out.jpg` |
| reveal | `jsteg reveal out.jpg extracted.txt` |
| info | `jsteg` без аргументов |

## cloakify/camouflage

cloakify кодирует секрет в «лингвистически правдоподобный» текст с невидимыми маркерами; camouflage декодирует.

```bash
# кодирование
cloakify -p passphrase "flag{hidden_in_text}" -o cloaked.txt
# декодирование
camouflage -p passphrase cloaked.txt
# из файла
cloakify -p secret -i message.txt -o cloaked.txt
camouflage -p secret cloaked.txt -o recovered.txt
```

Пароль обязателен: без него camouflage не восстановит текст.

## StegHide: полный CLI

StegHide — эталонный парольный стего-инструмент. Поддерживает JPEG, BMP, WAV, AU.

| Флаг | Назначение |
|---|---|
| `embed` | встроить данные |
| `extract` | извлечь данные |
| `info` | показать, есть ли данные |
| `-ef FILE` | файл для встраивания |
| `-cf FILE` | cover-файл (обложка) |
| `-sf FILE` | stego-файл (носитель) |
| `-p PASS` | пароль |
| `-sf`/`-xf` | выходной файл |
| `-e ALG` | алгоритм (aes128/256) |
| `-f` | force (перезапись) |

```bash
# информация без пароля
steghide info image.jpg
# извлечение
steghide extract -sf image.jpg -p '' -xf out.bin
# извлечение с паролем и указанием алгоритма
steghide extract -sf image.jpg -p 's3cr3t' -e aes256 -xf out.bin
# встраивание
steghide embed -cf cover.jpg -ef secret.txt -p 's3cr3t' -e aes256
# принудительно, с проверкой
steghide embed -cf cover.jpg -ef secret.txt -p pass -Z -f
```

## Разобранный пример

CTF: `cat.jpg`, подсказка «используй правильный инструмент».

```bash
$ steghide info cat.jpg
cat.jpg:
  format: jpeg
  capacity: 2.3 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase:
  embedded file "flag.txt":
    size: 20.0 Byte

$ steghide extract -sf cat.jpg -p 'password123' -xf flag.txt
wrote extracted data to "flag.txt".
$ cat flag.txt
flag{steghide_with_password}
```

Если `steghide info` показывает встроенный файл — нужен пароль. Дальше — `stegseek`/`stegcracker` по словарю (см. урок `stego-stegseek`), либо подсказка из задачи.

```bash
# брут пароля steghide через stegseek
stegseek cat.jpg rockyou.txt
# jsteg-вариант
stegdetect cat.jpg        # -> jsteg? -> jsteg reveal cat.jpg out.txt
```

## Краевые случаи и подводные камни

- **Пустой пароль ≠ отсутствие пароля:** `-p ''` иногда работает, но чаще нужен именно пароль.
- **Формат:** StegHide не работает с PNG/GIF — только JPEG/BMP/WAV/AU. Для PNG используй `zsteg`/`steghide`-аналог.
- **Алгоритм:** по умолчанию aes128; если встраивали с `-e aes256`, при извлечении лучше указать тот же.
- **`-f`/force:** без него StegHide не перезапишет выходной файл — частая «немая» ошибка.
- **jsteg хрупкий:** любая перекодировка JPEG убивает данные; извлекай из оригинала.
- **cloakify-пароль:** забудешь — данные не восстановить, бэкдора нет.

## Что дальше / решение

Пайплайн: `steghide info` (есть ли данные) → `steghide extract -sf ... -p ...` → при неизвестном пароле `stegseek`/`stegcracker` по словарю → для JPEG без steghide-метки проверить `stegdetect` → при jsteg `jsteg reveal` → для текстовых задач `camouflage -p`. Главное — точные флаги и понимание, что каждый инструмент работает только со «своими» форматами и паролями.

## Справочные таблицы

| Инструмент | Встраивание | Извлечение | Пароль |
|---|---|---|---|
| jsteg | `jsteg hide` | `jsteg reveal` | нет |
| cloakify | `cloakify` | `camouflage` | да |
| StegHide | `embed` | `extract` | да |
| stegseek | — | `stegseek` (брут) | брут |

| StegHide формат | Поддержка |
|---|---|
| JPEG | да |
| BMP | да |
| WAV | да |
| AU | да |
| PNG/GIF | нет |

## StegHide: диагностика ошибок

StegHide выдаёт лаконичные сообщения, и их важно правильно читать. Разберём типовые.

| Сообщение | Причина | Решение |
|---|---|---|
| `could not extract any data with that passphrase` | неверный пароль | `stegseek`/`stegcracker` |
| `the file ... is not a supported file type` | PNG/GIF | конвертировать или другой инструмент |
| `error while processing the cover file` | файл повреждён/недостаточно ёмкости | проверить `info`, взять больший cover |
| `... already exists. Use -f to overwrite` | выходной файл существует | добавить `-f` |
| `no valid steghide file` | данных нет | проверить другие инструменты |

```bash
# подробный вывод
steghide extract -sf image.jpg -p 'guess' -v
# проверить ёмкость и наличие данных без пароля
steghide info image.jpg
# форсировать перезапись
steghide extract -sf image.jpg -p 'pass' -f -xf out.bin
```

## Кодировки cloakify/camouflage

cloakify встраивает секрет, используя наборы невидимых/похожих символов; camouflage восстанавливает. Пароль здесь — не шифрование, а «ключ» выбора символов. Поэтому один и тот же текст с разными паролями даёт разный выход, а неверный пароль — «случайный» текст.

```bash
# базовый цикл
cloakify -p key123 "flag{text_stego}" -o cloaked.txt
camouflage -p key123 cloaked.txt
# из файла и обратно
cloakify -p key -i msg.txt -o cloaked.txt
camouflage -p key cloaked.txt -o recovered.txt
# если текст «не читается» — попробуйте другой пароль или инструмент (unicode-стего)
```

Практика: cloakify-текст выглядит как обычная речь, но содержит скрытые маркеры; при копировании через «умные» редакторы маркеры могут теряться — работайте с исходным файлом.

## Автоматизация брута и извлечения

Когда пароль неизвестен, а инструмент известен (steghide/jphide), брут по словарю — стандартный шаг. Делайте его через специализированные утилиты, а не цикл curl-подобных вызовов.

```bash
# steghide -> stegseek (быстрый брут)
stegseek image.jpg /usr/share/wordlists/rockyou.txt
# или stegcracker
stegcracker image.jpg rockyou.txt
# jphide -> jpseek с перебором (если есть утилита)
# проверить гипотезу через stegdetect
stegdetect image.jpg
```

Важно: брут **offline**-инструмента (steghide) дешёв и эффективен; брут сетевых сервисов — нет. Не путайте эти ситуации.

## Единый пайплайн по целевым инструментам

1. `file` — формат (JPEG/BMP/WAV/AU для steghide).
2. `steghide info` — есть ли встроенные данные.
3. `steghide extract -sf ... -p ...` (пароль из подсказки).
4. Неизвестный пароль → `stegseek`/`stegcracker` по словарю.
5. Не steghide → `stegdetect` → `jsteg reveal`/`jpseek`/`outguess -r`.
6. Текстовый носитель → `camouflage -p`.
7. Пусто → вернуться к общему пайплайну (метаданные, LSB, частотные методы).

Этот порядок покрывает большинство задач на «целевые» инструменты и не даёт зациклиться на одном из них.

## Разобранный пример 2: jsteg reveal

Задача: `sunset.jpg`, подсказка «частотная область».

```bash
$ stegdetect sunset.jpg
sunset.jpg: jsteg(**)

$ jsteg reveal sunset.jpg out.bin
$ file out.bin
out.bin: ASCII text
$ cat out.bin
flag{jsteg_dct_lsb}
```

Stegdetect указал на jsteg, а `jsteg reveal` извлёк данные. Важно: jsteg работает **только** с оригинальным JPEG; если файл пересохранили, данные потеряны. Поэтому для таких задач используйте исходный файл из условия, а не копию, прошедшую через редактор/мессенджер.

Если `jsteg reveal` возвращает пусто, а stegdetect настойчиво указывает на jsteg, возможны два варианта: (1) данные встроены с паролем (тогда это, скорее, jphide — пробуйте `jpseek`), (2) файл был пережат и метка разрушена (тогда ищите другой носитель). Не зацикливайтесь: одна неудачная попытка — повод проверить соседнюю гипотезу из таблицы «инструмент → извлекатель».

## Сводка по целевым инструментам

- **jsteg** — без пароля, хрупкий; извлекается только из оригинала.
- **jpseek** — парный к jphide, требует пароль.
- **outguess** — `outguess -r file out` для извлечения, поддерживает ключ.
- **steghide** — JPEG/BMP/WAV/AU, пароль, AES.
- **stegseek** — брут пароля steghide, быстрый и офлайн.
- **camouflage** — декод текстового cloakify, требует пароль.

Держите эту сводку рядом с таблицей соответствий — вместе они закрывают почти все задачи на «целевые» инструменты.

## Итоговый чек-лист по целевым инструментам

1. `file` — поддерживаемый формат (steghide: JPEG/BMP/WAV/AU).
2. `steghide info` — есть ли встроенные данные.
3. `steghide extract -sf ... -p ...` — пароль из подсказки.
4. Неизвестный пароль → `stegseek`/`stegcracker` (офлайн-брут).
5. Не steghide → `stegdetect` → `jsteg reveal`/`jpseek`/`outguess -r`.
6. Текстовый носитель → `camouflage -p`.
7. Пусто → вернуться к общему пайплайну (метаданные, LSB, частотные методы).

## Квиз

```quiz
- question: "В чём встраивает данные jsteg?"
  options:
    - "В младшие биты DCT-коэффициентов JPEG"
    - "В палитру PNG"
    - "В пробелы текста"
    - "В RIFF-чанки"
  answer: 0
- question: "Какой флаг StegHide извлекает данные?"
  options:
    - "extract"
    - "embed"
    - "info"
    - "hide"
  answer: 0
- question: "Что делает camouflage?"
  options:
    - "Декодирует текст, закодированный cloakify"
    - "Сжимает JPEG"
    - "Читает EXIF"
    - "Брутит пароль"
  answer: 0
- question: "С какими форматами НЕ работает StegHide?"
  options:
    - "PNG и GIF"
    - "JPEG"
    - "BMP"
    - "WAV"
  answer: 0
```

## Где пригодится

- **CTF Stego:** извлечение целевыми инструментами.
- **Красная команда:** скрытая передача данных через медиа.
- **Форензика:** извлечение данных из подозрительных файлов.
- **Работа:** понимание алгоритмов парольной стеганографии.
