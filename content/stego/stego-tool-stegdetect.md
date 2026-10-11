---
id: stego-tool-stegdetect
title: "stegdetect, jphide/jpseek и аудио-инструменты: DeepSound, SilentEye"
category: stego
parent: stego-tooling-advanced
difficulty: medium
order: 2
tags: [stego, stegdetect, jphide, jpseek, mp3stego, deepsound, silenteye, openstego, snow]
prerequisites: [stego-tooling-advanced]
useful_for:
  - "CTF Stego: детекторы и аудио-инструменты"
  - "Форензика: обнаружение стеганографии"
  - "Анализ медиа из реальных инцидентов"
estimated_minutes: 45
summary: "Инструменты-детекторы и встраиватели: stegdetect (jsteg/jphide/outguess/F5), jphide/jpseek, аудио-инструменты (mp3stego, DeepSound, SilentEye, OpenStego, snow)."
---

Если `zsteg`/StegSolve — это «посмотреть», то stegdetect и компания — это «угадать, каким инструментом прятали». Stegdetect анализирует JPEG и выдаёт вероятный алгоритм (jsteg, jphide, outguess, F5), после чего вы берёте парный извлекатель (jpseek для jphide и т.д.). Отдельная ветка — аудио-инструменты: DeepSound, SilentEye, mp3stego прячут данные в звуке, а `snow` — в пробелах текста. Знание этой «карты соответствий» инструмент→формат экономит часы перебора.

## stegdetect: детектор JPEG

Stegdetect смотрит статистику JPEG и оценивает, есть ли стеганография и каким алгоритмом.

```bash
# базовая проверка
stegdetect image.jpg
# чувствительность и вывод всех гипотез
stegdetect -s 2.0 -t jopi image.jpg    # j=jsteg o=outguess p=jphide i=invisible
# машиночитаемо
stegdetect -s 1.0 -t jopi -f image.jpg
```

Флаги: `-s` (чувствительность), `-t` (набор тестов), `-q` (тихо), `-n` (только имена). Вывод вида `image.jpg: jphide(***)` означает вероятный jphide.

## jphide/jpseek

jphide — встраивание в JPEG, jpseek — извлечение (часто с паролем).

```bash
# извлечение (потребует пароль)
jpseek image.jpg out.bin
# jphide для встраивания (проверка своего пайплайна)
jphide cover.jpg secret.txt out.jpg
```

## Аудио-инструменты

| Инструмент | Формат | Назначение |
|---|---|---|
| DeepSound | WAV/FLAC | GUI/CLI, пароль, извлечение |
| SilentEye | изображения+аудио | GUI, LSB-подобное |
| mp3stego | MP3 | встраивание/извлечение с паролем |
| OpenStego | PNG/BMP/WAV | Java, watermark + data hiding |
| snow | текст | сокрытие в пробелах (см. text-уроки) |

```bash
# mp3stego: извлечение (пароль)
mp3stego-decode -P passphrase cover.mp3 out.txt
# OpenStego CLI: извлечение
java -jar openstego.jar extract -a RandomLSB -sf marked.png -xd out/
# snow: извлечение из текста
snow -C -p password text_with_data.txt
```

## Разобранный пример

CTF: `song.wav` + подсказка «звук не прост».

```bash
$ stegdetect song.jpg 2>/dev/null   # не тот формат, для аудио иначе
$ strings -n 8 song.wav | grep -iE 'deepsound|silent|pass'
$ python3 -c "d=open('song.wav','rb').read(); print(b'DeepSound' in d)"
True
```

Наличие строки `DeepSound` — сильный сигнал: файл обработан этим инструментом. Дальше — извлечение (в GUI DeepSound или CLI), при пароле — брут по словарю из подсказки.

```bash
# проверка на mp3stego
mp3stego-decode -P '' song.mp3 out.txt 2>&1 | head
# проверка на OpenStego
java -jar openstego.jar extract -sf song.png -xd out/ 2>&1 | head
# stegdetect по JPEG-превью
stegdetect -s 2.0 preview.jpg
```

## Краевые случаи и подводные камни

- **stegdetect устарел:** не поддерживает F5-анализ в полном объёме и современные кодеки — воспринимай как подсказку, а не истину.
- **Пароль нужен часто:** jphide/jpseek, mp3stego, DeepSound, snow — почти всегда с паролем; без него данные не извлечь.
- **False positives:** stegdetect может ошибаться на сильно сжатых JPEG; проверяй вывод несколькими извлекателями.
- **Аудио-форматы:** MP3 — lossy (только mp3stego), WAV/FLAC — lossless (DeepSound/SilentEye LSB).
- **GUI vs CLI:** DeepSound/SilentEye в основном GUI; для скриптов бери OpenStego/steghide/mp3stego CLI.

## Что дальше / решение

Пайплайн: определить формат → `stegdetect` (JPEG) или `strings | grep` по имени инструмента (DeepSound/SilentEye) → подобрать парный извлекатель (`jpseek`, `mp3stego-decode`, OpenStego, `snow -C`) → пароль из подсказки/словаря → при неудаче вернуться к общему пайплайну (метаданные, LSB, спектрограмма для аудио). Ключ — карта «инструмент → формат → извлекатель», а не слепой перебор.

## Справочные таблицы

| Детектор-гипотеза | Извлекатель |
|---|---|
| jphide | jpseek |
| jsteg | jsteg (decode) |
| outguess | outguess -r |
| F5 | f5-steganography / stegseek |
| invisible secrets | invis-secrets |

| Инструмент | Формат | Пароль |
|---|---|---|
| DeepSound | WAV/FLAC | да |
| SilentEye | img/audio | опц. |
| mp3stego | MP3 | да |
| OpenStego | PNG/BMP/WAV | опц. |
| snow | текст | да |

## Расшифровка вывода stegdetect

Вывод stegdetect выглядит как `image.jpg: jphide(***)`. Число звёздочек — уверенность (1–3), имя в скобках — гипотеза об алгоритме. Понимание этого формата ускоряет подбор извлекателя.

| Гипотеза | Алгоритм | Извлекатель |
|---|---|---|
| jsteg | LSB DCT | `jsteg reveal` |
| jphide | FFT/DCT + пароль | `jpseek` |
| outguess | DCT + коррекция | `outguess -r` |
| invisible | LSB с секретом | invis-secrets |

```bash
# чувствительность выше -> больше гипотез (и больше ложных)
stegdetect -s 3.0 -t jopi image.jpg
# только имена файлов, тихо
stegdetect -q -n image.jpg
# набор тестов: j=jsteg p=jphide o=outguess i=invisible
stegdetect -t j image.jpg
```

Важно: `***` не гарантирует стего, а отсутствие звёздочек не гарантирует чистоту. Используйте вывод как приоритет, а не как вердикт.

## Аудио-стего: спектрограмма и сравнение

Для аудио stegdetect не применяется; вместо него — визуальный и статистический анализ. Спектрограмма — первый инструмент: текст/QR часто «нарисованы» в высоких частотах.

```bash
# спектрограмма
sox song.wav -n spectrogram -o spec.png
# или через sonic-visualiser / Audacity (Spectrogram view)
python3 -c "print('смотрите верхние частоты и периодические узоры')"
# разница с cover-версией (если дана)
python3 - <<'PY'
import numpy as np, wave
def rd(p):
    w=wave.open(p); d=np.frombuffer(w.readframes(w.getnframes()),dtype=np.int16); w.close(); return d
a=rd('cover.wav'); b=rd('marked.wav')
print('diff nonzero', int((a[:len(b)]!=b[:len(b)]).sum()))
PY
```

Периодический «текст» на спектрограмме — признак SSTV/спектральной стеганографии; ровные полосы на высоких частотах — FSK/морзе.

## Карта «инструмент → формат → извлекатель»

| Инструмент | Формат | Извлекатель | Пароль |
|---|---|---|---|
| jsteg | JPEG | jsteg reveal | нет |
| jphide | JPEG | jpseek | да |
| outguess | JPEG | outguess -r | да |
| F5 | JPEG | f5-steganography | да |
| steghide | JPEG/BMP/WAV/AU | steghide extract | да |
| mp3stego | MP3 | mp3stego-decode | да |
| DeepSound | WAV/FLAC | DeepSound | да |
| SilentEye | img/audio | SilentEye | опц. |
| OpenStego | PNG/BMP/WAV | openstego extract | опц. |
| snow | текст | snow -C | да |

Держите эту таблицу под рукой: она экономит время при подборе извлекателя под найденную гипотезу.

## Типовые ошибки и их лечение

- **«Файл не содержит данных», а stegdetect показывает гипотезу:** пароль неизвестен — пробуйте `stegseek`/`stegcracker` по словарю.
- **mp3stego не декодирует:** возможно, файл — WAV (нужен DeepSound) или пароль неверный.
- **OpenStego «extract» пусто:** не тот алгоритм (`-a`); попробуйте RandomLSB/LSB.
- **snow возвращает пусто:** пароль или неверный тип файла (нужен текст с трейлинг-пробелами).

## Разобранный пример 2: аудио DeepSound

Задача: `track.wav`, сказано «звук непростой». stegdetect тут не применим (JPEG-only), поэтому работаем по признакам.

```bash
$ strings -n 6 track.wav | grep -iE 'deepsound|silenteye|password|flag'
$ python3 -c "d=open('track.wav','rb').read();print('DeepSound' in d, b'flag' in d)"
False False
```

Метка может быть в «тихих» участках или в высоких частотах. Смотрим спектрограмму:

```bash
sox track.wav -n spectrogram -o spec.png
```

На `spec.png` в верхних частотах виден QR-код или текст — типичный признак спектральной стеганографии. Сканируем:

```bash
zbarimg spec.png
# или вручную читаем текст
```

Если спектрограмма чистая, а файл — WAV, пробуем инструменты LSB-аудио: `SilentEye`, `DeepSound` (GUI), `wav2png`-подобные. Для MP3 — `mp3stego-decode`. Общий принцип: сначала визуальный/спектральный анализ, затем — целевые инструменты по формату.

## Что делать, если ничего не сработало

Если ни stegdetect, ни спектрограмма, ни LSB-аудио не дали результата, вернитесь к основам: `exiftool` (метаданные аудио — ID3-теги, комментарии), `binwalk` (дописанные данные после аудио-потока), проверка на конкатенацию (второй файл после основного). Аудио часто несёт данные не «в звуке», а в контейнере (ID3, LIST-чанк WAV, хвост файла). Не игнорируйте контейнерные метаданные: там флаг встречается не реже, чем в спектре.

## Частые ошибки и как их избежать

Детекторы и целевые извлекатели экономят время, но только если понимать их ограничения.

- **Слепое доверие stegdetect:** он устарел и не покрывает современные схемы; воспринимайте звёздочки как подсказку, а не приговор. Отсутствие гипотезы ≠ отсутствие данных.
- **Не тот извлекатель:** гипотеза `jphide` требует `jpseek` с паролем, а не `jsteg reveal`. Сверяйтесь с таблицей соответствий.
- **Перекодирование убивает данные:** jsteg/F5 хрупкие; если файл прошёл через редактор, метка разрушена — работайте с оригиналом.
- **Пароль неизвестен:** для steghide используйте `stegseek`/`stegcracker` (офлайн-брут дешёв), для jphide — словарь из подсказки.
- **Аудио-формат перепутан:** mp3stego — только MP3, DeepSound — WAV/FLAC. Определяйте формат по `file`, а не по расширению.

Практический итог: сначала `file` и `exiftool`, затем визуальный/спектральный анализ, затем детектор, затем — парный извлекатель. Держите карту «инструмент → формат → извлекатель» под рукой, и большинство задач на целевые инструменты решатся за несколько минут.

## Квиз

```quiz
- question: "Что делает stegdetect?"
  options:
    - "Определяет вероятный алгоритм стеганографии в JPEG"
    - "Расшифровывает AES"
    - "Восстанавливает удалённые файлы"
    - "Строит спектрограмму"
  answer: 0
- question: "Какой извлекатель соответствует jphide?"
  options:
    - "jpseek"
    - "zsteg"
    - "exiftool"
    - "binwalk"
  answer: 0
- question: "Для какого аудиоформата предназначен mp3stego?"
  options:
    - "MP3"
    - "WAV"
    - "FLAC"
    - "OGG"
  answer: 0
- question: "О чём говорит строка DeepSound внутри WAV?"
  options:
    - "Файл, вероятно, обработан инструментом DeepSound"
    - "Файл повреждён"
    - "Файл зашифрован AES"
    - "Это не аудио"
  answer: 0
```

## Где пригодится

- **CTF Stego:** подбор инструмента под формат.
- **Форензика:** обнаружение стеганографии в медиа.
- **Bug bounty:** проверка подозрительных медиафайлов.
- **Работа:** инвентаризация инструментов анализа.
