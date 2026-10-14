---
id: media-audio-forensics
title: 'Аудио-форензика: метаданные, скрытые дорожки и стеганография'
category: forensics
parent: forensics-media-analysis
difficulty: medium
order: 1
tags: [forensics, audio, wav, mp3, metadata, stego]
prerequisites: [forensics-file-magic]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как анализировать аудиофайлы: метаданные, структура WAV/MP3, скрытые данные и восстановление.'
lab:
  kind: shell
  title: "Практика: структура WAV"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, wav_chunks.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "WAV = RIFF-контейнер из чанков (fmt, data, LIST…)."
    - "LIST/INFO может хранить произвольный текст."
    - "`grep nto wav_chunks.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Есть аудиозапись — возможно, доказательство, а возможно, носитель скрытых данных.
Нужно понять формат, метаданные и что внутри. Разберём.

## Наш пример: WAV-файл

## Шаг 1: определяем формат

```
$ file recording.wav
recording.wav: RIFF (little-endian) data, WAVE audio, PCM, 16 bit, mono 44100 Hz
```

WAV — несжатый PCM: `RIFF` + `fmt ` + `data`. Это удобно: каждый сэмпл на месте.

## Шаг 2: структура WAV

- `RIFF` — контейнер;
- `fmt ` — параметры (частота, каналы, битность);
- `data` — сами сэмплы;
- возможны **дополнительные чанки** (метаданные, скрытые данные).

```
$ xxd -l 64 recording.wav
00000000: 52494646 ... 57415645 666d7420
```

`52494646` = "RIFF", `57415645` = "WAVE".

## Шаг 3: метаданные

MP3/FLAC несут теги (ID3):

```
$ ffprobe -show_format recording.mp3 | head
artist : Ivan
comment : recorded at ...
```

Теги могут содержать GPS, время, устройство.

## Шаг 4: скрытые данные

Аудио — популярный носитель стеганографии:

- **LSB** (младшие биты сэмплов);
- добавленные чанки в WAV;
- **спектрограмма** (скрытый текст в спектре).

```
$ sox recording.wav -n spectrogram -o spec.png
```

На спектрограмме иногда видно текст, «нарисованный» в частотах.

## Шаг 5: что искать

- метаданные (автор, устройство, GPS);
- лишние чанки;
- LSB-модификации;
- аномалии спектра.

## Что мы теперь знаем

- WAV — RIFF с чанками fmt/data.
- MP3/FLAC несут теги (ID3).
- Аудио — носитель стеганографии (LSB, спектр).
- Спектрограмма выявляет скрытый текст.
- Метаданные дают контекст.

## Если не сработало

- Формат неизвестен? Используй `ffprobe`.
- Данные сжаты? Смотри сжатые контейнеры.
- Нужен звук? Воспроизведи/нормализуй (`sox`).

## Квиз

Проверь себя.

```quiz
- question: Что содержит WAV-файл?
  options:
    - 'сжатый звук'
    - 'несжатые PCM-сэмплы в RIFF-контейнере'
    - 'только метаданные'
    - 'видео'
  answer: 1
  explanation: 'WAV — RIFF с чанками fmt и data.'
- question: Где метаданные MP3?
  options:
    - 'в data'
    - 'в тегах ID3'
    - 'в fmt'
    - 'нет'
  answer: 1
  explanation: 'ID3-теги хранят автора, устройство и др.'
- question: Что такое спектрограмма в аудио-стего?
  options:
    - 'график частот, где виден скрытый текст'
    - 'пароль'
    - 'сеть'
    - 'обои'
  answer: 0
  explanation: 'Текст, «нарисованный» в частотах, виден на спектрограмме.'
- question: Какой метод стего применяют к сэмплам?
  options:
    - 'XOR'
    - 'LSB (младшие биты)'
    - 'gzip'
    - 'AES'
  answer: 1
  explanation: 'Изменение младших битов сэмплов почти незаметно на слух.'
```
