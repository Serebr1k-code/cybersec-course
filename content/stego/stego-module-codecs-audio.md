---
id: stego-module-codecs-audio
title: "Модуль: Современные аудиокодеки (FLAC, Opus, AAC, MIDI)"
category: stego
parent: stego-audio
difficulty: medium
order: 5
tags: [stego, roadmap, flac, opus, ogg, aac, midi, codec]
prerequisites: [stego-audio-advanced]
useful_for:
  - "CTF Stego: аудио-носители помимо WAV"
  - "Планирование порядка изучения стеганографии"
estimated_minutes: 8
summary: "Навигационный модуль по современным аудиоформатам: FLAC (lossless, метаданные-блоки), Ogg/Opus (страницы и комментарии), AAC (ADTS и ID3) и MIDI (события и дельта-времена). Каждый — контейнер со своими полями для сокрытия."
---

## Зачем этот модуль

Уроки про WAV и MP3 объясняют LSB в сэмплах и спектрограммы. Но в реальных CTF и
форензике всё чаще попадаются `song.flac`, `voice.opus`, `track.aac`, `tune.mid`.
У этих форматов другая структура: у FLAC — блоки метаданных, у Ogg — страницы, у
AAC — кадры ADTS плюс теги ID3, у MIDI — события с дельта-временами. Понимая
контейнер, ты находишь закладку до всякой обработки сигнала.

## Что разберём

- **stego-midi** — Standard MIDI File: заголовок `MThd`, треки `MTrk`, мета-события
  (текст, лирика, маркеры) и сокрытие в нотах/velocity/дельта-временах.
- **stego-flac-alac** — блоки метаданных FLAC (`STREAMINFO`, `APPLICATION`, `PADDING`,
  `VORBIS_COMMENT`) и то, как padding/application-блок становится носителем.
- **stego-ogg-opus** — Ogg-страницы (`OggS`) и комментарии `OpusTags`/Vorbis.
- **stego-aac** — кадры ADTS, теги ID3v2 (`TXXX`/`PRIV`) и MP4-обёртка для `.m4a`.

## Как проходить

По порядку. В каждом уроке — конкретный маленький файл, который разбирается байт за
байтом `xxd`, затем достаётся закладка вручную (`python3`), затем показываются
`exiftool`/`ffprobe`/`strings`. И только в конце — про обработку сигнала, если
контейнер чист.

## Что вы будете уметь

- Отличать lossless-контейнер (FLAC) от потокового (AAC/Opus).
- Читать блоки/страницы/кадры и находить нештатные поля.
- Доставать текст из мета-событий MIDI и тегов ID3.
- Понимать, где контейнерная закладка проще пиксельной/сэмпловой.
