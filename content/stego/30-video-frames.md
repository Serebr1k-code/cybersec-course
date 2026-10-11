---
id: stego-video-frames
title: "Видео-стеганография: манипуляция кадрами и DCT"
category: stego
parent: stego-jpeg-dct
difficulty: medium
order: 2
tags: [stego, video, frames, dct, mp4, ffmpeg, interframe]
prerequisites: [stego-video, stego-jpeg-dct]
useful_for:
  - "CTF Stego — видео-носители"
  - "Анализ покадровых различий"
  - "Forensics: скрытые данные в видео"
estimated_minutes: 40
summary: "Как прячут данные в видео: покадровые различия, скрытые кадры, DCT-манипуляции (как в JPEG), аудиодорожка и контейнерные метаданные; практическое извлечение."
---

Видео — это последовательность кадров + аудио + контейнер (MP4/MKV/AVI). Каналы сокрытия: покадровые различия (данные в отдельных кадрах/пикселях), скрытые/добавленные кадры, DCT-коэффициенты (как в JPEG, для каждого кадра), аудиодорожка (те же аудио-методы) и метаданные контейнера. В CTF чаще всего нужно разложить видео на кадры и найти отличающийся кадр или данные в различиях.

## Разбор на кадры

```bash
# все кадры
ffmpeg -i video.mp4 frames/%05d.png
# с частотой
ffmpeg -i video.mp4 -vf fps=10 frames/%05d.png
# только ключевые кадры
ffmpeg -skip_frame nokey -i video.mp4 frames/key_%05d.png
# аудиодорожка
ffmpeg -i video.mp4 -vn -acodec copy audio.aac
ffmpeg -i video.mp4 -vn audio.wav
```

## Поиск отличий

```bash
# сравнить кадры попарно (ImageMagick)
compare -metric AE frame1.png frame2.png diff.png 2>&1
# разница всех кадров с первым
for f in frames/*.png; do compare -metric AE frames/00001.png "$f" null: 2>&1; echo " $f"; done | sort -rn | head
# покадровая разница через ffmpeg
ffmpeg -i video.mp4 -vf "tblend=all_mode=difference" diff_%05d.png
```

Отличающийся кадр часто и содержит флаг/QR/текст.

## DCT и метаданные

- DCT-стего: как в JPEG — данные в младших битах DCT-коэффициентов кадра; ищите после декодирования кадров в JPEG.
- Контейнер: метаданные MP4/MKV (`ffprobe`, `exiftool`, `mkvinfo`), скрытые дорожки, комментарии.

```bash
ffprobe -v quiet -show_format -show_streams video.mp4
exiftool video.mp4
mkvinfo video.mkv
```

## Разобранный пример

CTF: MP4. Пентестер:
1. `ffmpeg -i video.mp4 frames/%05d.png`.
2. Сравнивает кадры → один резко отличается → на нём QR/текст.
3. Сканирует QR → флаг.

## Частые ошибки

- Смотреть видео в плеере и не разбирать на кадры.
- Не извлекать аудиодорожку (данные могут быть в звуке).
- Игнорировать метаданные контейнера.
- Пропускать скрытые/дублирующиеся дорожки.

## Что делать дальше

- **Отличающийся кадр** → QR/OCR/стего в нём.
- **Разница кадров как канал** → извлеките биты из различий.
- **Аудио** → примените аудио-методы.
- **Метаданные** → `ffprobe`/`exiftool`/`mkvinfo`.

## Структура видео и каналы сокрытия

Видео — контейнер + поток кадров + аудио. У каждого слоя свой набор каналов.

| Слой | Канал сокрытия | Как искать |
|------|----------------|-----------|
| Кадры | отличающийся/лишний кадр | экспорт кадров, сравнение |
| Пиксели кадра | LSB/RGB внутри кадра | zsteg на каждом кадре |
| DCT кадра | младшие биты коэффициентов | стего-инструменты на JPEG-кадрах |
| Тайминги | PTS/длительность кадров | `ffprobe` |
| Аудио | LSB/эхо/спектр | аудио-методы |
| Контейнер | метаданные, скрытые дорожки, хвост | `ffprobe`/`exiftool`/`binwalk` |
| Хвост файла | appended данные | `binwalk`, `grep -abo` |

## Разбор на кадры: полный набор ffmpeg

```bash
# все кадры (PNG без потерь)
ffmpeg -i video.mp4 frames/%05d.png
# с заданной частотой
ffmpeg -i video.mp4 -vf fps=10 frames/%05d.png
# только ключевые (I-) кадры
ffmpeg -skip_frame nokey -i video.mp4 frames/key_%05d.png
# кадры в JPEG (для DCT-анализа)
ffmpeg -i video.mp4 -q:v 2 frames/%05d.jpg
# извлечь аудио без перекодирования
ffmpeg -i video.mp4 -vn -acodec copy audio.aac
ffmpeg -i video.mp4 -vn -ac 1 -ar 44100 audio.wav
# контейнерная информация
ffprobe -v error -show_streams -show_format video.mp4
```

## Поиск отличающегося кадра: метрики и скрипты

```bash
# попарная разница (ImageMagick): AE = число различающихся пикселей
compare -metric AE frames/00001.png frames/00002.png null: 2>&1
# разница каждого кадра с первым, сортировка по величине
for f in frames/*.png; do
  v=$(compare -metric AE frames/00001.png "$f" null: 2>&1)
  echo "$v $f"
done | sort -rn | head -10
# визуальная разница всех кадров
ffmpeg -i video.mp4 -vf "tblend=all_mode=difference" diff_%05d.png
```

```python
# Альтернатива: перцептивный хеш (imagehash) — устойчив к мелким изменениям
import imagehash, glob
from PIL import Image
hs = {f: imagehash.phash(Image.open(f)) for f in sorted(glob.glob('frames/*.png'))}
base = list(hs.values())[0]
for f, h in hs.items():
    if (h - base) > 5:      # порог
        print('выбивается:', f, h - base)
```

Отличающийся кадр обычно и есть носитель: на нём QR, текст, другое изображение.

## Аудиодорожка

Аудио в видео — тот же WAV/AAC-поток: примените аудио-методы (LSB, спектрограмма, DTMF/SSTV/морзе).

```bash
ffmpeg -i video.mp4 -vn -acodec pcm_s16le audio.wav
sox audio.wav -n spectrogram -o spec.png
multimon-ng -a DTMF -t wav audio.wav
```

## Метаданные и скрытые дорожки контейнера

```bash
ffprobe -v quiet -show_format -show_streams video.mp4   # все потоки, теги
exiftool video.mp4                                      # теги/комментарии
mkvinfo video.mkv                                       # структура MKV
# скрытые дорожки (субтитры, data)
ffprobe -v error -show_entries stream=index,codec_type,codec_name video.mp4
# извлечь субтитры/доп. потоки
ffmpeg -i video.mp4 -map 0:s:0 subs.srt
```

## Инструменты (таблица)

| Инструмент | Назначение | Пример |
|------------|-----------|--------|
| `ffmpeg`/`ffprobe` | кадры, аудио, метаданные | `ffmpeg -i v.mp4 frames/%05d.png` |
| ImageMagick `compare` | попиксельная разница | `compare -metric AE a.png b.png null:` |
| `imagehash` (pip) | перцептивный хеш кадров | см. скрипт |
| `zsteg` | LSB в кадрах | `zsteg frame.png` |
| `exiftool`/`mkvinfo` | метаданные контейнера | `exiftool v.mp4` |
| `binwalk` | хвост/встроенные файлы | `binwalk v.mp4` |

## Разобранные примеры

**1. Лишний кадр.** 300 кадров, `compare` показывает, что кадр 217 резко отличается → QR → флаг.

**2. Аудио.** Видео «немое», но `ffmpeg -vn` извлекает дорожку с DTMF → цифры.

**3. Метаданные.** `ffprobe` показывает скрытый поток субтитров с текстом-флагом.

## Частые ошибки и отладка

- **Смотреть в плеере** — кадры/тайминги не видны.
- **Не извлекать аудио** — данные могут быть в звуке.
- **Сравнивать не все кадры** — берите каждый против первого.
- **Игнорировать метаданные/скрытые дорожки.**
- **Отладка:** если `compare` даёт 0 для всех — кадры идентичны, ищите в пикселях/DCT/аудио; если разница везде большая — видео сжато с потерями, смотрите перцептивный хеш.

## Что делать дальше / дерево решений

1. `ffmpeg` → кадры; `compare`/phash → отличающийся → QR/OCR/стего в нём.
2. Нет отличий → `zsteg` по кадрам (LSB) и DCT.
3. `ffmpeg -vn` → аудио → аудио-методы.
4. `ffprobe`/`exiftool`/`mkvinfo` → метаданные, скрытые дорожки.
5. Ничего → `binwalk` хвост контейнера.

## Шпаргалка: полный конвейер

```bash
# 1) кадры + аудио + метаданные
ffmpeg -i v.mp4 frames/%05d.png
ffmpeg -i v.mp4 -vn audio.wav
ffprobe -v error -show_streams -show_format v.mp4
# 2) поиск отличающегося кадра
for f in frames/*.png; do v=$(compare -metric AE frames/00001.png "$f" null: 2>&1); echo "$v $f"; done | sort -rn | head
# 3) LSB по кадрам и хвост
zsteg frames/00001.png
binwalk v.mp4
```

Практические подсказки: если все кадры «одинаковы» по `compare`, но видео странное — смотрите перцептивный хеш (phash), метаданные и аудио; если разница везде большая (сжатие с потерями), извлекайте кадры в PNG без потерь и сравнивайте по краям/центру. Не забывайте про скрытые дорожки (субтитры, data) — `ffprobe` покажет все потоки. В отчёте фиксируйте номер «выбивающегося» кадра, канал (кадр/аудио/метаданные) и результат.

## Квиз

```quiz
- question: "Как разложить видео на кадры?"
  options:
    - "ffmpeg -i video.mp4 frames/%05d.png"
    - "jadx video.mp4"
    - "zsteg video.mp4"
    - "mmls video.mp4"
  answer: 0
  explanation: "ffmpeg экспортирует кадры как изображения."
- question: "Где часто прячут флаг в видео?"
  options:
    - "В одном отличающемся кадре"
    - "В расширении файла"
    - "В размере"
    - "В имени"
  answer: 0
  explanation: "Отличия между кадрами выдают скрытый контент."
- question: "Каким инструментом посмотреть метаданные MP4/MKV?"
  options:
    - "ffprobe / exiftool / mkvinfo"
    - "zsteg"
    - "mutool"
    - "wrestool"
  answer: 0
  explanation: "Они показывают потоки и метаданные контейнера."
- question: "Как извлечь аудиодорожку?"
  options:
    - "ffmpeg -i video.mp4 -vn audio.wav"
    - "ffmpeg -i video.mp4 frames/%d.png"
    - "ffprobe"
    - "mkvinfo"
  answer: 0
  explanation: "-vn отключает видео, оставляя аудио."
- question: "Где в видео применяется DCT-стего?"
  options:
    - "В DCT-коэффициентах кадров (как в JPEG)"
    - "В имени контейнера"
    - "В частоте кадров"
    - "В битрейте"
  answer: 0
  explanation: "Кадры кодируются DCT, туда можно встроить данные."
```

## Где пригодится

- **CTF Stego:** видео-носители.
- **Forensics:** скрытые данные в видео.
- **Bug bounty:** нестандартные каналы.
- **Работа:** анализ медиаконтента.
