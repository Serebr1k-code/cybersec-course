---
id: stego-audio-spec
title: "Спектрограмма, DTMF, SSTV, FSK и морзе в аудио"
category: stego
parent: stego-audio-advanced
difficulty: medium
order: 1
tags: [stego, audio, spectrogram, dtmf, sstv, fsk, morse, fft]
prerequisites: [stego-audio-advanced]
useful_for:
  - "CTF Stego — сигналы в аудио"
  - "Радиолюбительские и телеком-задачи"
  - "Forensics: анализ скрытых сигналов"
estimated_minutes: 45
summary: "Глубокий разбор сигнальных методов в аудио: чтение спектрограммы, распознавание DTMF, декодирование SSTV, FSK/RTTY и морзе; инструменты и практические приёмы."
---

Аудио-стеганография — это не только LSB: данные часто передаются как **сигнал** — тональности, тоны, модуляции. Спектрограмма превращает звук в картинку (время × частота × амплитуда), на которой видны скрытые тона, текст, DTMF, SSTV. Далее декодируют конкретную схему: DTMF (телефонные тоны), SSTV (передача изображений по радио), FSK/RTTY, морзе.

## Спектрограмма

```bash
# sox → spectrogram PNG
sox audio.wav -n spectrogram -o spec.png
# или Sonic Visualiser / Audacity (Spectrogram view)
```

На спектрограмме ищите: текст, выписанный тонами; два тона (FSK); DTMF-пары; SSTV-паттерн (виден как «водопад»).

## DTMF

Два тона (строка+столбец) кодируют цифру. Инструменты: `dtmf` (multimon-ng), Audacity (чтение спектра).

```bash
multimon-ng -a DTMF -t wav audio.wav
# или
sox audio.wav -t raw - | multimon-ng -a DTMF -
```

## SSTV

SSTV передаёт изображения (Robot, Martin, Scottie). Декодеры: `qsstv`, `sstv` (Python), MMSSTV. Извлечённое изображение может содержать флаг/QR.

```bash
# pip install sstv
python3 -m sstv -d audio.wav -o out.png
```

## FSK/RTTY и морзе

```bash
# RTTY/FSK
multimon-ng -a RTTY -a AFSK1200 -t wav audio.wav
# морзе (спектрограммой вручную или декодером)
multimon-ng -a MORSE_CW -t wav audio.wav
```

Часто морзе/тоны читают прямо со спектрограммы (короткие/длинные штрихи).

## Разобранный пример

CTF: WAV, на слух — писк. Пентестер:
1. `sox audio.wav -n spectrogram -o spec.png` → видит текст буквами на спектре → флаг.
2. Или видит DTMF → `multimon-ng -a DTMF` → цифры → телефон/флаг.

## Частые ошибки

- Слушать аудио вместо анализа спектра.
- Не знать, что текст может быть «нарисован» тонами.
- Игнорировать SSTV (изображение внутри звука).
- Путать FSK (два тона) и DTMF (пары тонов).

## Что делать дальше

- **Текст на спектре** → прочитайте напрямую.
- **DTMF** → `multimon-ng -a DTMF`.
- **SSTV-паттерн** → декодируйте в изображение.
- **Морзе/FSK** → декодеры/спектрограмма.

## Спектрограмма: построение и чтение

Спектрограмма — рабочая лошадка аудио-стего. Правильные параметры FFT важнее инструмента.

```bash
# sox: PNG-спектрограмма
sox audio.wav -n spectrogram -o spec.png
# с настройками (окно, перекрытие, диапазон частот, лог-шкала)
sox audio.wav -n spectrogram -X 1000 -Y 400 -z 100 -r -o spec.png
#   -X ширина, -Y высота, -z диапазон dB, -r лог-частоты
# ffmpeg: показать спектр (showspectrumpic)
ffmpeg -i audio.wav -lavfi showspectrumpic=s=1920x1080 spec.png
# GUI: Audacity (Spectrogram view), Sonic Visualiser, Spek, baudline
```

Что искать: **горизонтальный текст** из тонов; два параллельных тона (FSK); короткие/длинные штрихи (морзе); «водопад» SSTV; характерные пары DTMF. Иногда спектр нужно инвертировать или взять лог-шкалу, чтобы текст стал читаемым.

## DTMF: полный декодер

DTMF — сумма двух синусов из матрицы 4×4 (низкая группа 697/770/852/941 Гц, высокая 1209/1336/1477/1633 Гц).

```bash
multimon-ng -a DTMF -t wav audio.wav
# из сырого потока
sox audio.wav -t raw -e signed -b 16 -r 8000 - | multimon-ng -t raw -a DTMF -
# GUI: Audacity → спектрограмма → прочитать пары частот вручную
```

```python
# ручной декодер (при наличии scipy): Goertzel по 8 частотам на окнах
import numpy as np, wave
w = wave.open('audio.wav'); sr = w.getframerate()
x = np.frombuffer(w.readframes(w.getnframes()), '<i2').astype(float)
lo = [697,770,852,941]; hi = [1209,1336,1477,1633]
keys = [['1','2','3','A'],['4','5','6','B'],['7','8','9','C'],['*','0','#','D']]
# для каждого кадра 40 мс — максимум энергии в lo и hi → индекс → keys
```

## SSTV: режимы и декодирование

SSTV (Slow-Scan TV) передаёт изображение построчно по аудиоканалу. Режимы: Robot 36/72, Martin M1/M2, Scottie S1/S2, PD-120/180, Wraase.

```bash
# Python-декодер (все режимы, автоопределение)
pip install sstv
python3 -m sstv -d audio.wav -o out.png
# qsstv (Linux GUI), MMSSTV (Windows), RXSSTV
# почистить сигнал перед декодом:
sox in.wav out.wav highpass 300 lowpass 3000 norm
```

Декодированное изображение часто содержит текст/QR с флагом. SSTV легко узнать по спектрограмме: чередующиеся яркие полосы с синхроимпульсами.

## FSK/RTTY и морзе: полный разбор

```bash
multimon-ng -a RTTY -a AFSK1200 -a AFSK2400 -t wav audio.wav   # RTTY/пакет
multimon-ng -a MORSE_CW -t wav audio.wav                        # морзе
# MFSK, POCSAG, FLEX и др.
multimon-ng -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -t wav audio.wav
```

RTTY: два тона (mark/space) с частотным сдвигом (обычно 170 Гц), 45.45 бод. Морзе: читается и вручную со спектрограммы — точки короткие, тире длинные; пробелы = границы символов/слов.

## Скрытый текст, «нарисованный» тонами

Иногда флаг выписан буквами прямо в спектре: каждый символ — это тон определённой частоты, меняющийся во времени. Рецепт: построить спектрограмму с узким FFT-окном (`-X`/`-Y`), при необходимости инвертировать по времени/частоте, прочитать текст глазами. Часто требуется «вытянуть» контраст (`-z`, лог-шкала).

## Инструменты и установка

| Инструмент | Назначение | Команда |
|------------|-----------|---------|
| `sox` | спектрограмма, чистка, конвертация | `sox in.wav -n spectrogram -o s.png` |
| `multimon-ng` | DTMF/RTTY/морзе/POCSAG | `multimon-ng -a DTMF -t wav a.wav` |
| `sstv` (pip) | декод SSTV | `python3 -m sstv -d a.wav -o o.png` |
| Audacity | GUI-спектр, ручное чтение | Spectrogram view |
| Sonic Visualiser | точные спектрограммы, слои | GUI |
| `ffmpeg` | showspectrumpic | см. выше |

## Разобранные примеры

**1. Текст в спектре.** WAV с «писком». `sox audio.wav -n spectrogram -o spec.png` → на картинке читается `flag{sp3ctr0}`.

**2. DTMF.** `multimon-ng -a DTMF` → `1 5 5 5 1 2 3 4` → это телефон/координаты → дальнейший шаг CTF.

**3. SSTV.** Спектрограмма показывает «водопад» → `python3 -m sstv -d audio.wav -o out.png` → картинка с флагом.

## Частые ошибки и отладка

- **Слушать вместо спектра** — большинство каналов неслышимы.
- **Слишком узкая/широкая FFT** — текст не читается; перебирайте `-X/-Y/-z`.
- **Игнорировать инверсию** частот/времени.
- **Путать FSK (два тона) и DTMF (пары тонов).**
- **Плохой вход** — почистите фильтром (highpass/lowpass) и нормируйте.
- **Отладка:** если `multimon-ng` молчит — проверьте частоту дискретизации и формат (`-t wav`/`-t raw`).

## Что делать дальше / дерево решений

1. `sox ... spectrogram` → текст виден? → прочитайте.
2. Тоны парами? → DTMF-декодер.
3. «Водопад»? → SSTV-декодер.
4. Ровные тона/штрихи? → RTTY/морзе.
5. Ничего? → LSB (`stego-audio-lsb`), эхо/фаза (`stego-audio-echo`), инверсия спектра.

## Шпаргалка и рабочий процесс

```bash
# 1) спектрограмма (главный инструмент)
sox audio.wav -n spectrogram -X 1200 -Y 500 -z 100 -r -o spec.png
# 2) сигнальные декодеры одним прогоном
multimon-ng -a DTMF -a MORSE_CW -a RTTY -a AFSK1200 -t wav audio.wav
# 3) SSTV
python3 -m sstv -d audio.wav -o out.png
# 4) чистка сигнала перед декодом
sox in.wav clean.wav highpass 300 lowpass 3000 norm
```

Рабочий процесс: сначала постройте спектрограмму и **посмотрите** её — большинство сигнальных задач решаются глазами (текст тонами, DTMF-пары, SSTV-«водопад»). Затем примените автоматические декодеры. Если `multimon-ng` молчит — проверьте формат (`-t wav` vs `-t raw`) и частоту дискретизации; если текст «не читается» — переберите `-X/-Y/-z` и лог-шкалу, попробуйте инверсию частот/времени. В отчёте фиксируйте: тип сигнала, инструмент, параметры FFT и результат.

## Квиз

```quiz
- question: "Что показывает спектрограмма?"
  options:
    - "Зависимость частоты от времени и амплитуды"
    - "Только громкость"
    - "EXIF"
    - "Длину файла"
  answer: 0
  explanation: "Спектрограмма — время × частота × амплитуда."
- question: "Сколько тонов кодируют одну цифру DTMF?"
  options:
    - "Два (строка + столбец)"
    - "Один"
    - "Три"
    - "Четыре"
  answer: 0
  explanation: "DTMF использует пару частот."
- question: "Что передаёт SSTV?"
  options:
    - "Изображения по радио"
    - "Только текст"
    - "Только цифры"
    - "Ключи"
  answer: 0
  explanation: "SSTV — медленное сканирование изображения."
- question: "Каким инструментом декодировать DTMF/RTTY?"
  options:
    - "multimon-ng"
    - "jadx"
    - "zsteg"
    - "mmls"
  answer: 0
  explanation: "multimon-ng поддерживает множество аудиомодуляций."
- question: "Как быстро построить спектрограмму из командной строки?"
  options:
    - "sox audio.wav -n spectrogram -o spec.png"
    - "jadx audio.wav"
    - "file audio.wav"
    - "nm audio.wav"
  answer: 0
  explanation: "sox умеет генерировать spectrogram PNG."
```

## Где пригодится

- **CTF Stego:** сигналы в аудио.
- **Радио/телеком:** декодирование передач.
- **Forensics:** скрытые сигналы.
- **Работа:** анализ аудиоканалов.
