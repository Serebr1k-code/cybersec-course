---
id: stego-audio-lsb
title: "Аудио LSB: сокрытие в сэмплах WAV/AU"
category: stego
parent: stego-audio
difficulty: easy
order: 1
tags: [stego, audio, wav, lsb, samples, pcm, au]
prerequisites: [stego-audio]
useful_for:
  - "CTF Stego — аудио-носители"
  - "Ручное извлечение из PCM-данных"
  - "Forensics: анализ аудио на скрытые данные"
estimated_minutes: 35
summary: "Как прячут данные в младших битах аудиосэмплов: структура WAV, ручное извлечение, инструменты (wav2png, DeepSound), и почему аудио — удобный носитель большой ёмкости."
---

WAV/AU — несжатые PCM-форматы: сэмплы лежат последовательно, младший бит почти не влияет на звук. Это делает LSB-стеганографию в аудио простой и ёмкой (десятки-сотни КБ). Задача — найти, в каких битах/каналах/порядке спрятаны данные, и извлечь их.

## Структура WAV

```
RIFF header (44 байта) | data chunk (PCM samples)
```
Сэмплы: 8/16/24/32 бита, моно/стерео. Для 16-бит LSB — младший бит каждого 2-байтового сэмпла.

## Извлечение LSB

```python
import wave, numpy as np
w = wave.open('audio.wav','rb')
n, sw, ch, sr = w.getnframes(), w.getsampwidth(), w.getnchannels(), w.getframerate()
raw = w.readframes(n)
if sw == 2:
    data = np.frombuffer(raw, dtype='<i2')
    bits = (data & 1).astype(str)
    bits = ''.join(bits)
    print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-7,8)))
```

Пробуйте: только левый/правый канал, порядок LSB/MSB, пропуск заголовка, интерливинг.

## Инструменты

```bash
# посмотреть LSB как картинку (иногда виден текст)
wav2png audio.wav          # или скриптом
# DeepSound (Windows GUI) — парольная стего в аудио
# Sonic Visualiser — спектрограмма/просмотр
# outguess/стего-аудио-скрипты
```

## Каналы и порядок

- **Каналы:** данные могут быть только в одном канале стерео.
- **Биты:** 1 LSB часто; иногда 2-4 LSB или MSB.
- **Заголовок:** пропустить 44 байта (или данные могут быть и в них).
- **Порядок:** little/big endian, interleaved.

## Разобранный пример

CTF: WAV 16-бит стерео. Пентестер:
1. Извлекает LSB левого канала → мусор.
2. Пробует правый канал → читаемый текст → флаг.
3. Если нет — пробует MSB/2 LSB.

## Частые ошибки

- Не учитывать каналы (стерео) и интерливинг.
- Игнорировать заголовок/сдвиг.
- Пробовать только 1 LSB.
- Путать эндианность.

## Что делать дальше

- **LSB канала** → извлеките и декодируйте.
- **Пусто** → переберите каналы/биты/порядок.
- **Нет LSB** → эхо/фаза/спектрограмма (`stego-audio-advanced`).
- **Пароль** → DeepSound/стего-парольные схемы.

## PCM и структура WAV/AU (byte-level)

Понимание раскладки сэмплов — ключ к правильному извлечению: где начинаются данные, как чередуются каналы, какой размер сэмпла.

| Поле WAV | Смещение | Размер | Значение |
|----------|----------|--------|----------|
| `RIFF` | 0x00 | 4 | сигнатура |
| ChunkSize | 0x04 | 4 | размер минус 8 |
| `WAVE` | 0x08 | 4 | формат |
| `fmt ` | 0x0C | 4 | подчанк формата |
| AudioFormat | 0x14 | 2 | 1 = PCM |
| NumChannels | 0x16 | 2 | 1/2/… |
| SampleRate | 0x18 | 4 | 8000/44100/… |
| BitsPerSample | 0x22 | 2 | 8/16/24/32 |
| `data` | 0x24 | 4 | подчанк данных |
| DataSize | 0x28 | 4 | размер PCM |
| Сэмплы | 0x2C | — | interleaved L,R,L,R… |

```bash
soxi audio.wav              # каналы, частота, биты, длительность
file audio.wav
xxd audio.wav | head -4     # заголовок
```

## Полный скрипт извлечения LSB (варианты)

```python
import wave, numpy as np

def load(path):
    w = wave.open(path, 'rb')
    sw, ch, sr, n = w.getsampwidth(), w.getnchannels(), w.getframerate(), w.getnframes()
    raw = w.readframes(n)
    return raw, sw, ch

def to_bytes(bits):
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8))

raw, sw, ch = load('audio.wav')
if sw == 1:
    data = np.frombuffer(raw, np.uint8)
elif sw == 2:
    data = np.frombuffer(raw, '<i2')
elif sw == 4:
    data = np.frombuffer(raw, '<i4')

# 1) LSB всех сэмплов
bits = ''.join(str(int(s) & 1) for s in data)
print(to_bytes(bits)[:300])

# 2) только один канал (левый/правый)
if ch == 2:
    left  = data[0::2]; right = data[1::2]
    for name, ch_data in [('L', left), ('R', right)]:
        b = ''.join(str(int(s) & 1) for s in ch_data)
        print(name, to_bytes(b)[:200])

# 3) MSB
b = ''.join(str((int(s) >> (sw*8-1)) & 1) for s in data)
print('MSB', to_bytes(b)[:200])

# 4) 2 младших бита
b = ''.join(format(int(s) & 3, '02b') for s in data)
print('2LSB', to_bytes(b)[:200])
```

## Каналы, биты, порядок: полный перебор

Данные могут быть спрятаны с десятком вариаций. Перебирайте системно:

- **Канал:** все / только левый / только правый / интерливинг.
- **Бит:** LSB (бит 0), 2–4 LSB, MSB.
- **Порядок бит:** LSB-first / MSB-first.
- **Эндианность сэмпла:** little (обычно) / big.
- **Сдвиг:** пропуск заголовка (44 байта) или нет.
- **Интерпретация:** ASCII / UTF-16 / биты → картинка.

Быстрый перебор в один проход:

```python
for chsel in ('all','L','R'):
    for bit in range(0,3):
        for msbfirst in (False, True):
            # ... собрать биты, собрать байты, искать b'flag' или PNG-сигнатуру
            pass
```

## Инструменты: wav2png, DeepSound, Sonic Visualiser, stegolsb

| Инструмент | Назначение | Пример |
|------------|-----------|--------|
| `stegolsb` (pip) | LSB в WAV с ёмкостью/кодированием | `stegolsb wavsteg -r -i a.wav -o out.txt -n 1000` |
| `wav2png` | LSB-сэмплы как картинка | `wav2png a.wav` |
| Sonic Visualiser | спектрограмма, слои, курсоры | GUI |
| DeepSound | парольная стего в аудио (Windows) | GUI |
| Audacity | спектр + ручное извлечение | Spectrogram |
| `sox` | конвертация/чистка | `sox in.wav out.wav` |

```bash
pip install stegolsb
stegolsb wavsteg -h
# декодировать из файла (если знаете схему)
stegolsb wavsteg -r -i audio.wav -o secret.bin -n <bytes>
```

## Другие аудио-схемы (кратко)

Если LSB пусто, данные могут быть в:

- **Эхо-скрытии** — изменение задержки/амплитуды эха кодирует биты (`stego-audio-echo`).
- **Фазовом кодировании** — сдвиг фазы сегментов.
- **Спектрограмме** — текст/DTMF/SSTV (`stego-audio-spec`).
- **Тоне/частоте** — FSK.

## Разобранные примеры

**1. Стерео-канал.** WAV 16-бит стерео: LSB «всех» даёт мусор, LSB **правого** канала — текст.

**2. MSB.** LSB пусто; MSB (старший бит) даёт `flag{...}` — редкий, но встречается.

**3. Картинка.** Биты LSB, собранные в строку шириной W, дают видимое изображение (не текст).

## Частые ошибки и отладка

- **Игнорировать каналы/интерливинг** — половина данных теряется.
- **Неверный размер сэмпла** — `sw` не 2, а 1/4; проверьте `soxi`.
- **Пропустить/не пропустить заголовок** — 44 байта сдвигают поток.
- **Только 1 LSB** — пробуйте 2–4 и MSB.
- **Эндианность** — `<i2` vs `>i2`.
- **Отладка:** ищите в выводе сигнатуры (`flag`, `PK`, `\x89PNG`) — они сразу показывают правильную комбинацию.

## Что делать дальше / дерево решений

1. `soxi` → параметры; LSB всех сэмплов → текст?
2. Нет → переберите канал/бит/порядок (скрипт выше).
3. Нет → MSB, 2 LSB, эндианность.
4. Нет → эхо/фаза (`stego-audio-echo`).
5. Нет → спектрограмма/сигналы (`stego-audio-spec`).

## Шпаргалка: быстрый перебор каналов

```bash
soxi audio.wav                                   # каналы/биты/частота
python3 -c "
import wave,numpy as np
w=wave.open('audio.wav');sw=w.getsampwidth();ch=w.getnchannels()
d=np.frombuffer(w.readframes(w.getnframes()),{1:'u1',2:'<i2',4:'<i4'}[sw])
for name,arr in [('all',d)]+([('L',d[0::2]),('R',d[1::2])] if ch==2 else []):
    for bit in range(0,3):
        b=''.join(str((int(s)>>bit)&1) for s in arr)
        print(name,bit,bytes(int(b[i:i+8],2) for i in range(0,len(b)-7,8))[:60])
"
```

Если ни один канал не даёт текст — попробуйте MSB, порядок MSB-first, эндианность `>i2`, и поищите в выводе сигнатуры `flag`, `PK`, `\x89PNG` (они сразу укажут правильную комбинацию). Не забывайте, что данные могут быть не текстом, а изображением: соберите биты в матрицу ширины W и сохраните как PNG. В отчёте фиксируйте: канал (L/R/all), бит (0/1/…), порядок и эндианность — без этого результат невоспроизводим.

## Квиз

```quiz
- question: "Почему аудио удобно для LSB-стего?"
  options:
    - "Сэмплы несжатые, младший бит почти не влияет на звук"
    - "Файл маленький"
    - "Он шифрован"
    - "Он содержит EXIF"
  answer: 0
  explanation: "PCM-сэмплы дают много младших бит без заметных искажений."
- question: "Сколько байт занимает стандартный WAV-заголовок?"
  options:
    - "44 байта"
    - "8 байт"
    - "256 байт"
    - "1024 байта"
  answer: 0
  explanation: "Стандартный RIFF/WAV заголовок — 44 байта."
- question: "Что проверить в стерео-файле?"
  options:
    - "Левый/правый каналы и интерливинг"
    - "Только имя"
    - "Только DPI"
    - "Только битрейт"
  answer: 0
  explanation: "Данные могут быть в одном из каналов."
- question: "Какой инструмент делает из WAV картинку для визуального анализа?"
  options:
    - "wav2png / Sonic Visualiser"
    - "jadx"
    - "mmls"
    - "zsteg"
  answer: 0
  explanation: "Визуализация LSB/спектра помогает увидеть данные."
- question: "Что делать, если LSB пусто?"
  options:
    - "Пробовать эхо/фазу/спектрограмму"
    - "Сдаться"
    - "Переименовать файл"
    - "Сжать в mp3"
  answer: 0
  explanation: "Продвинутые аудио-методы могут содержать данные."
```

## Где пригодится

- **CTF Stego:** аудио-носители.
- **Forensics:** скрытые данные в звуке.
- **Bug bounty:** нестандартные каналы.
- **Работа:** анализ аудио.
