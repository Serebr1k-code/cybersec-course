---
id: hardware-gnuradio
title: "GNU Radio и GRC: графы обработки сигналов и декодирование"
category: hardware
parent: hardware-sdr-deep
difficulty: hard
order: 1
tags: [gnuradio, grc, flowgraph, blocks, python, demodulation, sdr, dsp]
prerequisites: [hardware-sdr-deep, hardware-rtl-sdr]
useful_for:
  - "CTF-задачи категории Hardware/Radio"
  - "Реверс и декодирование сигналов"
  - "Разработка SDR-обработки"
estimated_minutes: 50
summary: "GNU Radio и GNU Radio Companion: как строить графы обработки сигналов, ключевые блоки, Python API и практическое декодирование."
---

**GNU Radio** — фреймворк для цифровой обработки сигналов, на котором строится большинство продвинутых SDR-инструментов. Вы соединяете **блоки** (источник, фильтр, демодулятор, приёмник) в **граф** (flowgraph), и GNU Radio выполняет его в реальном времени. **GNU Radio Companion (GRC)** — визуальный редактор графов. Этот урок — про то, как строить и понимать такие графы, что критично для декодирования нестандартных протоколов.

## Архитектура GNU Radio

GNU Radio — это библиотека C++ с Python-обвязкой. Основные понятия:

- **Block** — элементарная операция (фильтр, демодулятор, источник, сток).
- **Flowgraph** — граф соединённых блоков.
- **Stream** — поток данных между блоками (complex/float/int/byte).
- **Source/Sink** — вход/выход (SDR-устройство, файл, звук).

Данные текут от источника к стоку; каждый блок обрабатывает поток. GNU Radio планирует потоки и распределяет по потокам ОС.

## GRC: визуальный редактор

GRC позволяет собрать граф мышью и сгенерировать Python-скрипт.

```bash
gnuradio-companion   # запуск GRC
```

Типовой граф FM-приёмника: `RTL-SDR Source` → `Rational Resampler` → `WBFM Receive` → `Audio Sink`. Соединяете порты, задаёте параметры (частота, sample rate), нажимаете «Run» (F6) — и слышите радио.

Ключевые параметры блоков: тип данных (`Complex`, `Float`), `samp_rate`, центральная частота, усиление. Несовпадение типов или sample rate — самая частая причина «тишины».

## Полезные блоки

| Блок | Назначение |
|------|-----------|
| RTL-SDR Source | источник с донгла |
| File Source/Sink | чтение/запись IQ |
| Frequency Xlating FIR Filter | перенос и фильтрация |
| Rational Resampler | пересэмплирование |
| Quadrature Demod | FM-демодуляция |
| Binary Slicer | оцифровка в 0/1 |
| Clock Recovery MM | восстановление такта |
| Correlate Access Code | поиск преамбулы |
| Symbol Sync | синхронизация символов |
| Constellation Decoder | демодуляция символов |
| Packet Decoder | сборка пакетов |

Комбинация `Clock Recovery` + `Symbol Sync` + `Constellation Decoder` + `Packet Decoder` — типовой конвейер для цифровых протоколов.

## Python API

Граф можно построить и в Python:

```python
from gnuradio import gr, blocks, analog, filter
from gnuradio.blocks import file_sink
import osmosdr

class TopBlock(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self, "FM")
        self.src = osmosdr.source(args="rtl=0")
        self.src.set_sample_rate(1e6)
        self.src.set_center_freq(100e6)
        self.resamp = filter.rational_resampler_ccc(1, 2)
        self.demod = analog.wfm_rcv(quad_rate=500e3)
        self.sink = file_sink(gr.sizeof_float, "/tmp/audio.raw", False)
        self.connect(self.src, self.resamp, self.demod, self.sink)

tb = TopBlock()
tb.run()
```

Это позволяет встраивать SDR-обработку в свои скрипты, автоматизировать запись и анализ.

## Разобранный пример: декодирование OOK-пульта

```python
# Идея: OOK = амплитудная манипуляция. Демодулируем амплитуду и оцифровываем.
from gnuradio import gr, blocks, analog, digital
import osmosdr

class OOK(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self, "OOK")
        self.src = osmosdr.source(args="rtl=0")
        self.src.set_sample_rate(1e6)
        self.src.set_center_freq(433.92e6)
        self.src.set_gain(40)
        # Амплитуда комплексного сигнала -> magnitude
        self.mag = blocks.complex_to_mag(1)
        # Порог -> 0/1
        self.thr = blocks.threshold_ff(0.05, 0.05)
        # Запись битового потока
        self.sink = blocks.file_sink(gr.sizeof_float, "/tmp/ook.bin", False)
        self.connect(self.src, self.mag, self.thr, self.sink)

OOK().run()
```

Затем битовый поток анализируется скриптом: измеряются длительности импульсов, определяется кодирование (например, PWM/PPM) и декодируются биты. Для сложных протоколов используйте **URH** — он делает это интерактивно.

## Установка

```bash
# Debian/Ubuntu
sudo apt install gnuradio gr-osmosdr gqrx-sdr
# Проверка
gnuradio-config-info --version
# Для RTL-SDR
sudo apt install rtl-sdr librtlsdr-dev
```

Часто проще использовать готовые образы (DragonOS/GNU Radio Live), где всё предустановлено.

## Частые ошибки и подводные камни

- **Несовпадение sample rate**: ресемплер нужен при переходе между блоками с разной частотой.
- **Overflow (O) в консоли**: CPU не успевает — уменьшите sample rate/полосу.
- **Нет сигнала**: проверьте центр частоты, gain, антенну.
- **Типы данных**: complex → float через `complex_to_mag`/`complex_to_arg`.
- **Плавающий порог**: для OOK порог надо подбирать под сигнал.
- **Версии блоков**: в новых GNU Radio 3.10 часть блоков переименована.

## Синхронизация и восстановление такта

Цифровой сигнал приходит «смазанным»: нет точного момента начала символа, частота приёмника немного отличается от передатчика. Поэтому в конвейере декодирования есть два этапа синхронизации:

- **Clock recovery (восстановление такта)** — определяет моменты, когда считывать символы. Блоки `Clock Recovery MM`, `Symbol Sync` (Gardner/Mueller-Muller) решают эту задачу.
- **Frame sync (синхронизация кадра)** — находит начало пакета по корреляционной преамбуле (`Correlate Access Code`).

Типовой конвейер для FSK-протокола: `Quadrature Demod` → `Clock Recovery MM` → `Binary Slicer` → `Correlate Access Code` → `Packet Decoder`. Параметры (omega, gain mu, mu) подбираются под скорость символов; неверные значения дают «плавающие» биты и не декодируют пакет. Иногда проще сначала оцифровать сигнал в 0/1 и разобрать его в URH, где синхронизация настраивается интерактивно.

## Разбор реального протокола: FSK-датчик

Датчик температуры передаёт пакет FSK на 433.92 МГц. Порядок анализа:

1. Записать IQ (`rtl_sdr -f 433920000 -s 1024000 cap.iq`).
2. В inspectrum найти преамбулу и измерить длительность бита.
3. В GRC собрать FSK-демодулятор: `RTL-SDR Source` → `Frequency Xlating FIR Filter` (центрировать на сигнал) → `Quadrature Demod` → `Clock Recovery MM` → `Binary Slicer`.
4. Записать биты в файл и разобрать структуру (преамбула, ID, данные, CRC).
5. Свериться с `rtl_433` — возможно, протокол уже известен.

Такой подход даёт полный контроль: вы видите каждый бит и понимаете формат. Для воспроизведения сигнала нужен TX-SDR (см. `hardware-subghz`).

## Автоматизация записи и анализа

GNU Radio удобно вызывать из скриптов для пакетной обработки:

```bash
# Запустить сохранённый flowgraph в headless-режиме
python3 fm_receiver.py
# Или через grcc сгенерировать и запустить
grcc fm_receiver.grc
python3 fm_receiver.py --freq 100e6
```

Можно параметризовать частоту/усиление через переменные GRC и менять их из командной строки. Для массовой записи спектра используйте `rtl_power` + `inspectrum` + свои скрипты. Для автоматического декодирования — `rtl_433` в режиме потока. Комбинируя инструменты, вы строите конвейер «запись → детект → декод → отчёт», который экономит массу времени в пентесте эфира.

## Производительность и оптимизация

GNU Radio чувствителен к нагрузке CPU. Если видите `O` (overflow) в консоли, поток не успевает. Способы исправить:

- Уменьшить `sample_rate` и полосу.
- Использовать более эффективные блоки (FIR вместо произвольной свёртки).
- Включить SIMD/volk (обычно уже включён).
- Перенести обработку на GPU (gr-fosphor, CUDA-блоки) — редко нужно.
- Писать IQ в файл и обрабатывать офлайн, а не в реальном времени.

Для долгих записей лучше писать IQ «как есть» и анализировать позже: так вы не теряете данные при перегрузке и можете прогонять разные конвейеры по одному файлу.

## Расширения и экосистема

GNU Radio расширяется через out-of-tree (OOT) модули: `gr-osmosdr` (драйверы SDR), `gr-limesdr`, `gr-satellites` (спутники), `gr-ieee802-11` (Wi-Fi), `gr-gsm` (GSM), `gr-paint` (спектральный «рисунок»). Многие готовые декодеры собраны именно так — вы ставите модуль и используете блоки в GRC.

```bash
# Установка OOT-модуля (пример)
git clone https://github.com/.../gr-xxx
cd gr-xxx && mkdir build && cd build
cmake .. && make -j8 && sudo make install && sudo ldconfig
```

Для пентеста особенно полезны: `gr-gsm` (перехват GSM), `gr-ieee802-11` (Wi-Fi PHY), модули для BLE и Zigbee. Связка GNU Radio + готовые декодеры покрывает большинство беспроводных задач. Если нужного протокола нет — вы всегда можете собрать свой конвейер из блоков DSP. Именно так появляются декодеры для экзотических протоколов датчиков и телеметрии.

## Итог

GNU Radio — универсальный «конструктор» для обработки сигналов. Освоив базовые блоки и концепцию flowgraph, вы можете декодировать практически любой беспроводной протокол, если у вас есть достаточно данных. В связке с rtl_433/URH и SDR-железом это даёт полный контроль над радиоэфиром. Освоение GNU Radio открывает путь к собственным декодерам, которых нет в готовых утилитах.

## Что дальше / решение

- Нужен базовый SDR → `hardware-sdr-deep`.
- Нужен replay → `hardware-subghz`.
- Нужен BLE/Zigbee → `hardware-bluetooth`, `hardware-zigbee-zwave`.
- Нужна аппаратура → `hardware-sdr-radio`.

## Квиз

```quiz
- question: "Что такое flowgraph в GNU Radio?"
  options:
    - "Файл IQ"
    - "Граф соединённых блоков обработки"
    - "Тип модуляции"
    - "Антенна"
  answer: 1
  explanation: "Flowgraph связывает блоки в конвейер обработки."
- question: "Какой блок выполняет FM-демодуляцию?"
  options:
    - "Binary Slicer"
    - "Quadrature Demod / WBFM Receive"
    - "File Sink"
    - "RTL-SDR Source"
  answer: 1
  explanation: "Quadrature/WBFM блоки демодулируют FM."
- question: "Зачем нужен Rational Resampler?"
  options:
    - "Фильтровать шум"
    - "Согласовать sample rate между блоками"
    - "Декодировать биты"
    - "Усилить сигнал"
  answer: 1
  explanation: "Ресемплер меняет частоту дискретизации."
- question: "Что означает 'O' (overflow) в консоли GNU Radio?"
  options:
    - "Ошибка антенны"
    - "CPU не успевает обрабатывать поток"
    - "Нет сигнала"
    - "Переполнение файла"
  answer: 1
  explanation: "Overflow = обработка медленнее потока."
- question: "Какой инструмент удобен для реверса неизвестных протоколов?"
  options:
    - "aplay"
    - "Universal Radio Hacker (URH)"
    - "rtl_power"
    - "gqrx"
  answer: 1
  explanation: "URH интерактивно декодирует протоколы."
```

## Где пригодится

- **CTF:** Radio-задачи с нестандартными сигналами.
- **Реверс:** построение декодеров для неизвестных протоколов.
- **Пентест:** анализ и воспроизведение радиоканалов.
- **Разработка:** собственные SDR-приложения.
- **Дальше по дереву:** `hardware-sdr-deep`, `hardware-subghz`, `hardware-sdr-radio`.
