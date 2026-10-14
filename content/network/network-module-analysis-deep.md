---
id: network-module-analysis-deep
title: "Модуль: анализ глубоко — Scapy, Lua, Zeek, Suricata, pcap"
category: network
parent: network-pcap-analysis
difficulty: hard
order: 4
tags: [network, analysis, tooling, module]
prerequisites: [network-pcap-analysis]
useful_for:
  - "CTF Network (анализ)"
  - "Пентест: инструменты"
  - "Работа: детект"
estimated_minutes: 50
summary: "Навигационный модуль про инструменты анализа: Scapy, Lua-диссекторы Wireshark, скрипты Zeek, правила Suricata и формат pcap."
---

## Вопрос, с которого всё начинается

Анализ трафика — это не только «посмотреть в Wireshark». Нужны инструменты для создания пакетов, написания диссекторов, детекта и понимания формата дампов.

## Что покрывает

- [`network-scapy-deep`](network-scapy-deep) — Scapy.
- [`network-tshark-lua`](network-tshark-lua) — Lua-диссекторы.
- [`network-zeek-scripting`](network-zeek-scripting) — скрипты Zeek.
- [`network-suricata-rules`](network-suricata-rules) — правила Suricata.
- [`network-pcap-format`](network-pcap-format) — формат pcap.

## Что мы теперь знаем

- Анализ трафика — от обзора к деталям.
- Детект строится на правилах/скриптах.
- Scapy позволяет проверять гипотезы.

## Квиз

Проверь себя.

```quiz
- question: "С чего начинать анализ pcap?"
  options:
    - "С одного пакета"
    - "С обзора протоколов/потоков"
    - "С цвета"
    - "С пароля"
  answer: 1
  explanation: "Обзор → детали."
- question: "Зачем Zeek/Suricata?"
  options:
    - "Для логов и детекта"
    - "Для зарядки"
    - "Для GPS"
    - "Для цвета"
  answer: 0
  explanation: "Анализ/детект."
- question: "Чем полезен Scapy?"
  options:
    - "Формировать пакеты"
    - "Заряжать"
    - "Печатать"
    - "Красить"
  answer: 0
  explanation: "Создание трафика."
```

## Куда дальше

Смотри уроки модуля по порядку.

## Где пригодится

- CTF: анализ.
- Пентест: инструменты.
- Работа: детект.
