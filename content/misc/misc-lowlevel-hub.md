---
id: misc-lowlevel-hub
title: "Модуль: Низкий уровень и радио"
category: misc
parent: misc-games-systems
difficulty: medium
order: 2
tags: [misc, module, roadmap]
prerequisites: [misc-games-systems]
useful_for:
- CTF Misc.
- Реверс протоколов.
- Анализ SDR.
estimated_minutes: 10
summary: "Нестандартные протоколы, kernel misc (syscalls, /proc, ebpf) и радио/sdr"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Низкий уровень и радио»: нестандартные протоколы, kernel misc (syscalls, /proc, eBPF) и радио/SDR.

- **misc-weird-protocols** — Странные протоколы: raw TCP/UDP и кастомные форматы.
- **misc-kernel-misc** — Kernel misc: syscalls, /proc и eBPF.
- **misc-radio-misc** — Radio misc: SDR, IQ-данные и суб-GHz.

## Почему такой порядок

Эти темы работают близко к железу и ядру, поэтому идут после базовых форматов.

## Что вы сможете после этапа

- Разбирать кастомные протоколы.
- Анализировать IQ-данные и syscalls.

## Квиз

Проверь себя.

```quiz
- question: Что общего у этих тем?
  options:
    - "Работа близко к железу и ядру"
    - "Все про SQL"
    - "Все про браузер"
    - "Все про DNS"
  answer: 0
  explanation: Это низкоуровневые и радио-сюжеты.
- question: Что даёт eBPF?
  options:
    - "Наблюдение за событиями ядра без модулей"
    - "Шифрование диска"
    - "Сжатие"
    - "Резервное копирование"
  answer: 0
  explanation: eBPF позволяет инструментировать ядро.
- question: Что такое IQ-данные?
  options:
    - "Квадратурные отсчёты сигнала"
    - "Формат БД"
    - "Тип ключа"
    - "Сетевой протокол"
  answer: 0
  explanation: SDR отдаёт сигнал как I/Q-поток.
```

## Где пригодится

- CTF Misc.
- Реверс протоколов.
- Анализ SDR.
