---
id: network-module-telecom-ops
title: "Модуль: операции — sidelink и SIGINT"
category: network
parent: network-module-telecom-core
difficulty: hard
order: 4
tags: [network, telecom, sidelink, v2x, sigint, module]
prerequisites: [network-module-telecom-core]
useful_for:
  - "CTF Network (радиоразведка)"
  - "Пентест: V2X и D2D"
  - "Работа: SIGINT-процесс"
estimated_minutes: 50
summary: "Небольшой модуль о прямых линках (5G sidelink/PC5, V2X) и о процессе радиоразведки: захват, декодирование и атрибуция сигнала."
---

## Вопрос, с которого всё начинается

Обычно терминал общается через базовую станцию. Но бывают режимы «напрямую» — устройство-устройство. И отдельно стоит вопрос: как вообще исследовать радиоэфир системно, от захвата сигнала до вывода о том, чей он.

## Что покрывает этот модуль

- **Sidelink (PC5)**: прямые линки 5G, применение в V2X (связь машин), риски.
- **SIGINT-процесс**: как из сырого эфира получают осмысленный вывод.

## Как читать

Сначала [`network-nr-sidelink`](network-nr-sidelink), затем [`network-telecom-sigint`](network-telecom-sigint). Опирается на [`network-module-telecom-core`](network-module-telecom-core).

## Что мы теперь знаем

- Sidelink (PC5) — прямые линки без базовой станции, основа V2X.
- SIGINT — процесс: захват → декодирование → атрибуция.
- Прямые линки расширяют поверхность атаки за пределы оператора.

## Квиз

Проверь себя.

```quiz
- question: "Что такое sidelink/PC5?"
  options:
    - "Прямой линк устройство-устройство"
    - "Протокол зарядки"
    - "Тип SIM"
    - "Антенна"
  answer: 0
  explanation: "PC5 — прямой интерфейс, например для V2X."
- question: "Из чего состоит SIGINT-процесс?"
  options:
    - "Только запись"
    - "Захват, декодирование, атрибуция"
    - "Только шифрование"
    - "Только печать"
  answer: 1
  explanation: "Сырой сигнал нужно поймать, декодировать и понять, чей он."
```

## Куда дальше

Начнём с [`network-nr-sidelink`](network-nr-sidelink).

## Где пригодится

- CTF: задачи на радио.
- Пентест: V2X.
- Работа: SIGINT-навыки.
