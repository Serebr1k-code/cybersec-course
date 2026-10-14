---
id: network-module-tunnel-deep
title: "Модуль: туннели и прокси глубоко — HTTP, chisel/ligolo, WebSocket, GOST, proxy chains"
category: network
parent: network-module-tunnel
difficulty: hard
order: 4
tags: [network, tunnel, pivot, module]
prerequisites: [network-module-tunnel]
useful_for:
  - "CTF Network (туннели)"
  - "Пентест: pivoting"
  - "Работа (SOC): детект инкапсуляции"
estimated_minutes: 50
summary: "Навигационный модуль про продвинутые туннели и прокси: HTTP-туннели, chisel/ligolo, WebSocket-туннели, GOST/SoftEther и цепочки прокси."
---

## Вопрос, с которого всё начинается

Когда прямой доступ закрыт, а egress-фильтрация пропускает лишь определённые протоколы, нужны подходящие туннели. Этот модуль — про инструменты pivot и обхода.

## Что покрывает

- [`network-http-tunnel`](network-http-tunnel) — HTTP(S)-туннели.
- [`network-chisel-ligolo`](network-chisel-ligolo) — chisel/ligolo.
- [`network-websocket-tunnel`](network-websocket-tunnel) — wstunnel.
- [`network-gost-softether`](network-gost-softether) — GOST/SoftEther.
- [`network-proxy-chains`](network-proxy-chains) — цепочки прокси.

## Что мы теперь знаем

- Туннели переносят трафик через разрешённый канал.
- Выбор протокола определяется egress-фильтрацией.
- Pivot оставляет следы (бинарник, процесс, порт).

## Квиз

Проверь себя.

```quiz
- question: "Зачем нужны туннели?"
  options:
    - "Для красоты"
    - "Обход сегментации/фильтрации"
    - "Для зарядки"
    - "Для GPS"
  answer: 1
  explanation: "Перенос трафика."
- question: "Чем определяется выбор протокола туннеля?"
  options:
    - "Цветом"
    - "Egress-фильтрацией"
    - "Погодой"
    - "Размером"
  answer: 1
  explanation: "Что разрешено наружу."
- question: "Что оставляет pivot?"
  options:
    - "Ничего"
    - "Следы (бинарник/процесс/порт)"
    - "Только деньги"
    - "Только цвет"
  answer: 1
  explanation: "Артефакты."
```

## Куда дальше

Смотри уроки модуля по порядку.

## Где пригодится

- CTF: туннели.
- Пентест: pivot.
- Работа: детект.
