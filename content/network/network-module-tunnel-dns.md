---
id: network-module-tunnel-dns
title: "Модуль: экзотические каналы — DoH, ICMP, DNS-exfil, NAT, Tor"
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
summary: "Навигационный модуль про «нестандартные» каналы: DNS-over-HTTPS, ICMP-туннели, DNS-эксфильтрация, NAT-обход и Tor-мосты."
---

## Вопрос, с которого всё начинается

Иногда разрешён только DNS, или нужно пройти сквозь NAT, или спрятаться в Tor. Для этого есть специализированные каналы.

## Что покрывает

- [`network-doh-tunnel`](network-doh-tunnel) — туннель в DNS-over-HTTPS.
- [`network-icmp-tunnel-deep`](network-icmp-tunnel-deep) — ICMP-туннели.
- [`network-dns-exfil`](network-dns-exfil) — эксфильтрация через DNS.
- [`network-nat-traversal`](network-nat-traversal) — hole punching.
- [`network-tor-bridges`](network-tor-bridges) — мосты и транспорты Tor.

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
