---
id: network-module-voip-deep
title: "Модуль: VoIP глубоко — SIP, RTP/SRTP, SCCP и H.323"
category: network
parent: network-voip
difficulty: hard
order: 1
tags: [network, voip, sip, module]
prerequisites: [network-voip]
useful_for:
  - "CTF Network (VoIP-дампы)"
  - "Пентест: телефония"
  - "Работа: анализ VoIP"
estimated_minutes: 50
summary: "Навигационный модуль про голосовые протоколы: детальный SIP, медиа RTP/SRTP и корпоративные SCCP/H.323."
---

## Вопрос, с которого всё начинается

VoIP — это сигнализация плюс медиа. Разные системы используют разные протоколы: SIP (стандарт), SCCP (Cisco), H.323 (старый). Понимание каждого нужно для анализа телефонии.

## Что покрывает

- [`network-sip-deep`](network-sip-deep) — SIP детально.
- [`network-rtp-srtp`](network-rtp-srtp) — медиа и шифрование.
- [`network-sccp-skinny`](network-sccp-skinny) — Cisco IP-телефоны.
- [`network-h323`](network-h323) — старый стек H.323.

## Что мы теперь знаем

- Сигнализация (SIP/H.323) отделена от медиа (RTP).
- Медиа часто не шифровано (SRTP опционален).
- Toll fraud — дорогая ошибка конфигурации.

## Квиз

Проверь себя.

```quiz
- question: "Что управляет VoIP-вызовом?"
  options:
    - "RTP"
    - "SIP/H.323"
    - "TCP"
    - "ICMP"
  answer: 1
  explanation: "Сигнализация."
- question: "Чем несётся голос?"
  options:
    - "SIP"
    - "RTP/SRTP"
    - "HTTP"
    - "DNS"
  answer: 1
  explanation: "Медиа."
- question: "Что такое toll fraud?"
  options:
    - "Дешёвые звонки"
    - "Звонки на платные номера за чужой счёт"
    - "Шифрование"
    - "Порт"
  answer: 1
  explanation: "Фрод."
```

## Куда дальше

Смотри уроки модуля по порядку.

## Где пригодится

- CTF: VoIP.
- Пентест: телефония.
- Работа: анализ.
