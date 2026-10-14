---
id: cloud-net-perimeter
title: "Модуль: Периметр, DNS и утечки"
category: cloud
parent: cloud-network-egress
difficulty: medium
order: 2
tags: [cloud, module, roadmap]
prerequisites: [cloud-network-egress]
useful_for:
- Аудит облачной сети.
- Red team exfiltration.
- Bug bounty.
estimated_minutes: 10
summary: "Атаки на балансировщики, облачный dns (takeover/dnssec) и egress-контроль"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Периметр, DNS и утечки»: атаки на балансировщики, облачный DNS (takeover/DNSSEC) и egress-контроль.

- **cloud-load-balancer-attacks** — Балансировщики: smuggling, инъекции заголовков и обход origin.
- **cloud-dns-deep** — Облачный DNS deep: takeover, делегирование зон и DNSSEC.
- **cloud-egress-control** — Egress-контроль: firewall, NAT и обход для exfiltration.

## Почему такой порядок

Контроль периметра определяет, как данные покидают облако.

## Что вы сможете после этапа

- Искать DNS takeover и обход egress.
- Анализировать инъекции на балансировщиках.

## Квиз

Проверь себя.

```quiz
- question: Что такое DNS takeover?
  options:
    - "Захват повисшей записи на чужой ресурс"
    - "Шифрование DNS"
    - "Резервная зона"
    - "Тип записи"
  answer: 0
  explanation: Свободный CNAME/ресурс можно занять.
- question: Зачем нужен egress-контроль?
  options:
    - "Ограничить исходящий трафик и exfiltration"
    - "Ускорить вход"
    - "Шифровать диск"
    - "Логировать DNS"
  answer: 0
  explanation: Egress-контроль ограничивает утечки наружу.
- question: Чем опасна хедер-инъекция на балансировщике?
  options:
    - "Обходом контроля доступа к origin"
    - "Ускорением TLS"
    - "Сжатием"
    - "Резервным копированием"
  answer: 0
  explanation: Подмена заголовков обходит часть правил.
```

## Где пригодится

- Аудит облачной сети.
- Red team exfiltration.
- Bug bounty.
