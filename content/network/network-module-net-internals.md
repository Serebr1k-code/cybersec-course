---
id: network-module-net-internals
title: "Модуль: сетевой стек изнутри — tc/netem, raw sockets, automation, netfilter"
category: network
parent: network-wireshark
difficulty: hard
order: 3
tags: [network, analysis, tooling, module]
prerequisites: [network-wireshark]
useful_for:
  - "CTF Network (анализ)"
  - "Пентест: инструменты"
  - "Работа: детект"
estimated_minutes: 50
summary: "Навигационный модуль про низкоуровневые механизмы: traffic control/netem, raw sockets, автоматизацию сети и netfilter."
---

## Вопрос, с которого всё начинается

Иногда нужно не «посмотреть», а «повлиять»: создать помехи, отправить сырые пакеты, настроить сеть автоматически или написать firewall-правило.

## Что покрывает

- [`network-tc-netem`](network-tc-netem) — задержки/потери (netem).
- [`network-raw-sockets`](network-raw-sockets) — AF_PACKET.
- [`network-network-automation`](network-network-automation) — Ansible/NETCONF.
- [`network-netfilter`](network-netfilter) — iptables/nftables.

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
