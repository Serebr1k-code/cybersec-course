---
id: network-module-auto-wireless
title: "Модуль: Беспроводные и внешние интерфейсы"
category: network
parent: network-module-automotive-net
difficulty: medium
order: 2
tags: [network, module, roadmap]
prerequisites: [network-module-automotive-net]
useful_for:
- Пентест connected car.
- Аудит EV-зарядок.
- Red team.
estimated_minutes: 10
summary: "Релей-атаки pkes, зарядку ev (ccs/ocpp/iso 15118) и телематику/t-box"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Беспроводные и внешние интерфейсы»: релей-атаки PKES, зарядку EV (CCS/OCPP/ISO 15118) и телематику/T-Box.

- **network-keyless-relay** — Keyless entry и PKES: релей-атаки.
- **network-ev-charging** — EV-зарядка: CCS, OCPP и ISO 15118.
- **network-automotive-telematics** — Телематика и T-Box: связь авто с облаком.

## Почему такой порядок

Внешние интерфейсы связывают автомобиль с миром, поэтому разбираются после внутренних шин.

## Что вы сможете после этапа

- Оценивать релей-атаки бесключевого доступа.
- Разбирать OCPP/ISO 15118 и телематику.

## Квиз

Проверь себя.

```quiz
- question: Что эксплуатирует keyless relay-атака?
  options:
    - "Ретрансляцию сигнала ключа к машине"
    - "Пароль Wi-Fi"
    - "CAN-кадр"
    - "GPS"
  answer: 0
  explanation: Сигнал ключа ретранслируют, обманывая авто.
- question: Какой протокол управляет зарядными станциями?
  options:
    - "OCPP"
    - "SMB"
    - "LDAP"
    - "SMTP"
  answer: 0
  explanation: OCPP — протокол связи станции с бэкендом.
- question: Что такое T-Box?
  options:
    - "Телематический модуль связи авто с облаком"
    - "Тип шины"
    - "Формат файла"
    - "Протокол зарядки"
  answer: 0
  explanation: T-Box обеспечивает связь автомобиля с облаком.
```

## Где пригодится

- Пентест connected car.
- Аудит EV-зарядок.
- Red team.
