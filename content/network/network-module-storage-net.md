---
id: network-module-storage-net
title: "Модуль: сети хранения — iSCSI, NVMe-oF, FCoE, RoCE"
category: network
parent: network-nfs
difficulty: hard
order: 1
tags: [network, datacenter, overlay, module]
prerequisites: [network-nfs]
useful_for:
  - "CTF Network (ЦОД/оверлеи)"
  - "Пентест: контейнеры/ЦОД"
  - "Работа: анализ"
estimated_minutes: 50
summary: "Навигационный модуль про сети хранения: iSCSI, NVMe over Fabrics, FCoE и InfiniBand/RoCE."
---

## Вопрос, с которого всё начинается

Данные в ЦОД живут на storage-сетях, отделённых от обычных. iSCSI, NVMe-oF, FCoE, RoCE — их протоколы, и защита там часто слабая.

## Что покрывает

- [`network-iscsi`](network-iscsi) — iSCSI.
- [`network-nvme-of`](network-nvme-of) — NVMe over Fabrics.
- [`network-fcoe`](network-fcoe) — FCoE.
- [`network-infiniband-roce`](network-infiniband-roce) — IB/RoCE.

## Что мы теперь знаем

- Underlay и overlay — разные уровни.
- Контейнерные сети имеют свою маршрутизацию.
- Storage-сети часто без аутентификации.

## Квиз

Проверь себя.

```quiz
- question: "Что такое overlay?"
  options:
    - "Логическая сеть поверх физической"
    - "Кабель"
    - "Шифр"
    - "Порт"
  answer: 0
  explanation: "Overlay."
- question: "Чем опасна плоская сеть ЦОД?"
  options:
    - "Ничем"
    - "Одна точка входа = много систем"
    - "Ускорением"
    - "Цветом"
  answer: 1
  explanation: "Плоскостность."
- question: "Что часто не защищено в storage?"
  options:
    - "iSCSI/NVMe-oF"
    - "DNS"
    - "HTTP"
    - "SMTP"
  answer: 0
  explanation: "Storage."
```

## Куда дальше

Смотри уроки модуля по порядку.

## Где пригодится

- CTF: ЦОД.
- Пентест: контейнеры.
- Работа: анализ.
