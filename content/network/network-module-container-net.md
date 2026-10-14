---
id: network-module-container-net
title: "Модуль: Kubernetes-сеть, service mesh и eBPF/XDP"
category: network
parent: network-gre-vxlan
difficulty: hard
order: 2
tags: [network, datacenter, overlay, module]
prerequisites: [network-gre-vxlan]
useful_for:
  - "CTF Network (ЦОД/оверлеи)"
  - "Пентест: контейнеры/ЦОД"
  - "Работа: анализ"
estimated_minutes: 50
summary: "Навигационный модуль про контейнерную сеть в масштабе: Kubernetes CNI, service mesh и eBPF/XDP."
---

## Вопрос, с которого всё начинается

Kubernetes, service mesh и eBPF — современный стек сетей ЦОД. Понимание их нужно для анализа облаков и контейнерных платформ.

## Что покрывает

- [`network-k8s-network`](network-k8s-network) — CNI, kube-proxy.
- [`network-service-mesh`](network-service-mesh) — Istio/Linkerd, mTLS.
- [`network-ebpf-xdp`](network-ebpf-xdp) — eBPF/XDP.

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
