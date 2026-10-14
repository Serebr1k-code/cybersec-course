---
id: network-module-scan-deep
title: "Модуль: сканирование глубоко — IPv6, фингерпринт, firewall mapping"
category: network
parent: network-module-analysis
difficulty: hard
order: 4
tags: [network, scanning, module]
prerequisites: [network-module-analysis]
useful_for:
  - "CTF Network (сканирование)"
  - "Пентест: разведка"
  - "Работа: инвентаризация"
estimated_minutes: 50
summary: "Навигационный модуль про продвинутое сканирование: IPv6, фингерпринт стека (p0f), инференс правил firewall и детали детекта версий."
---

## Вопрос, с которого всё начинается

Базовый nmap знает каждый. Но есть нюансы: IPv6-пространство огромно, фингерпринт требует нескольких признаков, а firewall нужно «картировать» по поведению.

## Что покрывает

- [`network-ipv6-scanning`](network-ipv6-scanning) — IPv6-скан.
- [`network-p0f-fingerprint`](network-p0f-fingerprint) — пассивный фингерпринт.
- [`network-firewall-fingerprint`](network-firewall-fingerprint) — инференс правил.
- [`network-service-version-detect`](network-service-version-detect) — детект версий.

## Что мы теперь знаем

- Различай закрытый и отфильтрованный порт.
- Фингерпринт строится на нескольких признаках.
- UDP-сервисы легко пропустить.

## Квиз

Проверь себя.

```quiz
- question: "Чем отличается закрытый порт от отфильтрованного?"
  options:
    - "Ничем"
    - "Закрытый отвечает, отфильтрованный — тишина"
    - "Цветом"
    - "Размером"
  answer: 1
  explanation: "Ответ vs тишина."
- question: "Сколько признаков нужно для фингерпринта?"
  options:
    - "Один"
    - "Несколько"
    - "Ноль"
    - "Сто"
  answer: 1
  explanation: "Комбинация признаков."
- question: "Почему важен UDP-скан?"
  options:
    - "Он быстрее"
    - "Многие сервисы на UDP"
    - "Он шифрует"
    - "Он дешевле"
  answer: 1
  explanation: "DNS/SNMP/DHCP и др."
```

## Куда дальше

Смотри уроки модуля по порядку.

## Где пригодится

- CTF: разведка.
- Пентест: сканирование.
- Работа: инвентаризация.
