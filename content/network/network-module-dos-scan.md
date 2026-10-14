---
id: network-module-dos-scan
title: "Модуль: отказ в обслуживании и массовый скан — амплификация, taxonomy, SYN-flood, zmap"
category: network
parent: network-portscan
difficulty: hard
order: 5
tags: [network, scanning, module]
prerequisites: [network-portscan]
useful_for:
  - "CTF Network (сканирование)"
  - "Пентест: разведка"
  - "Работа: инвентаризация"
estimated_minutes: 50
summary: "Навигационный модуль про DoS/DDoS и интернет-масштабное сканирование: амплификация, taxonomy атак, SYN-flood и zmap/masscan."
---

## Вопрос, с которого всё начинается

DoS/DDoS и массовое сканирование идут рука об руку: амплификацию используют для атак, а zmap/masscan — для разведки в масштабе интернета.

## Что покрывает

- [`network-reflection-amplification`](network-reflection-amplification) — каталог усилителей.
- [`network-dos-taxonomy`](network-dos-taxonomy) — виды DoS.
- [`network-syn-flood`](network-syn-flood) — истощение TCP.
- [`network-zmap-masscan-deep`](network-zmap-masscan-deep) — массовый скан.

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
