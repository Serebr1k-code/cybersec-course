---
id: pwn-linux-kernel-cve
title: "Модуль: Linux kernel CVE"
category: pwn
parent: pwn-cve-exploitation
difficulty: medium
order: 2
tags: [pwn, module, roadmap, cve]
prerequisites: [pwn-kernel-core]
useful_for:
  - "Эксплуатация реальных CVE"
  - "Red team: повышение привилегий"
estimated_minutes: 10
summary: "Навигационный модуль: эксплуатацию уязвимостей ядра Linux: netfilter, nf_tables, io_uring и свежие гонки."
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Linux kernel CVE»: эксплуатацию уязвимостей ядра Linux: netfilter, nf_tables, io_uring и свежие гонки.

- nf_tables — CVE-2023-32233 и CVE-2024-1086.
- netfilter — CVE-2022-0185 и CVE-2022-2588.
- io_uring — серия уязвимостей асинхронного ввода-вывода.
- Сводка свежих kernel CVE и методология kernelCTF.

## Почему такой порядок

Kernel идёт после user-space: нужны спрей кучи, обход KASLR и понимание аллокаторов ядра из предыдущих уроков.

## Что вы сможете после этапа

- Собирать kernel-эксплойт из примитива UAF/переполнения.
- Стабилизировать через modprobe_path и обход KASLR.

## Квиз

Проверь себя.

```quiz
- question: Что нужно для kernel-эксплойта помимо примитива?
  options:
    - "Только shell"
    - "Спрей кучи и обход KASLR"
    - "Только сеть"
    - "Только пароль"
  answer: 1
  explanation: Примитив бесполезен без раскладки памяти и знания адресов.
- question: Какой подсистеме посвящён CVE-2024-1086?
  options:
    - "netfilter/nf_tables"
    - "USB"
    - "Wi-Fi"
    - "Блочный слой"
  answer: 0
  explanation: CVE-2024-1086 — use-after-free в nf_tables.
- question: Зачем в kernel-эксплойте modprobe_path?
  options:
    - "Для сети"
    - "Как цель перезаписи для выполнения команды от root"
    - "Для шифрования"
    - "Для логов"
  answer: 1
  explanation: Перезапись modprobe_path — популярный способ получить root-выполнение.
```

## Где пригодится

- Локальное повышение привилегий до root на Linux.
- Эксплуатация n-day в ядре.
- Подготовка к kernelCTF.
