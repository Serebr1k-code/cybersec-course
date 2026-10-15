---
id: misc-kernel-isolation
title: 'Модуль: ядро Linux — изоляция и политики (cgroups, Landlock, netfilter, MAC)'
category: misc
parent: misc-kernel-deep
difficulty: expert
order: 6
tags: [cgroups, landlock, netfilter, selinux, apparmor, isolation, roadmap]
prerequisites: [misc-kernel-deep]
useful_for:
  - 'CTF misc/pwn: контейнеры и песочницы'
  - 'Аудит изоляции'
  - 'Разбор политик доступа'
estimated_minutes: 15
summary: 'Четвёртая ступень низкоуровневой ветки: cgroups v2 и лимиты ресурсов, Landlock как непривилегированная песочница, netfilter/nftables и политики SELinux/AppArmor.'
---

Этот модуль продолжает низкоуровневую ветку после `misc-kernel-deep`, где были модули ядра, namespaces, seccomp и heap. Здесь — про **изоляцию и политики**: как ядро ограничивает процесс по ресурсам, по файлам, по сети и по доступу к объектам.

## Что покрывает модуль

- **cgroups v2** — учёт и лимиты ресурсов: CPU, память, число процессов, ввод-вывод.
- **Landlock** — LSM-песочница, которой непривилегированный процесс может ограничить себя по файлам.
- **netfilter / nftables** — фильтрация и преобразование сетевых пакетов на уровне ядра.
- **SELinux / AppArmor** — мандатный контроль доступа (MAC): политики, контексты и профили.

## Почему такой порядок

Сначала ресурсы (cgroups) — это «сколько можно». Потом Landlock — «к каким файлам можно». Затем netfilter — «куда можно в сеть». В конце — SELinux/AppArmor, которые накладываются поверх всего и ограничивают доступ даже root. Такой порядок отражает, как слои изоляции строятся друг на друге.

## Как проходить ступень

Общий навык: увидеть, что процесс ограничен, и понять, каким слоем. Каждый урок — со сквозным артефактом (вывод инструмента) и лабораторией, где ограничение разбирается руками.

## Связь с другими ветками

Модуль опирается на `misc-kernel-deep` (namespaces, seccomp) и продолжается в `misc-runtimes-iso` (gVisor, Firecracker) и `misc-sandbox-containers-hub` (containers). Все они используют механизмы этого модуля.

## Квиз

Проверь себя.

```quiz
- question: За что отвечают cgroups?
  options:
    - Учёт и лимиты ресурсов процесса
    - Фильтрацию пакетов
    - Права на файлы
    - Шифрование диска
  answer: 0
  explanation: cgroups — про ресурсы.
- question: Чем Landlock отличается от SELinux?
  options:
    - Landlock можно включить без root, SELinux — системная политика
    - Landlock только для сети
    - SELinux не про файлы
    - Они идентичны
  answer: 0
  explanation: Landlock — самоограничение непривилегированного процесса.
- question: Где работает netfilter?
  options:
    - В сетевом стеке ядра
    - В браузере
    - В файловой системе
    - В драйвере GPU
  answer: 0
  explanation: netfilter обрабатывает пакеты в ядре.
- question: Что такое MAC?
  options:
    - Мандатный контроль доступа поверх обычных прав
    - Сетевой протокол
    - Тип файла
    - Шифр
  answer: 0
  explanation: MAC ограничивает даже root.
```
