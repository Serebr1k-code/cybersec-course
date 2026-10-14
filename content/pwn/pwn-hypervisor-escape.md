---
id: pwn-hypervisor-escape
title: 'Модуль: побег из гипервизора (Hyper-V, VBS/HVCI)'
category: pwn
parent: pwn-sandbox-escape
difficulty: hard
order: 1
tags: [roadmap, module, pwn]
prerequisites: []
useful_for:
  - 'CTF Pwn'
  - 'Exploit development'
estimated_minutes: 12
summary: 'Модуль: побег из гипервизора (Hyper-V, VBS/HVCI)'
---

## Что покрывает этот модуль

побег из виртуальной машины: архитектуру Hyper-V (VMBus, синтетические устройства) и обход Virtualization-Based Security / HVCI.

## Рекомендуемый порядок изучения

1. `pwn-hyperv-escape` — Hyper-V: VMBus, VSP/VSC и типовые баги.
2. `pwn-vbs-hvci` — VBS/HVCI: что защищает и как обходится.

## Что вы будете уметь

- Понимать поверхность атаки гипервизора Hyper-V.
- Разбирать сообщения VMBus и синтетические устройства.
- Понимать назначение VBS/HVCI и классы обхода.

## Квиз

```quiz
- question: Что такое VMBus в Hyper-V?
  options:
    - Шина обмена сообщениями между гостем и хостом
    - Сетевой протокол
    - Файловая система
    - Драйвер видеокарты
  answer: 0
  explanation: VMBus — канал для синтетических устройств.
- question: Что защищает HVCI?
  options:
    - Целостность кода режима ядра
    - Пароли
    - Сеть
    - Диск
  answer: 0
  explanation: Hypervisor-Protected Code Integrity запрещает исполнять неподписанный код ядра.
- question: Почему побег из гипервизора ценен?
  options:
    - Даёт контроль над хостом и другими ВМ
    - Ускоряет сеть
    - Меняет обои
    - Ставит обновления
  answer: 0
  explanation: Компрометация гипервизора выходит за пределы одной ВМ.
```

## Куда дальше

Модуль опирается на предыдущие уроки ветки. Пройди его целиком — каждый
подпункт раскрывает отдельную технику, и вместе они дают полную картину.

## Где пригодится

- Исследование безопасности гипервизоров.
- Обход VBS/HVCI в red team.
- Понимание границ изоляции облачных хостов.
