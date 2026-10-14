---
id: pwn-windows-deep
title: 'Модуль: Windows userspace deep (ROP, ASLR, CFG/CET)'
category: pwn
parent: pwn-windows-intro
difficulty: hard
order: 3
tags: [roadmap, module, pwn]
prerequisites: []
useful_for:
  - 'CTF Pwn'
  - 'Exploit development'
estimated_minutes: 12
summary: 'Модуль: Windows userspace deep (ROP, ASLR, CFG/CET)'
---

## Что покрывает этот модуль

глубокую эксплуатацию Windows userland: сборку ROP-цепочек под x64-соглашение, обход ASLR через утечки и частичную перезапись, обход Control Flow Guard и аппаратного CET.

## Рекомендуемый порядок изучения

1. `pwn-windows-rop` — ROP под Windows x64 (rcx/rdx/r8/r9, shadow space, выравнивание).
2. `pwn-windows-aslr-bypass` — утечки адресов и частичная перезапись.
3. `pwn-windows-cfg-cet` — обход Control Flow Guard и аппаратного CET.

## Что вы будете уметь

- Собирать ROP-цепочку под Windows x64.
- Обходить ASLR через info-leak и partial overwrite.
- Обходить CFG и понимать ограничения CET.

## Квиз

```quiz
- question: Какие регистры держат первые аргументы в Windows x64?
  options:
    - rdi, rsi, rdx, rcx
    - rcx, rdx, r8, r9
    - eax, ebx, ecx, edx
    - r8-r15
  answer: 1
  explanation: Windows x64 использует rcx, rdx, r8, r9.
- question: Что такое shadow space?
  options:
    - 32 байта стека для callee перед вызовом
    - Кэш
    - Секретный ключ
    - Область кучи
  answer: 0
  explanation: Вызывающий резервирует 32 байта перед call.
- question: Что делает CFG?
  options:
    - Проверяет косвенные вызовы по битмапу
    - Шифрует стек
    - Чистит реестр
    - Балансирует нагрузку
  answer: 0
  explanation: Control Flow Guard ограничивает цели косвенных вызовов.
```

## Куда дальше

Модуль опирается на предыдущие уроки ветки. Пройди его целиком — каждый
подпункт раскрывает отдельную технику, и вместе они дают полную картину.

## Где пригодится

- Эксплуатация Windows-приложений и сервисов.
- Обход современных митигаций Windows.
- Разработка эксплойтов для CTF и red team.
