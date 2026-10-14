---
id: reversing-mod-arch
title: "Модуль: Архитектуры и системы команд"
category: reversing
parent: reversing-architectures
difficulty: hard
order: 1
tags: [reversing, architecture, isa, arm, risc-v, roadmap]
prerequisites: [reversing-architectures]
useful_for:
  - "Embedded / IoT reversing"
  - "Mobile reversing"
  - "Retro / console reversing"
estimated_minutes: 8
summary: "Навигационный модуль по системам команд за пределами x86-64: ARM, RISC-V, PowerPC, MIPS и 8-битные MCU."
---

Ты умеешь читать x86-64. Но как только цель — телефон, роутер, автомобиль или ретро-консоль, появляется другая система команд (ISA). Этот модуль — про то, как читать ассемблер незнакомой архитектуры.

## Что покрывает подмодуль

- **reversing-asm-arm64** — ARM64/AArch64 вручную: регистры, AAPCS64, режимы адресации.
- **reversing-asm-arm32** — ARM32/Thumb и переключение режимов, IT-блоки.
- **reversing-riscv-advanced** — RISC-V: расширения, компрессия, привилегированные режимы.
- **reversing-mips-delay-slots** — MIPS: branch delay slots, HI/LO, MIPS16.

## Почему такой порядок

ARM64 — самая востребованная (мобильные и серверные ARM). ARM32 — для старых устройств. RISC-V — восходящая открытая архитектура. MIPS — legacy embedded. Все они разделяют идею RISC: простые инструкции фиксированной длины.

## Что вы будете уметь

- Читать ARM64-ассемблер и восстанавливать вызовы функций по AAPCS64.

- Понимать Thumb-переключения и delay slots.

- Не путать endianness и режимы адресации разных ISA.

## Квиз

Проверь себя.

```quiz
- question: "Чем RISC-архитектуры (ARM, MIPS) отличаются от x86?"
  options:
    - "Инструкции обычно фиксированной длины и простые"
    - "Они не имеют регистров"
    - "Они работают только в ядре"
    - "Они всегда big-endian"
  answer: 0
- question: "Почему ARM64 сейчас самая востребованная для реверса?"
  options:
    - "Мобильные устройства и серверы на ARM"
    - "Она самая старая"
    - "Только она поддерживает сеть"
    - "Она единственная с FPU"
  answer: 0
- question: "Почему знание ABI (соглашения о вызовах) критично для реверса?"
  options:
    - "Оно говорит, в каких регистрах искать аргументы и результат"
    - "Оно определяет цвет интерфейса"
    - "Оно задаёт формат PNG"
    - "Оно нужно только для компиляции"
  answer: 0
```

## Куда дальше

Начни с ARM64 — это база для мобильного и embedded реверса. Пока главное: **смена архитектуры меняет синтаксис, но не методологию анализа**.

## Где пригодится

- **Embedded / IoT reversing:** прошивки роутеров, камер, MCU.

- **Mobile reversing:** ARM64 на Android/iOS.

- **Console / retro:** PowerPC, MIPS, 6502.
