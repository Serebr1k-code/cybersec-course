---
id: reversing-mod-obf2
title: "Модуль: Обфускация и деобфускация кода"
category: reversing
parent: reversing-obfuscation
difficulty: hard
order: 3
tags: [reversing, obfuscation, ollvm, deobfuscation, roadmap]
prerequisites: [reversing-obfuscation]
useful_for:
  - "Malware analysis"
  - "CTF Reversing"
  - "Vuln research"
estimated_minutes: 8
summary: "Навигационный модуль о техниках обфускации (OLLVM, Tigress, строковые, control-flow) и способах их снятия."
---

Упаковка прячет код целиком, а **обфускация** меняет его так, что код остаётся исполняемым, но становится нечитаемым для аналитика. Это другой класс защиты: здесь не «распаковать один раз», а разбирать искажённую логику постоянно. Модуль — про основные семейства обфускаций и инструменты деобфускации.

## Что покрывает подмодуль

- **reversing-ollvm-tigress** — OLLVM (control-flow flattening, bogus flow, substitution), Tigress, Hikari и их снятие.
- **reversing-anti-disassembly** — anti-disassembly: наложение байтов, мусорный поток, opaque-предикаты.
- **reversing-string-obfuscation** — строковые обфускации: stack-strings, XOR, API-hashing.
- **reversing-virtualization-custom** — кастомные VM-протекторы и девиртуализация хендлеров.

## Почему такой порядок

Сначала самые распространённые компиляторные обфускации (OLLVM). Затем трюки уровня дизассемблера (anti-disassembly). Потом работа со строками и API. И в конце — самая тяжёлая техника: виртуализация, где код превращён в байткод собственной VM.

## Что вы будете уметь

- Узнавать OLLVM/Tigress по форме графа и паттернам.

- Снимать control-flow flattening и восстанавливать логику.

- Расшифровывать строки и резолвить API-хеши.

- Понимать, как устроена виртуализация, и подступаться к девиртуализации.

## Квиз

Проверь себя.

```quiz
- question: "Что делает control-flow flattening?"
  options:
    - "Превращает поток управления в switch по состоянию"
    - "Шифрует строки"
    - "Упаковывает файл"
    - "Меняет архитектуру"
  answer: 0
- question: "Почему обфускацию сложнее снять, чем упаковку?"
  options:
    - "Код остаётся исполняемым и искажён постоянно, а не спрятан один раз"
    - "Она всегда в ядре"
    - "Её нельзя запустить"
    - "Она не влияет на код"
  answer: 0
- question: "Какой проход OLLVM превращает граф в switch-диспетчер?"
  options:
    - "Control-flow flattening"
    - "String encryption"
    - "Packing"
    - "JIT"
  answer: 0
```

## Куда дальше

Начни с OLLVM — это самая частая компиляторная обфускация в мобильном и защищённом коде. Пока главное: **обфускация не прячет код, а искажает его логику, и снимают её пониманием шаблонов**.

## Где пригодится

- **Malware analysis:** разбор защищённых образцов.

- **CTF Reversing:** задачи с обфусцированным кодом.

- **Mobile reversing:** OLLVM в защищённых приложениях.
