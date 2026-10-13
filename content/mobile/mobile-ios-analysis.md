---
id: mobile-ios-analysis
title: "Анализ iOS-приложения"
category: mobile
parent: mobile-ios-basics
difficulty: hard
order: 1
tags: [mobile, ios, static, dynamic, frida]
prerequisites: [mobile-ios-basics]
useful_for:
  - "CTF: Mobile/Reversing"
  - "Пентест: iOS"
  - "Работа: reverse engineering"
estimated_minutes: 12
summary: "Этап статического и динамического анализа iOS-приложений."
lab:
  kind: shell
  title: 'Практика: анализ iOS-приложения'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, Payload]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`Payload/` — распакованный IPA. Ищи бинарник и Info.plist.'
    - 'Определи тип Mach-O (`file`) и извлеки строки.'
    - 'Секрет есть в бинарнике — найди `nto{` и запиши в `found.txt`.'
---

Этот урок — **этап-навигатор** в ветке. Он короткий: его задача — объяснить, что вы будете изучать на этом этапе, почему темы идут именно в таком порядке и что вы сможете делать после прохождения.

## О чём этот этап

Первый этап глубокого iOS: статический анализ (class-dump, Hopper, Swift) и динамический анализ (Frida, LLDB, runtime-хуки).

## Что вы освоите

- iOS static analysis: class-dump, Hopper, Swift
- iOS dynamic analysis: Frida, LLDB и runtime-хуки
- Разбирать Mach-O и работать с рантаймом iOS

## Как проходить

Начните со статики Mach-O и class-dump, затем динамика через Frida/LLDB. Нужно джейлбрейк-устройство или Corellium для динамики.

## Квиз

```quiz
- question: "Какой формат у исполняемого файла iOS?"
  options:
    - "Mach-O"
    - "PE"
    - "ELF"
    - "DEX"
  answer: 0
  explanation: "iOS использует формат Mach-O."
- question: "Чем class-dump полезен при анализе iOS?"
  options:
    - "Показывает объявления классов и методов"
    - "Расшифровывает трафик"
    - "Подписывает IPA"
    - "Создаёт бэкап"
  answer: 0
  explanation: "class-dump извлекает заголовки Objective-C-классов."
- question: "Что нужно для динамического анализа на устройстве?"
  options:
    - "Jailbreak или исследовательская среда"
    - "Только Wi-Fi"
    - "Только аккаунт Apple"
    - "Только Xcode"
  answer: 0
  explanation: "Динамика требует привилегий на устройстве."
```

## Где пригодится

- **CTF:** Mobile/Reversing
- **Пентест:** iOS
- **Работа:** reverse engineering
