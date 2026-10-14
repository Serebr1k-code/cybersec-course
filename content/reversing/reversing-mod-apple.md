---
id: reversing-mod-apple
title: "Модуль: Реверс macOS и iOS"
category: reversing
parent: reversing-ios
difficulty: hard
order: 1
tags: [reversing, apple, macos, ios, codesign, roadmap]
prerequisites: [reversing-ios]
useful_for:
  - "Apple platform reversing"
  - "Mobile reversing"
  - "Malware analysis"
estimated_minutes: 8
summary: "Навигационный модуль о реверсе Apple-платформ: код-сайнинг, entitlements, Objective-C runtime, PAC, dyld cache."
---

Apple-платформы защищены не только кодом, но и экосистемой: подписи, entitlements, hardened runtime, notarization, PAC. Чтобы разбирать приложения, нужно понимать эти механизмы — иначе бинарник просто не запустится под анализом.

## Что покрывает подмодуль

- **reversing-macos-codesign-entitlements** — код-сайнинг, entitlements, hardened runtime.
- **reversing-objc-runtime** — Objective-C runtime: `objc_msgSend`, метаданные классов, swizzling.
- **reversing-ios-arm64e-pac** — ARM64e и Pointer Authentication (PAC).
- **reversing-dyld-shared-cache** — dyld shared cache: извлечение системных библиотек.

## Почему такой порядок

Сначала подписи и entitlements — без них ничего не запустить. Затем язык и рантайм (Objective-C). Потом низкоуровневая защита (PAC). И в конце — работа с системными библиотеками из кэша.

## Что вы будете уметь

- Понимать и обходить проверки подписи при анализе.

- Читать Objective-C метаданные и восстанавливать классы.

- Работать с ARM64e/PAC и извлекать библиотеки из dyld cache.

## Квиз

Проверь себя.

```quiz
- question: "Что такое entitlements в Apple-приложениях?"
  options:
    - "Список разрешений, подписанных вместе с бинарником"
    - "Формат картинки"
    - "Сетевой протокол"
    - "Тип шифрования"
  answer: 0
- question: "Зачем нужен dyld shared cache?"
  options:
    - "Системные библиотеки хранятся в одном общем кэше"
    - "Он шифрует диск"
    - "Он ускоряет сеть"
    - "Он заменяет ядро"
  answer: 0
- question: "Как называется рантайм Objective-C вызов?"
  options:
    - "objc_msgSend"
    - "sendMsg"
    - "callObjC"
    - "rtSend"
  answer: 0
```

## Куда дальше

Начни с код-сайнинга и entitlements — это вход в экосистему Apple. Пока главное: **на Apple реверс начинается с подписи и разрешений, а не с дизассемблера**.

## Где пригодится

- **Apple platform reversing:** приложения macOS/iOS.

- **Mobile reversing:** iOS-приложения и их защита.

- **Malware analysis:** macOS-малварь.
