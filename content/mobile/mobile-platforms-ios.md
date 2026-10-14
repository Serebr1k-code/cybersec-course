---
id: mobile-platforms-ios
title: "Модуль: iOS: основы, подписи и продвинутый анализ"
category: mobile
parent: mobile-platforms
difficulty: medium
order: 2
tags: [mobile, module, roadmap]
prerequisites: [mobile-platforms]
useful_for:
- Пентест iOS-приложений.
- CTF Mobile.
- Анализ мобильного malware.
estimated_minutes: 10
summary: "Основы ios (ipa, class-dump, hopper), подписи и entitlements, ipc/рантайм и продвинутый анализ"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «iOS: основы, подписи и продвинутый анализ»: основы iOS (IPA, class-dump, Hopper), подписи и entitlements, IPC/рантайм и продвинутый анализ.

- **mobile-ios-basics** — Основы iOS: IPA, class-dump, Hopper и особенности тестирования.
- **mobile-ios-signing** — Модуль: подписи, entitlements и доверие iOS.
- **mobile-ios-ipc** — Модуль: IPC и рантайм iOS.
- **mobile-ios-advanced** — Модуль: Продвинутый анализ iOS.

## Почему такой порядок

iOS строже изолирован: без понимания подписи и entitlements не обойтись, поэтому разбираем их до продвинутого анализа.

## Что вы сможете после этапа

- Разбирать Mach-O и IPA.
- Понимать entitlements и цепочку доверия iOS.

## Квиз

Проверь себя.

```quiz
- question: Что такое entitlements в iOS?
  options:
    - "Права, подписанные вместе с приложением"
    - "Список иконок"
    - "База SQLite"
    - "Настройки Wi-Fi"
  answer: 0
  explanation: Entitlements — подписанные права доступа приложения.
- question: Чем разбирают Mach-O?
  options:
    - "class-dump / Hopper"
    - "jadx"
    - "apktool"
    - "frida-server"
  answer: 0
  explanation: Для Mach-O используют class-dump/Hopper.
- question: Что даёт Frida на iOS?
  options:
    - "Динамическую инструментацию рантайма"
    - "Ускорение UI"
    - "Резервную копию"
    - "Смену темы"
  answer: 0
  explanation: Frida перехватывает вызовы в рантайме.
```

## Где пригодится

- Пентест iOS-приложений.
- CTF Mobile.
- Анализ мобильного malware.
