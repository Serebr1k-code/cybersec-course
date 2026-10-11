---
id: mobile-ios-security
title: "Безопасность iOS: хранилища, jailbreak и ссылки"
category: mobile
parent: mobile-ios-basics
difficulty: hard
order: 2
tags: [mobile, ios, keychain, jailbreak, urlscheme]
prerequisites: [mobile-ios-basics]
useful_for:
  - "CTF: Mobile"
  - "Bug bounty: iOS"
  - "Работа: AppSec"
estimated_minutes: 12
summary: "Этап про iOS Keychain, обход jailbreak-детекта и URL schemes."
---

Этот урок — **этап-навигатор** в ветке. Он короткий: его задача — объяснить, что вы будете изучать на этом этапе, почему темы идут именно в таком порядке и что вы сможете делать после прохождения.

## О чём этот этап

Второй этап iOS: защита данных через Keychain и Data Protection, обход jailbreak-детекта и работа с URL schemes/Universal Links (hijacking и редиректы).

## Что вы освоите

- iOS Keychain и Data Protection: секреты и их защита
- Jailbreak-детект и его обход на iOS
- iOS URL schemes и Universal Links: hijacking и редиректы

## Как проходить

Сначала Keychain (где iOS хранит секреты), затем jailbreak-детект и URL schemes. Проверяйте класс защиты элементов Keychain.

## Квиз

```quiz
- question: "Где iOS хранит секреты приложения?"
  options:
    - "В Keychain"
    - "В Info.plist"
    - "В .ipa"
    - "В Mach-O"
  answer: 0
  explanation: "Keychain — защищённое хранилище секретов iOS."
- question: "Зачем обходить jailbreak-детект?"
  options:
    - "Чтобы запустить приложение на джейлбрейк-устройстве"
    - "Чтобы ускорить приложение"
    - "Чтобы сменить язык"
    - "Чтобы сжать IPA"
  answer: 0
  explanation: "Детект блокирует работу на скомпрометированном устройстве."
- question: "Чем опасны URL schemes?"
  options:
    - "Другое приложение может перехватить их обработку"
    - "Они шифруют данные"
    - "Они замедляют запуск"
    - "Они удаляют Keychain"
  answer: 0
  explanation: "Незанятую схему может зарегистрировать вредоносное приложение."
```

## Где пригодится

- **CTF:** Mobile
- **Bug bounty:** iOS
- **Работа:** AppSec
