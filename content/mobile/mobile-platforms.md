---
id: mobile-platforms
title: "Платформы: Android и iOS"
category: mobile
parent: mobile-intro
difficulty: easy
order: 1
tags: [mobile, android, ios, fundamentals]
prerequisites: [mobile-intro]
useful_for:
  - "CTF: Mobile"
  - "Пентест: мобильные приложения"
  - "Работа: AppSec-анализ"
estimated_minutes: 12
summary: "Первый этап: анатомия Android-приложения и основы iOS."
---

Этот урок — **этап-навигатор** в ветке. Он короткий: его задача — объяснить, что вы будете изучать на этом этапе, почему темы идут именно в таком порядке и что вы сможете делать после прохождения.

## О чём этот этап

Первый этап мобильной ветки закладывает фундамент обеих платформ. Вы разберёте структуру Android-приложения (APK, манифест, DEX) и основы iOS (IPA, class-dump, Hopper), чтобы понимать, с чем вообще работаете дальше.

## Что вы освоите

- Анатомия Android-приложения: APK, манифест, DEX
- Основы iOS: IPA, class-dump, Hopper
- Ориентироваться в артефактах обеих платформ

## Как проходить

Начните с Android (проще и доступнее инструментально), затем iOS. Разберите по одному реальному приложению каждой платформы и составьте карту его компонентов.

## Квиз

```quiz
- question: "Что содержит APK-файл Android-приложения?"
  options:
    - "Манифест, DEX-байткод и ресурсы"
    - "Только иконки"
    - "Исходный код на Java"
    - "Базу данных приложения"
  answer: 0
  explanation: "APK — это архив с манифестом, DEX и ресурсами."
- question: "Какой инструмент декомпилирует iOS-приложение?"
  options:
    - "class-dump / Hopper"
    - "jadx"
    - "apktool"
    - "frida-server"
  answer: 0
  explanation: "Для iOS используют class-dump и Hopper для разбора Mach-O."
- question: "Где в Android описан список компонентов и разрешений?"
  options:
    - "AndroidManifest.xml"
    - "build.gradle"
    - "classes.dex"
    - "resources.arsc"
  answer: 0
  explanation: "Манифест объявляет компоненты, разрешения и точки входа."
```

## Где пригодится

- **CTF:** Mobile
- **Пентест:** мобильные приложения
- **Работа:** AppSec-анализ
