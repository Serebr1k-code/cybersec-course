---
id: mobile-reverse-native
title: "Реверс native и кросс-платформенных приложений"
category: mobile
parent: mobile-static-analysis
difficulty: hard
order: 1
tags: [mobile, native, flutter, crossplatform, reverse]
prerequisites: [mobile-static-analysis]
useful_for:
  - "CTF: Reversing/Mobile"
  - "Пентест: обфусцированные приложения"
  - "Работа: reverse engineering"
estimated_minutes: 12
summary: "Этап реверса нативного кода (.so), Flutter/React Native и гибридных фреймворков."
---

Этот урок — **этап-навигатор** в ветке. Он короткий: его задача — объяснить, что вы будете изучать на этом этапе, почему темы идут именно в таком порядке и что вы сможете делать после прохождения.

## О чём этот этап

Первый этап продвинутой статики: реверс нативного кода JNI (.so), разбор Flutter/React Native и гибридных фреймворков (Cordova, Ionic, Xamarin, .NET MAUI).

## Что вы освоите

- Android native/JNI: реверс .so и нативных проверок
- Flutter и React Native: реверс кросс-платформенных приложений
- Гибридные фреймворки: Cordova, Ionic, Xamarin

## Как проходить

Идите от нативного кода к кросс-платформенным фреймворкам. Для .so используйте Ghidra/IDA, для Flutter — разбор libapp.so, для гибридов — распаковку веб-ассетов.

## Квиз

```quiz
- question: "Где в Android-приложении лежит нативный код?"
  options:
    - "В .so-библиотеках (JNI)"
    - "В resources.arsc"
    - "В AndroidManifest.xml"
    - "В strings.xml"
  answer: 0
  explanation: "JNI-код компилируется в разделяемые библиотеки .so."
- question: "Что нужно разобрать в Flutter-приложении?"
  options:
    - "libapp.so (скомпилированный Dart)"
    - "classes.dex"
    - "AndroidManifest.xml"
    - "proguard-rules.pro"
  answer: 0
  explanation: "Dart-код компилируется в libapp.so."
- question: "Почему гибридные приложения проще анализировать?"
  options:
    - "Логика часто в веб-ассетах"
    - "В них нет кода"
    - "Они не используют API"
    - "Они не компилируются"
  answer: 0
  explanation: "Cordova/Ionic хранят логику в JS/HTML, которые легко прочитать."
```

## Где пригодится

- **CTF:** Reversing/Mobile
- **Пентест:** обфусцированные приложения
- **Работа:** reverse engineering
