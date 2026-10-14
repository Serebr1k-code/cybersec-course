---
id: reversing-mod-android
title: "Модуль: Реверс Android-приложений"
category: reversing
parent: reversing-android-apk
difficulty: hard
order: 1
tags: [reversing, android, dex, frida, packers, roadmap]
prerequisites: [reversing-android-apk]
useful_for:
  - "Mobile reversing"
  - "Malware analysis"
  - "Bug bounty"
estimated_minutes: 8
summary: "Навигационный модуль о глубоком реверсе Android: упаковщики, динамическая инструментация, символы .so и защита от анализа."
---

Базовый разбор APK ты уже знаешь: `jadx`, `apktool`, smali. Но реальные приложения упакованы, защищены от root и отладки, а логика вынесена в нативные `.so`. Этот модуль — про то, как разбирать такие приложения.

## Что покрывает подмодуль

- **reversing-android-packers** — упаковщики (Bangcle, Legu, Tencent) и дамп DEX из памяти.
- **reversing-android-dynamic-instrumentation** — Frida, Xposed, Zygisk для динамического анализа.
- **reversing-android-native-symbols** — восстановление символов `.so`, JNI-регистрация, анти-хук.
- **reversing-android-root-detect** — детект root/эмулятора/Frida и его обход.

## Почему такой порядок

Сначала распаковка (без неё нечего анализировать). Затем динамика (заставить приложение работать под контролем). Потом нативная часть (где прячут логику). И в конце — обход детекта, который мешает всему перечисленному.

## Что вы будете уметь

- Распаковывать защищённые APK и восстанавливать DEX.

- Строить динамический анализ через Frida/Xposed.

- Восстанавливать символы в нативных библиотеках.

- Обходить root/emulator/frida-detection.

## Квиз

Проверь себя.

```quiz
- question: "Где существует настоящий DEX в упакованном приложении?"
  options:
    - "В памяти после расшифровки"
    - "В манифесте"
    - "В интернете"
    - "В ресурсах"
  answer: 0
- question: "Зачем нужен обход root-detection?"
  options:
    - "Иначе приложение откажется работать под анализом"
    - "Чтобы ускорить его"
    - "Чтобы уменьшить размер"
    - "Чтобы подписать APK"
  answer: 0
- question: "Что нужно, чтобы дампить DEX из памяти?"
  options:
    - "Запущенное приложение и root/Frida"
    - "Только unzip"
    - "Только strings"
    - "Только jadx"
  answer: 0
```

## Куда дальше

Начни с распаковки: без оригинального DEX дальше идти некуда. Пока главное: **современное Android-приложение — это упакованный DEX плюс защищённый нативный код**.

## Где пригодится

- **Mobile reversing:** разбор коммерческих приложений.

- **Malware analysis:** Android-малварь упакована и защищена.

- **Bug bounty:** анализ защищённых приложений.
