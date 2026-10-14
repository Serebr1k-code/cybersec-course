---
id: mobile-android-re-tooling
title: 'Модуль: инструменты реверса Android'
category: mobile
parent: mobile-android-analysis
difficulty: medium
order: 3
tags: [mobile, android, module]
prerequisites: []
useful_for:
  - 'Навигация по ветке'
  - 'Пентест мобильных приложений'
estimated_minutes: 10
summary: 'Инструменты статического реверса Android: JADX, apktool, MobSF и Ghidra — от чтения кода до нативного анализа.'
---

## О чём этот этап

Этот этап — про инструменты, которыми разбирают Android-приложение. Сначала JADX даёт Java-код,
затем apktool позволяет править и пересобирать, MobSF автоматизирует первичный разбор, а Ghidra
открывает нативные библиотеки.

## Что вы освоите

- Извлекать максимум из JADX (деобфускация, скрипты)
- Разбирать и пересобирать APK через apktool
- Автоматизировать анализ через MobSF API
- Разбирать нативный код в Ghidra

## Как проходить

Идите по порядку: JADX для чтения, apktool для правки, MobSF для массового прохода, Ghidra для
нативных библиотек. Каждый инструмент опирается на предыдущий.

## Квиз

Проверь себя.

```quiz
- question: Какой инструмент декомпилирует DEX в Java?
  options:
    - apktool
    - JADX
    - MobSF
    - Ghidra
  answer: 1
  explanation: JADX декомпилирует DEX.
- question: Какой инструмент собирает APK обратно после правки smali?
  options:
    - apktool
    - jadx
    - nm
    - adb
  answer: 0
  explanation: apktool делает build.
- question: Для чего нужен Ghidra?
  options:
    - Для ресурсов
    - Для нативного кода .so
    - Для подписи
    - Для сети
  answer: 1
  explanation: Ghidra разбирает машинный код.
```

## Куда дальше

Дальше — углублённый реверс native: символьное исполнение и эмуляция.

## Где пригодится

- Выбор инструмента под задачу реверса Android.
- Пентест мобильных приложений.
- CTF Mobile.
