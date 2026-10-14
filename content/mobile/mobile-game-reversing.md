---
id: mobile-game-reversing
title: 'Модуль: реверс мобильных игр и движков'
category: mobile
parent: mobile-crossplatform
difficulty: hard
order: 1
tags: [unity, unreal, godot, il2cpp, game, roadmap]
prerequisites: [mobile-crossplatform]
useful_for:
  - 'Реверс мобильных игр'
  - 'Пентест мобильных приложений'
  - 'CTF Mobile/Game Hacking'
estimated_minutes: 22
summary: 'Навигационный модуль: как устроены мобильные игры на популярных движках, где лежит игровая логика и как её достать — Unity (Mono/IL2CPP), Unreal (.pak/.uasset) и Godot (.pck).'
---

Обычное приложение на Kotlin/Swift мы уже разбирали. Но значительная часть мобильных
приложений — игры и «супер-приложения» — собрана на игровых движках, и их логика лежит **не** в
DEX, а в отдельном формате. Этот модуль показывает, где именно искать код в трёх самых
распространённых движках.

## Что покрывает модуль

1. **Unity** — два бэкенда: Mono (`Assembly-CSharp.dll`) и IL2CPP (`libil2cpp.so` +
   `global-metadata.dat`).
2. **Unreal Engine** — нативные `libUE4.so`/`libUnreal.so` и контейнеры ассетов `.pak`,
   `.uasset`, IoStore (`.utoc`/`.ucas`).
3. **Godot** — контейнер `.pck` с ресурсами и (опционально) скомпилированным GDScript.

## Почему такой порядок

Сначала Unity — самый частый случай, и у него два принципиально разных пути (управляемый
Mono и нативный IL2CPP), поэтому он задаёт обе базовые техники. Потом Unreal — полностью
нативный движок с собственными контейнерами ассетов. Затем Godot — маленький движок с одним
файлом ресурсов, отличная тренировка на «найти ключ и распаковать».

## Как проходить ступень

Начните с `mobile-unity`. В каждом уроке есть лаборатория: разберите строки/метаданные
движка до флага и ответьте на квиз. Не пропускайте лаборатории — именно на них закрепляется
навык распознавания формата.

## Связь с другими ветками

Это продолжение `mobile-crossplatform` (Flutter/React Native) и `mobile-native-reversing`.
Общие приёмы хукинга — в `mobile-dynamic-frida`; работа с нативным кодом — в `mobile-native-so-deep`.


## Квиз

Проверь себя.

```quiz
- question: Какой файл содержит управляемый код в Mono-сборке Unity?
  options:
    - libil2cpp.so
    - Assembly-CSharp.dll
    - global-metadata.dat
    - libmono.so
  answer: 1
  explanation: Mono хранит C# в управляемых сборках, главная — Assembly-CSharp.dll.
- question: Что нужно Il2CppDumper для разбора IL2CPP-игры?
  options:
    - Только APK
    - libil2cpp.so и global-metadata.dat
    - Только .pak
    - Онлайн-сервис
  answer: 1
  explanation: Дампер сопоставляет нативный код и метаданные, поэтому нужны оба файла.
- question: В каком контейнере Unreal лежат игровые ассеты?
  options:
    - .pck
    - .pak
    - .dex
    - .so
  answer: 1
  explanation: Ассеты Unreal упакованы в .pak (или IoStore .utoc/.ucas).
- question: Что даёт разбор .pck в Godot?
  options:
    - Список IP-адресов
    - Ресурсы и, возможно, скрипты игры
    - Пароль Wi-Fi
    - Ничего
  answer: 1
  explanation: .pck — это контейнер ресурсов движка Godot.
```

## Где пригодится

- **Реверс мобильных игр:** выбор инструмента под конкретный движок.
- **Пентест мобильных приложений:** разбор логики покупок и проверок в играх.
- **Game Hacking:** поиск клиентских проверок и секретов.
- **CTF:** Mobile/Game-задачи на движках.
