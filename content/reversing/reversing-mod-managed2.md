---
id: reversing-mod-managed2
title: "Модуль: Языковые рантаймы и байткод"
category: reversing
parent: reversing-mod-managed
difficulty: hard
order: 3
tags: [reversing, bytecode, v8, hermes, dotnet, roadmap]
prerequisites: [reversing-mod-managed]
useful_for:
  - "Browser / JS reversing"
  - "Mobile reversing"
  - "Malware analysis"
estimated_minutes: 8
summary: "Навигационный модуль о реверсе языковых рантаймов: V8, Hermes/Flutter, .NET AOT, LuaJIT и другие байткоды."
---

Современный код редко бывает «просто нативным». Он компилируется в байткод (JS, Python, .NET, Lua) или AOT-нативно (Dart, .NET NativeAOT, Kotlin/Native). Понимание конкретного рантайма — ключ к разбору такого кода.

## Что покрывает подмодуль

- **reversing-v8-bytecode** — V8: Ignition, TurboFan, snapshots.
- **reversing-hermes-flutter** — Hermes (React Native) и Dart/Flutter AOT.
- **reversing-dotnet-aot-readytorun** — .NET ReadyToRun/NativeAOT.
- **reversing-luajit-bytecode** — LuaJIT и трассирующая компиляция.

## Почему такой порядок

Сначала самые распространённые веб/десктоп рантаймы (V8). Затем мобильные (Hermes/Flutter). Затем .NET-ветка (AOT). И LuaJIT — как пример рантайма с трассирующей компиляцией.

## Что вы будете уметь

- Определять рантайм по артефактам (снапшот, байткод-файл).

- Дизассемблировать и читать байткод конкретного рантайма.

- Понимать, как AOT-компиляция превращает байткод в нативный код.

## Квиз

Проверь себя.

```quiz
- question: "Какой рантайм используется в React Native?"
  options:
    - "Hermes"
    - "V8"
    - "SpiderMonkey"
    - "CLR"
  answer: 0
- question: "Что делает NativeAOT в .NET?"
  options:
    - "Компилирует сборку в нативный код заранее"
    - "Шифрует сборку"
    - "Сжимает IL"
    - "Запускает JIT"
  answer: 0
- question: "Чем анализируют Hermes bytecode?"
  options:
    - "hbctool и дизассемблер Hermes"
    - "jadx"
    - "dnSpy"
    - "Ghidra"
  answer: 0
```

## Куда дальше

Начни с V8 — он самый распространённый и хорошо документирован. Пока главное: **у каждого рантайма свой байткод, и его формат определяет метод анализа**.

## Где пригодится

- **Browser / JS reversing:** веб и десктоп на JS.

- **Mobile reversing:** Hermes и Dart/Flutter.

- **Malware analysis:** байткод-малварь.
