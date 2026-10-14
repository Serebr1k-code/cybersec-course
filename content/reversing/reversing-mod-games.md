---
id: reversing-mod-games
title: "Модуль: Реверс игр, DRM и античитов"
category: reversing
parent: reversing-game-anticheat
difficulty: hard
order: 2
tags: [reversing, games, unity, unreal, drm, anticheat, roadmap]
prerequisites: [reversing-game-anticheat]
useful_for:
  - "Game reversing / cheating"
  - "DRM research"
  - "Kernel reversing"
estimated_minutes: 8
summary: "Навигационный модуль о реверсе игровых движков, DRM-платформ и античит-систем."
---

Игровой реверс — отдельный мир: огромные бинарники, собственные движки, DRM-платформы и агрессивные античиты, часть которых работает в ядре. Если ты умеешь разбирать обычные приложения, здесь понадобится добавить понимание движков и защит.

## Что покрывает подмодуль

- **reversing-unity-il2cpp** — Unity IL2CPP/Mono: `global-metadata.dat`, `libil2cpp.so`, Il2CppDumper.
- **reversing-unreal-engine** — Unreal Engine: пакеты `.pak`, Blueprints, `.uasset`.
- **reversing-steam-drm** — Steam DRM/Steamworks и его обход.
- **reversing-eac-battleye** — ядерные античиты (EAC, BattlEye) в пользовательском и ядерном режиме.

## Почему такой порядок

Сначала движки: понять, где вообще лежит логика игры (IL2CPP или Unreal). Затем DRM: как игра защищена от копирования. И в конце античиты — самая сложная часть, потому что они уходят в ядро и активно противодействуют анализу.

## Что вы будете уметь

- Разбирать Unity IL2CPP и Unreal-игры, восстанавливать логику.

- Понимать, как работают Steam DRM и обёртки.

- Ориентироваться в архитектуре ядерных античитов и их проверках.

## Квиз

Проверь себя.

```quiz
- question: "Какие два файла нужны для разбора Unity IL2CPP?"
  options:
    - "libil2cpp.so и global-metadata.dat"
    - "pak и exe"
    - "dll и pdb"
    - "dex и apk"
  answer: 0
- question: "Где работает часть современных античитов?"
  options:
    - "В ядре (kernel-mode)"
    - "Только в браузере"
    - "Только на сервере"
    - "В BIOS"
  answer: 0
- question: "Какой движок использует global-metadata.dat?"
  options:
    - "Unity IL2CPP"
    - "Unreal"
    - "Godot"
    - "CryEngine"
  answer: 0
```

## Куда дальше

Начни с Unity IL2CPP — самый распространённый движок в мобильных играх. Пока главное: **игровой реверс = движок + DRM + античит, и каждый слой требует своего подхода**.

## Где пригодится

- **Game reversing:** анализ логики, читов и защиты.

- **DRM research:** изучение механизмов защиты.

- **Kernel reversing:** античиты — пример ядерных компонентов.
