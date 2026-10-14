---
id: mobile-app-reversing
title: 'Реверс мобильных приложений: APK, DEX и нативные библиотеки'
category: forensics
parent: forensics-mobile-android-deep
difficulty: hard
order: 6
tags: [forensics, mobile, android, reversing, apk, native]
prerequisites: [forensics-mobile]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как разбирать мобильные приложения: структура APK, декомпиляция DEX, нативные библиотеки и защита.'
lab:
  kind: shell
  title: 'Практика: Реверс мобильных приложений'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Нужно понять логику приложения: куда оно ходит, как хранит данные, есть ли вредонос.
Разберём реверс Android-приложений.

## Наш пример: APK

## Шаг 1: структура

APK — ZIP:

```
$ unzip -l app.apk | head
  classes.dex
  lib/arm64-v8a/libnative.so
  res/
  AndroidManifest.xml
```

`classes.dex` — байткод, `lib/` — нативные библиотеки (C/C++).

## Шаг 2: декомпиляция DEX

```
$ jadx -d out app.apk
$ grep -rE 'http|token|encrypt' out/sources/ | head
```

`jadx` даёт Java-подобный код. Ищем URL, ключи, логику.

## Шаг 3: манифест

```
$ apktool d app.apk -o out_apktool
$ grep -E 'activity|permission|service' out_apktool/AndroidManifest.xml | head
```

Манифест показывает компоненты и разрешения.

## Шаг 4: нативный код

Сложную логику прячут в `.so`:

```
$ file lib/arm64-v8a/libnative.so
ELF 64-bit LSB shared object, ARM aarch64
```

Анализ — как обычного ARM-бинарника (Ghidra/IDA).

## Шаг 5: защита

- **обфускация** (ProGuard/R8);
- **шифрование DEX** (загрузчик расшифрует в рантайме);
- **anti-debug/anti-Frida**;
- **проверка целостности**.

## Что мы теперь знаем

- APK = ZIP с DEX, lib, res, манифестом.
- `jadx` декомпилирует DEX.
- Нативный код в `.so` (ARM).
- Манифест даёт компоненты/разрешения.
- Защита: обфускация, шифрование DEX, anti-debug.

## Если не сработало

- DEX зашифрован? Ищи загрузчик, снимай дамп из памяти.
- Обфускация? Деобфусцируй/динамически.
- Anti-Frida? Обходи проверки.

## Квиз

Проверь себя.

```quiz
- question: Что содержит classes.dex?
  options:
    - 'картинки'
    - 'байткод приложения'
    - 'шрифты'
    - 'сеть'
  answer: 1
  explanation: 'DEX — исполняемый байткод Android.'
- question: Какой инструмент декомпилирует DEX?
  options:
    - 'grep'
    - 'jadx'
    - 'nmap'
    - 'ssh'
  answer: 1
  explanation: 'jadx восстанавливает Java-подобный код.'
- question: Где прячут сложную логику?
  options:
    - 'в res'
    - 'в нативных .so библиотеках'
    - 'в манифесте'
    - 'в обои'
  answer: 1
  explanation: 'Нативный код (C/C++) сложнее анализировать.'
- question: Что за защита «шифрование DEX»?
  options:
    - 'обои'
    - 'DEX расшифровывается загрузчиком в рантайме'
    - 'сеть'
    - 'шрифт'
  answer: 1
  explanation: 'Обфускатор шифрует DEX; код появляется только при запуске.'
```
