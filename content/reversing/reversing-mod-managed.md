---
id: reversing-mod-managed
title: "Модуль: Управляемый байткод и JIT"
category: reversing
parent: reversing-module-symbolic
difficulty: medium
order: 2
tags: [reversing, dotnet, jvm, bytecode, scripting, jit, roadmap]
prerequisites: [reversing-intro]
useful_for:
  - "CTF Reversing: .NET и Java задачи"
  - "Malware analysis: разбор скриптов и байткода"
estimated_minutes: 6
summary: "Подмодуль об управляемом и интерпретируемом коде: деобфускация .NET, байткод JVM, скриптовые языки и анализ JIT-компиляции."
---

Не весь код компилируется в машинные инструкции. .NET и Java исполняют байткод на виртуальной
машине, скриптовые языки интерпретируются, а JIT-компиляторы генерируют машинный код на лету. У
каждого из этих миров свои форматы, инструменты и подводные камни.

## Что покрывает подмодуль

- **reversing-dotnet-deobfuscation** — деобфускация .NET: de4dot, dnSpy/ILSpy, восстановление
  имён, работа с ControlFlow и string-encryption, разбор IL.
- **reversing-jvm-bytecode-deep** — байткод JVM: class-файлы, javap, jadx/CFR/Procyon, обфускация
  (ProGuard, Allatori) и её снятие.
- **reversing-scripting-langs** — скриптовые языки: Python-байткод (`pycdc`, `decompyle3`), Lua
  (`luadec`, `unluac`), Perl и Ruby, восстановление исходников.
- **reversing-jit-analysis** — JIT-анализ: как найти сгенерированный код, отладка JIT-регионов,
  особенности V8/Java HotSpot/.NET RyuJIT.

## Почему такой порядок

.NET и JVM — наиболее структурированные из управляемых сред, с зрелыми инструментами, поэтому идут
первыми. Скриптовые языки проще по формату, но разнообразнее. JIT-анализ сложнее всех: код
появляется в памяти во время выполнения, и его надо поймать.

## Что вы будете уметь

- Деобфусцировать .NET-сборки и читать IL.
- Разбирать байткод JVM и снимать обфускацию.
- Восстанавливать исходники скриптовых языков.
- Находить и отлаживать JIT-сгенерированный машинный код.

## Квиз

```quiz
- question: "Какой инструмент деобфусцирует .NET-сборки?"
  options:
    - "de4dot"
    - "upx"
    - "readelf"
    - "objdump"
  answer: 0
- question: "Что делает javap?"
  options:
    - "Дизассемблирует байткод class-файлов JVM"
    - "Компилирует Java в нативный код"
    - "Распаковывает JAR"
    - "Оbfuscates код"
  answer: 0
- question: "Почему JIT-код трудно анализировать статически?"
  options:
    - "Он генерируется в память во время выполнения и его нет в файле"
    - "Он слишком короткий"
    - "Он зашифрован всегда"
    - "Его нельзя исполнить"
  answer: 0
```

## Где пригодится

- **CTF Reversing:** .NET/Java/Python crackme, обфусцированные задачи.
- **Malware analysis:** разбор скриптов и байткода без нативной компиляции.
- **Аудит:** анализ управляемого кода на скрытую логику.
