---
id: hardware-arm-cortex-a
title: "ARM Cortex-A: TrustZone, MMU и эксплойты"
category: hardware
parent: hardware-mod-mcu
difficulty: hard
order: 2
tags: [hardware, arm, cortex-a, trustzone, mmu, tee, aarch64, exploit]
prerequisites: [hardware-arm-cortex-m, hardware-secure-enclave]
useful_for:
  - "Реверс и эксплуатация Cortex-A"
  - "CTF Hardware/Embedded"
  - "Анализ TEE и secure world"
estimated_minutes: 55
summary: "Как устроены прикладные ядра Cortex-A: уровни привилегий, MMU, TrustZone и переход между мирами — и почему граница secure/normal world так важна."
lab:
  kind: shell
  title: "Практика: разбор TrustZone"
  toolset: [core]
  workdir: /home/student/cortexa
  files: [task.md, tz-log.txt, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Открой лог: `cat tz-log.txt`."
    - "Найди строку с флагом: `grep nto tz-log.txt`."
    - "Флаг идёт после `world=`."
    - "Итог: `grep world tz-log.txt | grep nto | cut -d= -f2 > found.txt`."
---

## Вопрос, с которого всё начинается

Cortex-M — это микроконтроллеры. Но в телефонах, роутерах и ТВ-приставках стоят прикладные ядра **Cortex-A**, на которых работает Linux. Там есть не только пользовательский и привилегированный режимы, но и целых **два мира**. Как это устроено и почему граница между ними — ключевая цель атакующего?

## Наш пример: лог перехода между мирами

Перед нами `tz-log.txt` — упрощённая запись работы с **TrustZone**. Смотрим:

```
$ head -8 tz-log.txt
EL0: user app running
EL1: kernel (normal world) syscall
SMC call -> secure monitor (EL3)
EL1S: secure world entry (TEE)
MMU: stage-1/stage-2 translation
world=nto{c0rt3x_4_7ru5tz0n3}
```

Здесь ключевые понятия: **EL0/EL1/EL3**, **SMC**, **secure world**, **MMU stage-2**. Разберём.

## Шаг 1: уровни привилегий (Exception Levels)

В AArch64 (64-битный ARM) есть **Exception Levels**:

| Уровень | Где работает |
|---------|-------------|
| EL0 | пользовательские приложения |
| EL1 | ядро ОС (Linux) |
| EL2 | гипервизор |
| EL3 | secure monitor (TrustZone) |

Чем выше уровень, тем больше прав. Переход вниз — по исключениям, вверх — через специальные инструкции.

## Шаг 2: MMU и трансляция адресов

**MMU** (Memory Management Unit) транслирует виртуальные адреса в физические через таблицы страниц. Это даёт изоляцию процессов. В виртуализации добавляется **stage-2** трансляция (гипервизор), а в TrustZone — разделение адресных пространств для двух миров.

## Шаг 3: TrustZone — два мира

**TrustZone** делит систему на:

- **Normal world** — обычная ОС (Linux, Android).
- **Secure world** — доверенная среда (**TEE**), где живут секреты: ключи DRM, крипто-операции, платёжные данные.

Переключение миров идёт через **SMC** (Secure Monitor Call) — инструкцию, которая передаёт управление secure monitor (EL3). Монитор решает, что можно делать secure world.

## Шаг 4: что защищает TrustZone

Идея: даже если normal world скомпрометирован (взломан Linux/Android), secure world остаётся изолированным. Секреты и криптография — в TEE. Именно поэтому TrustZone используют для:

- DRM (защита контента);
- платёжных приложений;
- отпечатков пальцев;
- крипто-ключей.

## Шаг 5: где ищут уязвимости

Граница миров — самая интересная цель:

1. **Secure monitor (EL3)** — ошибки в SMC-обработчике.
2. **TEE-приложения (TA)** — доверенные приложения внутри secure world.
3. **Драйверы normal world**, которые общаются с TEE.
4. **Общая память** между мирами — некорректная проверка буферов.
5. **Реализации TEE** (OP-TEE, Trustonic, QSEE) — исторически находили серьёзные баги.

Типовая цель — **эскалация из normal world в secure world** или чтение секретов TEE.

## Шаг 6: что мы нашли в логе

В файле есть строка с указанием мира:

```
$ grep world tz-log.txt
world=nto{c0rt3x_4_7ru5tz0n3}
```

Смысл: разобрав переход между мирами, мы поняли архитектуру. В реальной работе дальше ищут, как из normal world добраться до secure world, — это и есть «святой грааль» эксплуатации Cortex-A.

## Шаг 7: инструменты

- **OpenOCD + GDB** — отладка на уровне EL.
- **Ghidra/IDA** — дизассемблирование AArch64.
- **Firmware-дампы TEE** — OP-TEE, QSEE, Trustonic.
- **Fuzzing SMC** — поиск ошибок в мониторе.
- **Анализ драйверов** — интерфейс normal↔secure.

## Шаг 8: защита

- **Минимизация TEE** — чем меньше кода в secure world, тем меньше поверхность.
- **Валидация SMC-интерфейса** — проверка всех параметров.
- **Изоляция TA** — доверенные приложения не должны доверять друг другу.
- **Обновления** — TEE тоже патчится.
- **Аппаратные корни доверия** — secure boot, eFuse.

## Что мы теперь знаем

1. Cortex-A использует **Exception Levels** (EL0–EL3) для привилегий.
2. **MMU** транслирует адреса и обеспечивает изоляцию; в виртуализации — stage-2.
3. **TrustZone** делит систему на normal и secure world.
4. Переключение — через **SMC** и secure monitor (EL3).
5. Граница миров — главная цель: ошибки SMC, TEE-приложений, драйверов.

## Квиз

Проверь себя.

```quiz
- question: "Сколько миров создаёт TrustZone?"
  options:
    - "Два: normal world и secure world"
    - "Один"
    - "Три"
    - "Четыре"
  answer: 0
  explanation: "TrustZone изолирует normal и secure world."
- question: "Какой уровень отвечает за secure monitor в AArch64?"
  options:
    - "EL3"
    - "EL0"
    - "EL1"
    - "EL2"
  answer: 0
  explanation: "EL3 — монитор TrustZone."
- question: "Как переключаются миры в TrustZone?"
  options:
    - "Через инструкцию SMC (Secure Monitor Call)"
    - "Через перезагрузку"
    - "Через Wi-Fi"
    - "Через смену частоты"
  answer: 0
  explanation: "SMC передаёт управление secure monitor."
- question: "Зачем нужна MMU?"
  options:
    - "Трансляция виртуальных адресов и изоляция памяти"
    - "Хранение паролей"
    - "Шифрование Wi-Fi"
    - "Зарядка батареи"
  answer: 0
  explanation: "MMU обеспечивает изоляцию через таблицы страниц."
- question: "Где чаще всего ищут уязвимости в TrustZone?"
  options:
    - "На границе миров: SMC-обработчик, TEE-приложения, драйверы"
    - "В пользовательских приложениях normal world"
    - "В драйвере Wi-Fi"
    - "В файловой системе"
  answer: 0
  explanation: "Граница secure/normal — основная цель."
```

## Куда дальше

ARM — самая массовая архитектура, но не единственная. Разберём открытую **RISC-V**: её расширения безопасности, PMP и особенности реверса. А пока главное: **TrustZone создаёт второй мир — и вся борьба идёт на границе между ними.**

## Где пригодится

- **CTF:** Hardware/Embedded-задачи по TEE и Cortex-A.
- **Пентест:** анализ мобильных и встраиваемых платформ.
- **Работа:** разработка защищённых систем, DRM, платёжные TEE.
- **Дальше по дереву:** `hardware-riscv`, `hardware-secure-enclave`.
