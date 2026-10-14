---
id: macos-apple-silicon
title: 'Apple Silicon и Secure Enclave: что меняется для форензики'
category: forensics
parent: forensics-macos-system
difficulty: hard
order: 1
tags: [macos, apple-silicon, arm, secure-enclave, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Чем Apple Silicon отличается от Intel: ARM, унифицированная память, Secure Enclave и влияние на сбор и анализ данных.'
lab:
  kind: shell
  title: 'Практика: Apple Silicon и Secure Enclave'
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

Старые инструкции по форензике macOS писались для Intel. На новых Mac — **Apple
Silicon** (M1/M2/M3), и многое изменилось: другая архитектура, другой способ защиты
ключей, даже память устроена иначе. Разберём, что именно.

## Наш пример: определяем платформу

## Шаг 1: архитектура

```
$ uname -m
arm64
```

`arm64` (он же `aarch64`) означает ARM-процессор. Это не просто «другая ISA»: у ARM
другая модель памяти и загрузки. Скомпилированные под x86 инструменты работают через
Rosetta 2 — и могут оставлять свои артефакты.

## Шаг 2: унифицированная память

На Apple Silicon память **общая** для CPU и GPU (UMA). Практическое следствие:
разделение «память CPU» и «видеопамять» исчезает. При сборе дампа это меняет то, что
вообще доступно.

```
$ system_profiler SPHardwareDataType | grep -E 'Chip|Memory'
      Chip: Apple M2
      Memory: 16 GB
```

## Шаг 3: Secure Enclave

**Secure Enclave** — отдельный защищённый сопроцессор. Он хранит ключи шифрования
диска, ключи Touch ID и ключи iCloud. Из него ключи **не извлекаются** обычными
методами.

```
$ system_profiler SPiBridgeDataType 2>/dev/null | head
```

Это значит: снять ключ шифрования диска напрямую нельзя. Приходится либо знать
пароль пользователя, либо использовать живую систему с разблокированным ключом.

## Шаг 4: что это меняет для сбора

- **Шифрование диска по умолчанию**: на Apple Silicon всё шифруется аппаратно.
- **Без разблокировки** прочитать диск нельзя даже с физическим доступом.
- **Загрузка только подписанного ПО** (Secure Boot) — сложнее загрузить внешний
  форензик-образ.
- **Память**: сбор возможен, но требует отключённого SIP или особых привилегий.

## Шаг 5: проверяем защиту

```
$ csrutil status
System Integrity Protection status: enabled.
$ nvram boot-args
(none)
```

`enabled` означает, что SIP защищает системные файлы. Для живой форензики часто
требуется временно отключить SIP — но это меняет состояние системы, поэтому фиксируй
это в отчёте.

## Что мы теперь знаем

- Apple Silicon = ARM (`arm64`), x86 через Rosetta 2.
- Унифицированная память меняет модель сбора.
- Secure Enclave хранит ключи и не отдаёт их наружу.
- Диск шифруется аппаратно; без разблокировки чтения нет.
- SIP и Secure Boot ограничивают живой сбор.

## Если не сработало

- Нужен диск без разблокировки? Только официальные средства Apple (не сработает).
- Нужна память? Отключи SIP в recovery-режиме и зафиксируй это.
- Нужны ключи iCloud? Только через аккаунт пользователя.

## Квиз

Проверь себя.

```quiz
- question: Какая архитектура у Apple Silicon?
  options:
    - 'x86_64'
    - 'arm64/aarch64'
    - 'mips'
    - 'riscv'
  answer: 1
  explanation: 'Чипы M-серии используют ARM64; x86 идёт через Rosetta 2.'
- question: Что такое Secure Enclave?
  options:
    - 'сетевой адаптер'
    - 'защищённый сопроцессор, хранящий ключи'
    - 'файловая система'
    - 'браузер'
  answer: 1
  explanation: 'Secure Enclave изолированно хранит ключи и не отдаёт их наружу.'
- question: Почему на Apple Silicon диск нельзя прочитать без разблокировки?
  options:
    - 'он медленный'
    - 'шифрование аппаратное, ключ в Secure Enclave'
    - 'нет драйверов'
    - 'диск только для чтения'
  answer: 1
  explanation: 'Ключ шифрования защищён Secure Enclave и недоступен извне.'
- question: Что проверяет csrutil status?
  options:
    - 'сеть'
    - 'System Integrity Protection'
    - 'батарею'
    - 'реестр'
  answer: 1
  explanation: 'SIP защищает системные файлы и процессы.'
```
