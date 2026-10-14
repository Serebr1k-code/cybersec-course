---
id: forensics-win-persistence-advanced
title: "Модуль: хайджек загрузки и телеметрия PowerShell"
category: forensics
parent: forensics-win-artifacts-advanced
difficulty: expert
order: 5
tags: [windows, persistence, ifeo, com, sysmon, powershell, registry, forensics, roadmap]
prerequisites: [forensics-win-artifacts-advanced]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 14
summary: "Этап ветки «Артефакты Windows»: восстановление исполненного PowerShell-кода (транскрипты, Script Block) и реестровые техники закрепления (IFEO, AppInit, COM-хайджек)."
---

Предыдущий этап дал защищённые секреты и следы удалённых сессий. Но два вопроса остаются
открытыми: **что именно исполнялось** (если история команд подчищена) и **как малварь
возвращается** без служб и `Run`-ключей. Этот модуль закрывает оба.

## Что покрывает этот модуль

- **PowerShell-логи** — четыре независимых журнала: транскрипты на диске, Script Block
  Logging (4104), Module Logging и Operational. Они позволяют восстановить код даже после
  обфускации.
- **Sysmon** — телеметрия уровня процессов: хеши, командные строки, родители, сетевые
  соединения и DNS. Важно понимать, что конфигурация фильтрует события.
- **IFEO / AppInit / AppCert** — реестровые техники, заставляющие Windows запускать чужой
  код вместе с легитимными программами.
- **COM-хайджек** — подмена зарегистрированного COM-объекта в HKCU, которая грузит DLL
  атакующего в доверенный процесс.

## Как читать модуль

Сначала — логи: «что исполнялось». Потом — реестровые техники: «как закрепились». Каждый
урок даёт связку «где артефакт → чем распарсить → что искать», а также показывает, какие
события Sysmon подтверждают находку.

## Квиз

```quiz
- question: "Сколько независимых источников PowerShell-логов существует?"
  options:
    - "Четыре: транскрипты, Script Block, Module и Operational"
    - "Один"
    - "Два"
    - "Их нет"
  answer: 0
  explanation: "PowerShell пишет транскрипты, Script Block Logging, Module Logging и Operational-журнал."
- question: "Что даёт Sysmon поверх стандартных журналов?"
  options:
    - "Телеметрию процессов: хеши, командные строки, родителей, сеть"
    - "Только входы"
    - "Только файлы"
    - "Только DNS"
  answer: 0
  explanation: "Sysmon добавляет детальную телеметрию процессов и сети."
- question: "Что делает IFEO-хайджек?"
  options:
    - "Заставляет Windows запускать чужой отладчик вместо программы"
    - "Ускоряет загрузку"
    - "Шифрует диск"
    - "Меняет DNS"
  answer: 0
  explanation: "IFEO/AppInit/AppCert заставляют загружать чужой код при запуске программ."
```

## Куда дальше

Открывай урок **«PowerShell-логи: транскрипты, Script Block и Module Logging»** — начнём с
восстановления исполненного кода.

## Где пригодится

**CTF:** Windows-forensics.
**DFIR:** разбор скрытой персистентности.
**Работа:** анализ PowerShell- и Sysmon-телеметрии.
