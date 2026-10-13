---
id: forensics-win-misc
title: "Модуль: Linux-артефакты и анти-форензика"
category: forensics
parent: forensics-windows-artifacts
difficulty: hard
order: 4
tags: [linux, artifacts, anti-forensics, timestomp, roadmap]
prerequisites: [forensics-win-logs]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 12
summary: "Четвёртый этап артефактов: следы в Linux и распознавание анти-форензики — что читать и в каком порядке."
lab:
  kind: shell
  title: "Практика: Linux-артефакты и анти-форензика"
  toolset: [core, linux]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{l1nux_4rt1f4cts_4nd_4nt1_f0r3ns1cs}' answer.txt"
  hints:
    - "История команд: `cat home/analyst/.bash_history`."
    - "Журнал входов: `cat var/log/auth.log` — ищи разрыв."
    - "Скрытые файлы: `ls -la tmp`."
    - "Прочитай закладку и вытащи метку: `grep nto tmp/.hidden_backdoor.sh > answer.txt`."
---

Последний модуль ветки артефактов выходит за пределы Windows. Здесь — **артефакты Linux** (такой же структурированный разбор, но для другой ОС) и **анти-форензика**: как распознать, что злоумышленник пытался уничтожить или подделать следы.

## Что покрывает этот модуль

- **Linux-артефакты** — `bash_history`, `/var/log`, `systemd`, автозапуск, пользователи.
- **Анти-форензика** — timestomping, очистка логов, сокрытие файлов, подмена метаданных.

## Рекомендуемый порядок изучения

1. `forensics-linux-artifacts` — базовые артефакты Linux; далее `forensics-linux-artifacts-deep`.
2. `forensics-anti-forensics` — приёмы сокрытия следов; далее `forensics-timestomp`.

Порядок: сначала научиться читать «нормальные» следы Linux, затем — замечать их отсутствие или искажение (признак анти-форензики).

## Что вы будете уметь

- Извлекать ключевые артефакты Linux-хоста.
- Замечать признаки подделки временных меток (timestomping).
- Распознавать попытки очистки логов и сокрытия файлов.
- Отличать естественное «отсутствие следа» от его уничтожения.

## Квиз

```quiz
- question: "Какой Linux-артефакт напрямую показывает выполненные пользователем команды?"
  options:
    - "MFT"
    - "bash_history"
    - "Prefetch"
    - "EVTX"
  answer: 1
  explanation: "История shell фиксирует команды, хотя её могут очистить."
- question: "Что такое timestomping?"
  options:
    - "Синхронизация часов"
    - "Подделка временных меток файлов для сокрытия следов"
    - "Шифрование журнала"
    - "Сжатие логов"
  answer: 1
  explanation: "Атакующий меняет timestamps, чтобы запутать таймлайн."
- question: "О чём говорит внезапный разрыв в логах?"
  options:
    - "О штатной ротации"
    - "О возможной попытке очистки следов"
    - "О шифровании диска"
    - "О подключении USB"
  answer: 1
  explanation: "Пропуск событий может указывать на уничтожение логов; его проверяют по другим источникам."
```

## Где пригодится

- **CTF:** задачи с Linux-хостами и подделкой метаданных.
- **DFIR:** выявление анти-форензики в ходе расследования.
- **Threat Hunting:** поиск аномалий в логах и временных метках.
- **Работа:** SOC/IR, работа с Linux-инфраструктурой.
