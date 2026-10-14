---
id: forensics-win-logs
title: "Модуль: журналы, события и таймлайн"
category: forensics
parent: forensics-windows-artifacts
difficulty: hard
order: 2
tags: [windows, evtx, logs, powershell, timeline, plaso, roadmap]
prerequisites: [forensics-win-registry]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 14
summary: "Третий этап артефактов Windows: журналы событий, логи PowerShell и построение таймлайна — что читать и в каком порядке."
lab:
  kind: shell
  title: "Практика: событие входа в EVTX"
  toolset: [core, evtx]
  workdir: /home/student/task
  files: [task.md, Security.evtx]
  check: "grep -q 'nto{3vtx_4624_l0g0n_typ3_10}' answer.txt"
  hints:
    - "Сигнатура: `xxd -l 7 Security.evtx` (`45 6c 66 46 69 6c 65` = `ElfFile`)."
    - "Разбери журнал: `evtx_dump.py Security.evtx -o events.json`."
    - "Ищи Event ID 4624 (вход) с Logon Type 10."
    - "Метка в сообщении события: `grep nto events.json > answer.txt`."
waystone: true
waystone_tasks: [forensics-carving, forensics-archives, forensics-filesystems, forensics-memory, forensics-disk-images]
---

Артефакты выполнения и файлов дают разрозненные факты. **Журналы** превращают их в связную историю: кто вошёл, какая служба запустилась, что выполнил PowerShell. Этот модуль — про логи и про то, как свести всё в единый таймлайн.

## Что покрывает этот модуль

- **Общие журналы** — где лежат логи Windows и Linux, как их читать.
- **EVTX** — формат журналов событий Windows, ключевые Event ID.
- **PowerShell** — script block logging, транскрипты, обфускация.
- **Таймлайн** — построение хронологии из разнородных источников (plaso/timesketch).

## Рекомендуемый порядок изучения

1. `forensics-logs` — общие принципы работы с логами.
2. `forensics-evtx-deep` — глубокий разбор журналов событий Windows.
3. `forensics-powershell-logs` — логи PowerShell как источник кода атакующего.
4. `forensics-timeline` — построение таймлайна; далее `forensics-plaso`.

Порядок: сначала общие логи, затем самый детальный источник (EVTX/PowerShell), затем агрегация в таймлайн.

## Что вы будете уметь

- Читать EVTX и связывать Event ID с действиями.
- Восстанавливать код, выполненный через PowerShell.
- Строить единый таймлайн из логов и артефактов.
- Отличать нормальные события от признаков компромисса.

## Инструмент: evtx_dump (разбор EVTX)

Windows-журнал `.evtx` — бинарный; в текст его переводит `evtx_dump` из
python-evtx:

```
$ xxd -l 7 Security.evtx
00000000: 456c 6646 696c 65                      ElfFile
$ evtx_dump.py Security.evtx -o events.json
$ grep -o '"EventID":[0-9]*' events.json | sort | uniq -c
```

Магия `ElfFile` — подпись формата EVTX. На выходе — JSON, где по `EventID`
ищут события: 4624 — вход в систему, 4688 — создание процесса, 1102 —
очистка журнала.

## Квиз

```quiz
- question: "Что даёт script block logging в PowerShell?"
  options:
    - "Скорость сети"
    - "Записанный код скриптов, которые выполнялись"
    - "Содержимое реестра"
    - "Историю USB"
  answer: 1
  explanation: "Он сохраняет блоки кода, что критично при разборе атак через PowerShell."
- question: "Зачем строить таймлайн из разных источников?"
  options:
    - "Чтобы уменьшить число файлов"
    - "Чтобы увидеть события в единой хронологии и восстановить ход атаки"
    - "Чтобы зашифровать данные"
    - "Чтобы заменить EVTX"
  answer: 1
  explanation: "Единая временная шкала связывает разрозненные артефакты в сценарий."
- question: "Почему EVTX считают ключевым источником в Windows?"
  options:
    - "Он хранит только пароли"
    - "Он фиксирует входы, запуск служб и другие значимые события"
    - "Он заменяет файловую систему"
    - "Он всегда пуст"
  answer: 1
  explanation: "Журналы событий документируют значимые изменения состояния системы."
```

## Где пригодится

- **CTF:** задачи с EVTX и логами.
- **DFIR:** реконструкция хронологии инцидента.
- **Threat Hunting:** поиск подозрительных событий и команд PowerShell.
- **Работа:** SOC/IR, тир-1/тир-2 анализ.
