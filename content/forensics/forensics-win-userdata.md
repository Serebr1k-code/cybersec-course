---
id: forensics-win-userdata
title: 'Модуль: пользовательские данные и сетевые следы Windows'
category: forensics
parent: forensics-windows-artifacts
difficulty: hard
order: 6
tags: [windows, credentials, vault, dns, wer, appcompat, roadmap]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Пентест Windows'
estimated_minutes: 14
summary: 'Ветка «Артефакты Windows»: сохранённые учётки, DNS-следы, отчёты о падениях и кэш совместимости приложений.'
---

Пользовательские данные и сетевые следы отвечают на вопросы «чем пользовались», «куда
ходили» и «что запускалось». Этот модуль объединяет артефакты, которые связывают
конкретного пользователя с действиями в системе и сети.

## Что покрывает этот модуль

- **Credential Manager / Vault** — сохранённые логины и пароли.
- **DNS-кэш и журналы DNS Client** — к каким именам обращалась машина.
- **Windows Error Reporting** — пути и имена упавших программ.
- **AppCompat cache** — независимый след запуска приложений.

## Рекомендуемый порядок изучения

1. `win-credential-vault` — учётки, которые использовались.
2. `win-dns-cache` — сетевые контакты.
3. `win-wer` — следы запуска через падения.
4. `win-app-compat` — ещё один источник execution-следов.

## Что вы будете уметь

- Разбирать Credential Manager и Windows Vault.
- Восстанавливать DNS-запросы из кэша и журналов.
- Читать Report.wer и доставать пути запуска.
- Использовать AppCompat cache в связке с другими артефактами.

## Квиз

```quiz
- question: "Что хранит Credential Manager / Vault?"
  options:
    - "Сохранённые логины и пароли"
    - "Сетевые пакеты"
    - "Задачи cron"
    - "Сертификаты только"
  answer: 0
  explanation: "Credential Manager/Vault хранит сохранённые учётные данные."
- question: "Что показывает DNS-кэш?"
  options:
    - "К каким именам обращалась машина"
    - "Кто входил в систему"
    - "Какие файлы открывались"
    - "Какие службы запущены"
  answer: 0
  explanation: "DNS-кэш содержит недавние обращения к доменным именам."
- question: "Что содержит Windows Error Reporting (WER)?"
  options:
    - "Пути и имена упавших программ"
    - "Пароли"
    - "DNS-зону"
    - "SYSVOL"
  answer: 0
  explanation: "WER фиксирует пути и имена приложений, вызвавших ошибку."
```

## Куда дальше

Начни с урока **«Credential Manager и Windows Vault»** — учётные данные чаще всего
двигают расследование вперёд.

## Где пригодится

**CTF:** Windows-forensics.
**DFIR:** пользовательские и сетевые следы.
**Работа:** анализ Credential Vault и DNS-кэша.
