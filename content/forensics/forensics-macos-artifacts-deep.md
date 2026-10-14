---
id: forensics-macos-artifacts-deep
title: "Модуль: пользовательские артефакты macOS"
category: forensics
parent: forensics-macos-artifacts
difficulty: hard
order: 2
tags: [macos, launchservices, spotlight, notifications, safari, imessage, forensics, roadmap]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ macOS-хостов"
estimated_minutes: 13
summary: "Этап ветки «macOS»: где система хранит пользовательскую активность — запуск приложений, поиск, уведомления, установки, браузер и сообщения."
---

macOS хранит историю активности в десятках SQLite-баз и plist-файлов, разбросанных по
`~/Library`. Этот модуль — про шесть источников, которые чаще всего дают ответы в
расследовании.

## Что покрывает этот модуль

- **LaunchServices** — что и когда запускалось и открывалось.
- **Spotlight** — индекс и поисковые запросы.
- **Уведомления** — тексты тостов и их источники.
- **Установки** — что инсталлировали и откуда.
- **Safari** — история, загрузки, кэш.
- **iMessage** — переписка и вложения.

## Рекомендуемый порядок изучения

1. `macos-launchservices` — базовый «журнал запусков».
2. `macos-spotlight` — индекс как источник метаданных.
3. `macos-notification-db` — тексты уведомлений.
4. `macos-install-logs` — история установок.
5. `macos-safari` — браузерные артефакты.
6. `macos-imessage` — сообщения.

## Что вы будете уметь

- Читать базы LaunchServices и Spotlight.
- Восстанавливать тексты уведомлений.
- Находить историю установок ПО.
- Извлекать историю Safari и переписку iMessage.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Путь |
|----------|--------------------|------|
| `com.apple.LaunchServices` | что запускалось | `~/Library/Preferences/` |
| `store.db` (Spotlight) | поисковые запросы | `~/Library/Application Support/com.apple.spotlight/` |
| `record.db` | уведомления | `~/Library/Group Containers/group.com.apple.usernoted/db2/` |
| `history.db` (Safari) | история браузера | `~/Library/Safari/` |
| `chat.db` (iMessage) | переписка | `~/Library/Messages/` |

## Куда дальше

Открывай урок **«LaunchServices: что запускалось»** — начнём с самого
универсального журнала macOS.
