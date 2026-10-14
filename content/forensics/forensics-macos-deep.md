---
id: forensics-macos-deep
title: "Модуль: глубокая форензика macOS"
category: forensics
parent: forensics-macos-artifacts
difficulty: hard
order: 2
tags: [macos, apple, keychain, tcc, unified-log, privacy, roadmap]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "macOS forensics"
estimated_minutes: 14
summary: "Этап ветки macOS: защищённые базы macOS — связка ключей (Keychain), база согласий приватности (TCC) и бинарные unified-логи."
---

Базовый урок macOS дал FSEvents, quarantine и обзор артефактов. Но самые ценные данные
лежат в **защищённых базах Apple**: пароли и токены — в **Keychain**, разрешения
приложений — в **TCC**, а подробная история событий — в **unified logs**. Эти три артефакта
отвечают на вопросы «какие секреты были на машине», «что приложению разрешили» и «что
происходило в системе минута за минутой».

## Что покрывает этот модуль

- **Keychain** — связка ключей macOS: пароли сайтов и приложений, сертификаты, ключи.
  Формат `login.keychain-db` (SQLite) и способы его разбора.
- **TCC** — Transparency, Consent, Control: база согласий, кто получил доступ к камере,
  микрофону, экрану, диску.
- **Unified logs** — единый бинарный журнал (tracev3), собираемый в `logarchive` и
  разбираемый инструментами Apple и сторонними парсерами.

## Как читать модуль

Сначала — **Keychain**: это «что утекло». Потом — **TCC**: «что приложению разрешили»,
часто это ключ к тому, как malware закрепился. В конце — **unified logs**: «что происходило
во времени». Каждый урок даёт связку «где лежит артефакт → чем разобрать → что в выводе
искать».

## Куда дальше

Открывай урок **«Keychain: связка ключей macOS»** — начнём с самого ценного приза на
macOS-хосте.
