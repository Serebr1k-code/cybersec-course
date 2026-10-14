---
id: pwn-windows-cve
title: "Модуль: Windows CVE"
category: pwn
parent: pwn-cve-exploitation
difficulty: medium
order: 3
tags: [pwn, module, roadmap, cve]
prerequisites: [pwn-windows-intro]
useful_for:
  - "Эксплуатация реальных CVE"
  - "Red team: повышение привилегий"
estimated_minutes: 10
summary: "Навигационный модуль: известные уязвимости Windows: сетевые (SMB, Kerberos) и локальные (CLFS, драйверы)."
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Windows CVE»: известные уязвимости Windows: сетевые (SMB, Kerberos) и локальные (CLFS, драйверы).

- CLFS и PrintNightmare — локальное повышение привилегий.
- EternalBlue (MS17-010) — удалённый код через SMBv1.
- Zerologon (CVE-2020-1472) — обход аутентификации в Netlogon.

## Почему такой порядок

Windows-блок требует понимания PE, SMB и Kerberos, поэтому идёт после соответствующей подготовки.

## Что вы сможете после этапа

- Отличать сетевой RCE от локального EoP.
- Применять публичные эксплойты с учётом версии патча.

## Квиз

Проверь себя.

```quiz
- question: Что делает Zerologon?
  options:
    - "Шифрует диск"
    - "Обходит аутентификацию Netlogon"
    - "Ставит обновление"
    - "Пишет в реестр"
  answer: 1
  explanation: CVE-2020-1472 позволяет сбросить пароль DC без аутентификации.
- question: EternalBlue эксплуатирует протокол...
  options:
    - "Kerberos"
    - "SMBv1"
    - "HTTP"
    - "LDAP"
  answer: 1
  explanation: MS17-010 — переполнение в SMBv1.
- question: PrintNightmare относится к классу...
  options:
    - "Удалённый DoS"
    - "Локальное/удалённое повышение привилегий через Spooler"
    - "XSS"
    - "SQLi"
  answer: 1
  explanation: Печально известный баг в Windows Print Spooler.
```

## Где пригодится

- Локальное и сетевое повышение привилегий в Windows.
- Red team в AD-сетях.
- Разбор патчей Windows.
