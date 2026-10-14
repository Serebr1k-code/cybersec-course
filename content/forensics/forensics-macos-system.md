---
id: forensics-macos-system
title: "Модуль: система macOS — Apple Silicon, память, бэкапы и защита"
category: forensics
parent: forensics-macos-artifacts
difficulty: hard
order: 3
tags: [macos, apple-silicon, memory, timemachine, xprotect, icloud, forensics, roadmap]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ macOS-хостов"
estimated_minutes: 13
summary: "Этап ветки «macOS»: чем отличается современный Mac — ARM-процессоры и унифицированная память, локальные снимки, встроенная защита и синхронизация iCloud."
---

Пользовательские артефакты мы разобрали. Теперь — системный уровень macOS: архитектура
Apple Silicon, особенности сбора памяти, снимки Time Machine и встроенная защита
(XProtect). Плюс облачная синхронизация iCloud, которая «уводит» данные с устройства.

## Что покрывает этот модуль

- **Apple Silicon** — ARM, Secure Enclave и что это значит для форензики.
- **Память macOS** — как снимать и что в ней искать.
- **Time Machine** — локальные снимки как источник удалённых версий.
- **XProtect** — встроенный антивирус и его журналы.
- **iCloud** — синхронизация и её следы.

## Рекомендуемый порядок изучения

1. `macos-apple-silicon` — понять архитектуру и её ограничения.
2. `macos-memory` — сбор и анализ памяти.
3. `macos-timemachine` — удалённые версии из снимков.
4. `macos-xprotect` — что обнаружила защита.
5. `macos-icloud` — синхронизация данных.

## Что вы будете уметь

- Учитывать особенности ARM/Secure Enclave при сборе.
- Снимать и анализировать память macOS.
- Доставать удалённые файлы из снимков Time Machine.
- Читать журналы XProtect.
- Оценивать, что ушло в iCloud.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| Secure Enclave | где ключи и защита | архитектура |
| `*.vmem` / `memory_pressure` | что было в памяти | osxpmem, Volatility |
| `/.MobileBackups`, APFS snapshots | удалённые версии | `tmutil` |
| `XProtect.log` | что нашла защита | `log show` |
| `~/Library/Mobile Documents` | что в iCloud | `brctl` |

## Куда дальше

Открывай урок **«Apple Silicon и Secure Enclave»** — начнём с того, чем
современный Mac отличается от Intel.
