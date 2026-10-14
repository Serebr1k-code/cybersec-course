---
id: forensics-mobile-data
title: "Модуль: мобильные данные — мессенджеры, облако, SIM, chip-off"
category: forensics
parent: forensics-mobile
difficulty: hard
order: 6
tags: [forensics, mobile, whatsapp, signal, cloud, sim, chip-off, roadmap]
prerequisites: [forensics-mobile]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Мобильная форензика"
estimated_minutes: 13
summary: "Этап ветки «мобильные»: где живут данные мессенджеров, облачная синхронизация, SIM/USIM и физическое снятие чипа."
---

Самое ценное на телефоне — переписка и данные аккаунтов. Они распределены между
приложениями, облаком и SIM. Плюс крайний метод — физическое снятие чипа. Разберём.

## Что покрывает этот модуль

- **WhatsApp** — переписка и вложения.
- **Signal/Telegram** — защищённые мессенджеры.
- **Облачная синхронизация** — что ушло в облако.
- **SIM/USIM** — данные на карте.
- **Chip-off/JTAG** — физическое снятие.

## Рекомендуемый порядок изучения

1. `mobile-whatsapp` — самый частый.
2. `mobile-signal-telegram` — защищённые.
3. `mobile-cloud-sync` — облако.
4. `mobile-sim-usim` — SIM.
5. `mobile-chipoff-jtag` — физический уровень.

## Что вы будете уметь

- Разбирать базы мессенджеров.
- Понимать пределы защиты Signal.
- Работать с облачной синхронизацией.
- Извлекать данные SIM.
- Оценивать chip-off.

## Артефакт → вопрос | Инструмент

| Артефакт | Инструмент |
|----------|-----------|
| `msgstore.db` | `sqlite3` |
| Signal DB | парсер |
| облако | консоль/токен |
| SIM | ридер/`pySim` |
| NAND/eMMC | chip-off оборудование |

## Куда дальше

Открывай урок **«WhatsApp-форензика»** — начнём с переписки.
