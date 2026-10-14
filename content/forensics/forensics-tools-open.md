---
id: forensics-tools-open
title: "Модуль: открытые инструменты — платформы и live-сбор"
category: forensics
parent: forensics-tooling
difficulty: medium
order: 2
tags: [forensics, tools, plaso, velociraptor, osquery, grr, hindsight, roadmap]
prerequisites: [forensics-tooling]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Работа с инструментами"
estimated_minutes: 13
summary: "Этап ветки «инструменты»: открытые платформы для таймлайна, live-сбора и охоты — plaso, Velociraptor, osquery, GRR, Hindsight."
---

Коммерческие платформы дороги. Открытые инструменты не хуже в своих нишах: одни строят
таймлайны, другие собирают данные с тысяч хостов, третьи охотятся за угрозами. Этот
модуль — про них.

## Что покрывает этот модуль

- **plaso** — построение супертаймлайна.
- **Velociraptor** — live-сбор и охота на флоте.
- **osquery** — SQL-запросы к хосту.
- **GRR** — удалённый live-осмотр.
- **Hindsight** — разбор истории браузеров.

## Рекомендуемый порядок изучения

1. `tool-plaso-deep` — таймлайн из артефактов.
2. `tool-velociraptor` — охота на множестве хостов.
3. `tool-osquery` — SQL к системе.
4. `tool-grr` — удалённый сбор.
5. `tool-hindsight` — браузерные артефакты.

## Что вы будете уметь

- Строить супертаймлайн (plaso).
- Собирать данные с флота (Velociraptor).
- Делать live-запросы (osquery).
- Проводить удалённый осмотр (GRR).
- Разбирать браузеры (Hindsight).

## Артефакт → вопрос

| Задача | Инструмент |
|--------|-----------|
| таймлайн | plaso/psort |
| охота на флоте | Velociraptor |
| live-запросы | osquery |
| удалённый сбор | GRR |
| история браузера | Hindsight |

## Куда дальше

Открывай урок **«plaso: супертаймлайн»** — начнём с таймлайна.
