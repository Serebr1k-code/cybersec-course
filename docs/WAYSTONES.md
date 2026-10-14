# Вейстоуны (waystone gates)

> Спецификация узла-гейта в дереве обучения: вейстоун запирает ветку, пока
> ученик не решит N объединяющих задач из этой ветки.
> Область: контент (front-matter урока) + фронтенд (`utils/waystone.js`,
> `TreeGraph.vue`, `LessonNode.vue`).

## Зачем

Дерево растёт, и по ветке можно проскочить поверхностно. **Вейстоун** ставит
контрольную точку: дальше не пустит, пока не решены несколько **капстоун-задач**,
каждая из которых тренирует свой навык ветки (например: recon → инъекция →
привилегии). Это превращает пассивное чтение в подтверждённый навык.

## Как это выглядит

```
урок A ── урок B ── [🔒 ВЕЙСТОУН 2/5] ── урок C ── урок D ── [🔒 ВЕЙСТОУН 5/5]
                          │                                     │
                   заперто, пока не решены               заперто, пока не решены
                   задачи ветки (2 из 5)                  задачи ветки
```

* Вейстоун — это **обычный урок** с флагом `waystone: true`; он виден в дереве и
  на нём рисуется бейдж «🔒 N/M» (заперт) или «🔓 N/M» (открыт).
* Пока задачи не решены, **всё поддерево вейстоуна скрыто** — это жёсткий замок,
  а не туман войны: ни «Развернуть всё», ни ручное раскрытие его не обходят.
* Как только решены **все** задачи из `waystone_tasks`, ветка открывается сама.

## Front-matter

```yaml
---
id: network-module-analysis
title: "Анализ трафика глубоко: NetFlow, IDS и инфраструктура на пути"
category: network
parent: network-pcap-analysis
difficulty: easy
order: 1
waystone: true
waystone_tasks: [network-tcpdump, network-wireshark, network-zeek, network-pcap-analysis, network-traffic-analysis-ctf]
tags: [network, netflow, ipfix, ids]
---
```

| Поле | Смысл |
|---|---|
| `waystone` | `true` — узел является гейтом (по умолчанию `false`). |
| `waystone_tasks` | Список **id уроков**, которые надо пройти (`completed`), чтобы открыть ветку. N = длина списка. |

**Правила корректного вейстоуна** (проверяются `tools/waystone-gen.py check`):

1. `waystone_tasks` — непустой; иначе гейт считается **инертным** и НЕ запирает
   ветку (страховка от «намертво запертой» ветки из-за недописанного гейта).
2. Каждый id из `waystone_tasks` **существует** в контенте.
3. Ни один id задачи **не лежит внутри** запираемого поддерева вейстоуна —
   иначе задача недостижима (скрыта самим гейтом) и ветка запирается навсегда.
   Задачи должны быть **до** вейстоуна (предки/ранние соседи по ветке).

## Размещение (правило пользователя)

* Вейстоун стоит **каждые 2–3 урока** вдоль ветки.
* И **один — в самом конце** каждой ветки.

## Капстоун-задачи

Задача — это **интерактивная лаба** (`lab:` + `content/labs/<id>.json`), которая
объединяет несколько навыков ветки. «Решено» для целей гейта = урок отмечен
пройденным (`progress.completed`, тот же учёт, что у зелёной заливки дерева).
Обычно это отдельные уроки-капстоуны, размещённые ДО вейстоуна.

## Как автору добавить вейстоун

```bash
# 1. Скелет урока-вейстоуна (файл content/<cat>/<id>.md)
python3 tools/waystone-gen.py new \
  --id network-waystone-analysis \
  --category network \
  --parent network-pcap-analysis \
  --title "Вейстоун: аналитик трафика" \
  --tasks network-tcpdump,network-wireshark,network-zeek,network-pcap-analysis,network-traffic-analysis-ctf

# 2. Проверить ВСЕ вейстоуны дерева (ссылки, недостижимые задачи, дубли)
python3 tools/waystone-gen.py check

# 3. (опционально) список вейстоунов и их состояние
python3 tools/waystone-gen.py list
```

## Реализация

| Слой | Файл | Роль |
|---|---|---|
| Парсер | `internal/content/content.go` (`getBool`, `parseLesson`) | читает `waystone`/`waystone_tasks` из front-matter |
| Модель/API | `internal/model/model.go` (`LessonMeta`, `TreeNode`) | поля `waystone`, `waystone_tasks` в `/api/tree` |
| Логика | `frontend/src/utils/waystone.js` | `isGateLocked`, `gatedIds`, `gateSolved`… |
| Туман | `frontend/src/components/TreeGraph.vue` (`visibleSet`) | вычитает `gatedIds` из видимого набора |
| Индикатор | `frontend/src/components/LessonNode.vue` (`.gate`) | бейдж «🔒 N/M» / «🔓 N/M» |
| Тесты | `waystone.spec.js`, `TreeGraph.spec.js`, `LessonNode.spec.js` | заперто-до-решения, открытие, индикатор |

## Пилот

`content/network/network-module-analysis.md` — первый реальный вейстоун: он
запирает подмодуль «Анализ трафика глубоко» (NetFlow/IDS/WAF/сканирование) до
решения 5 задач по анализу трафика.
