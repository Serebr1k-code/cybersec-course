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

Дубли id уроков `check` показывает предупреждением (полный аудит дублей —
`python3 tools/audit-content.py`), чтобы команда оставалась про вейстоуны.

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

## Раскатка (вейстоуны по веткам)

Первый прогон покрывает 8 категорий / 11 гейтов (все `N=5`, все задачи —
ранние лабы той же ветки, `python3 tools/waystone-gen.py check` → 0 ошибок):

| Категория | Гейт (id) | Запирает ветку | Задачи (id) |
|---|---|---|---|
| network | `network-module-analysis` (пилот) | Анализ трафика глубоко (NetFlow/IDS/WAF) | network-tcpdump, network-wireshark, network-zeek, network-pcap-analysis, network-traffic-analysis-ctf |
| network | `network-module-wireless` | Беспроводные/телеком/RF глубоко | network-tcpip, network-arp, network-frag-attacks, network-mitm, network-arp-deep |
| network | `network-module-telecom` (вложен) | Сотовая связь и сигнализация | network-tcpip, network-arp, network-mitm, network-arp-deep, network-wireless-80211 |
| web | `web-sqli` | Глубокие SQLi-подветки | web-recon-fuzzing, web-recon-surface, web-recon-attack-entry, web-tls-certs, web-cookies-sessions |
| pwn | `pwn-rop` | ROP и всё глубже (heap/kernel) | pwn-buffer-overflow, pwn-pwntools, pwn-calling-conventions, pwn-methodology, pwn-gdb-pwndbg |
| forensics | `forensics-windows-artifacts` | Артефакты Windows и глубже | forensics-file-magic, forensics-carving, forensics-archives, forensics-filesystems, forensics-memory |
| forensics | `forensics-win-logs` (вложен) | Журналы, события, таймлайн | forensics-carving, forensics-archives, forensics-filesystems, forensics-memory, forensics-disk-images |
| crypto | `crypto-rsa-attacks` | Продвинутые атаки на RSA | crypto-encodings, crypto-classical, crypto-xor-otp, crypto-number-theory, crypto-rsa-basics |
| stego | `stego-appended` | Дописанные данные и скрытые контейнеры | stego-media-basics, stego-audio, stego-lsb, stego-image-tools, stego-container-formats |
| reversing | `reversing-decompiler` | Декомпилятор и глубокий статический анализ | reversing-asm, reversing-file-formats, reversing-architectures, reversing-static-analysis, reversing-analysis-methodology |
| osint | `osint-search-identifiers` | Идентификаторы и DNS-ветка | osint-collection, osint-automation, osint-threat-intel, osint-search-operators, osint-whois-asn |

**Правило размещения (пользователя):** вейстоун каждые 2–3 урока вдоль ветки и
один в самом конце. Первый прогон ставит гейт на входе в глубокую подветку
(+ вложенный гейт для network и forensics); сплошная нарезка «каждые 2–3 урока»
по всем 12 категориям — следующий шаг (генератор `tools/waystone-gen.py new`).

**Проверка в браузере (:8095):** ветка `web-sqli` показывает `🔒 1/5`; после
решения всех 5 задач бейдж становится `🔓 5/5`, а скрытые ранее дочерние уроки
(`web-sqli-dbms*`) появляются даже под «Развернуть всё» — до этого их не было в DOM.
