---
id: forensics-win-telemetry
title: "Модуль: телеметрия Windows и централизованные журналы"
category: forensics
parent: forensics-win-misc
difficulty: hard
order: 4
tags: [windows, defender, edr, sysmon, event-forwarding, rdp, windows-search, roadmap]
prerequisites: [forensics-win-misc]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response (Windows)"
  - "Threat Hunting"
estimated_minutes: 14
summary: "Этап ветки «Артефакты Windows»: телеметрия защиты (Defender/EDR), централизованный сбор журналов (WEF), следы удалённых сессий (RDP) и индексы поиска/активности (Windows Search, ActivitiesCache)."
---

Базовые уроки дали реестр и журналы событий. Но современная Windows генерирует ещё один слой улик — **телеметрию защиты и централизованные логи**: что увидел антивирус, что записал EDR, что ушло на сервер сбора, какие следы оставила удалённая сессия и что индексировал поиск. Этот модуль закрывает именно эти источники — их часто пропускают, хотя они дают самую прямую картину атаки.

## Что покрывает этот модуль

- **Defender и EDR** — журнал антивируса (`MPLog`, Event ID 1116/1117), карантин, обнаружения и действия защиты. Это ответ на вопрос «что система уже знала об угрозе».
- **Централизованные журналы (WEF)** — пересылка событий на коллектор (`ForwardedEvents`). Показывает, что ушло в SIEM и что могло быть утеряно локально.
- **RDP-следы** — события удалённых сессий, кэш `bitmap` (`bcache`), настройки `Terminal Server`. Позволяют восстановить, кто и как подключался.
- **Windows Search и ActivitiesCache** — индекс файлов (`Windows.edb`) и база активности пользователя (`ActivitiesCache.db`) как источники «что открывали и когда».

## Рекомендуемый порядок изучения

1. `forensics-defender-edr` — что защита видела и делала: детекты, карантин, EDR-телеметрия.
2. `forensics-wef` — как журналы уходят на сервер и что остаётся локально.
3. `forensics-rdp-forensics` — восстановление удалённых сессий и кэша экрана.
4. `forensics-windows-search` — индекс и таймлайн активности пользователя.

## Источник → вопрос

| Источник | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| MPLog / Defender EVTX | что нашёл антивирус | `MpCmdRun`, EvtxECmd |
| ForwardedEvents | что ушло в SIEM | `wevtutil`, EvtxECmd |
| TerminalServices logs | кто подключался по RDP | EvtxECmd, `RDPCache` |
| bcache*.bmc | что было на экране сессии | `bmc-tools`, `RDPCacheStitcher` |
| Windows.edb | какие файлы индексировались | `libesedb` |
| ActivitiesCache.db | что и когда открывал пользователь | `WxTCmd` |

## Что вы будете уметь

- Читать журнал Defender и восстанавливать историю детектов и карантина.
- Понимать разницу между локальными логами и пересланными событиями (WEF).
- Восстанавливать RDP-сессию: кто, когда, откуда, и что было на экране.
- Извлекать таймлайн активности из `ActivitiesCache.db` и индекс Windows Search.

## Квиз

```quiz
- question: "Что показывает журнал Microsoft Defender (Event ID 1116/1117)?"
  options:
    - "сетевой трафик"
    - "обнаружение угрозы (1116) и действие защиты (1117)"
    - "содержимое реестра"
    - "таблицу разделов"
  answer: 1
  explanation: "1116 — обнаружена угроза, 1117 — предпринято действие (удаление/карантин)."
- question: "Что такое Windows Event Forwarding (WEF)?"
  options:
    - "пересылка событий на центральный коллектор"
    - "сжатие журналов"
    - "очистка Event Log"
    - "шифрование журналов"
  answer: 0
  explanation: "WEF отправляет события с хостов на collector-сервер, где они попадают в ForwardedEvents."
- question: "Какой артефакт помогает увидеть, что было на экране RDP-сессии?"
  options:
    - "pagefile.sys"
    - "кэш bitmap (bcache*.bmc)"
    - "prefetch"
    - "USN journal"
  answer: 1
  explanation: "RDP кэширует фрагменты экрана в bcache*.bmc; их восстанавливают bmc-tools."
- question: "Какую базу SQLite использует Windows для таймлайна активности пользователя?"
  options:
    - "Windows.edb"
    - "ActivitiesCache.db"
    - "SRUM.dat"
    - "OBJECTS.DATA"
  answer: 1
  explanation: "ActivitiesCache.db хранит активности (запуски приложений, открытые документы)."
```

## Где пригодится

- **CTF:** флаг в карантине Defender, журнале RDP или базе активности.
- **IR:** понять, что защита знала и сделала, восстановить удалённые сессии.
- **Threat Hunting:** искать «пропавшие» события — то, что не дошло до коллектора.
- **Судебная экспертиза:** доказательство действий пользователя по индексу и таймлайну.
