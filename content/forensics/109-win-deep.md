---
id: forensics-win-deep
title: "Модуль: глубокие артефакты Windows"
category: forensics
parent: forensics-win-misc
difficulty: hard
order: 2
tags: [windows, prefetch, shimcache, amcache, jumplists, srum, ads, roadmap]
prerequisites: [forensics-win-misc]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response (Windows)"
  - "Threat Hunting"
estimated_minutes: 14
summary: "Этап ветки «Артефакты Windows»: артефакты выполнения (Prefetch/ShimCache/AmCache), артефакты пользовательской активности (JumpLists/SRUM/BAM) и Alternate Data Streams."
---

Этот модуль углубляет ветку артефактов Windows. Базовые уроки дали реестр, логи и «следы выполнения»; здесь мы собираем **тонкие артефакты**, которые прямо доказывают запуск программы, работу с файлами и переключение пользователей: Prefetch, ShimCache, AmCache, JumpLists, SRUM, BAM/DAM, а также Alternate Data Streams как канал сокрытия.

## Что покрывает этот модуль

- **Артефакты выполнения** — Prefetch (что и когда запускалось), ShimCache/AppCompatCache (следы запуска, в т. ч. удалённых файлов), AmCache (хеши и пути).
- **Артефакты активности пользователя** — JumpLists (недавние файлы/задачи), SRUM (сетевая и процессная активность по приложениям), BAM/DAM (доступ к исполняемым файлам).
- **Alternate Data Streams** — потоки NTFS как канал сокрытия данных и признак заражения.

## Рекомендуемый порядок изучения

1. `forensics-prefetch-shimcache` — сначала «что запускалось»: это базовый вопрос почти любой задачи.
2. `forensics-jumplists-srum` — затем «что открывал пользователь» и сколько тратил сети.
3. `forensics-ads` — наконец, скрытые потоки: где малварь и флаги прячут данные.

## Что вы будете уметь

- Читать Prefetch (`PECmd`), ShimCache и AmCache и строить хронологию запусков.
- Разбирать JumpLists и SRUM-базу (`SRUMDump`) для доказательства активности.
- Находить и извлекать Alternate Data Streams через sleuthkit и ntfs-3g.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| Prefetch | что запускалось и сколько раз | `PECmd`, `prefetch.py` |
| ShimCache | какие EXE «видел» загрузчик | `AppCompatCacheParser` |
| AmCache | пути и хеши программ | `AmcacheParser` |
| JumpLists | недавние документы/задачи | `JLECmd` |
| SRUM | трафик и время CPU по приложениям | `SrumECmd` |
| ADS | скрытые потоки данных | `fls`, `icat`, `ntfs-3g` |

## Квиз

```quiz
- question: "Какой артефакт Windows показывает, какие программы запускались и сколько раз?"
  options:
    - "SRUM"
    - "Prefetch"
    - "JumpLists"
    - "BAM"
  answer: 1
  explanation: "Prefetch хранит счётчик запусков и время последнего запуска программы."
- question: "Зачем аналитику ShimCache, если есть Prefetch?"
  options:
    - "Он показывает сетевой трафик"
    - "Он хранит следы исполняемых файлов, включая уже удалённые и не запускавшиеся"
    - "Он заменяет реестр"
    - "Он расшифровывает BitLocker"
  answer: 1
  explanation: "ShimCache/AppCompatCache фиксирует EXE, которые «видел» загрузчик, даже если файл удалён."
- question: "Чем Alternate Data Stream опасен с точки зрения форензики?"
  options:
    - "Он шифрует весь диск"
    - "Он позволяет спрятать данные в отдельном потоке файла, невидимом в обычном листинге"
    - "Он удаляет файлы"
    - "Он меняет MBR"
  answer: 1
  explanation: "ADS — дополнительный поток NTFS; без fls | grep ':' или dir /r его не видно."
```

## Где пригодится

- **CTF:** задачи «что запускалось/открывалось» на Windows-образах.
- **IR:** доказательство выполнения малвари и работы с файлами.
- **Threat Hunting:** поиск аномальных запусков и скрытых потоков.
- **Судебная экспертиза:** реконструкция действий пользователя по времени.
