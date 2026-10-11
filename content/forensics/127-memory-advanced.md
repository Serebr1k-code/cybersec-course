---
id: forensics-memory-advanced
title: "Модуль: продвинутая форензика памяти"
category: forensics
parent: forensics-volatility-deep
difficulty: expert
order: 3
tags: [memory, volatility3, malware, symbols, isf, roadmap]
prerequisites: [forensics-volatility-deep]
useful_for:
  - "CTF Forensics категория"
  - "Malware Analysis"
  - "Incident Response"
estimated_minutes: 14
summary: "Этап ветки «Память»: охота на малварь в дампе (malfind, yarascan, pool tags) и работа с символами Volatility3 (ISF, kernel debug)."
---

Этот модуль углубляет ветку анализа памяти. Базовые уроки дали плагины Volatility3 и извлечение ключей; здесь мы добавляем **охоту на вредоносный код** в дампе и **работу с символами** — без правильного symbol table продвинутые плагины не запустятся.

## Что покрывает этот модуль

- **Охота на малварь в памяти** — `malfind`, `yarascan`, поиск по pool tags, перехваты (hooks), аномальные VAD-регионы.
- **Символы Volatility3** — ISF (Intermediate Symbol Format), генерация профилей для Linux/macOS/Windows, kernel debug.

## Рекомендуемый порядок изучения

1. `forensics-memory-symbols` — сначала символы: без них Volatility не разбирает структуры ядра.
2. `forensics-memory-malware` — затем охота: malfind, yarascan, pool tags, hooks.

## Что вы будете уметь

- Готовить и подключать symbol tables/ISF для нужного ядра.
- Находить инжектированный код и подозрительные регионы в дампе.
- Сканировать память YARA-правилами и анализировать перехваты.

## Плагин → задача

| Плагин | Задача |
|--------|--------|
| `windows.malfind` | найти инжектированный/исполняемый код в аномальных регионах |
| `yarascan` | просканировать память YARA-правилами |
| `windows.handles` / `pool tags` | найти объекты малвари |
| `banners` / `isfinfo` | проверить символы и версию ядра |

## Квиз

```quiz
- question: "Зачем Volatility3 нужны символы (ISF)?"
  options:
    - "для расшифровки диска"
    - "чтобы разбирать структуры ядра (процессы, объекты) по смещениям"
    - "для ускорения сканирования"
    - "для сжатия дампа"
  answer: 1
  explanation: "ISF даёт смещения полей структур ядра — без них плагины не смогут интерпретировать память."
- question: "Что делает плагин `windows.malfind`?"
  options:
    - "собирает PCAP"
    - "ищет инжектированный/исполняемый код в аномальных регионах памяти"
    - "монтирует диск"
    - "читает реестр"
  answer: 1
  explanation: "malfind ищет регионы с правами исполнения и характерными заголовками инжектированного кода."
- question: "Зачем сканировать дамп памяти YARA-правилами?"
  options:
    - "чтобы найти сигнатуры известной малвари прямо в памяти"
    - "чтобы расшифровать TLS"
    - "чтобы собрать RAID"
    - "чтобы восстановить удалённые файлы"
  answer: 0
  explanation: "yarascan применяет YARA-правила к памяти, находя известные семейства даже без файла на диске."
```

## Где пригодится

- **CTF:** задачи с дампами памяти и малварью.
- **Malware Analysis:** анализ fileless-угроз.
- **IR:** охота на инжектированный код в скомпрометированной системе.
- **Threat Hunting:** проактивный поиск по памяти.
