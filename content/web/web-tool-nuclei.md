---
id: web-tool-nuclei
title: "nuclei: полный практический справочник"
category: web
parent: web-tools-recon
difficulty: medium
order: 2
tags: [nuclei, templates, scanner, cve, dast, fuzzing, oob, tooling]
prerequisites: [web-tooling, web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 50
summary: "Все флаги nuclei: цели, фильтрация шаблонов, rate-limit, вывод, свой YAML-шаблон, DAST-режим и Interactsh OOB."
---

## Задача

Ты нашёл живые хосты и эндпоинты. Теперь нужно проверить их на **известные** уязвимости: CVE, мисконфиги, дефолтные креды, takeover. Вручную это сотни проверок. **nuclei** — шаблонный сканер: он гоняет готовые YAML-шаблоны (их тысячи) и репортит только совпадения. Запускать его стоит **рано** — он быстро закрывает класс «известные баги».

Пройдём по одному хосту.

## Данные, с которыми работаем

Цель — `https://app.example`. Сначала обновим шаблоны (они часто меняются) и запустим базовый скан:

```bash
$ nuclei -update-templates
$ nuclei -u https://app.example -severity critical,high,medium -silent
[CVE-2021-44228] [http] [critical] https://app.example/api/log
[laravel-debug-enabled] [http] [medium] https://app.example/_ignition/health-check
[nginx-version] [http] [info] https://app.example
```

Флаг `-severity` оставляет только нужные уровни (чтобы не тонуть в `info`), `-silent` печатает только находки. Мы сразу получили Log4Shell-точку и включённый debug Laravel.

## Шаг 1: фильтрация шаблонов — ключевой навык

Главная ошибка новичка — **грепать библиотеку шаблонов по имени продукта**. CVE-шаблоны названы по CVE-id (`CVE-2025-1234.yaml`), поэтому поиск по «jenkins» их пропустит. Фильтруй правильно:

| Флаг | Что делает |
|------|-----------|
| `-severity critical,high` | по уровню |
| `-tags cve,rce` | по тегам шаблона |
| `-t http/cves/2024/` | по пути/каталогу |
| `-t cves/` | только CVE |
| `-etags dos` | исключить теги (например, DoS) |
| `-include-templates` | добавить отдельные файлы |
| `-exclude-templates` | исключить отдельные файлы |

```bash
$ nuclei -u https://app.example -tags cve,rce -severity critical,high -silent
```

## Шаг 2: цели, rate-limit, заголовки

nuclei принимает одну цель (`-u`), список (`-l`), URL из stdin. Важные флаги для управляемой нагрузки:

| Флаг | Что делает |
|------|-----------|
| `-u` / `-l` | цель / список |
| `-rate-limit N` | запросов в секунду |
| `-c N` | параллельных шаблонов |
| `-timeout N` | таймаут на запрос |
| `-H 'Cookie: x'` | добавить заголовок (авторизация) |
| `-V key=value` | переменная для шаблонов |
| `-j` / `-o file` | JSON / сохранить |
| `-stats` | прогресс |

```bash
$ nuclei -l urls.txt -rate-limit 50 -c 25 -H 'Authorization: Bearer eyJ...' -j -o n.json
```

`-rate-limit` защищает цель от перегрузки и снижает шум в логах.

## Шаг 3: форматы вывода

| Флаг | Формат |
|------|--------|
| `-silent` | только находки |
| `-j` | JSON-строки (для парсинга) |
| `-o file` | в файл |
| `-me file` | отдельный файл для каждого матча |
| `-stats` | статистика скана |

JSON (`-j`) — то, что нужно пайплайну: каждая строка — объект с `template-id`, `info.severity`, `matched-at`.

## Шаг 4: свой шаблон

nuclei расширяется YAML-шаблонами. Простейший шаблон проверяет наличие файла:

```yaml
id: my-secret-file
info:
  name: Exposed .env
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
    matchers:
      - type: word
        words:
          - "APP_KEY"
          - "DB_PASSWORD"
        condition: and
```

Ключевые части: `id`, `info` (метаданные), `http` (запросы), `path` (с `{{BaseURL}}`), `matchers` (что считать находкой). Условие `and` требует оба слова. Запуск: `nuclei -u https://app.example -t my-secret-file.yaml`.

## Шаг 5: DAST и OOB через Interactsh

**DAST-режим** (`-dast`) включает шаблоны, которым нужны параметры для фаззинга, — фактически встроенный фаззер. **Interactsh** — сервис для out-of-band проверок: шаблон заставляет цель обратиться к внешнему хосту, и если обращение пришло — уязвимость подтверждена (это ловит blind-SSRF, blind-RCE, Log4Shell).

```bash
$ nuclei -u https://app.example -dast -silent
$ nuclei -u https://app.example -tags oob -interactsh-server oast.pro -silent
```

## Полный прогон от начала до конца

1. `nuclei -update-templates` — свежие проверки.
2. `nuclei -u https://app.example -severity critical,high` → Log4Shell + debug.
3. `nuclei -tags cve,rce -silent` → только CVE/RCE.
4. `nuclei -dast -silent` → параметрный фаззинг.
5. `nuclei -j -o n.json` → машинный вывод для отчёта.

## Частые ошибки

- **Грепать шаблоны по продукту.** CVE-шаблоны названы по CVE-id — фильтруй `-tags`/`-severity`.
- **Слишком широкий скан без лимитов.** `-rate-limit` и `-c` обязательны на боевых хостах.
- **Игнорировать обновление шаблонов.** Без `-update-templates` пропустишь свежие CVE.
- **Доверять находке без проверки.** Подтверди результат вручную через `curl`.
- **Забыть про авторизацию.** Внутри аккаунта баги другие — передавай `-H`.
- **Ложные срабатывания.** Некоторые шаблоны шумные; читай `matcher-name` в JSON.

## На что смотреть дальше

- **nuclei — ранний скан.** Он закрывает «известное», пока ты исследуешь «неизвестное».
- **Фильтруй по `-tags`/`-severity`, не по имени продукта.**
- **`-json` для пайплайна.** Парси `template-id` и `matched-at`.
- **Свой шаблон — 10 строк YAML.** Под конкретную проверку это быстрее, чем руками.
- **OOB через Interactsh ловит blind-баги.** Незаменимо для SSRF/RCE без вывода.
- **Только в scope и с лимитами.** Активный скан — нагрузка; согласуй окно.

## Квиз

Проверь себя.

```quiz
- question: "Почему нельзя искать CVE-шаблоны grep'ом по имени продукта?"
  options:
    - "grep медленный"
    - "CVE-шаблоны названы по CVE-id, поэтому поиск по продукту их пропустит"
    - "Шаблоны зашифрованы"
    - "Их нельзя фильтровать"
  answer: 1
  explanation: "Файлы вида CVE-2025-XXXX.yaml не содержат названия продукта в имени — фильтруй по -tags/-severity."
- question: "Что делает флаг -severity critical,high?"
  options:
    - "Ускоряет скан"
    - "Оставляет только шаблоны этих уровней"
    - "Включает OOB"
    - "Меняет формат вывода"
  answer: 1
  explanation: "Фильтрация по важности, чтобы не тонуть в info/low."
- question: "Для чего нужен Interactsh в nuclei?"
  options:
    - "Для скорости"
    - "Для out-of-band проверок: цель обращается к внешнему хосту, подтверждая blind-баг"
    - "Для краулинга"
    - "Для TLS"
  answer: 1
  explanation: "OOB ловит уязвимости без прямого вывода (blind SSRF/RCE, Log4Shell)."
- question: "Что задаёт флаг -rate-limit?"
  options:
    - "Число потоков"
    - "Запросов в секунду — защита цели от перегрузки"
    - "Таймаут"
    - "Формат вывода"
  answer: 1
  explanation: "Лимит скорости снижает нагрузку и шум в логах."
- question: "Что описывает YAML-шаблон nuclei?"
  options:
    - "Только имя"
    - "id, info, HTTP-запросы и matchers — что и как проверять"
    - "Список целей"
    - "Только severity"
  answer: 1
  explanation: "Шаблон задаёт запрос(ы) и условия совпадения (matchers), по которым фиксируется находка."
```

## Куда дальше

Следующий урок (`web-tool-ffuf`) разберёт фаззинг — как находить скрытые пути и параметры, которые nuclei и katana не видят. А пока главное запомни: `nuclei` быстро закрывает «известные» баги; фильтруй шаблоны по тегам и severity, а вывод бери в JSON.

## Где пригодится

- **CTF (Web):** быстрая проверка на известные CVE и мисконфиги.
- **Bug bounty:** автоматизация широкого охвата при разведке.
- **Пентест:** ранний скан по шаблонам перед ручной работой.
- **Работа (AppSec):** собственный шаблон под внутренние проверки.
