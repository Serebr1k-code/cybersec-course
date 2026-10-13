---
id: web-tool-gobuster-feroxbuster
title: "gobuster и feroxbuster: полный практический справочник"
category: web
parent: web-tools-fuzz
difficulty: medium
order: 2
tags: [gobuster, feroxbuster, fuzzing, discovery, dns, vhost, recursion, tooling]
prerequisites: [web-tooling, web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 42
summary: "Все режимы и флаги gobuster (dir/dns/vhost/fuzz) и feroxbuster (рекурсия, авто-фильтры, extract-links) с рецептами."
lab:
  kind: shell
  title: "Практика: feroxbuster (рекурсия)"
  toolset: [core, feroxbuster, curl]
  workdir: /home/student/task
  files: [task.md, raft-medium-directories.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - `gobuster dir` плоский — вложенные каталоги пропустит.
    - Запусти рекурсивный скан: `feroxbuster -u https://shop.acme-lab.test -w raft-medium-directories.txt -x php,html -d 3 --smart -q`.
    - В выводе есть `/api/internal` (200) — вложенная ветка.
    - Запроси её: `curl -s https://shop.acme-lab.test/api/internal | grep 'nto{' > found.txt`, затем `check`.
---

## Задача

В прошлом уроке `ffuf` нашёл на `https://shop.acme-lab.test` каталог `/api`. Но дерево директорий глубже: внутри могут быть `/api/v1/`, `/api/internal/`, а рядом — забытый `/backup/`. `ffuf` перебирает **один уровень за раз**, а `gobuster dir` и вовсе не углубляется. Нужен инструмент, который сам заходит в найденные каталоги.

Здесь и помогают **gobuster** (специализированные режимы: `dir`, `dns`, `vhost`, `fuzz`) и **feroxbuster** (рекурсивный обход с авто-фильтрацией).

## Данные, с которыми работаем

Цель `https://shop.acme-lab.test`, словарь `raft-medium-directories.txt`. Отдельно нужны поддомены (`subdomains.txt`) и виртуальные хосты.

## Пробуем в лоб: `gobuster dir`

```bash
$ gobuster dir -u https://shop.acme-lab.test -w raft-medium-directories.txt -x php,html -q
/admin                (Status: 301) [Size: 178]
/api                  (Status: 200) [Size: 1024]
/assets               (Status: 301) [Size: 178]
```

`/admin`, `/api`, `/assets` найдены. Но `gobuster dir` — **плоский**: он проверил только имена из словаря в корне. `/api/v1/` или `/admin/backup/` он не найдёт, пока ты не запустишь его вручную внутри каждого каталога. Это утомительно и легко пропустить ветку.

## Приём 1: рекурсия — `feroxbuster`

`feroxbuster` устроен иначе: найдя каталог, он **сам** запускает перебор внутри него. Флаг `-d 3` ограничивает глубину (по умолчанию 4), `-x` задаёт расширения.

```bash
$ feroxbuster -u https://shop.acme-lab.test -w raft-medium-directories.txt -x php,html -d 3 --smart -q
200      GET  1024l  4096w  51200c https://shop.acme-lab.test/api
200      GET   120l   300w   4096c https://shop.acme-lab.test/api/v1
200      GET    40l   120w   2048c https://shop.acme-lab.test/api/internal
301      GET     7l    11w    178c https://shop.acme-lab.test/admin
403      GET     9l    15w    512c https://shop.acme-lab.test/admin/backup
```

Вот оно: `/api/v1`, `/api/internal`, `/admin/backup`. Без рекурсии мы бы их не увидели. Флаг `--smart` включает умный режим: авто-фильтрацию wildcard, пополнение словаря словами из ответов и запрос бэкапов.

> **Wildcard-ответ** — когда сервер отдаёт `200` на любой путь. `feroxbuster` по умолчанию сам вычисляет такой отпечаток и отсеивает его (`-D`/`--dont-filter` отключает это).

## Приём 2: поддомены и виртуальные хосты

`gobuster dns` перебирает поддомены через DNS-резолвер, `gobuster vhost` — виртуальные хосты по заголовку `Host` (сервер на одном IP может отдавать разные сайты).

```bash
$ gobuster dns -d acme-lab.test -w subdomains.txt -r 1.1.1.1 --check-cname -q
api.acme-lab.test     Found
staging.acme-lab.test Found
```

```bash
$ gobuster vhost -u https://10.0.0.5 -w vhosts.txt --append-domain --exclude-length 5211 -q
dev.acme-lab.test     Status: 200 [Size: 3120]
```

`--append-domain` дописывает домен из URL к словам, а `--exclude-length` отсеивает дефолтный сайт (его размер снимаем заранее `curl`-ом).

## Приём 3: произвольная подстановка — `gobuster fuzz`

Режим `fuzz` подставляет `FUZZ` не только в путь, но и в заголовки/тело:

```bash
$ gobuster fuzz -u 'https://shop.acme-lab.test/api?key=FUZZ' -w keys.txt -b 404 -q
key=2f8a...  (Status: 200) [Size: 4096]
```

`-b 404` исключает коды (аналог фильтра). Так же проверяются скрытые заголовки и параметры.

## Полный прогон от начала до конца

1. `gobuster dir -u ... -w raft.txt -x php,html` → плоские находки (`/admin`, `/api`).
2. `feroxbuster -u ... -w raft.txt -d 3 --smart` → вся ветка (`/api/v1`, `/api/internal`, `/admin/backup`).
3. `gobuster dns -d acme-lab.test -w subs.txt` → поддомены.
4. `gobuster vhost -u https://10.0.0.5 -w vhosts.txt --append-domain` → виртуальные хосты.
5. `gobuster fuzz -u '...?key=FUZZ'` → скрытые параметры.

Найденное (`/api/internal`, `staging`) — новые цели для ручной проверки.

## Если не сработало

- **Слишком много вывода.** Добавь `-q`, `--no-progress`, фильтры `-C`/`-S` (feroxbuster) или `--exclude-length` (gobuster).
- **Рекурсия улетела.** Ограничь `-d 3` и `--scan-limit 2`, добавь `--rate-limit 100`.
- **Сервер начал банить.** `--auto-tune` (feroxbuster) сам снизит скорость; у gobuster — `-t 20` и `-d 1500ms` (задержка).
- **Нужен JSON.** `feroxbuster --json -o ferox.json`; у gobuster вывод простой, парси `-o`.
- **Нужны cookie.** `feroxbuster -b 'session=abc'`, `gobuster dir -c 'session=abc'`.

## Шпаргалка: флаги

**gobuster dir** (основное):

| Флаг | Что делает |
|------|-----------|
| `-u` / `-w` | URL / словарь |
| `-x php,html` | расширения |
| `-s 200,301,403` / `-b 404` | какие коды показывать / исключать |
| `-t` / `-d 1500ms` | потоки / задержка |
| `-k` / `--proxy` | без TLS-проверки / прокси |
| `--db` | искать бэкапы найденных файлов |
| `-q -o dirs.txt` | тихо + в файл |

**gobuster dns / vhost / fuzz:** `dns -d DOMAIN -w LIST -r 8.8.8.8 --check-cname`; `vhost -u URL -w LIST --append-domain --exclude-length N`; `fuzz -u 'URL?FUZZ=x' -w LIST -b 404`.

**feroxbuster** (основное):

| Флаг | Что делает |
|------|-----------|
| `-u` / `-w` | URL / словарь |
| `-x` / `-d` | расширения / глубина рекурсии |
| `-t` / `--rate-limit` | потоки / лимит rps |
| `-C 404` / `-S 1234` / `-W` / `-N` | фильтр кодов / размеров / слов / строк |
| `--smart` / `--thorough` | авто-режим / максимум сбора |
| `-B` / `-g` / `-E` | сбор бэкапов / слов / расширений |
| `--dont-extract-links` | не тянуть ссылки из ответов |
| `--json -o FILE` | JSON-вывод |
| `--burp` / `-P` | весь трафик / replay в Burp |

Выбор: **рекурсия и умная фильтрация → feroxbuster; конкретный режим dns/vhost или простая надёжность → gobuster; тонкие фильтры и автоматизация → ffuf**.

## Почему «плоский» перебор теряет цели

Разница между gobuster и feroxbuster — не в скорости и не в количестве флагов, а в модели обхода. Понять её — значит понять, где именно теряются находки.

Представь дерево каталогов как структуру. `gobuster dir` проверяет имена из словаря **только в том каталоге, который ты указал в URL**. Если словарь содержит `api`, он найдёт `/api`. Но чтобы найти `/api/v1`, ему нужно снова запуститься с `-u .../api/` и словарём, в котором есть `v1`. А для `/api/internal` — снова, уже внутри `/api/`. Каждый уровень — отдельный запуск, и ты должен вручную заметить, что каталог найден, и решить, стоит ли в него заходить. На глубоком дереве это превращается в десятки запусков, и любой пропущенный каталог обрывает целую ветку.

`feroxbuster` меняет модель: найдя каталог, он добавляет его в очередь и продолжает перебор внутри. Глубину задаёт `-d`, поэтому рекурсия не бесконечна. Это принципиально другой охват: ты запускаешь одну команду и получаешь весь срез дерева до заданной глубины. Именно так находятся `/api/internal` и `/admin/backup` — вложенные цели, до которых плоский скан просто не доходит.

Есть у рекурсии и цена — шум и риск. Глубокий обход на живом сайте может сгенерировать тысячи запросов и словить бан. Поэтому у feroxbuster есть авто-тюнинг: он следит за частотой ошибок и снижает скорость. А wildcard-фильтрация решает другую проблему — когда сервер отвечает `200` на всё подряд (частая ловушка SPA), рекурсия без фильтра раздувается взрывным образом. feroxbuster по умолчанию снимает отпечаток такой страницы и отсеивает её.

Отсюда рабочее правило выбора. Если задача — «увидеть всё дерево целиком», бери feroxbuster. Если задача точечная — проверить конкретный набор имён или обойти один уровень, — gobuster проще и предсказуемее. А его режимы `dns`, `vhost` и `fuzz` вообще не про дерево: они про разные пространства имён — поддомены, заголовок Host и произвольные позиции. Смешивать эти задачи в одной команде не нужно.

И помни: рекурсия — это инструмент охвата, а не замены мышления. Прежде чем углубляться на три уровня, стоит понять структуру приложения: иногда один вложенный каталог важнее сотни плоских имён. Глубина сама по себе не цель — цель найти ветку, ведущую к данным или коду.

## Что мы теперь знаем

- `gobuster dir` — плоский: рекурсию делаешь руками.
- `feroxbuster` рекурсирует сам и по умолчанию фильтрует wildcard.
- `gobuster dns` — поддомены, `gobuster vhost` — виртуальные хосты, `gobuster fuzz` — любая позиция.
- `--smart`/`--thorough` включают сбор слов, расширений и бэкапов.
- Всё это — разведка; находки надо проверять руками.

## На что смотреть дальше

- **Различай «мягкий 403» и реальный запрет.** Иногда `/admin/backup` обходится `/.`, `//` или `X-Original-URL`.
- **Vhost по IP.** Если DNS не показывает хостов, `gobuster vhost -u https://<IP>` часто находит сайты, которые резолвятся только локально.
- **Записывай словари.** Не гоняй один список по одному `host:port` дважды.
- **Следи за `--auto-tune`.** Всплеск ошибок — сигнал бана; не игнорируй его.
- **Дальше — параметры.** Найденные эндпоинты (`/api/internal`) подавай в `ffuf`/`arjun` на перебор параметров.

## Квиз

Проверь себя.

```quiz
- question: "Чем gobuster dir принципиально отличается от feroxbuster по рекурсии?"
  options:
    - "gobuster рекурсирует глубже"
    - "gobuster плоский — вложенные каталоги нужно запускать вручную"
    - "feroxbuster не умеет перебирать пути"
    - "Разницы нет"
  answer: 1
  explanation: "feroxbuster сам углубляется в найденные каталоги; gobuster dir — нет."
- question: "Какой режим gobuster перебирает поддомены через DNS?"
  options:
    - "gobuster dir"
    - "gobuster dns"
    - "gobuster vhost"
    - "gobuster fuzz"
  answer: 1
  explanation: "gobuster dns -d DOMAIN -w LIST использует резолвер и умеет показывать CNAME."
- question: "Что делает флаг feroxbuster --smart?"
  options:
    - "Только ускоряет скан"
    - "Включает авто-фильтр wildcard, сбор слов и бэкапов"
    - "Отключает рекурсию"
    - "Меняет User-Agent"
  answer: 1
  explanation: "--smart = --auto-tune + --collect-words + --collect-backups."
- question: "Зачем нужен режим gobuster vhost?"
  options:
    - "Чтобы перебирать пароли"
    - "Чтобы найти сайты, отдаваемые сервером для чужого заголовка Host"
    - "Чтобы включить TLS"
    - "Чтобы скачать файл"
  answer: 1
  explanation: "Один IP может отдавать разные сайты в зависимости от Host — это виртуальные хосты."
- question: "Как feroxbuster по умолчанию обрабатывает wildcard-ответы?"
  options:
    - "Игнорирует их полностью"
    - "Автоматически вычисляет отпечаток и фильтрует (отключается -D)"
    - "Считает их находками"
    - "Прекращает скан"
  answer: 1
  explanation: "Авто-фильтр wildcard включён по умолчанию; -D/--dont-filter его выключает."
```

## Куда дальше

Дальше (`web-tool-wfuzz-burp-intruder`) мы разберём `wfuzz` с его движком payload и типы атак Burp Intruder. А пока главное запомни: для глубокого дерева каталогов бери `feroxbuster` — он рекурсирует сам, а `gobuster` хорош своими точечными режимами `dns` и `vhost`.

## Где пригодится

- **CTF (Web):** быстрый рекурсивный поиск скрытых каталогов и поддоменов.
- **Bug bounty:** расширение поверхности через vhost и вложенные API-версии.
- **Пентест:** стандартный content discovery; JSON feroxbuster идёт в отчёт.
- **Работа (AppSec):** регулярный скан после релизов на новые забытые пути.
