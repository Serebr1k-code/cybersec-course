---
id: web-tool-curl
title: "curl: полный практический справочник"
category: web
parent: web-tools-cli
difficulty: easy
order: 1
tags: [curl, http, cli, tooling, api, requests, debugging]
prerequisites: [web-http-basics, web-tooling]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
  - "Работа с API и CI"
estimated_minutes: 45
summary: "Полный справочник по curl: все рабочие флаги, сессии, JSON-API, загрузка файлов, SSRF-пробы, отладка и разбор вывода — от первого запроса до готового PoC."
---

`curl` — это HTTP-клиент, который умеет буквально всё: любой метод, любой заголовок, любой байт тела, любую версию протокола, cookie-банк, прокси, TLS-трюки и точный разбор ответа. В веб-тестировании это **основной инструмент доказательства**: то, что вы воспроизвели одной командой `curl`, принимается как PoC в отчёте, в баг-баунти и в CTF.

Проблема большинства гайдов в том, что они показывают три флага (`-X`, `-H`, `-d`) и на этом заканчиваются. А потом в реальной задаче выясняется, что нужен cookie-jar, `--path-as-is`, `--resolve` или `-w` с форматом. Этот урок — **рабочий справочник**: сгруппированные по задачам флаги, копируемые команды и раздел «типичные сценарии», который подсказывает, что делать в любой ситуации.

## Шпаргалка: флаги, которые нужны в 90% задач

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-s` | тихий режим (без прогресса) | `curl -s https://t/` |
| `-o /dev/null -w '%{http_code}'` | только код ответа, без тела | `curl -so /dev/null -w '%{http_code}' https://t/` |
| `-i` / `-I` | заголовки+тело / только заголовки (HEAD) | `curl -si https://t/` |
| `-L` | следовать редиректам | `curl -sL https://t/` |
| `-k` | не проверять TLS-сертификат | `curl -sk https://t/` |
| `-X` | задать HTTP-метод | `curl -sX DELETE https://t/api/1` |
| `-H` | добавить/переопределить заголовок | `curl -s -H 'Content-Type: application/json' ...` |
| `-d` / `--data-raw` | тело запроса (POST) | `curl -s -d 'a=1&b=2' https://t/login` |
| `-F` | multipart-форма (файлы) | `curl -s -F 'file=@shell.php' https://t/up` |
| `-b` / `-c` | отправить cookie / сохранить cookie в банку | `curl -s -c jar.txt -b jar.txt https://t/` |
| `-u` | HTTP Basic-аутентификация | `curl -s -u admin:pass https://t/admin` |
| `-x` | через прокси (Burp) | `curl -s -x http://127.0.0.1:8080 -k https://t/` |
| `-v` | показать запрос и ответ целиком (отладка) | `curl -sv https://t/api 2>&1` |

## Когда curl, а когда другой инструмент

Не всё делается через curl. Прежде чем писать команду, выберите инструмент по задаче.

| Задача | Инструмент | Почему |
|--------|-----------|--------|
| Точное воспроизведение запроса / PoC | **curl** | Полный контроль над каждым байтом, выводится «сырой» обмен |
| Перехват и модификация «на лету» | Burp / mitmproxy | Нужен прокси, curl так не умеет интерактивно |
| Массовый фаззинг путей/параметров | ffuf / gobuster | Скорость, фильтры, словари |
| Человекочитаемый ручной запрос | httpie | Меньше флагов, цветной вывод |
| Скрипт в CI / одна команда | **curl** | Есть везде, нулевые зависимости, стабильный формат |
| Построение запроса без отправки | httpie `--offline` | Показывает, что уйдёт на сервер |

Правило: **Burp — чтобы найти, curl — чтобы доказать**. Если вы нашли что-то в Burp, немедленно воспроизведите это curl (правый клик по запросу → *Copy as cURL* — отличная заготовка).

## Базовый синтаксис и анатомия команды

Общая форма:

```bash
curl [флаги] URL
```

Ключевые идеи:

- URL по умолчанию — GET. Порядок флагов неважен, но URL обычно последний.
- Тело (`-d`, `-F`, `-T`) автоматически переключает метод на POST, если вы не задали `-X` явно.
- Ответ по умолчанию идёт в stdout — без заголовков. Чтобы увидеть больше, нужны `-i`, `-I`, `-v`, `-w`.
- Всё, что вы видите в DevTools, curl умеет повторить.

Минимальный запрос и его «сырой» вид:

```bash
curl https://example.com
curl -s -v https://example.com 2>&1 | head -40
```

## Методы и тело запроса

Метод задаётся `-X`/`--request`, тело — семейством `-d`/`-F`/`-T`.

| Флаг | Что делает | Когда нужен |
|------|-----------|-------------|
| `-X METHOD` / `--request` | задаёт HTTP-метод явно | `PUT`, `PATCH`, `DELETE`, нестандартные методы, verb tampering |
| `-d DATA` / `--data` | тело; `@file` — из файла; метод → POST | `application/x-www-form-urlencoded`, JSON строкой |
| `--data-raw DATA` | как `-d`, но **не** трактует `@` как файл | когда в данных есть `@` (email, JSON) |
| `--data-binary DATA` | тело байт-в-байт, без склейки/удаления переводов строк | загрузка бинарных данных, точное тело |
| `--data-urlencode K=V` | URL-кодирует значение перед отправкой | значения с пробелами, `&`, `=`, юникодом |
| `-F K=V` / `--form` | multipart/form-data; `@file` = файл, `@-` = stdin | загрузка файлов, формы с файлами |
| `-T FILE` / `--upload-file` | PUT-загрузка файла по URL | WebDAV, S3-совместимые хранилища |
| `--data-ascii DATA` | как `-d`, но явно ASCII (устаревающий алиас) | `curl --data-ascii 'a=1' https://t/` |
| `--form-string K=V` | multipart, но `@`/`<` в значении **не** трактуются как файл | `curl -F 'a=1' --form-string 'note=@home' https://t/` |
| `-G` / `--get` | перенести `-d`/`--data-urlencode` в query-строку GET | `curl -sG https://t/s --data-urlencode 'q=a b'` |
| `--url-query DATA` | добавить query-параметр, не трогая остальные | `curl --url-query 'page=2' https://t/` |
| `-Q CMD` / `--quote` | послать команду серверу до передачи (FTP/SFTP) | `curl -Q '-DELE old.txt' ftp://t/` |

Практика:

```bash
# POST с form-urlencoded
curl -s -X POST https://t.local/login -d 'user=admin&pass=admin'

# POST с JSON (обязательно задать Content-Type)
curl -s -X POST https://t.local/api/users \
  -H 'Content-Type: application/json' \
  -d '{"name":"bob","role":"admin"}'

# Значение с пробелами и амперсандом — кодируем автоматически
curl -s -X POST https://t.local/search --data-urlencode 'q=a b & c'

# PUT c телом из файла
curl -s -X PUT https://t.local/api/item/1 --data-binary @body.json

# multipart: поле + файл
curl -s -X POST https://t.local/upload \
  -F 'title=avatar' \
  -F 'file=@/etc/hosts;type=image/png;filename=shell.php'
```

**Тонкость, которая спасает:** `-d @file` читает файл, а `--data-raw '@literal'` отправляет строку. Если в JSON есть `@`, используйте `--data-raw`, иначе curl попытается открыть файл и упадёт.

## Заголовки, cookie и аутентификация

| Флаг | Что делает |
|------|-----------|
| `-H 'K: V'` | добавить/переопределить заголовок; `-H 'K:'` — удалить |
| `-b 'k=v; k2=v2'` / `--cookie` | отправить cookie строкой **или** из файла Netscape |
| `-c FILE` / `--cookie-jar` | сохранить полученные `Set-Cookie` в файл |
| `-u user:pass` | HTTP Basic auth |
| `--digest` | использовать Digest-аутентификацию |
| `-A 'UA'` / `--user-agent` | задать User-Agent |
| `-e URL` / `--referer` | задать Referer |
| `--oauth2-bearer TOKEN` | подставить `Authorization: Bearer TOKEN` |
| `--ntlm` / `--negotiate` | NTLM / Kerberos-аутентификация |
| `--anyauth` | выбрать любую поддерживаемую схему аутентификации (по ответу 401) |
| `--basic` | принудительно Basic (вместо авто-выбора) |
| `-j` / `--junk-session-cookies` | игнорировать сессионные cookie, прочитанные из файла |
| `-n` / `--netrc` | взять логин/пароль из `~/.netrc` (`--netrc-file FILE`) |
| `-E` / `--cert cert[:pass]` | клиентский сертификат (и пароль к нему) |
| `--cert-type` / `--key-type` | формат клиентского серта/ключа (PEM/DER/P12/ENG) |
| `--key KEY` / `--pass PHRASE` | приватный ключ и пароль к нему |
| `--aws-sigv4 PROVIDER` | подпись AWS SigV4 (`--aws-sigv4 'aws:amz:eu-west-1:s3'`) |
| `--krb LEVEL` | Kerberos-аутентификация с уровнем защиты |

```bash
# Bearer-токен
curl -s https://t.local/api/me -H 'Authorization: Bearer eyJ...'

# Basic
curl -s -u admin:s3cret https://t.local/admin

# Cookie из строки + сохранить новые Set-Cookie в банку
curl -s -c jar.txt -b 'session=abc123' https://t.local/dashboard

# Дальше вся сессия живёт в jar.txt — переиспользуем её
curl -s -b jar.txt https://t.local/api/profile
```

`-c` + `-b` — это **полноценный session-менеджмент**: один раз залогинились, банка запомнила cookie, дальше все запросы идут «от имени» этой сессии. Именно так воспроизводят CSRF/IDOR-сценарии, где важен валидный сессионный cookie.

## Вывод и отладка

Самая недооценённая группа флагов. Здесь решается, увидите вы баг или нет.

| Флаг | Что делает |
|------|-----------|
| `-i` / `--include` | добавить заголовки ответа в вывод (перед телом) |
| `-I` / `--head` | сделать HEAD-запрос и вывести только заголовки |
| `-v` / `--verbose` | показать `>` запрос и `<` ответ целиком (в stderr) |
| `--trace FILE` | полный hex-дамп обмена в файл |
| `-s` / `--silent` | не показывать прогресс/ошибки |
| `-S` / `--show-error` | вместе с `-s` всё равно показать ошибку |
| `-o FILE` / `--output` | тело в файл |
| `-O` / `--remote-name` | сохранить под именем из URL |
| `-w FMT` / `--write-out` | вывести свою строку с кодами после ответа |
| `--compressed` | запросить gzip/deflate/br и распаковать ответ |
| `-D FILE` / `--dump-header` | заголовки ответа в отдельный файл |
| `-#` / `--progress-bar` | прогресс-бар вместо счётчика |
| `-L` / `--location` | следовать редиректам (в т.ч. на другой хост) |
| `--location-trusted` | как `-L`, но отправлять креды и на другие хосты |
| `--max-redirs N` | максимум редиректов (по умолчанию 50; `-1` = без лимита) |
| `-f` / `--fail` | при HTTP-ошибке не выводить тело и вернуть ненулевой код |
| `--fail-with-body` | как `-f`, но тело ошибки всё равно сохранить |
| `-J` / `--remote-header-name` | имя файла брать из `Content-Disposition` |
| `-R` / `--remote-time` | выставить локальное время файла по серверу |
| `--create-dirs` | создать каталоги, нужные для `-o` |
| `-N` / `--no-buffer` | не буферизовать вывод (потоковая передача) |
| `--stderr FILE` | перенаправить stderr в файл |
| `--trace-ascii FILE` | как `--trace`, но без hex-дампа |
| `--trace-time` | метки времени в verbose/trace |
| `--out-null` | выбросить тело ответа «в пустоту» |

Классические комбинации:

```bash
# Заголовки + тело
curl -s -i https://t.local/

# Только заголовки (быстро, без тела)
curl -s -I https://t.local/

# Отладка «что реально ушло» (запрос + ответ)
curl -s -v https://t.local/api 2>&1 | less

# Тело в файл, а на экран — код и размер
curl -s -o /tmp/body.html -w 'code=%{http_code} size=%{size_download}\n' https://t.local/

# Заголовки ответа в файл (для разбора Set-Cookie)
curl -s -D /tmp/hdr.txt -o /dev/null https://t.local/login
```

**`-w` — это язык программирования для отчётов.** Полный список кодов в `man curl`, но рабочая шпаргалка:

| Код | Значение |
|-----|----------|
| `%{http_code}` | код состояния (200, 302, …) |
| `%{response_code}` | то же самое (алиас) |
| `%{size_download}` | размер тела в байтах |
| `%{size_header}` | размер заголовков |
| `%{time_total}` | общее время, сек |
| `%{time_connect}` | время TCP-connect |
| `%{time_starttransfer}` | время до первого байта (TTFB) |
| `%{time_appconnect}` | время TLS-handshake |
| `%{url_effective}` | итоговый URL (после редиректов) |
| `%{num_redirects}` | сколько редиректов прошли |
| `%{remote_ip}` | IP, к которому подключились |
| `%{content_type}` | Content-Type ответа |
| `%{json}` | весь ответ как JSON (удобно + jq) |

## Сеть: прокси, TLS, DNS, версии HTTP, таймауты

| Флаг | Что делает | Когда |
|------|-----------|-------|
| `-x URL` / `--proxy` | отправить через прокси (http/socks4/socks5) | Burp, pivoting, обход гео-блоков |
| `--proxy-user u:p` | аутентификация на прокси | прокси с паролем |
| `--noproxy '*'` | игнорировать переменные `*_proxy` | когда curl вдруг «ходит» через системный прокси |
| `-k` / `--insecure` | не проверять TLS-сертификат | self-signed, лаборатория, CTF |
| `--cacert FILE` | доверять указанному CA | внутренние PKI, pinning-обход |
| `--capath DIR` | каталог с CA | набор корневых сертификатов |
| `--cert / --key` | клиентский сертификат и ключ | mTLS-эндпоинты |
| `--resolve HOST:PORT:IP` | подменить DNS для одного хоста | тест vhost, обход DNS |
| `--connect-to HOST1:P1:HOST2:P2` | соединиться с другим адресом, сохранив Host/SNI | пиннинг на конкретный backend |
| `--http1.1` / `--http2` / `--http3` | зафиксировать версию протокола | request smuggling, HTTP/2-специфика |
| `--http2-prior-knowledge` | HTTP/2 без апгрейда | h2c-эндпоинты |
| `-m SEC` / `--max-time` | общий таймаут запроса | не висеть вечно |
| `--connect-timeout SEC` | таймаут на соединение | быстрая проверка «жив ли порт» |
| `--retry N` | повторить при временных ошибках | нестабильные сервисы |
| `--retry-all-errors` | повторять при любых ошибках | флаки-сети |
| `--limit-rate RATE` | ограничить скорость (k/M) | не уронить слабый сервис |
| `--interface IFACE` | исходящий интерфейс/IP | мультихом, source-IP |
| `--local-port RANGE` | зафиксировать локальный порт | редкие проверки |
| `-4` / `-6` | только IPv4 / IPv6 | разные пути к цели |
| `--socks5 HOST:PORT` | SOCKS5-прокси (резолв на стороне прокси) | `curl --socks5 127.0.0.1:9050 https://t/` |
| `--socks5-hostname H:P` | SOCKS5, имя хоста передаётся прокси | `curl --socks5-hostname 127.0.0.1:9050 https://t/` |
| `--preproxy URL` | первый прокси в цепочке (напр. SOCKS5 → HTTP) | `curl --preproxy socks5://127.0.0.1:9050 -x http://t2:8080 https://t/` |
| `-p` / `--proxytunnel` | туннель через HTTP CONNECT | `curl -p -x http://127.0.0.1:8080 https://t/` |
| `--retry-delay SEC` | пауза между повторами | `curl --retry 3 --retry-delay 2 https://t/` |
| `--retry-connrefused` | повторять при connection refused | `curl --retry 3 --retry-connrefused https://t/` |
| `--retry-max-time SEC` | предел общего времени повторов | `curl --retry 5 --retry-max-time 30 https://t/` |
| `--speed-limit B` / `--speed-time S` | прервать, если медленнее B байт/с дольше S сек | `curl --speed-limit 1000 --speed-time 10 -O https://t/f` |
| `--tlsv1.0`…`--tlsv1.3` | минимальная версия TLS | `curl --tlsv1.2 https://t/` |
| `--tls-max VERSION` | максимальная версия TLS | `curl --tls-max 1.2 https://t/` |
| `--ciphers LIST` | набор шифров TLS ≤1.2 (напр. ослабить SECLEVEL) | `curl --ciphers 'DEFAULT@SECLEVEL=1' https://t/` |
| `--tls13-ciphers LIST` | набор шифров TLS 1.3 | `curl --tls13-ciphers TLS_AES_128_GCM_SHA256 https://t/` |
| `--pinnedpubkey HASH` | проверка публичного ключа сервера (pinning) | `curl --pinnedpubkey sha256//abc... https://t/` |
| `--doh-url URL` | резолвить имена через DNS-over-HTTPS | `curl --doh-url https://1.1.1.1/dns-query https://t/` |
| `--dns-servers ADDRS` | свои DNS-серверы | `curl --dns-servers 1.1.1.1 https://t/` |
| `--happy-eyeballs-timeout-ms MS` | задержка перед переходом IPv6→IPv4 | `curl --happy-eyeballs-timeout-ms 200 https://t/` |
| `--interface IFACE` | исходящий интерфейс/IP (алиас `--interface eth0`) | `curl --interface 10.0.0.9 https://t/` |

```bash
# Через Burp
curl -s -x http://127.0.0.1:8080 -k https://t.local/api

# Игнорировать системный прокси
curl -s --noproxy '*' https://t.local/

# Прибить домен к конкретному IP, сохранив Host и SNI
curl -s --resolve t.local:443:10.0.0.5 https://t.local/

# Ходить на внутренний IP, но Host/SNI оставить боевыми
curl -s --connect-to t.local:443:10.0.0.5:443 https://t.local/

# Таймауты: 5с на соединение, 20с всего, 3 ретрая
curl -s -m 20 --connect-timeout 5 --retry 3 https://t.local/

# Ограничить скорость, чтобы не положить сервис
curl -s --limit-rate 200k -O https://t.local/big.iso
```

`--resolve` и `--connect-to` — два разных инструмента: первый меняет то, **куда резолвится имя**, второй — **куда идёт соединение**, не трогая имя. Для теста vhost'ов и внутренних backend'ов это ключевые флаги.

## Продвинутое: globbing, range, resume, upload, спец-флаги

| Флаг | Что делает |
|------|-----------|
| `-G` / `--get` | данные из `-d`/`--data-urlencode` уходят в query-строку GET |
| `--json '{}'` | шорткат: `Content-Type: application/json` + `Accept: application/json` + тело |
| `--path-as-is` | не нормализовать `../` и `//` в пути (path traversal!) |
| `-g` / `--globoff` | выключить globbing `{}` `[]` (чтобы URL с `[]` не ломался) |
| `-r A-B` / `--range` | Range-запрос (байты) |
| `-C -` / `--continue-at` | докачать файл с места обрыва |
| `-T FILE` | PUT-загрузка файла |
| `--url-query` | добавить query-параметр, не трогая остальные |
| `--data-raw` | тело без обработки `@` |
| `--proto LIST` | разрешить/запретить протоколы (`--proto '=https,http'` — только их) |
| `--proto-redir LIST` | протоколы, разрешённые при редиректах |
| `-0` / `--http1.0` | использовать HTTP/1.0 |
| `--http3-only` | только HTTP/3, без fallback на h1/h2 |
| `--max-filesize BYTES` | не скачивать файл больше N байт |
| `--url URL` | задать URL флагом, а не позиционным аргументом |
| `-K` / `--config FILE` | читать опции из файла конфигурации |
| `-q` / `--disable` | игнорировать `~/.curlrc` |
| `-:` / `--next` | отделить опции, действующие для следующего URL |
| `-Z` / `--parallel` | параллельные передачи (`--parallel-max N`) |
| `--variable name=value` | задать переменную для `--expand-*` |
| `--unix-socket PATH` | соединиться через UNIX-доменный сокет |
| `--libcurl FILE` | сгенерировать C-код libcurl для этой команды |
| `-M` / `--manual` | открыть полный мануал |

> Сознательно опущены узкоспециальные и косметические флаги: FTP/FTPS (`--ftp-*`), почтовые (`--mail-*`), TFTP, telnet (`-t`), SSH (`--pubkey`, `--knownhosts`, `--compressed-ssh`), Windows/Schannel (`--ssl-*`, `--ssl-auto-client-cert`), IPv6-специфика (`--dns-ipv4-addr`), а также чисто оформительские (`--styled-output`, `--trace-config`, `--trace-ids`) и прокси-подфлаги (`--proxy-*`, `--proxy1.0`).

```bash
# GET с параметрами через --data-urlencode + -G (кодирует автоматически)
curl -sG https://t.local/search \
  --data-urlencode 'q=SELECT * FROM x' \
  --data-urlencode 'page=1'

# JSON-шорткат
curl -s --json '{"q":"x"}' https://t.local/api/search

# Path traversal: curl НЕ должен нормализовать ../
curl -s --path-as-is 'https://t.local/static/../../etc/passwd'
curl -s --path-as-is 'https://t.local/..%2f..%2fetc/passwd'

# Range-запрос (иногда отдаёт куски файлов и обходит лимиты)
curl -s -r 0-1023 https://t.local/backup.zip -o head.bin

# Докачать прерванную загрузку
curl -s -C - -O https://t.local/big.iso

# Загрузить файл методом PUT
curl -s -T shell.php https://t.local/uploads/shell.php
```

`--path-as-is` и `-g` — те флаги, которые отличают «curl не сработал» от «curl сам починил атаку». По умолчанию curl нормализует путь и может незаметно убить traversal-пейлоад.

## Рецепты: разведка и карта приложения

**1. Заголовки сервера и технологии:**

```bash
curl -s -I https://t.local/
curl -s -D - -o /dev/null https://t.local/ | grep -iE 'server|x-powered|set-cookie|location'
```

**2. Проверка существования путей пачкой (без цикла в bash — см. также ffuf):**

```bash
curl -s -o /dev/null -w '%{http_code} %{url_effective}\n' \
  https://t.local/admin https://t.local/api https://t.local/.git/config
```

**3. Виртуальные хосты на одном IP:**

```bash
curl -s -H 'Host: admin.t.local' https://t.local/ -o /dev/null -w '%{http_code}\n'
curl -s --resolve admin.t.local:443:10.0.0.5 https://admin.t.local/
```

**4. Скрытые параметры через `--json` (быстрый ручной чек):**

```bash
curl -s --json '{"debug":true}' https://t.local/api/config
curl -s 'https://t.local/api?debug=1&admin=1' -w '\n%{http_code}\n'
```

**5. Обзор методов (Allow-заголовок):**

```bash
curl -s -X OPTIONS -i https://t.local/api/item -o /dev/null -D -
```

## Рецепты: сессии, авторизация, JSON-API

**Логин → сохранение сессии → повторное использование:**

```bash
# 1) логин, cookie пишутся в jar
curl -s -c jar.txt -X POST https://t.local/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pass":"hunter2"}'

# 2) проверяем, кто мы
curl -s -b jar.txt https://t.local/api/me

# 3) меняем объект (IDOR-проба): свой id → чужой
curl -s -b jar.txt https://t.local/api/orders/1001
curl -s -b jar.txt https://t.local/api/orders/1002
```

**JWT / Bearer:**

```bash
TOKEN='eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjF9.sig'
curl -s https://t.local/api/admin -H "Authorization: Bearer $TOKEN"
```

**Массовое назначение (mass assignment) — пробуем лишние поля:**

```bash
curl -s -X PATCH https://t.local/api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data-raw '{"nickname":"x","role":"admin","is_admin":true}'
```

**Фаззинг JSON-значения (ручной, точечный):**

```bash
for v in 1 2 0 -1 999999; do
  curl -s "https://t.local/api/item/$v" -o /dev/null -w "$v -> %{http_code} %{size_download}\n"
done
```

## Рецепты: инъекции, SSRF, обход

Это те команды, ради которых curl вообще нужен в вебе.

**SQLi-проба вручную (дальше — sqlmap):**

```bash
curl -s -G 'https://t.local/product' --data-urlencode "id=1' OR '1'='1"
curl -s -G 'https://t.local/product' --data-urlencode "id=1 AND SLEEP(5)" -w '\ntime=%{time_total}\n'
```

**SSRF-проба (если параметр принимает URL):**

```bash
curl -s -G 'https://t.local/fetch' --data-urlencode 'url=http://127.0.0.1:22'
curl -s -G 'https://t.local/fetch' --data-urlencode 'url=http://169.254.169.254/latest/meta-data/'
curl -s -G 'https://t.local/fetch' --data-urlencode 'url=file:///etc/passwd'
```

**Path traversal / LFI:**

```bash
curl -s --path-as-is 'https://t.local/download?file=../../../../etc/passwd'
curl -s --path-as-is 'https://t.local/download?file=....//....//etc/passwd'
curl -s --path-as-is 'https://t.local/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd'
```

**SSTI-проба (эхо-параметр):**

```bash
curl -s -G 'https://t.local/greet' --data-urlencode 'name={{7*7}}'
curl -s -G 'https://t.local/greet' --data-urlencode 'name=${7*7}'
```

**Open redirect / redirect chain:**

```bash
curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' \
  -G 'https://t.local/login' --data-urlencode 'next=https://evil.tld/'
```

**Timing (time-based слепая инъекция) — сравниваем времена:**

```bash
curl -s -o /dev/null -w 'baseline %{time_total}\n' 'https://t.local/?id=1'
curl -s -o /dev/null -w 'sleep5   %{time_total}\n' 'https://t.local/?id=1%20AND%20SLEEP(5)'
```

## Сохранение и парсинг вывода

Сохранять ответы в файлы и разбирать их структурно — обязательная привычка. Три приёма.

**1. Разделить тело и заголовки:**

```bash
curl -s -D hdr.txt -o body.txt https://t.local/api/items
head -1 hdr.txt
jq '.items[0]' body.txt
```

**2. Собрать структурированную строку через `-w` и `%{json}`:**

```bash
curl -s -o /dev/null -w '%{json}\n' https://t.local/ | jq '{code:.http_code, size:.size_download, t:.time_total}'
```

**3. Собрать таблицу по списку URL и передать в jq/awk:**

```bash
while read -r u; do
  curl -s -o /dev/null -w '%{http_code}\t%{size_download}\t%{url_effective}\n' "$u"
done < urls.txt | sort -n
```

**4. Разбор JSON-массива из ответа:**

```bash
curl -s https://t.local/api/users | jq -r '.[] | [.id, .email] | @tsv'
```

`-w` + `jq` — это готовый мини-сканер: цикл по URL, вывод кода/размера/времени, сортировка, отбор аномалий.

## Типичные сценарии: что делать в любой ситуации

**«Запрос не воспроизводится из браузера».** DevTools → Copy as cURL. Добавьте `-H` с cookie и всеми заголовками. Проверьте `-v`, что запрос реально ушёл так, как надо.

**«Редирект съедает тело».** Без `-L` curl покажет `302` и `Location`. С `-L` — пойдёт по цепочке. Хотите увидеть всю цепочку: `-L -w '%{num_redirects} %{url_effective}\n'`.

**«Сервер за прокси/Burp».** `-x http://127.0.0.1:8080 -k`. Если curl «ходит» сам по себе — проверьте `--noproxy '*'` и переменные `http_proxy`.

**«TLS-ошибка на лаборатории».** `-k`. Для внутреннего PKI — `--cacert ca.pem`. Для mTLS — `--cert client.pem --key client.key`.

**«Нужно попасть на конкретный backend за балансировщиком».** `--resolve host:443:IP` (меняет DNS) или `--connect-to host:443:IP:443` (меняет соединение, сохраняя SNI).

**«Path traversal не работает».** Добавьте `--path-as-is`, попробуйте `-g` для URL со скобками, и отдельно — двойное кодирование (`%2e%2e%2f`).

**«Подозрение на слепую инъекцию».** Сравнивайте `%{time_total}` для baseline и sleep-пейлоада; повторяйте 3 раза, чтобы отсечь шум.

**«Сайт отдаёт разные версии протокола».** `--http1.1`, `--http2`, `--http3`, `--http2-prior-knowledge` — тестируйте smuggling/h2c.

**«Нужно не уронить слабый сервис».** `--limit-rate 100k`, `-m 10`, `--retry 2`.

**«Хочу отправить реальный email/JSON с символом @».** `--data-raw`, иначе curl решит, что это файл.

## Частые ошибки

- **Забыли `-H 'Content-Type: application/json'`** — сервер не распарсит тело, увидите 400/415. Используйте `--json`, он ставит заголовок сам.
- **`-d` вместо `--data-raw`** при наличии `@` — curl пытается открыть файл и падает.
- **Отсутствие `-L`** — вы анализируете `302`, а не реальную страницу.
- **Отсутствие `-k`** на self-signed — запрос вообще не уходит, а вы думаете, что сервис мёртв.
- **Нет `-b`/`-c`** — сессия не сохраняется, все запросы «анонимные», авторизация «не работает».
- **Забыли `--path-as-is`** — curl нормализовал `../` и убил вашу traversal-атаку.
- **Грепать сырой HTML вместо `-w`/jq** — хрупко; сохраняйте тело в файл и разбирайте структуру.
- **`-I` (HEAD) на эндпоинте, который HEAD не поддерживает** — получите 405 и ложный вывод; сравнивайте с `-i` (GET).
- **Молчаливое «пусто»** — `-s` без `-S` прячет ошибки; используйте `-sS`, чтобы видеть сбои.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какой флаг заставляет curl следовать по цепочке редиректов?"
  options:
    - "-i"
    - "-L"
    - "-k"
    - "-v"
  answer: 1
  explanation: "`-L` включает следование за Location. Без него вы увидите только первый 3xx."
- question: "Что делает флаг -G вместе с -d?"
  options:
    - "Отключает проверку TLS"
    - "Сохраняет cookie в файл"
    - "Отправляет данные в query-строке GET-запроса"
    - "Заставляет curl повторить запрос"
  answer: 2
  explanation: "`-G` переносит данные из -d/--data-urlencode в URL как параметры GET."
- question: "Как отправить multipart-форму с файлом?"
  options:
    - "-d 'file=/etc/hosts'"
    - "--data-raw 'file=@/etc/hosts'"
    - "-T /etc/hosts"
    - "-F 'file=@/etc/hosts'"
  answer: 3
  explanation: "`-F` формирует multipart/form-data, а `@file` прикладывает содержимое файла."
- question: "Как вывести только HTTP-код и размер ответа, не печатая тело?"
  options:
    - "-I -v"
    - "-o /dev/null -w '%{http_code} %{size_download}'"
    - "-s -i"
    - "--trace -"
  answer: 1
  explanation: "`-o /dev/null` убирает тело, а `-w` печатает выбранные метаданные."
- question: "Зачем нужен --path-as-is при проверке path traversal?"
  options:
    - "Чтобы включить HTTP/2"
    - "Чтобы сохранить сертификат"
    - "Чтобы curl не нормализовал ../ в пути и отправил пейлоад как есть"
    - "Чтобы ограничить скорость"
  answer: 2
  explanation: "По умолчанию curl схлопывает ../ — флаг отключает эту нормализацию."
```

## Где пригодится

- **CTF (Web):** точное воспроизведение запроса, SSRF/LFI/SSTI-пробы, разбор редиректов и сессий — всё одной командой.
- **Bug bounty:** PoC в отчёте почти всегда принимается в виде `curl`-команды; session-jar и `-w` экономят время на доказательстве.
- **Пентест:** ручная проверка находок сканеров, воспроизведение IDOR/mass-assignment, тест vhost'ов через `--resolve`.
- **Работа (AppSec/DevOps):** проверки в CI, smoke-тесты API, отладка интеграций и reverse-proxy без браузера.
