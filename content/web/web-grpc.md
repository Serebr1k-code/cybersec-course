---
id: web-grpc
title: "gRPC и protobuf: реверс и атаки"
category: web
parent: web-api-rest-graphql-soap
difficulty: hard
order: 3
tags: [grpc, protobuf, http2, reflection, reverse]
prerequisites: [web-api-rest-graphql-soap, web-http2-attacks]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 40
summary: "gRPC/protobuf: реверс .proto, gRPC reflection, вызов методов без схемы, grpc-web, атаки на HTTP/2-транспорт."
---

gRPC — современный RPC-фреймворк на HTTP/2 и protobuf. Он не отдаёт человекочитаемый REST, поэтому при пентесте приходится сначала восстановить схему (`.proto`), а затем работать с методами напрямую. Атаки — те же, что и в REST (IDOR/BOLA, инъекции, отсутствие authz), но обнаружить их сложнее из-за бинарного формата. Reflection и `grpcurl` сильно упрощают жизнь.

## Теория: как выглядит gRPC

- Транспорт — HTTP/2, `Content-Type: application/grpc`.
- Тело — length-prefixed protobuf-сообщения (не JSON).
- Метод кодируется в пути: `/package.Service/Method`.
- Статус — в HTTP/2-трейлерах (`grpc-status`, `grpc-message`).
- Часто есть **server reflection** — сервис сам отдаёт свои `.proto`.

Определить gRPC:

```bash
curl -s -I https://app.example/ | grep -i 'content-type\|grpc'
grpcurl -plaintext app.example:443 list        # если reflection включён
```

## Реверс: восстановление .proto

Если reflection выключен, схему достают из клиента:

- **Мобильное/десктоп-приложение** — распаковать и найти `.proto` или строки с именами методов.
- **`strings`/`binwalk`** по бинарю.
- **Из сообщений:** protobuf-поля нумеруются; по форме можно частично восстановить схему (`protobuf-inspector`, `blackboxprotobuf`).
- **`grpcurl` с `-proto`** — если схема найдена, можно вызывать методы.

## Атаки

- **BOLA/IDOR:** вызвать метод с чужим ID/токеном.
- **Отсутствие authz:** методы admin/internal без проверки.
- **Инъекции:** значения protobuf уходят в SQL/команды/шаблоны.
- **DoS:** большие/рекурсивные сообщения.
- **Reflection** как «карта» эндпоинтов.

## Разобранный пример: reflection → вызов без схемы

Шаг 1 — перечисляем сервисы:

```bash
grpcurl -plaintext app.example:50051 list
grpcurl -plaintext app.example:50051 list myapp.UserService
```

Шаг 2 — описываем метод:

```bash
grpcurl -plaintext app.example:50051 describe myapp.UserService.GetUser
```

Шаг 3 — вызываем:

```bash
grpcurl -plaintext -d '{"id":"123"}' app.example:50051 myapp.UserService/GetUser
```

Шаг 4 — перебираем ID/токены (IDOR).

## Разобранный пример: реверс без reflection

Шаг 1 — находим `.proto`/строки в приложении:

```bash
unzip -o app.apk -d app && grep -rl "\.proto" app | head
strings libapp.so | grep -iE 'Service|/Method|protobuf'
```

Шаг 2 — если нашли `.proto`, вызываем:

```bash
grpcurl -plaintext -import-path . -proto user.proto \
  -d '{"id":"123"}' app.example:50051 myapp.UserService/GetUser
```

Шаг 3 — если схемы нет, используем `blackboxprotobuf` для разбора/сборки сообщений по номерам полей.

## gRPC-web

Веб-клиенты используют gRPC-web (HTTP/1.1 или HTTP/2, base64 или binary). Заголовки: `Content-Type: application/grpc-web+proto`, `application/grpc-web-text`. Перехват в браузере → разбор через `grpc-web`-десериализатор; атаки те же.

## Инструменты

- **`grpcurl`** — вызовы/reflection.
- **`grpcui`** — веб-UI для gRPC.
- **`protobuf-inspector`/`blackboxprotobuf`** — разбор без схемы.
- **Burp** — перехват (gRPC-web читаем, gRPC-HTTP2 — через плагины).
- **`ghz`** — нагрузочное/фаззинг gRPC.

## Что дальше / decision

1. Есть gRPC → проверьте reflection (`grpcurl list`).
2. Reflection есть → перечислите методы, вызовите, ищите IDOR/authz.
3. Reflection нет → реверсните `.proto` из клиента.
4. Схемы нет вовсе → `blackboxprotobuf` по номерам полей.
5. Дальше — инъекции в значениях и BOLA на методах.

## Разобранный пример: IDOR/BOLA в gRPC

Шаг 1 — перечисляем методы через reflection.
Шаг 2 — вызываем метод с чужим ID:

```bash
grpcurl -plaintext -d '{"user_id":"1002"}' app.example:50051 myapp.UserService/GetUser
```

Шаг 3 — если вернулся чужой пользователь — IDOR/BOLA. gRPC часто не проверяет авторизацию на уровне метода, доверяя клиенту.

## Метаданные и аутентификация

gRPC передаёт auth/tenant в **metadata** (аналог заголовков):

```bash
grpcurl -plaintext -H 'authorization: Bearer <token>' -H 'x-tenant: 2' \
  -d '{"id":"1"}' app.example:50051 myapp.UserService/GetUser
```

Тестируйте: подмена `x-tenant`/`x-user-id` (мультитенантность), отсутствие токена, чужой токен. Иногда metadata-поля уходят в запрос без проверки.

## Частые ошибки

- **Игнорировать gRPC, считая его «закрытым».** Это HTTP/2 — всё тестируемо.
- **Ждать JSON.** Тело — protobuf; нужен десериализатор.
- **Не проверить reflection.** Часто включён и отдаёт всю схему.
- **Забыть про gRPC-web.** В браузере другой Content-Type.
- **Ломать прод.** Только с согласия.

## Полный арсенал grpcurl: флаги и режимы

`grpcurl` — основной инструмент для ручного общения с gRPC. Держите под рукой полный набор флагов.

| Флаг | Значение |
|------|----------|
| `-plaintext` | без TLS (h2c, порт 50051) |
| `-insecure` | TLS без проверки сертификата |
| `-import-path DIR` | каталог с `.proto` |
| `-proto file.proto` | использовать конкретный proto |
| `-rpc-header 'k: v'` | метаданные (аналог заголовка) |
| `-H 'k: v'` | HTTP/2-заголовки |
| `-d '{...}'` | JSON-тело запроса |
| `-d @` | читать тело из stdin |
| `-format-error` | печатать status-код |
| `-max-time N` | таймаут в секундах |
| `-emit-defaults` | выводить поля со значением по умолчанию |

```bash
# список сервисов (reflection)
grpcurl -plaintext localhost:50051 list
# методы сервиса
grpcurl -plaintext localhost:50051 list my.pkg.UserService
# описание сообщения
grpcurl -plaintext localhost:50051 describe my.pkg.User
# вызов метода
grpcurl -plaintext -d '{"id":1}' localhost:50051 my.pkg.UserService/GetUser
# с авторизацией через метаданные
grpcurl -plaintext -rpc-header 'authorization: Bearer TOKEN' \
  -d '{"id":1}' localhost:50051 my.pkg.UserService/GetUser
```

Если reflection выключен, обязательно указывайте `-proto` и `-import-path`.

## Статус-коды gRPC и что они означают для атакующего

gRPC использует свои коды, и они прямо подсказывают состояние проверки прав.

| Код | Число | Значение для теста |
|-----|-------|--------------------|
| OK | 0 | запрос прошёл |
| PERMISSION_DENIED | 7 | права проверены — ищите обход |
| UNAUTHENTICATED | 16 | нужен токен |
| NOT_FOUND | 5 | объект есть, но не виден (часто IDOR!) |
| INVALID_ARGUMENT | 3 | парсер принял, валидация отклонила |
| UNIMPLEMENTED | 12 | метод есть в схеме, но не реализован |
| RESOURCE_EXHAUSTED | 8 | rate-limit/DoS-точка |

Разница между `PERMISSION_DENIED` и `NOT_FOUND` — ключевой оракул: если при подмене `id` возвращается `NOT_FOUND` вместо `PERMISSION_DENIED`, авторизация, скорее всего, не проверяется, и объект просто не существует.

## Потоковые вызовы и их абуз

gRPC поддерживает четыре режима: unary, server-streaming, client-streaming, bidirectional. Потоки часто лишены тех же проверок, что и unary.

```bash
# server-streaming: читаем всё, что отдаёт сервер
grpcurl -plaintext -d '{}' localhost:50051 my.pkg.Feed/Subscribe

# client-streaming: отправляем много сообщений из файла
grpcurl -plaintext -d @ localhost:50051 my.pkg.Upload/Send < lines.json

# bidirectional: интерактивно, удобно для fuzzing
grpcurl -plaintext -d @ localhost:50051 my.pkg.Chat/Stream
```

Типичные баги: сервер отдаёт подписки на чужие топики, не ограничивает число сообщений (RESOURCE_EXHAUSTED не наступает), client-streaming принимает бесконечный поток и падает по памяти.

## gRPC-web и прокси-трансляция

Браузерные приложения общаются с gRPC через **gRPC-web** и прокси (Envoy `grpc_web`, `grpc-web` filter). Это добавляет слой, который может ослабить аутентификацию.

```bash
# gRPC-web использует POST /pkg.Service/Method с телом length-prefixed
curl -s -X POST https://api.example/pkg.UserService/GetUser \
  -H 'Content-Type: application/grpc-web+proto' \
  -H 'X-Grpc-Web: 1' --data-binary @req.bin --output resp.bin
```

Проверяйте: (а) прокси не требует `X-Grpc-Web`; (б) CORS настроен слишком широко (`Access-Control-Allow-Origin: *` с credentials); (в) через тот же прокси доступны нативные gRPC-методы.

## Что делать дальше / решение

1. **Определите транспорт.** Порт 50051/443, h2c или TLS, есть ли gRPC-web-путь.
2. **Проверьте reflection.** Если включён — получите схему через `list`/`describe`.
3. **Восстановите .proto.** Нет reflection — реверс бинаря или proto из клиента.
4. **Перечислите методы.** Ищите админские, отладочные, `Delete*`, `Admin*`.
5. **Тестируйте авторизацию.** Подмена `id`, отсутствие метаданных, чужой токен.
6. **Проверьте потоки и лимиты.** RESOURCE_EXHAUSTED, бесконечные подписки.
7. **Зафиксируйте PoC.** `grpcurl`-команда + ответ с чужими данными/обходом.

## Практика и справочники

- **grpcui / grpcurl** — интерактивный и CLI-клиент.
- **Burp + gRPC-расширения** (например, «gRPC»/«Protobuf») — перехват и повтор.
- **HackTricks** — «gRPC» (реверс proto, reflection).
- **grpc-js / grpcio** — написать свой клиент, когда нужно нестандартное поведение.

## Health checking и reflection как точки входа

Два стандартных механизма gRPC часто остаются включёнными и дают атакующему больше, чем нужно.

```bash
# 1) health checking — стандартный сервис grpc.health.v1.Health
grpcurl -plaintext localhost:50051 grpc.health.v1.Health/Check
# {"status":"SERVING"}
# 2) reflection — отдаёт всю схему
grpcurl -plaintext localhost:50051 list
# my.pkg.UserService
# my.pkg.AdminService      <- интересно!
grpcurl -plaintext localhost:50051 list my.pkg.AdminService
```

Признаки, на которые стоит смотреть: наличие сервисов `Admin`, `Debug`, `Internal`, `Test`; методы `Delete*`, `Reset*`, `Impersonate*`. Reflection сам по себе — не уязвимость, но он превращает разведку в пятисекундное дело, а админские сервисы часто защищены слабее пользовательских.

## Сводка: gRPC vs REST — что меняется для тестировщика

| Аспект | REST | gRPC |
|--------|------|------|
| Транспорт | HTTP/1.1 | HTTP/2 (h2c/h2) |
| Формат | JSON | protobuf (binary) |
| Схема | OpenAPI (часто) | `.proto` (не всегда доступна) |
| Reflection | нет | есть (если включён) |
| Ошибки | HTTP-коды | status-коды gRPC |
| Метаданные | заголовки | metadata |
| Стриминг | SSE/WS | встроенный |

Практический вывод: инструменты для REST (Burp в стандартной настройке) «не видят» бинарный protobuf — нужны gRPC-расширения или `grpcurl`, а авторизацию проверяют в metadata, а не в заголовках в привычном виде.

## Квиз

```quiz
- question: "Как выглядит путь gRPC-метода?"
  options:
    - "/api/v1/users"
    - "/package.Service/Method"
    - "/graphql"
    - "/rest"
  answer: 1
  explanation: "Полное имя сервиса и метода."
- question: "Какой инструмент вызывает gRPC-методы из CLI?"
  options:
    - "curl"
    - "grpcurl"
    - "nmap"
    - "ffuf"
  answer: 1
  explanation: "grpcurl поддерживает reflection."
- question: "Что даёт gRPC reflection?"
  options:
    - "Пароли"
    - "Схему сервисов и методов"
    - "TLS-ключ"
    - "Логи"
  answer: 1
  explanation: "Сервер отдаёт .proto-дескрипторы."
- question: "Как декодировать protobuf без схемы?"
  options:
    - "base64"
    - "protoc --decode_raw"
    - "openssl"
    - "jq"
  answer: 1
  explanation: "Показывает поля/значения по номерам."
- question: "Какая топ-угроза в gRPC-методах?"
  options:
    - "XSS"
    - "BOLA/IDOR — доступ к чужим объектам по id"
    - "CSRF"
    - "Clickjacking"
  answer: 1
  explanation: "Как и в REST API."
```

## Где пригодится

- **CTF (Web):** задачи на gRPC.
- **Bug bounty:** внутренние gRPC-API, IDOR.
- **Пентест:** реверс и аудит RPC.
- **Работа (AppSec):** отключение reflection в проде, authz на методах, mTLS.
