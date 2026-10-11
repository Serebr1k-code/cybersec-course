---
id: mobile-mass-assignment
title: "Mass assignment в мобильном API: подмена полей и ролей"
category: mobile
parent: mobile-api-security-deep
difficulty: hard
order: 3
tags: [mobile, api, mass-assignment, bola, idor, backend]
prerequisites: [mobile-api-bola]
useful_for:
  - "Bug bounty: API мобильных приложений"
  - "Пентест: серверная сторона мобильного продукта"
estimated_minutes: 45
summary: "Как мобильное приложение доверяет полям, которые присылает клиент, и как это приводит к mass assignment: подмена role, is_admin, balance, повышение привилегий и обход лимитов."
---

## Что такое mass assignment

Mass assignment (массовое присваивание) — уязвимость, при которой сервер автоматически привязывает все присланные клиентом поля к объекту модели, не проверяя, какие из них клиент имеет право менять. В мобильном API это особенно часто: клиент — ваш собственный APK, и разработчик предполагает, что он пришлёт только «правильные» поля. Но API публичен: любой может отправить запрос напрямую и добавить лишние поля.

Пример: мобильное приложение отправляет профиль пользователя на `PUT /api/profile`:

```json
{ "name": "Ivan", "email": "ivan@example.com", "phone": "+79001234567" }
```

Сервер в контроллере делает что-то вроде:

```python
user.update(**request.json)   # Flask/SQLAlchemy — массовое присваивание
```

Если добавить поле `is_admin`:

```json
{ "name": "Ivan", "is_admin": true }
```

и сервер примет его — вы повысили себе привилегии. Аналогично `balance`, `role`, `verified`, `credits`, `subscription_plan`.

## Как мобильный контекст усиливает риск

В мобильном API атака удобнее, чем в вебе, по нескольким причинам:
- **Клиент — APK**, и вы можете его декомпилировать, чтобы увидеть все поля модели (в `Response`/`Request` DTO).
- **Прямой доступ к API** — можно слать запросы без приложения (curl/Postman), обходя клиентскую валидацию.
- **Схема полей известна** — из JSON-ответов вы видите все атрибуты объекта.
- **Клиент часто шлёт больше, чем нужно** — например, весь объект при PATCH.

Типовой пайплайн: декомпилируйте APK → найдите DTO-классы (`jadx`) → определите endpoint'ы (`grep /api/`) → перехватите запрос в Burp → добавьте поля из DTO, которых не было в запросе → наблюдайте эффект.

## Разведка: где искать поля

Статически, из APK:

```bash
jadx -d out app.apk
grep -rn "class .*Request\|class .*Dto\|class .*Model" out/sources | head
grep -rn "is_admin\|isAdmin\|role\|balance\|credits\|verified" out/sources | head
```

Динамически, из ответов API:

```bash
# получить профиль и посмотреть все поля
curl -s https://api.example.com/v1/me -H "Authorization: Bearer $TOKEN" | jq .
# ответ покажет, какие поля существуют у объекта
```

Из ответа вы видите `"role": "user", "is_premium": false, "balance": 0` — эти поля и есть кандидаты на подмену.

## Практика: подмена роли

Перехваченный запрос:

```
PATCH /api/v1/users/me HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJ...
Content-Type: application/json

{"displayName":"Ivan"}
```

Пробуем добавить поля:

```bash
curl -s -X PATCH https://api.example.com/api/v1/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"displayName":"Ivan","role":"admin","is_premium":true,"balance":1000000}' | jq .
```

Анализируем ответ:
- Если `role` стал `admin` — критично (эскалация привилегий).
- Если `is_premium` стал `true` — обход платежа.
- Если сервер вернул ошибку «unknown field» — mass assignment нет (или поле отфильтровано).
- Если поле молча проигнорировано — проверьте, не применилось ли оно на самом деле (перезапросите профиль).

## Техники обхода фильтрации

Многие фреймворки фильтруют поля через allowlist, но обходы существуют:
- **Вложенные объекты:** `{"profile":{"is_admin":true}}` — фильтр верхнего уровня пропустит.
- **Разный регистр:** `Is_Admin`, `IS_ADMIN` — если сравнение регистрозависимое.
- **Дубликаты:** `{"role":"user","role":"admin"}` — парсер возьмёт последнее.
- **Разные content-type:** `application/json` vs `multipart/form-data` vs `application/x-www-form-urlencoded` — разные парсеры.
- **Массивы:** `{"roles":["admin"]}` — если модель принимает массив.
- **GraphQL:** если есть GraphQL, мутации часто принимают input-объекты с лишними полями.

```bash
# вложенный объект
-d '{"displayName":"Ivan","profile":{"is_admin":true}}'
# дубликат
-d '{"role":"user","role":"admin"}'
# form-encoded
-d 'displayName=Ivan&is_admin=true'
```

## GraphQL и мобильные API

Современные мобильные приложения часто ходят в GraphQL. Здесь mass assignment проявляется через input-типы мутаций. Разведка:

```bash
# introspection (если включена) — карта схемы
curl -s https://api.example.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | jq .
```

Если introspection открыта — вы видите все поля мутаций, включая потенциально опасные (`updateUser(input:{role:ADMIN})`). Даже без introspection попробуйте добавить поля в input.

## Влияние и оценка

Mass assignment ранжируется по эффекту:
- **Критично:** `role`/`is_admin` → полный захват аккаунта/админки.
- **Высоко:** `balance`/`credits` → финансовый ущерб; `verified` → обход KYC.
- **Средне:** `is_premium` → обход подписки; `email_verified` → обход подтверждения.
- **Низко:** косметические поля без последствий.

В отчёте опишите: точный запрос, добавленное поле, наблюдаемое изменение, влияние. Приложите доказательство (до/после).

## Защита (что рекомендовать)

- **Allowlist полей** на входе: сервер явно перечисляет, какие поля клиент может менять.
- **DTO/схемы** с валидацией (Pydantic, JSON Schema, protobuf) и `additionalProperties: false`.
- **Запрет привилегированных полей** на уровне сериализации (`read_only`/`write_only`).
- **Отдельные endpoint'ы** для админских операций с проверкой роли.
- **Не доверять клиенту** — всегда валидировать на сервере.

## Частые ошибки и подводные камни

- **Путать с IDOR** — IDOR про доступ к чужому объекту, mass assignment про изменение полей своего.
- **Тестировать только через приложение** — клиентская валидация скроет поля; шлите запросы напрямую.
- **Не перезапросить объект** — сервер мог применить поле, но не вернуть его в ответе.
- **Игнорировать вложенные структуры** — фильтр верхнего уровня пропускает вложенные.
- **Забыть про GraphQL** — если REST чистый, GraphQL может быть дырой.

## Справочная таблица

| Поле | Возможный эффект | Severity |
|------|------------------|----------|
| role / is_admin | эскалация привилегий | критично |
| balance / credits | финансовый ущерб | высоко |
| verified / kyc_status | обход верификации | высоко |
| is_premium | обход платежа | средне |
| email_verified | обход подтверждения | средне |
| user_id / owner_id | подмена владельца | высоко |

## Что дальше / решение

Декомпилируйте APK, выпишите поля DTO, перехватите запросы и добавляйте лишние поля. Проверьте вложенные структуры, дубликаты и GraphQL. Подтверждённый эффект — находка с severity по таблице. Дальше — `mobile-app2app` и `mobile-api-bola`.

## Практический сценарий: полный разбор уязвимости

Разберём типичный кейс от начала до подтверждения. Приложение — маркетплейс с подпиской. Декомпилируем APK и находим DTO:

```java
// из jadx
public class UserProfileRequest {
    public String displayName;
    public String avatarUrl;
    public boolean isPremium;
    public String role;
    public int balance;
}
```

Видим поля `isPremium`, `role`, `balance` — явные кандидаты. Перехватываем запрос обновления профиля в Burp:

```
PATCH /api/v1/profile HTTP/1.1
Authorization: Bearer eyJhbGciOi...
Content-Type: application/json

{"displayName":"Ivan","avatarUrl":"https://cdn.example.com/a.png"}
```

Добавляем поля и отправляем через Repeater:

```json
{"displayName":"Ivan","avatarUrl":"https://cdn.example.com/a.png","isPremium":true,"role":"admin","balance":999999}
```

Смотрим ответ. Если сервер вернул `200` и в теле `"isPremium": true` — подписка получена бесплатно. Если `"role": "admin"` — эскалация привилегий. Проверяем на отдельном тестовом аккаунте, чтобы не вредить.

## Валидация и границы теста

Mass assignment — это активное изменение данных. Соблюдайте правила:
- Тестируйте только на своих аккаунтах.
- Не устанавливайте `balance` на огромные значения в продакшене — это финансовый ущерб.
- Фиксируйте минимальное доказательство (одно поле, один запрос).
- В отчёте указывайте, какие поля уязвимы, а не только те, что вы пробовали.

Если сервер принимает `role`, достаточно один раз увидеть, что роль изменилась (например, в ответе `me`), и вернуть её назад, если возможно.

## Фреймворки и их поведение

Разные стеки ведут себя по-разному:
- **Rails** (ActiveRecord): исторически уязвим к mass assignment; `strong_parameters` решает.
- **Django**: `ModelForm`/DRF-сериализаторы фильтруют по `fields`; если используется `__all__` — риск.
- **Flask + SQLAlchemy**: `user.update(**data)` — классическая дыра.
- **Express + Mongoose**: `User.findByIdAndUpdate(id, req.body)` — принимает всё.
- **Spring**: `@ModelAttribute` с привязкой всех параметров — риск; `@RequestBody` с DTO — зависит от DTO.
- **GraphQL**: input-типы; если схема не ограничивает поля — риск.

```javascript
// уязвимо (Express/Mongoose)
app.patch('/profile', async (req, res) => {
  await User.findByIdAndUpdate(req.user.id, req.body);  // req.body = всё
  res.json({ ok: true });
});
```

```javascript
// безопасно
const { displayName, avatarUrl } = req.body;
await User.findByIdAndUpdate(req.user.id, { displayName, avatarUrl });
```

## Как находить endpoint'ы и поля автоматически

Для больших API полезен полуавтоматический подход: собрать все поля из ответов и проверить их на запись.

```bash
# собрать все ключи из JSON-ответов (через прокси-лог)
cat api.log | jq -r 'paths(scalars) | join(".")' | sort -u > fields.txt
# прогнать по каждому PATCH/PUT endpoint
while read ep; do
  for f in role is_admin isPremium balance verified; do
    curl -s -X PATCH "https://api.example.com$ep" \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d "{\"$f\":true}" -o /dev/null -w "$ep $f -> %{http_code}\n"
  done
done < endpoints.txt
```

Так вы системно покрываете поля, а не угадываете.

## Влияние на модель угроз

Mass assignment часто недооценивают, потому что «нужно лишь добавить поле». Но эффект может быть критичным:
- **Захват админки** — `role: admin` даёт доступ к панели управления.
- **Финансовое мошенничество** — изменение `balance`, `withdrawal_limit`.
- **Обход KYC/AML** — `verified: true`, `kyc_status: approved`.
- **Обход бана** — `banned: false`, `status: active`.
- **Доступ к платному** — `subscription: enterprise`.

В отчёте обязательно укажите бизнес-эффект, а не только техническую возможность.

## Квиз

```quiz
- question: "В чём суть mass assignment?"
  options:
    - "Сервер привязывает все присланные клиентом поля, не проверяя право их менять"
    - "Сервер рассылает массовые push-уведомления"
    - "Клиент загружает несколько файлов"
    - "Сервер шифрует базу данных"
  answer: 0
- question: "Почему в мобильном API mass assignment удобнее эксплуатировать?"
  options:
    - "Клиент — APK, из которого видны все поля DTO, и можно слать запросы напрямую"
    - "Мобильные API не используют HTTPS"
    - "Android не поддерживает JSON"
    - "iOS блокирует запросы"
  answer: 0
- question: "Какой обход работает, если фильтр проверяет только верхний уровень?"
  options:
    - "Вложенный объект: {'profile':{'is_admin':true}}"
    - "Отключение TLS"
    - "Смена User-Agent"
    - "Удаление cookies"
  answer: 0
- question: "Как корректно защититься от mass assignment?"
  options:
    - "Allowlist изменяемых полей + валидация схемы на сервере"
    - "Скрыть поля в APK"
    - "Использовать HTTP вместо HTTPS"
    - "Увеличить таймаут"
  answer: 0
```

## Где пригодится

- **Bug bounty:** эскалация привилегий и обход платежей в API мобильных приложений.
- **Пентест:** аудит серверной стороны мобильного продукта.
- **Работа:** безопасная реализация API для мобильного клиента.
