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

## Зачем этот урок

Операторы — это контроллеры, которые расширяют Kubernetes: они смотрят на **кастомные ресурсы (CRD)** и приводят реальный мир в соответствие с их состоянием. Оператор запускается под **service account с широкими правами** (часто `cluster-admin`), потому что ему нужно создавать поды, секреты, роли, облачные ресурсы. Для атакующего это золотая жила: если вы можете **создать или изменить CR**, оператор обработает его и выполнит привилегированное действие от своего имени. Это «confused deputy» в чистом виде. Этот урок — про устройство операторов, поиск избыточных прав и практические цепочки эскалации через CRD.

## Как устроены операторы и CRD

- **CRD (CustomResourceDefinition)** — описание нового типа ресурса (`kind: MyApp`). После установки CRD в кластере появляется новый API-ресурс.
- **CR (Custom Resource)** — экземпляр этого типа (`kubectl get myapps`).
- **Controller/Operator** — процесс, который `watch`-ит CR и реагирует: создаёт/обновляет/удаляет стандартные ресурсы (Deployment, Service, Secret, RoleBinding).
- **Reconciliation loop** — «желаемое состояние» из CR → «фактическое» в кластере.
- **Admission webhooks** — оператор может регистрировать validating/mutating webhook.

Типовые операторы: cert-manager (сертификаты), external-secrets (секреты из внешних хранилищ), Crossplane (облачные ресурсы), ArgoCD (GitOps), Prometheus Operator, Elastic Operator, клауд-специфичные (AWS Controllers for Kubernetes, GCP Config Connector).

Опасности:

- Оператор с `cluster-admin` реагирует на CR, который может создать обычный пользователь.
- CR содержит поля, влияющие на создаваемые ресурсы (образ, serviceAccount, volume, command).
- `external-secrets` создаёт Secret из внешнего хранилища — если вы контролируете `ExternalSecret`, вы можете вытянуть любой секрет, к которому у оператора есть доступ.
- `Crossplane` создаёт облачные ресурсы — CR может создать IAM-роль, бакет, VM.
- Оператор с правом на `roles`/`rolebindings` может выдать вам права.
- Webhook-мисконфиги: `failurePolicy: Ignore` или отсутствие TLS-проверки.

## Инструменты и команды

Разведка CRD и операторов:

```bash
kubectl get crd
kubectl api-resources --api-group=<group>
kubectl get crd -o json | jq -r '.items[] | "\(.metadata.name) scope=\(.spec.scope)"'

# Какие операторы запущены и под каким SA
kubectl get pods -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name) sa=\(.spec.serviceAccountName)"' | grep -iE 'operator|controller|cert-manager|external-secrets|argocd|crossplane'
```

Права оператора:

```bash
SA=cert-manager
NS=cert-manager
kubectl get clusterrolebinding -o json | jq -r --arg sa "$SA" '.items[] | select(.subjects[]?.name==$sa) | .roleRef.name'
# Если это cluster-admin — оператор всемогущ
kubectl get clusterrole <role> -o json | jq '.rules'
```

Проверка CRD, которые вы можете создавать:

```bash
kubectl auth can-i create myapps.example.com
kubectl auth can-i create externalsecrets.external-secrets.io
kubectl auth can-i create composite resources
```

## Разобранный пример: от CR к секретам через external-secrets

Сценарий: в кластере установлен `external-secrets`, его SA имеет доступ к внешнему хранилищу (например, AWS Secrets Manager или Vault), а вы можете создавать `ExternalSecret` в своём namespace.

Шаг 1 — проверяем возможность:

```bash
kubectl auth can-i create externalsecrets.external-secrets.io -n attacker
# yes
kubectl get crd | grep external-secrets
# externalsecrets.external-secrets.io
```

Шаг 2 — создаём `ExternalSecret`, ссылающийся на секрет в внешнем хранилище:

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

Шаг 3 — оператор (с его правами) читает секрет из внешнего хранилища и создаёт Kubernetes Secret `stolen-secret` в вашем namespace:

```bash
kubectl apply -f es.yaml
sleep 5
kubectl get secret stolen-secret -n attacker -o jsonpath='{.data.password}' | base64 -d
```

Шаг 4 — если оператор имеет доступ ко **всем** секретам внешнего хранилища, вы можете вытянуть любые — это классическая эскалация через confused deputy.

Шаг 5 — аналогично с другими операторами:

- **Crossplane:** создайте CR, который создаёт IAM-роль/пользователя с широкими правами в облаке.
- **cert-manager:** CR `Certificate` с `issuerRef` на привилегированный Issuer может выпустить сертификат с произвольным CN.
- **ArgoCD:** `Application` с произвольным репозиторием → деплой вашего кода в кластер.
- **Prometheus Operator:** CR может смонтировать секрет/ConfigMap в привилегированный под.

## Варианты атак и обходы

- **CR, влияющий на образ.** Если оператор создаёт Deployment из полей CR, подставьте свой образ → выполнение кода.
- **CR, влияющий на serviceAccount.** Если CR позволяет указать `serviceAccountName`, используйте привилегированный SA.
- **CR, создающий RoleBinding.** Оператор может выдать вам права.
- **CR, читающий секреты.** external-secrets, sealed-secrets, vault-operator.
- **Webhook-мисконфиг.** `failurePolicy: Ignore` позволяет обойти валидацию; отсутствие `caBundle`-проверки — подмена.
- **Operator status leaks.** Некоторые операторы пишут чувствительные данные в `.status` CR.
- **Reconcile loops.** Массовое создание CR может перегрузить оператор (DoS) — не делайте без согласования.
- **Finalizers.** CR с finalizer может застрять; иногда используется для DoS.
- **Cross-namespace references.** Оператор может читать CR/Secret в других namespace, расширяя ваши возможности.

## Частые ошибки и подводные камни

- **Считать CRD безобидным.** CRD — это API, а оператор — привилегированный исполнитель.
- **Не проверять SA оператора.** Именно его права определяют, что вы можете сделать.
- **Игнорировать `ClusterSecretStore`/`SecretStore`.** Они определяют, к каким внешним хранилищам имеет доступ оператор.
- **Путать validating и mutating webhook.** Первый отклоняет, второй меняет объект — у них разные слабости.
- **Забывать про scope CRD.** Cluster-scoped CR могут создавать ресурсы в любом namespace.
- **Пробовать destructive CR.** Некоторые CR удаляют ресурсы — согласуйте.

## Защита и детект

- **Минимум прав оператора.** Не давайте `cluster-admin`; ограничивайте `create` на конкретные ресурсы и namespace.
- **RBAC на CRD.** Не позволяйте обычным пользователям создавать CR, влияющие на привилегированные ресурсы.
- **Ограничьте внешние хранилища.** Оператор external-secrets должен иметь доступ только к нужным путям/секретам, не ко всему хранилищу.
- **Webhook с `failurePolicy: Fail`** и корректным TLS.
- **Детект.** Audit logs: создание CR, изменения RBAC, создание Deployment из оператора. Алерты на `create externalsecrets` в неожиданных namespace, на новые CR, ведущие к привилегированным SA. Falco может детектить подозрительные действия операторов.
- **Pod Security Standards** и ограничение образов (admission).

## GitOps-операторы: ArgoCD, Flux и их поверхность

GitOps-операторы заслуживают отдельного внимания, потому что они **деплоят код** и часто имеют широкие права:

- **ArgoCD.** `Application` описывает источник (Git-репозиторий) и назначение (кластер/namespace). Если вы можете создать `Application`, вы можете указать **свой** репозиторий с манифестами и заставить ArgoCD задеплоить их — включая привилегированные поды, RBAC и CRD. ArgoCD также хранит креды репозиториев и кластеров; его API/UI — отдельная цель.
- **Flux.** `GitRepository` + `Kustomization`; аналогичная модель. Если вы контролируете источник, вы контролируете деплой.
- **ArgoCD Projects/AppProjects.** Ограничивают, какие репозитории и namespace доступны; слабый Project = широкий деплой.
- **ApplicationSet.** Генерирует Application по шаблону; поля-генераторы могут быть инъекцией.
- **Repo credentials.** Секреты Git в namespace ArgoCD; если у вас есть к ним доступ — вы можете изменить источник и «легитимно» задеплоить код.

Практический сценарий: вы нашли `kubectl auth can-i create applications.argoproj.io -n argocd` = yes. Создаёте `Application`, указывающий на ваш публичный Git-репозиторий с `DaemonSet`, который монтирует hostPath и запускает reverse shell. ArgoCD синхронизирует его и разворачивает от своего имени — привилегированный код в кластере. Это одна из самых чистых эскалаций через операторы.

## Практический чек-лист аудита операторов

1. Список CRD и соответствующих операторов (`kubectl get crd`, pods с `operator/controller`).
2. Для каждого оператора — его SA и привязанные роли (особенно `cluster-admin`).
3. Какие CR вы можете создавать (`kubectl auth can-i create <crd>`), включая cluster-scoped.
4. Поля CR, влияющие на создаваемые ресурсы: образ, `serviceAccountName`, volume, command, env.
5. Ссылки на внешние хранилища (SecretStore, ClusterSecretStore, репозитории Git).
6. Webhooks: `failurePolicy`, TLS, что валидируется.
7. Cross-namespace/cluster-scoped доступ оператора.
8. GitOps: проекты, репозитории, права на Application/Kustomization.
9. `.status` CR — нет ли там утечек секретов.
10. Finalizers и потенциальный DoS.

Этот чек-лист отделяет «безобидные» CRD от тех, через которые можно получить выполнение кода или секреты, и указывает, какие поля CR нужно использовать для эскалации.

## Итог: оператор как привилегированный исполнитель

Главная мысль урока: оператор — это привилегированный исполнитель, который реагирует на **ваши** объекты. Поэтому вопрос не «что я могу», а «что оператор сделает, если я создам такой CR». Ответ определяется его SA и логикой reconcile. Если вы научитесь читать CRD-схемы и права операторов, вы найдёте путь от обычного права `create` на кастомный ресурс до выполнения кода или чтения секретов. Это один из самых «чистых» путей эскалации в Kubernetes, потому что он не требует ломать RBAC — вы используете легитимный механизм по назначению.

## Что дальше / решение

Операторы — это «confused deputy»: они действуют от имени привилегированного SA по вашей заявке (CR). Начните с инвентаризации CRD и операторов, определите SA и их права, затем — какие CR вы можете создавать. Если оператор читает секреты, создаёт поды или облачные ресурсы, CR становится вектором эскалации. Проверьте webhook-мисконфиги и cross-namespace доступ. Эксплуатируйте минимально инвазивно (создание CR, чтение результата), избегая destructive-полей. Записывайте найденные операторы, их права и достигнутый результат как отдельные находки.

## Квиз

```quiz
- question: "Почему оператор — цель для эскалации?"
  options:
    - "Он действует от имени привилегированного SA, реагируя на ваши CR"
    - "Он не имеет прав"
    - "Он только читает логи"
    - "Он работает вне кластера"
  answer: 0
  explanation: "Оператор reconcile-ит CR и создаёт ресурсы с правами своего SA."
- question: "Что делает external-secrets при создании ExternalSecret?"
  options:
    - "Читает секрет из внешнего хранилища и создаёт Kubernetes Secret"
    - "Удаляет секреты"
    - "Создаёт NetworkPolicy"
    - "Меняет RBAC"
  answer: 0
  explanation: "Оператор подтягивает секрет из внешнего хранилища в кластер."
- question: "Чем опасен webhook с failurePolicy: Ignore?"
  options:
    - "Валидация может быть пропущена при недоступности webhook"
    - "Он ускоряет работу"
    - "Он шифрует данные"
    - "Он создаёт CRD"
  answer: 0
  explanation: "Ignore позволяет объекту пройти, если webhook недоступен."
- question: "Как найти права оператора?"
  options:
    - "Проверить его service account и привязанные ClusterRole/ClusterRoleBinding"
    - "Посмотреть логи пода"
    - "Прочитать ConfigMap"
    - "Выполнить kubectl top"
  answer: 0
  explanation: "Права определяются SA оператора и его rolebindings."
```

## Где пригодится

- **Пентест:** платформенные кластеры с операторами.
- **Red team:** эскалация через CRD.
- **Blue team:** аудит прав операторов и RBAC на CRD.
- **Сертификация:** CKS.
