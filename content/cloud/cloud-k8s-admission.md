---
id: cloud-k8s-admission
title: "Admission-контроллеры Kubernetes: OPA, Kyverno и обход политик"
category: cloud
parent: cloud-kubernetes-rbac
difficulty: expert
order: 2
tags: [cloud, kubernetes, admission, opa, kyverno, pod-security, policy, bypass]
prerequisites: [cloud-kubernetes-rbac, cloud-kubernetes-escape]
useful_for:
  - "Понимание, как кластер ограничивает поды"
  - "Обход admission-политик"
  - "Аудит политик безопасности k8s"
estimated_minutes: 40
summary: "Как работают admission-контроллеры, Pod Security Standards и политики OPA/Kyverno. Классы обхода и практические приёмы, когда политика разрешает больше, чем кажется."
---
## Зачем этот урок

Admission-контроллеры — последний рубеж перед созданием ресурса в кластере. Они решают, попадёт ли под/деплой в кластер. Если политики настроены неверно, атакующий обходит их и запускает привилегированный под. Разберём цепочку admission, Pod Security Standards, классы обхода и защиту.

## Где находится admission в цепочке

Запрос к API-серверу: authentication → authorization (RBAC) → admission (mutating → validating) → etcd. Admission может изменять объект (mutating: мутирует, например добавляет sidecar) или отклонять (validating: webhook, PSA). Если RBAC разрешает `create pods`, но PSA блокирует privileged — под не создастся.

## Уровни Pod Security Standards

| Уровень | Что запрещено |
|---------|---------------|
| privileged | ничего (всё разрешено) |
| baseline | privileged, hostPath, hostPID/Network, лишние capabilities |
| restricted | всё из baseline + non-root, seccomp, readOnlyRootFilesystem |

Namespace помечается: `pod-security.kubernetes.io/enforce=restricted`. Проверка:
```bash
kubectl get ns --show-labels | grep pod-security
kubectl label --dry-run=server ns default pod-security.kubernetes.io/enforce=restricted
```

## Классы обхода

- **Namespace без метки** — если PSA применяется только к части namespace, создайте под в непомеченном.
- **Привилегированный ServiceAccount с exempt** — `admissionregistration` может исключать system-namespaces.
- **Mutating webhook с ошибкой** — `failurePolicy: Ignore` пропускает объект при недоступности webhook.
- **Право `update` на namespace** — можно снять метку PSA.
- **Создание pod через другой контроллер** (Deployment/CronJob) — политика та же, но легко забыть про aggregator-API.

## Разобранный пример: обход через исключение namespace

1. PSA enforce=restricted на namespace `prod`, но `kube-system` исключён.
2. Имея `create pods` в `kube-system` (через широкий RBAC), запускаем privileged под:
```bash
kubectl -n kube-system run pwn --image=alpine --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"pwn","image":"alpine",
  "securityContext":{"privileged":true},"command":["sleep","100000"]}]}}'
```
3. Через privileged под выходим на ноду.

## Mutating/Validating порядок

Сначала все mutating webhook (в порядке, затем по алфавиту), потом validating. Если mutating добавляет securityContext после проверки — возможна рассинхронизация. Проверяйте `kubectl get mutatingwebhookconfigurations -o yaml` на `failurePolicy: Ignore` и `namespaceSelector`.

## Проверка покрытия политик

```bash
kubectl get psp                      # legacy, до 1.25
kubectl get podsecuritypolicies
kubectl get validatingwebhookconfigurations
kubectl auth can-i create pods --as=system:serviceaccount:default:default -n prod
kubectl get rolebindings -A -o wide | grep -i admin
```

## Защита

- PSA enforce=restricted на всех пользовательских namespace.
- Не давать `create pods`/`update ns` вне доверенных SA.
- Webhook `failurePolicy: Fail` для критичных политик.
- OPA/Gatekeeper/Kyverno для гибких правил.
- Аудит admission-отказов.

## Частые ошибки

- Полагаться только на RBAC, забывая про PSA.
- Оставлять system-namespaces без контроля.
- `failurePolicy: Ignore` на security-webhook.
- Не проверять, какие namespace исключены.
- Забывать про aggregator API и контроллеры.

## Что дальше / решение

Убедившись, что PSA закрыт, ищите обход через права на namespace/webhook. Если нашли — запускайте привилегированный под и переходите к побегу (`cloud-kubernetes-escape`). Для защиты — централизованные политики и мониторинг.

## OPA, Gatekeeper и Kyverno

Помимо PSA, политики задают:
- **Gatekeeper** (OPA) — `ConstraintTemplate` + `Constraint`.
- **Kyverno** — политики на YAML, mutate/validate/generate.
Проверка покрытия:
```bash
kubectl get constrainttemplates
kubectl get constraints -A
kubectl get clusterpolicies   # Kyverno
kubectl get clusterpolicyreport -A
```
Если constraint не привязан к нужным namespace или в `match` ошибка — политика не работает.

## Разобранный пример 2: обход через mutating webhook

Webhook с `failurePolicy: Ignore` и `namespaceSelector`, исключающим `default`. Атакующий создаёт под в `default` с privileged — webhook недоступен → под создаётся. Проверка:

```bash
kubectl get mutatingwebhookconfigurations -o json | \
  jq '.items[] | {name:.metadata.name, fail:.webhooks[].failurePolicy, ns:.webhooks[].namespaceSelector}'
```

## Практика: проверка, что privileged не пройдёт

```bash
kubectl -n default run test --image=alpine --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"t","image":"alpine",
  "securityContext":{"privileged":true}}]}}'
# Error from server (Forbidden): pods "test" is forbidden:
# violates PodSecurity "restricted:latest": privileged
```

Если под создался — политика не покрывает namespace.

## Таблица классов обхода

| Обход | Условие | Защита |
|-------|---------|--------|
| Непомеченный ns | PSA не глобальный | enforce на всех ns |
| failurePolicy Ignore | webhook недоступен | Fail для security |
| update namespace | RBAC широкий | запрет update ns |
| system-namespace exempt | исключения в admission | ограничить RBAC |
| aggregator API | забытые контроллеры | аудит всех путей create |

## Практическое задание

Разверните kind-кластер, включите PSA enforce=restricted на namespace `app`, затем попробуйте создать privileged-под — он должен быть отклонён. Снимите метку (`kubectl label ns app pod-security.kubernetes.io/enforce-`) при наличии прав и повторите — под создастся. Это демонстрирует, что RBAC и PSA — независимые рубежи, и компромисс любого из них ломает защиту.

Проверьте также, какие namespace исключены из webhook, и есть ли у вашего SA право `update` на namespace.

## Как PSA взаимодействует с RBAC

RBAC отвечает на вопрос «можешь ли ты вызвать create pods», а PSA — «соответствует ли под политике». Это независимые проверки. Поэтому слабый RBAC (лишние `create pods` у сервис-аккаунта) сам по себе не даёт побега, если PSA закрыт. И наоборот: строгий RBAC не спасёт, если PSA не покрывает namespace. Аудируйте оба слоя отдельно.

```bash
kubectl auth can-i create pods --as=system:serviceaccount:app:builder -n app
kubectl get ns app -o jsonpath='{.metadata.labels}'
```

## Практика: разница между уровнями

Создайте три namespace с разными уровнями (`privileged`, `baseline`, `restricted`) и попробуйте один и тот же манифест в каждом. Вы увидите, что baseline блокирует privileged и hostPath, а restricted дополнительно требует non-root и seccomp. Это поможет быстро определять, какой уровень где стоит в реальном кластере, и искать namespace без меток — самую частую дыру.

## Разница между PSA и PSP (legacy)

PodSecurityPolicy (PSP) был удалён в Kubernetes 1.25. До этого он был отдельным admission-плагином, требовавшим RBAC-привязки. Его главная проблема — сложность: легко было забыть привязать PSP, и тогда политика не действовала. PSA заменил его, перенеся контроль на метки namespace. Если вы встречаете кластер < 1.25, проверяйте `kubectl get psp` и `kubectl get clusterrole | grep psp`. Для атакующего мигрированный кластер безопаснее: PSA сложнее «забыть», потому что он применяется автоматически по метке namespace.

## Связка с аудитом API-сервера

Admission-отказы фиксируются в audit-логах API-сервера. Настройте политику аудита так, чтобы записывались `create`/`update` pod-ресурсов и решения admission. Тогда вы увидите, кто и когда пытался создать privileged-под и был ли он отклонён. Это ключевой источник для IR: без audit-логов попытка обхода PSA остаётся невидимой, и вы не узнаете, что защита сработала.

## Быстрая проверка покрытия

```bash
kubectl get ns --show-labels | grep pod-security
kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations
kubectl get constrainttemplates
```

Если namespace без метки PSA или webhook с `failurePolicy: Ignore` — это дыра. Проверяйте оба механизма до попытки создания привилегированного пода.

## Квиз

```quiz
- question: "Какие три уровня задаёт Pod Security Admission?"
  options:
    - "low/medium/high"
    - "privileged/baseline/restricted"
    - "open/closed/mixed"
    - "dev/test/prod"
  answer: 1
  explanation: "PSA использует уровни privileged, baseline и restricted."
- question: "Где чаще всего находят ослабленный admission-режим?"
  options:
    - "В /etc/hosts"
    - "В системных/служебных namespace с исключениями политик"
    - "В DNS"
    - "В Service"
  answer: 1
  explanation: "Системные namespace часто исключены из строгих политик."
- question: "Какая лазейка связана с порядком mutating и validating?"
  options:
    - "Мутация происходит после валидации, добавляя опасные поля"
    - "Валидация всегда после мутации"
    - "Они выполняются одновременно"
    - "Порядок не важен"
  answer: 0
  explanation: "Если валидатор смотрит до финальной мутации, опасные поля могут проскочить."
- question: "Почему ephemeral containers (kubectl debug) интересны для обхода?"
  options:
    - "Они быстрее"
    - "Политики могут не покрывать их так же строго, как обычные контейнеры"
    - "Они не создаются"
    - "Они требуют root"
  answer: 1
  explanation: "Политики часто забывают про ephemeral-контейнеры."
- question: "Что из перечисленного политика может упустить, проверяя только containers?"
  options:
    - "metadata"
    - "initContainers и ephemeral containers"
    - "labels"
    - "annotations"
  answer: 1
  explanation: "initContainers и ephemeral-контейнеры — частая слепая зона политик."
```

## Где пригодится

- **Пентест Kubernetes** — обход политик безопасности.
- **Red team** — от низких прав к привилегированному поду.
- **IR/Blue team** — аудит покрытия политик.
- **DevSecOps** — написание корректных OPA/Kyverno-политик.
- **Сертификации** — CKS (Certified Kubernetes Security Specialist).
