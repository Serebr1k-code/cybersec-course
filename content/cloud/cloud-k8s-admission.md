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

## Задача

В прошлом уроке у нас было право `create pods` — и мы сразу побежали запускать привилегированный под. Но иногда кластер отвечает: **«Forbidden»**. Значит, на пути стоит второй рубеж — **admission-контроллеры**. Они решают, попадёт ли объект в кластер, даже если RBAC разрешил сам вызов. Цель урока: понять, как устроена эта защита, и научиться находить в ней щели.

## Данные, с которыми работаем

У нас по-прежнему под `web-7f9c-abc` и права `create pods` в namespace `prod`. Пробуем самое очевидное — привилегированный под, который даёт побег на ноду:

```bash
$ kubectl -n prod run test --image=alpine --restart=Never \
    --overrides='{"spec":{"containers":[{"name":"t","image":"alpine",
    "securityContext":{"privileged":true}}]}}'
Error from server (Forbidden): pods "test" is forbidden:
violates PodSecurity "restricted:latest": privileged
```

Кластер **отклонил** под. RBAC был не против, но сработала политика **Pod Security Admission** (PSA). Это и есть тема урока.

## Шаг 1: что такое admission и где он в цепочке

Когда ты обращаешься к API-серверу, запрос проходит четыре стадии по порядку:

1. **authentication** — кто ты (SA-токен);
2. **authorization** — RBAC: разрешён ли сам вызов `create pods`;
3. **admission** — можно ли принять **этот конкретный объект**;
4. запись в **etcd**.

Admission-контроллеры бывают двух видов:
- **mutating** — меняют объект (например, дописывают sidecar или `securityContext`);
- **validating** — только одобряют или отклоняют.

Сначала отрабатывают все mutating, потом validating. PSA — это validating: он сверяет под с набором правил и отклоняет несоответствующие.

## Шаг 2: читаем политику — какие уровни и где

PSA применяется к **namespace** по метке. Уровней три:

| Уровень | Что запрещено |
|---------|---------------|
| `privileged` | ничего (всё разрешено) |
| `baseline` | privileged, hostPath, hostPID/Network, лишние capabilities |
| `restricted` | всё из baseline + non-root, seccomp, readOnlyRootFilesystem |

Смотрим, какие namespace чем помечены:

```bash
$ kubectl get ns --show-labels | grep pod-security
prod          pod-security.kubernetes.io/enforce=restricted
app           pod-security.kubernetes.io/enforce=baseline
kube-system   <none>
default       <none>
```

Вот первая щель: `prod` защищён `restricted`, `app` — слабее (`baseline`), а `kube-system` и `default` **вообще без метки**. Непомеченный namespace означает, что PSA к нему не применяется.

## Шаг 3: обходим через непомеченный namespace

Если у нас есть право создавать поды в `default` (RBAC действует по namespace), политика нас там не остановит. Проверяем:

```bash
$ kubectl -n default run pwn --image=alpine --restart=Never \
    --overrides='{"spec":{"containers":[{"name":"pwn","image":"alpine",
    "securityContext":{"privileged":true},"command":["sleep","100000"]}]}}'
pod/pwn created
```

Под создан. Дальше — знакомый побег из прошлого урока: примонтировать `/` ноды и прочитать её файлы.

```bash
$ kubectl -n default exec -it pwn -- chroot /host /bin/sh
```

Вывод простой: **PSA — не глобальная защита, а метка на namespace**. Один namespace без метки обнуляет всю политику.

## Полный прогон от начала до конца

1. Попробовали privileged-под в `prod` → `Forbidden` (PSA restricted).
2. Посмотрели метки namespace → нашли `kube-system` и `default` без метки.
3. Создали privileged-под в `default` → успех.
4. Вышли на ноду через `chroot /host`.

Урок: **RBAC и PSA — независимые рубежи**. RBAC отвечает на «можешь ли ты вызвать create pods», PSA — на «соответствует ли под политике». Ломается любой из двух — защиты нет.

## Если не сработало: другие классы обхода

PSA — не единственный admission. Гибкие политики задают **OPA/Gatekeeper** (`ConstraintTemplate` + `Constraint`) и **Kyverno** (политики на YAML). Вот типовые щели:

| Обход | Условие | Защита |
|-------|---------|--------|
| Непомеченный namespace | PSA не глобальный | enforce на всех ns |
| `failurePolicy: Ignore` | webhook недоступен при сбое | `Fail` для security-webhook |
| `update` на namespace | можно снять метку PSA | запрет `update ns` |
| system-namespace exempt | исключения в admission | ограничить RBAC |
| initContainers / ephemeral | политика проверяет только `containers` | покрывать все типы контейнеров |

Проверяем webhook'и — их `failurePolicy` и селекторы:

```bash
$ kubectl get mutatingwebhookconfigurations -o json | \
    jq '.items[] | {name:.metadata.name, fail:.webhooks[].failurePolicy}'
{ "name": "policy-webhook", "fail": "Ignore" }
```

`Ignore` значит: если webhook недоступен, объект **пропускается**. Атакующий может дождаться сбоя или задеть селектор.

Отдельная лазейка — **порядок мутации и валидации**. Если mutating-webhook дописывает опасное поле **после** того, как валидатор посмотрел объект, оно проскакивает. И `ephemeral`-контейнеры (`kubectl debug`) политики часто не покрывают — их проверяют реже, чем обычные.

## Частые ошибки и подводные камни

- **Полагаться только на RBAC.** RBAC разрешает вызвать `create pods`, а PSA может отклонить сам под — это два независимых рубежа, и смотреть надо оба.
- **Забывать про system-namespace.** `kube-system` часто исключён из строгих политик; туда же ведут многие широкие права.
- **Не проверять `failurePolicy`.** Webhook с `Ignore` пропускает объект при своём сбое — это лазейка, а не защита.
- **Считать, что политика проверяет все контейнеры.** `initContainers` и ephemeral-контейнеры часто выпадают из правил.
- **Пробовать вслепую.** Сначала прочитайте метки namespace и определения webhook'ов — это дешевле и тише, чем серия отклонённых подов.

## Что мы теперь знаем

- Admission — третья стадия после authn/authz; mutating меняет объект, validating отклоняет.
- PSA задаёт уровни `privileged`/`baseline`/`restricted` и применяется **по метке namespace**.
- Namespace без метки — не защищён; это самая частая дыра.
- RBAC и PSA независимы: слабый RBAC не даёт побега при строгом PSA, и наоборот.
- `failurePolicy: Ignore`, право `update ns`, init/ephemeral-контейнеры — типовые обходы.
- Audit-логи API-сервера фиксируют отказы admission — это источник для детекта.

## На что смотреть дальше

- **k8s-image-supply-chain**: как через образ обойти политику и попасть на ноды.
- **runc-escape-deep**: побег из контейнера на уровне рантайма, мимо admission.
- **k8s-falco-bypass**: обход runtime-детекта, когда admission уже пройден.

## Квиз

Проверь себя.

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
    - "В namespace без метки или в системных namespace с исключениями политик"
    - "В DNS-записях"
    - "В объекте Service"
  answer: 1
  explanation: "Системные и непомеченные namespace часто не покрыты строгими политиками."
- question: "Какая лазейка связана с порядком mutating и validating?"
  options:
    - "Мутация происходит после валидации, добавляя опасные поля"
    - "Валидация всегда идёт после мутации"
    - "Они выполняются одновременно"
    - "Порядок не важен"
  answer: 0
  explanation: "Если валидатор смотрит объект до финальной мутации, опасные поля могут проскочить."
- question: "Почему ephemeral-контейнеры (kubectl debug) интересны для обхода?"
  options:
    - "Они запускаются быстрее"
    - "Политики могут не покрывать их так же строго, как обычные контейнеры"
    - "Они вообще не создаются"
    - "Они требуют root-доступ"
  answer: 1
  explanation: "Политики часто забывают про ephemeral-контейнеры."
- question: "Что политика может упустить, проверяя только поле containers?"
  options:
    - "metadata"
    - "initContainers и ephemeral-контейнеры"
    - "labels"
    - "annotations"
  answer: 1
  explanation: "initContainers и ephemeral-контейнеры — частая слепая зона политик."
```

## Куда дальше

В следующем уроке мы поднимемся с уровня одного кластера на уровень управляемых Kubernetes — EKS, AKS и GKE — и посмотрим, как их специфика (node SA, managed identity, метаданные) открывает новые пути. А пока главное запомни: **admission — это рубеж по namespace, а не по кластеру**, и один непомеченный namespace стоит дороже любой стены.

## Где пригодится

- **Пентест Kubernetes** — обход политик безопасности.
- **Red team** — от низких прав к привилегированному поду.
- **IR/Blue team** — аудит покрытия политик.
- **DevSecOps** — написание корректных OPA/Kyverno-политик.
- **Сертификации** — CKS (Certified Kubernetes Security Specialist).
