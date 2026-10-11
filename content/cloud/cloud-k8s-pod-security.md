---
id: cloud-k8s-pod-security
title: "Pod Security Admission: уровни, labels и обход restricted"
category: cloud
parent: cloud-k8s-security-deep
difficulty: hard
order: 2
tags: [cloud, kubernetes, pod-security, psa, pss, admission, restricted, baseline]
prerequisites: [cloud-k8s-security-deep, cloud-kubernetes-rbac]
useful_for:
  - "Обход Pod Security Admission"
  - "Пентест кластеров с PSA"
  - "Понимание ограничений подов"
estimated_minutes: 45
summary: "Pod Security Admission: уровни privileged/baseline/restricted, режимы enforce/audit/warn, labels namespace и version-pinned. Как читать политику и находить обходы."
---

## Зачем этот урок

Pod Security Admission (PSA) — встроенный admission-контроллер Kubernetes, пришедший на смену PodSecurityPolicy. Он применяет стандарты Pod Security Standards (PSS) к namespace по меткам. Для атакующего PSA — это «стена», которая может запретить привилегированные поды, hostPath, hostPID и опасные capabilities. Понимание PSA критично: часто обход находится не в самой политике, а в конфигурации namespace, версии или в другом namespace без метки.

## Модель PSA

- **Уровни**: `privileged` (без ограничений), `baseline` (запрещает опасные поля), `restricted` (baseline + жёсткие требования по securityContext).
- **Режимы**: `enforce` (отклоняет), `audit` (пишет в audit log), `warn` (предупреждение пользователю).
- **Labels namespace**: `pod-security.kubernetes.io/enforce`, `.../audit`, `.../warn`, и `.../<mode>-version` (например, `enforce-version: v1.29`).
- **Default**: кластер может задавать default-уровень через `--admission-control-config-file`.
- **Version pinning**: поведение зависит от версии стандарта — можно использовать более старую версию с известными послаблениями.

Ключевое: PSA действует **на namespace**, а не на отдельный под. Если namespace без метки (или с `privileged`), ограничений нет.

## Инструменты и команды

```bash
# Метки PSA на namespace
kubectl get ns --show-labels | grep pod-security
kubectl get ns prod -o jsonpath='{.metadata.labels}'

# Что именно enforce
kubectl get ns prod -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}'
# restricted

# Проверить, отклоняется ли под (dry-run)
kubectl apply --dry-run=server -f privileged-pod.yaml
# Error from server (Forbidden): pods "evil" is forbidden: violates PodSecurity "restricted:latest"

# Аудит-события PSA
kubectl get events -A --field-selector reason=FailedCreate | grep -i podsecurity

# Какие namespace без меток (потенциально privileged)
kubectl get ns -o json | jq -r '.items[] | select(.metadata.labels["pod-security.kubernetes.io/enforce"] == null) | .metadata.name'
```

## Разобранный пример: поиск namespace без PSA

Сценарий: кластер использует PSA, но не все namespace помечены.

```bash
# 1. Ищем namespace без enforce-метки
kubectl get ns -o json | jq -r '.items[] | select(.metadata.labels["pod-security.kubernetes.io/enforce"] == null) | .metadata.name'
# kube-system
# monitoring
# legacy-apps

# 2. Проверяем, можем ли мы создавать поды в legacy-apps
kubectl auth can-i create pods -n legacy-apps
# yes

# 3. Запускаем привилегированный под там
cat <<'EOF' | kubectl apply -n legacy-apps -f -
apiVersion: v1
kind: Pod
metadata: { name: escape }
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: c
    image: alpine
    securityContext: { privileged: true }
    command: ["sleep","infinity"]
EOF
# pod/escape created
```

Namespace `legacy-apps` без метки PSA = нет ограничений. Даже если в `prod` стоит `restricted`, отсутствие метки в другом namespace открывает путь к привилегированному поду, а оттуда — к побегу на узел.

## Обходы и нюансы

- **Namespace без метки.** Самый простой обход: создать/использовать namespace, где PSA не настроен (default часто `privileged`, если не задан иначе).
- **Смена метки.** Если у вас есть право `update` на namespace, снимите/ослабьте метку. Проверьте `kubectl auth can-i update ns/prod`.
- **Version pinning.** `enforce-version: v1.24` может разрешать то, что запрещено в `v1.29`. Проверяйте версию.
- **Объекты, не подпадающие под PSA.** PSA применяется к Pod и контроллерам (Deployment/Job и т.п.), но не к, например, статическим подам kubelet или к некоторым CRD, создающим поды напрямую.
- **Привилегированные контроллеры.** Если контроллер (DaemonSet, operator) уже привилегированный, используйте его как «лазейку» — измените его spec.
- **Baseline vs restricted.** `baseline` разрешает, например, `hostNetwork`, `hostPort`, некоторые capabilities. Проверьте, какой уровень стоит.

## Чек-лист атаки

1. Инвентаризация меток PSA по namespace.
2. Найти namespace без метки или с `privileged`.
3. Проверить права на создание подов и на изменение namespace.
4. Проверить версию стандарта (version pinning).
5. Проверить существующие привилегированные контроллеры.
6. Проверить, какие поля разрешает текущий уровень (baseline).
7. Проверить default-уровень кластера.

## Обход защит и edge cases

- **Restricted требует**: `runAsNonRoot`, `seccompProfile: RuntimeDefault`, drop ALL capabilities, запрет `privileged`, `hostPath`, `hostPID/Network/IPC`. Обход — искать namespace без restricted.
- **Право update namespace.** Часто недооценивается; проверяйте.
- **Aggregated API / CRD.** Некоторые CRD создают поды в обход PSA.
- **Ephemeral containers.** `kubectl debug` добавляет ephemeral-контейнеры; PSA проверяет их, но некоторые старые версии — нет.
- **Init-контейнеры.** Проверяются, но конфигурация может отличаться.
- **kube-system.** Часто privileged; если есть доступ — прямая лазейка.

## Частые ошибки и подводные камни

- Считать, что «restricted стоит везде»: проверяйте каждый namespace.
- Не проверить права на изменение namespace-метки.
- Игнорировать version pinning.
- Забыть про CRD/агрегированные API.
- Путать режимы enforce/audit/warn.

## Защита и детект

- Пометить ВСЕ namespace (включая kube-system) уровнем не ниже baseline; prod — restricted.
- Запретить изменение меток namespace для непривилегированных ролей.
- Использовать актуальную версию стандарта (без pinning на старую).
- Аудит: PSA-события, `kubectl get events`; алертить на создание привилегированных подов.
- Дополнительно — Kyverno/OPA для политик, которые PSA не покрывает.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — namespace без метки. Второй — `privileged` в kube-system с доступом. Третий — права update на namespace. Четвёртый — version pinning на старую версию. Пятый — CRD, создающий поды. Все они позволяют обойти PSA.

## Практическое задание

1. Помечайте namespace `restricted` и попробуйте создать привилегированный под — получите ошибку.
2. Создайте namespace без метки и создайте тот же под — успех.
3. Выдайте роль с правом update namespace и снимите метку.
4. Настройте default-уровень кластера и проверьте.

## Что дальше / решение

Обход PSA открывает путь к привилегированному поду и побегу. Дальше — nsenter/hostPath (см. урок про runc). Зафиксируйте путь «namespace без метки → привилегированный под → узел» в графе. Если все namespace помечены строго — ищите CRD/контроллеры или CVE.

## Разобранный пример 2: version pinning и baseline

Версия стандарта влияет на то, что разрешено. `enforce-version: v1.24` может разрешать поля, запрещённые в `v1.29`. А уровень `baseline` (в отличие от `restricted`) разрешает, например, `hostNetwork`, `hostPort` и некоторые capabilities.

```bash
# Смотрим версию стандарта
kubectl get ns prod -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce-version}'
# v1.24

# Проверяем, какие поля разрешает baseline
kubectl label ns test pod-security.kubernetes.io/enforce=baseline --overwrite
# Затем пробуем под с hostNetwork: true -> допускается baseline
cat <<'EOF' | kubectl apply -n test -f -
apiVersion: v1
kind: Pod
metadata: { name: hostnet }
spec:
  hostNetwork: true
  containers: [{ name: c, image: alpine, command: ["sleep","infinity"] }]
EOF
# pod/hostnet created
```

`baseline` допускает `hostNetwork`/`hostPort`, что уже даёт доступ к сети хоста и потенциальный перехват трафика. Плюс version pinning на старую версию оставляет известные послабления. Для атакующего: проверьте и уровень, и версию, и наличие default-уровня; часто хотя бы один namespace окажется на `baseline` или без метки.

## Квиз

```quiz
- question: "На каком уровне действует Pod Security Admission?"
  options:
    - "На namespace (по меткам)"
    - "На отдельный под"
    - "На узел"
    - "На контейнер"
  answer: 0
  explanation: "PSA применяет стандарты к namespace через labels."
- question: "Что означает режим enforce?"
  options:
    - "Отклоняет поды, нарушающие стандарт"
    - "Только предупреждает"
    - "Пишет в аудит"
    - "Ничего"
  answer: 0
  explanation: "enforce блокирует; audit/warn — нет."
- question: "Самый простой обход PSA?"
  options:
    - "Использовать namespace без метки PSA"
    - "Отключить KMS"
    - "Сменить образ"
    - "Использовать SSH"
  answer: 0
  explanation: "Без метки namespace ограничения не применяются."
- question: "Что запрещает уровень restricted?"
  options:
    - "privileged, hostPath, hostPID, требует runAsNonRoot и seccomp"
    - "Только привилегированные поды"
    - "Только сеть"
    - "Только образы"
  answer: 0
  explanation: "restricted — самый строгий уровень PSS."
```

## Где пригодится

- **Пентест k8s:** обход admission.
- **Blue team:** настройка PSA.
- **Red team:** поиск namespace-лазейки.
- **Сертификация:** CKS.
