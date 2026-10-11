---
id: cloud-k8s-networkpolicy
title: "NetworkPolicy: обход изоляции и lateral movement"
category: cloud
parent: cloud-k8s-deep
difficulty: expert
order: 2
tags: [cloud, kubernetes, networkpolicy, lateral-movement, cni, dns]
prerequisites: [cloud-k8s-deep, cloud-kubernetes-rbac]
useful_for:
  - "Lateral movement внутри кластера"
  - "Оценка сетевой изоляции Kubernetes"
  - "Пентест managed-кластеров"
estimated_minutes: 50
summary: "Как работают NetworkPolicy в Kubernetes, почему изоляция часто неполная и как обходить её легитимными механизмами: DNS, kubelet, hostNetwork, node network и разрешённые egress-пути."
---

## Зачем этот урок

NetworkPolicy — это механизм сетевой изоляции в Kubernetes: правила, какие поды могут общаться с какими. В теории он ограничивает lateral movement. На практике изоляция часто **неполная**: политики применяются не ко всему, CNI может их игнорировать, а разрешённые каналы (DNS, kubelet, node network) дают обход. Пентестеру важно понимать, что «есть NetworkPolicy» ≠ «изолировано», и уметь находить пути обхода. Этот урок — про семантику NetworkPolicy, типовые дыры и практические приёмы продвижения внутри кластера.

## Как устроена NetworkPolicy

Ключевая семантика:

- **Если нет ни одной NetworkPolicy, применённой к поду, весь трафик разрешён** (default allow all). Изоляция начинается только с первой политики.
- Политика применяется к подам по `podSelector`. `policyTypes: [Ingress]` открывает только ingress-правила, **egress остаётся разрешён**. `policyTypes: [Ingress, Egress]` контролирует оба.
- `namespaceSelector` и `podSelector` выбирают источники/назначения. `ipBlock` — CIDR.
- Политики **аддитивны**: если хотя бы одна разрешает трафик, он проходит.

Отсюда типовые дыры:

- Egress не ограничен (policyTypes только Ingress) → под может ходить куда угодно.
- Нет политики для `kube-system` → CoreDNS доступен всем, DNS-туннелирование.
- Нет политики для доступа к kubelet (10250) → обход через `/exec`.
- `hostNetwork: true` поды обходят pod-сеть.
- Доступ к node network и metadata (`169.254.169.254`) не закрыт.
- CNI не поддерживает NetworkPolicy (например, некоторые конфигурации) → политики игнорируются.

## Инструменты и команды

Разведка политик:

```bash
kubectl get networkpolicy -A
kubectl describe networkpolicy -n default
kubectl get pods -A -o wide   # какие поды где, hostNetwork?

# Поды с hostNetwork
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.hostNetwork==true) | "\(.metadata.namespace)/\(.metadata.name)"'
```

Анализ изоляции:

```bash
# Cyclonus / netpol-analyzer для проверки, что реально разрешено
netpol-analyzer list --dir . --output-file -
# Или вручную: смотрим, какие egress-правила есть
kubectl get networkpolicy -A -o json | jq '.items[] | {name:.metadata.name,ingress:.spec.ingress,egress:.spec.egress,types:.spec.policyTypes}'
```

Проверка достижимости изнутри пода:

```bash
# DNS
nslookup kubernetes.default.svc.cluster.local
# API-сервер
curl -sk https://kubernetes.default.svc/api
# kubelet
curl -sk https://<node-ip>:10250/pods
# metadata
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/
# Другой namespace
curl -s http://<service>.<namespace>.svc.cluster.local/
```

## Разобранный пример: обход изоляции через DNS и kubelet

Сценарий: вы в поде `default/attacker`, применена политика, разрешающая только ingress и egress к своему namespace. Цель — дойти до `monitoring`.

Шаг 1 — смотрим, что разрешено:

```bash
kubectl get networkpolicy -n default -o yaml
# policyTypes: [Ingress]   ← egress не ограничен!
```

Раз egress не ограничен, вы можете инициировать соединения куда угодно (при условии, что на той стороне нет запрещающего ingress).

Шаг 2 — проверяем DNS. CoreDNS в `kube-system` обычно доступен всем; через DNS можно резолвить имена и, при желании, туннелировать данные:

```bash
nslookup prometheus.monitoring.svc.cluster.local
# Address: 10.96.45.12
```

Шаг 3 — пробуем подключиться к целевому сервису. Если у `monitoring` нет ingress-политики (default allow), соединение пройдёт:

```bash
curl -s http://prometheus.monitoring.svc.cluster.local:9090/api/v1/targets | head
```

Шаг 4 — если целевой под изолирован, ищем обход: доступ к **kubelet** на узле (10250) часто не покрыт политикой, потому что это node-порт, а не pod-сервис. Через kubelet можно exec в целевой под:

```bash
curl -sk https://<node-ip>:10250/pods | jq -r '.items[].metadata.name'
curl -sk -X POST "https://<node-ip>:10250/run/monitoring/prometheus-0/prometheus" -d "cmd=id"
```

Шаг 5 — node network и metadata. Поды без egress-ограничений часто достигают `169.254.169.254` (IMDS) и внутренних узловых сервисов; это путь к node IAM-роли (`cloud-metadata-ssrf`).

Шаг 6 — `hostNetwork` поды (часто в `kube-system`: CNI, ingress-контроллер) видят сеть узла целиком. Если вы можете exec в такой под (или у вас там есть под), изоляция обходится полностью.

## Варианты атак и обходы

- **Egress не ограничен.** Проверяйте `policyTypes`: только Ingress означает свободный исходящий трафик.
- **DNS-туннелирование.** CoreDNS обычно доступен; через DNS-запросы можно передавать данные и обходить egress-фильтры (особенно если фильтрация по доменам слабая).
- **Kubelet как обход.** 10250 на узле — вне pod-сети; NetworkPolicy его не покрывает.
- **hostNetwork поды.** Полный доступ к сети узла.
- **Node IP и node ports.** Сервисы `NodePort` и метрики узла могут быть доступны с подов.
- **Metadata endpoint.** `169.254.169.254` даёт креды node IAM.
- **Namespace без политик.** Политики применяются выборочно; ищите namespace без изоляции.
- **CNI-различия.** Calico, Cilium, Weave по-разному применяют политики; некоторые игнорируют часть правил.
- **Sidecar/istio mTLS.** Если есть service mesh, политики могут быть на уровне mesh — проверяйте, не обходится ли через порты без mesh.
- **DNS rebinding/rebinding к metadata.** Если egress-фильтр по именам, DNS rebinding обходит.

## Частые ошибки и подводные камни

- **Считать, что политика = изоляция.** Политика без egress не изолирует исходящий трафик.
- **Забывать про `kube-system`.** CoreDNS, CNI, ingress — часто без политик.
- **Игнорировать node-порты.** NetworkPolicy покрывает поды, а не узлы.
- **Путать namespaceSelector и podSelector.** Ошибка в селекторе оставляет трафик открытым.
- **Не проверять CNI.** Некоторые конфигурации не поддерживают NetworkPolicy.
- **Пробовать «в лоб» и сдаваться.** Если прямой путь закрыт, ищите разрешённый канал (DNS, kubelet, hostNetwork).

## Защита и детект

- **Default-deny политика** в каждом namespace (и ingress, и egress), затем явные разрешения.
- **Ограничьте egress**, включая доступ к metadata (169.254.169.254) и node-сети.
- **Политики для kube-system** и доступа к kubelet.
- **Избегайте hostNetwork** для прикладных подов.
- **CNI с поддержкой политик** (Calico/Cilium) и проверкой, что они применяются.
- **Детект.** Cilium/Calico flow logs, Falco (подозрительные соединения), audit logs API-сервера. Алерты на соединения к 10250/169.254.169.254 с подов, на DNS-аномалии, на трафик между namespace вне разрешённых.
- **Service mesh** с mTLS для дополнительного контроля.

## Service mesh, CNI и реальное применение политик

NetworkPolicy — это API-объект; **применяет** его CNI. И здесь кроется разница:

- **Calico** и **Cilium** полноценно поддерживают NetworkPolicy (и расширения — Calico GlobalNetworkPolicy, Cilium CiliumNetworkPolicy). Cilium может работать на уровне eBPF и давать более строгий контроль.
- **Flannel** сам по себе NetworkPolicy не поддерживает; нужен дополнительный контроллер (например, Calico в режиме policy-only).
- **Weave, kube-router** — свои особенности.
- **Managed-кластеры** (EKS с VPC CNI, GKE с Dataplane V2, AKS с Azure CNI) имеют собственные режимы; политики могут применяться по-разному или требовать включения.

Если CNI не применяет политики, они существуют как объекты, но трафик не фильтруется — это классическая ложная уверенность. Проверка: создайте тестовый трафик, который политика должна блокировать, и посмотрите, проходит ли он.

**Service mesh (Istio/Linkerd)** добавляет mTLS и свои политики (AuthorizationPolicy). Но mesh покрывает только трафик **через sidecar-прокси**; трафик в обход sidecar (например, к kubelet, к metadata, к узлу) не контролируется. Поэтому даже при строгом mesh остаются пути обхода — ровно те, что мы разбирали.

## Практический чек-лист оценки изоляции

1. Есть ли NetworkPolicy вообще (`kubectl get networkpolicy -A`)? Если нет — default allow.
2. Для каждой политики — `policyTypes`: ограничен ли egress?
3. Какие namespace **без** политик (`kube-system`, `monitoring`, `default`)?
4. Какие поды имеют `hostNetwork: true`?
5. Доступен ли CoreDNS всем? Можно ли туннелировать через DNS?
6. Доступен ли kubelet (10250) с подов?
7. Доступен ли metadata endpoint (169.254.169.254)?
8. Какой CNI и применяет ли он политики (тест реальным трафиком)?
9. Есть ли service mesh и что он **не** покрывает?
10. Какие egress-пути разрешены (внешний интернет, другие namespace, узлы)?

Этот чек-лист превращает оценку изоляции в конкретные проверки и вскрывает типовые дыры, которые «на бумаге» выглядят закрытыми.

## Диагностика: как доказать обход

На пентесте важно не только найти обход, но и **доказать** его воспроизводимо. Практический метод: используйте два пода — «источник» и «приёмник» — и проверяйте, проходит ли трафик, который политика должна блокировать. Например, запустите в изолированном namespace простой HTTP-сервер (`python3 -m http.server`) в поде-приёмнике, затем из пода-источника сделайте `curl`. Если соединение устанавливается вопреки политике — обход подтверждён. Для kubelet проверьте `curl -sk https://<node-ip>:10250/pods` и наличие ответа. Для metadata — запрос к `169.254.169.254` и наличие/отсутствие ответа. Фиксируйте: имя политики, ожидаемое действие, фактический результат. Такой подход отделяет реальные дыры от предположений и делает находку убедительной для заказчика.

## Что дальше / решение

NetworkPolicy — это ограничение, но не барьер. Начните с чтения политик: какие podSelector, какие `policyTypes`, где их нет. Затем проверьте разрешённые каналы: DNS, kubelet, node-порты, metadata, hostNetwork. Если прямой путь закрыт — используйте обход (kubelet, hostNetwork-под, DNS-туннель). Помните, что цель — не «сломать» политику, а найти путь, который она не покрывает. Записывайте найденные пути lateral movement и поды/узлы, через которые они проходят.

## Квиз

```quiz
- question: "Что происходит, если к поду не применена ни одна NetworkPolicy?"
  options:
    - "Весь трафик разрешён (default allow)"
    - "Весь трафик запрещён"
    - "Разрешён только DNS"
    - "Разрешён только ingress"
  answer: 0
  explanation: "Изоляция начинается только с первой применённой политики; без неё — allow all."
- question: "Что означает policyTypes: [Ingress]?"
  options:
    - "Egress не ограничен"
    - "Ingress не ограничен"
    - "Весь трафик запрещён"
    - "Политика не действует"
  answer: 0
  explanation: "Если egress не указан, исходящий трафик разрешён."
- question: "Почему kubelet — обход NetworkPolicy?"
  options:
    - "Это порт узла, а политики покрывают pod-сеть"
    - "Kubelet шифрует трафик"
    - "Kubelet отключён"
    - "Политики применяются к kubelet"
  answer: 0
  explanation: "NetworkPolicy управляет трафиком подов, а kubelet слушает на узле вне pod-сети."
- question: "Какой под обходит pod-сеть целиком?"
  options:
    - "Под с hostNetwork: true"
    - "Под с двумя контейнерами"
    - "Под с initContainer"
    - "Под с sidecar"
  answer: 0
  explanation: "hostNetwork помещает под в сеть узла, минуя pod-сеть."
```

## Где пригодится

- **Пентест:** lateral movement внутри кластера.
- **Red team:** обход сетевой изоляции.
- **Blue team:** аудит NetworkPolicy и flow logs.
- **Сертификация:** CKS.
