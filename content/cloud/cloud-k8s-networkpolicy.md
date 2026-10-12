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

## Задача

В прошлых уроках мы разобрали, как получить exec в поде. Но получив под, ты ещё не можешь свободно ходить по кластеру: между подами стоят **NetworkPolicy** — правила, какие поды могут с какими общаться. В теории это ограничивает lateral movement. На практике изоляция часто **неполная**.

Цель урока: из пода `default/attacker` дойти до пода в другом namespace, который «должен быть изолирован».

## Данные, с которыми работаем

Мы в поде `default/attacker`. Знаем, что админ настраивал изоляцию. Первым делом читаем, что именно настроено:

```bash
$ kubectl get networkpolicy -n default
NAME        POD-SELECTOR   AGE
allow-web   app=web        5d
$ kubectl get networkpolicy -n default -o jsonpath='{.items[0].spec.policyTypes}'
["Ingress"]
```

Ключевой момент: `policyTypes: ["Ingress"]`. Политика ограничивает только **входящий** трафик (ingress), а **исходящий (egress) не трогает**. Значит, мы можем инициировать соединения куда угодно — вопрос лишь в том, есть ли на той стороне запрещающий ingress.

Это первая большая ошибка конфигурации: **изоляция начинается только с первой применённой политики**, а указание только `Ingress` оставляет egress полностью открытым.

## Шаг 1: разведка через DNS

**CoreDNS** — служба DNS кластера, которая превращает имена вида `service.namespace.svc.cluster.local` в IP. Она живёт в `kube-system` и почти всегда доступна всем подам. Проверяем:

```bash
$ nslookup prometheus.monitoring.svc.cluster.local
Server:		10.96.0.10
Address:	10.96.0.10#53
Name:	prometheus.monitoring.svc.cluster.local
Address: 10.96.45.12
```

DNS отдал нам IP пода в namespace `monitoring`. Уже это — утечка топологии: мы узнали, что там есть сервис `prometheus`, и его адрес.

## Шаг 2: идём на цель

Раз egress не ограничен, пробуем подключиться напрямую. Если у `monitoring` нет ingress-политики (а её нет — там default allow), соединение пройдёт:

```bash
$ curl -s http://prometheus.monitoring.svc.cluster.local:9090/api/v1/targets | jq -r '.data.activeTargets[].labels.job' | head
kubernetes-nodes
kubernetes-pods
```

Мы читаем внутренний API Prometheus из другого namespace. Никакого эксплойта — только неполная политика.

## Шаг 3: если цель всё-таки изолирована — обход через kubelet

Допустим, у `monitoring` есть строгая ingress-политика. Есть канал, который **не покрывается** NetworkPolicy вообще: **kubelet на узле** (`10250`). NetworkPolicy управляет трафиком **подов**, а kubelet слушает на сетевом интерфейсе **узла** — вне pod-сети.

```bash
$ curl -sk https://10.0.1.12:10250/pods | jq -r '.items[] | select(.metadata.namespace=="monitoring") | .metadata.name'
prometheus-0
$ curl -sk -X POST "https://10.0.1.12:10250/run/monitoring/prometheus-0/prometheus" -d "cmd=id"
uid=65534(nobody) gid=65534(nogroup)
```

Мы выполнили команду в изолированном поде через kubelet — в обход политики. Правило «NetworkPolicy = изоляция» ломается о порт узла.

## Полный прогон от начала до конца

1. Прочитали политику → `policyTypes: [Ingress]`, egress свободен.
2. Через DNS узнали IP сервиса в другом namespace.
3. Подключились к нему напрямую — ingress-политики нет.
4. Для изолированной цели зашли через kubelet узла (`10250`).

Плюс два оставшихся канала, о которых стоит помнить:
- **`hostNetwork: true`** помещает под в сеть узла целиком — он обходит pod-сеть и все pod-политики. Такие поды часто в `kube-system` (CNI, ingress-контроллер).
- **metadata endpoint** `169.254.169.254` — сервис метаданных облака. Если egress к нему не закрыт, из пода достаётся node IAM-роль.

## Если не сработало: почему «есть политика» ≠ «изолировано»

Важный слой, который часто забывают: NetworkPolicy — это **объект API**, а применяет его **CNI** — сетевой плагин кластера. Если CNI политики не поддерживает, объект существует, но трафик **не фильтруется**:

- **Calico** и **Cilium** поддерживают полноценно (Cilium — на уровне eBPF).
- **Flannel** сам по себе — нет; нужен дополнительный контроллер.
- **Managed-кластеры** (EKS VPC CNI, GKE Dataplane V2, AKS Azure CNI) имеют свои режимы и иногда требуют включения.

Проверить это можно только **реальным трафиком**: подними в изолированном namespace простой HTTP-сервер и попробуй достучаться. Если соединение проходит вопреки политике — обход подтверждён.

Отдельно — **service mesh** (Istio/Linkerd): он добавляет mTLS и свои `AuthorizationPolicy`, но покрывает только трафик **через sidecar-прокси**. Трафик в обход sidecar (к kubelet, к metadata, к узлу) не контролируется — ровно те пути, что мы разбирали.

## Частые ошибки и подводные камни

- **Считать, что «есть политика» = «изолировано».** Политику применяет CNI; если плагин её не поддерживает, объект существует, а трафик не фильтруется.
- **Читать только `Ingress`.** `policyTypes` без `Egress` оставляет исходящий трафик полностью открытым — самый частый мисконфиг.
- **Забывать про `kube-system`.** CoreDNS, CNI и ingress-контроллер часто живут без политик и служат мостом.
- **Путать `namespaceSelector` и `podSelector`.** Ошибка в селекторе тихо оставляет трафик открытым, хотя «политика есть».
- **Не проверять реальным трафиком.** Единственный способ доказать обход — поднять приёмник и попробовать соединение вопреки правилу.

- **Не смотреть, какой CNI установлен.** Calico и Cilium применяют политики, Flannel сам по себе — нет.
- **Считать service mesh полной защитой.** Istio/Linkerd покрывают только трафик через sidecar; путь к kubelet и metadata остаётся открытым.

- **Не документировать доказательство.** Для отчёта фиксируйте имя политики, ожидаемое действие и фактический результат — так обход отделяется от предположения.

## Что мы теперь знаем

- Без NetworkPolicy — default allow; изоляция начинается с первой политики.
- `policyTypes: [Ingress]` оставляет egress открытым.
- CoreDNS доступен почти всем — источник разведки и канал DNS-туннелирования.
- kubelet (10250) — вне pod-сети, NetworkPolicy его не покрывает.
- `hostNetwork: true` поды обходят pod-сеть целиком.
- metadata `169.254.169.254` даёт креды узла, если egress не закрыт.
- Политику применяет CNI; без поддержки CNI объекты существуют, но трафик не фильтруется.

## На что смотреть дальше

- **k8s-csi**: storage-плагины и снапшоты, ещё один канал к данным.
- **k8s-operator**: контроллеры и CRD, которые могут обойти политики.
- **cloud-metadata-ssrf**: как из egress-канала дойти до кредов облака.

## Квиз

Проверь себя.

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
    - "Kubelet отключён по умолчанию"
    - "Политики применяются к kubelet автоматически"
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
- question: "Почему NetworkPolicy может не действовать, даже если объект создан?"
  options:
    - "Политику применяет CNI; если плагин её не поддерживает, трафик не фильтруется"
    - "Политики работают только ночью"
    - "Их нужно перезапускать вручную"
    - "Они действуют только на DNS"
  answer: 0
  explanation: "NetworkPolicy — объект API, а применяет правила сетевой плагин (CNI)."
```

## Куда дальше

В следующем уроке мы займёмся **CSI и storage в Kubernetes** — снапшотами, PersistentVolume и тем, как через них добраться до данных кластера. А пока главное запомни: **NetworkPolicy — это ограничение, а не барьер**, и путь вперёд всегда лежит через канал, который политика не покрывает.

## Где пригодится

- **Пентест:** lateral movement внутри кластера.
- **Red team:** обход сетевой изоляции.
- **Blue team:** аудит NetworkPolicy и flow logs.
- **Сертификация:** CKS.
