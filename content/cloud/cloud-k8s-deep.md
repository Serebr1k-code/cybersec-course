---
id: cloud-k8s-deep
title: "Модуль: Kubernetes глубоко"
category: cloud
parent: cloud-kubernetes-rbac
difficulty: expert
order: 4
tags: [cloud, kubernetes, kubelet, networkpolicy, csi, operator, module]
prerequisites: [cloud-kubernetes-rbac]
useful_for:
  - "Пентест кластеров Kubernetes"
  - "Атаки на kubelet, CSI и операторы"
  - "Подготовка к CKS"
estimated_minutes: 20
summary: "Подмодуль Kubernetes: kubelet API, обход NetworkPolicy, атаки на CSI/storage и злоупотребление операторами и CRD."
---

Этот подмодуль — часть ветки Kubernetes. Базовый урок `cloud-kubernetes-rbac` дал RBAC, SA-токены и побег из пода. Здесь мы разбираем компоненты, которые обычно остаются незамеченными: kubelet, сетевые политики, CSI и операторы.

## Что покрывает подмодуль

1. **Kubelet API** (`cloud-k8s-kubelet`) — порты 10250/10255, анонимный доступ, exec и логи.
2. **NetworkPolicy** (`cloud-k8s-networkpolicy`) — обход изоляции, DNS-туннели и lateral movement.
3. **CSI и storage** (`cloud-k8s-csi`) — снапшоты, PV, кража данных и hostPath через драйверы.
4. **Операторы и CRD** (`cloud-k8s-operator`) — злоупользование контроллерами и кастомными ресурсами.

## Почему такой порядок

Kubelet — самый частый источник анонимного RCE/чтения. Затем — сеть: даже с доступом внутрь пода нужен путь к другим сервисам. Дальше — storage: там данные. Операторы завершают подмодуль, потому что их привилегии часто выше, чем кажется, и именно они ломают модель наименьших привилегий.

## Как проходить

- Держите под рукой `kubectl`, `curl` к kubelet и инструменты вроде `kubeletctl`.
- Проверяйте каждый шаг в тестовом кластере (kind/minikube) — не на боевом.
- Обратите внимание на раздел «Защита и детект»: CKS любит именно эти вопросы.

## Чему вы научитесь

- Эксплуатировать открытый kubelet и превращать его в RCE.
- Обходить NetworkPolicy легитимными механизмами.
- Использовать CSI-драйверы для доступа к данным узла.
- Находить опасные CRD и операторы с избыточными правами.

## Квиз

```quiz
- question: "Чем опасен открытый kubelet на порту 10250?"
  options:
    - "Через него можно выполнять команды в подах и читать логи"
    - "Он только отдаёт метрики"
    - "Он шифрует трафик"
    - "Он управляет биллингом"
  answer: 0
  explanation: "Kubelet API позволяет exec/logs/port-forward; при слабой аутентификации это RCE в поде."
- question: "Почему NetworkPolicy не всегда защищает?"
  options:
    - "Её обходят через разрешённые каналы (DNS, kubelet, hostNetwork) или не покрывают все поды"
    - "Она не существует"
    - "Она работает только в AWS"
    - "Она шифрует данные"
  answer: 0
  explanation: "Политики применяются не ко всем трафикам и часто не покрывают DNS/метаданные."
- question: "Чем опасны операторы с избыточными правами?"
  options:
    - "Они действуют с широкими RBAC-правами от имени кластера"
    - "Они только рисуют графики"
    - "Они не имеют доступа к API"
    - "Они ускоряют сборку"
  answer: 0
  explanation: "Оператор — привилегированный контроллер; компрометация его CRD даёт его права."
```

## Где пригодится

- **Пентест:** кластеры Kubernetes и managed-кластеры (EKS/AKS/GKE).
- **Red team:** lateral movement внутри кластера.
- **CTF:** задачи Kubernetes.
- **Сертификация:** Certified Kubernetes Security Specialist (CKS).
