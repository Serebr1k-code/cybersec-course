---
id: cloud-k8s-security-deep
title: "Модуль: Kubernetes — образы, рантайм и политики"
category: cloud
parent: cloud-network-deep
difficulty: expert
order: 4
tags: [cloud, kubernetes, runc, images, pod-security, falco, module]
prerequisites: [cloud-kubernetes-rbac, cloud-k8s-deep]
useful_for:
  - "Пентест Kubernetes-кластеров"
  - "Побег из контейнера и обход политик"
  - "Атаки на supply chain образов"
estimated_minutes: 16
summary: "Подмодуль Kubernetes: supply chain образов, побег через runc, Pod Security Admission и обход Falco. Как от подозрительного образа дойти до хоста."
---

Этот подмодуль — часть ветки «Основы облака → сеть и разведка». Он собирает четыре урока о низкоуровневой безопасности Kubernetes: от образов до рантайма и политик.

## Что покрывает подмодуль

1. **Supply chain образов** (`cloud-k8s-image-supply-chain`) — реестры, подписи, admission по образам и подмена тега.
2. **Побег через runc** (`cloud-runc-escape-deep`) — CVE runc, `nsenter`, capabilities и обход seccomp.
3. **Pod Security Admission** (`cloud-k8s-pod-security`) — PSS/PSA, labels, обход restricted-профиля.
4. **Обход Falco** (`cloud-k8s-falco-bypass`) — как снизить детектируемость runtime-мониторинга.

## Почему такой порядок

Образ — точка входа: подозрительный образ можно запустить или подменить. Затем runc/nsenter — как из привилегированного пода выйти на хост. Pod Security и Falco идут последними как «защиты», которые надо понять и обойти, чтобы остаться незамеченным.

## Как проходить

- В примерах используйте `kubectl`, `ctr`/`crictl`, `nsenter` и `falco`.
- Проверяйте версии runc/containerd: старые сборки уязвимы к CVE-2024-21626 и др.
- Смотрите, какие labels `pod-security.kubernetes.io/*` стоят на namespace.

## Чему вы научитесь

- Находить слабые политики образов и подменять их.
- Выполнять побег из контейнера через runc/capabilities.
- Оценивать и обходить Pod Security Admission и Falco.

## Квиз

```quiz
- question: "Что даёт CVE-2024-21626 в runc?"
  options:
    - "Побег из контейнера через утечку файлового дескриптора"
    - "Кражу DNS"
    - "Биллинг"
    - "Шифрование диска"
  answer: 0
  explanation: "Уязвимость позволяет выйти за пределы контейнера и получить доступ к файловой системе хоста."
- question: "Зачем нужны labels pod-security.kubernetes.io/*?"
  options:
    - "Включают режим Pod Security Admission (enforce/audit/warn) для namespace"
    - "Меняют образ"
    - "Удаляют поды"
    - "Шифруют секреты"
  answer: 0
  explanation: "Эти labels задают уровень (privileged/baseline/restricted) и режим применения."
- question: "Как обойти runtime-детект Falco?"
  options:
    - "Избегать детектируемых syscall/поведения и работать в рамках легитимных процессов"
    - "Удалить Falco из образа хоста"
    - "Отключить KMS"
    - "Сменить регион"
  answer: 0
  explanation: "Falco триггерится на правила (shell в контейнере, mount, ptrace); обход — не делать этого или маскироваться."
```

## Где пригодится

- **Пентест k8s:** от образа до хоста.
- **Red team:** обход admission и runtime-детекта.
- **Supply chain:** компрометация образов.
- **Blue team:** понимание защит, чтобы их настроить.
