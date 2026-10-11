---
id: cloud-azure-platform-deep
title: "Модуль: Azure — платформа, DevOps и безопасность"
category: cloud
parent: cloud-iam-identity
difficulty: expert
order: 4
tags: [cloud, azure, aks, sentinel, logic-apps, app-registration, module]
prerequisites: [cloud-azure-deep, cloud-azure-iam]
useful_for:
  - "Пентест Azure-платформы"
  - "Атаки на AKS и serverless-сервисы Azure"
  - "Анализ Entra ID app registrations"
estimated_minutes: 18
summary: "Подмодуль Azure: AKS, Microsoft Sentinel, Logic Apps и app registrations Entra ID. Кластеры, SIEM, low-code и регистрации приложений как поверхность атаки."
---

Этот подмодуль — часть ветки «Основы облака → идентичность». Он собирает четыре урока по платформенным сервисам Azure, которые часто оказываются «сбоку» от основного внимания: AKS, Sentinel, Logic Apps и регистрации приложений Entra ID.

## Что покрывает подмодуль

1. **AKS** (`cloud-azure-aks`) — managed кластер, kubelet identity, Azure RBAC для k8s и захват managed identity пода.
2. **Microsoft Sentinel** (`cloud-azure-sentinel`) — SIEM/SOAR, analytics rules, workbooks и слепые зоны.
3. **Logic Apps** (`cloud-azure-logic-apps`) — low-code workflows, connectors, managed identity и инъекции.
4. **App registrations Entra ID** (`cloud-azure-app-registrations`) — приложения, сервис-принципалы, API-разрешения и злоупотребление consent.

## Почему такой порядок

AKS — основная контейнерная платформа Azure: захват managed identity пода даёт доступ к подписке. Sentinel идёт вторым как SIEM: понимание его правил объясняет, что видно защите. Logic Apps — low-code, где connector'ы держат креды и часто имеют широкие права. Замыкают модуль app registrations: слабые разрешения приложений дают постоянный доступ к Graph и подпискам.

## Как проходить

- В примерах используйте `az aks`, `az monitor`, `az logic` и Microsoft Graph.
- Проверяйте, какие API-разрешения выданы приложениям и есть ли admin consent.
- Отмечайте, какие события попадают в Sentinel, а какие — нет.

## Чему вы научитесь

- Захватывать managed identity пода AKS.
- Анализировать правила Sentinel и слепые зоны.
- Эксплуатировать Logic Apps через connector'ы и managed identity.
- Использовать app registrations для доступа к Graph.

## Квиз

```quiz
- question: "Чем AKS-managed identity пода полезна атакующему?"
  options:
    - "Даёт токен, которым можно действовать от имени роли в подписке"
    - "Отключает сеть"
    - "Меняет DNS"
    - "Шифрует диск"
  answer: 0
  explanation: "Workload Identity/под-identity выдаёт токен Entra ID для доступа к Azure-ресурсам."
- question: "Что проверять у app registration в первую очередь?"
  options:
    - "API permissions (особенно с admin consent) и секреты/сертификаты"
    - "Только название"
    - "Регион"
    - "Биллинг"
  answer: 0
  explanation: "Выданные Graph/ARM разрешения и креды приложения определяют, что можно делать."
- question: "Почему Logic Apps — интересная цель?"
  options:
    - "Connector'ы хранят креды и выполняют действия с широкими правами"
    - "Они заменяют Kubernetes"
    - "Они не имеют IAM"
    - "Они только для писем"
  answer: 0
  explanation: "Workflow с managed identity/connector может читать почту, файлы, вызывать ARM."
```

## Где пригодится

- **Пентест Azure:** AKS, Sentinel, Logic Apps, app registrations.
- **Red team:** захват подписок через managed identity и consent.
- **Blue team:** настройка Sentinel и оценка слепых зон.
- **Сертификация:** AZ-500 / SC-200.
