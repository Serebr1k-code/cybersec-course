---
id: cloud-gcp-deep
title: "Модуль: GCP глубоко"
category: cloud
parent: cloud-provider-deep
difficulty: hard
order: 3
tags: [cloud, gcp, metadata, cloud-functions, cloud-run, wif, org-policy, module]
prerequisites: [cloud-provider-deep, cloud-gcp-basics]
useful_for:
  - "Пентест GCP-проектов"
  - "Атаки на сервисные аккаунты и Workload Identity"
  - "Подготовка к Google Professional Cloud Security Engineer"
estimated_minutes: 18
summary: "Подмодуль GCP: metadata-сервис, Cloud Functions/Cloud Run, Workload Identity Federation и resource hierarchy с org policies."
---

Этот подмодуль — часть этапа «Модуль: провайдеры глубоко». Четыре урока по GCP: от захвата сервисного аккаунта через metadata до подделки федеративного доверия и понимания границ организации.

## Что покрывает подмодуль

1. **GCP metadata** (`cloud-gcp-metadata`) — `metadata.google.internal`, service-account токены и их захват через SSRF/RCE.
2. **Cloud Functions и Cloud Run** (`cloud-gcp-functions`) — инъекции, публичные эндпоинты и захват runtime service account.
3. **Workload Identity Federation** (`cloud-gcp-wif`) — подделка доверия между внешним IdP и GCP.
4. **Resource hierarchy и org policies** (`cloud-gcp-orgpolicy`) — проекты, папки, организации и границы, которые нельзя обойти политикой.

## Почему такой порядок

Сначала — самый прямой путь к кредам: metadata-сервис GCP (аналог IMDS, но с токенами OAuth). Затем — серверлесс, где эти токены живут в рантайме. Дальше — федерация: механизм, через который внешний CI или Kubernetes получает GCP-права. Завершает подмодуль иерархия ресурсов: она объясняет, почему одни права наследуются, а другие ограничены на уровне организации.

## Как проходить

- Для каждого урока нужен `gcloud` и доступ к тестовому проекту.
- Обратите внимание на разницу между AWS и GCP в выдаче токенов: в GCP токен привязан к сервисному аккаунту и его scopes.
- В уроках про WIF и org policies много конфигураций — читайте их как код, а не как текст.

## Чему вы научитесь

- Забирать OAuth-токен сервисного аккаунта через metadata-эндпоинт.
- Атаковать серверлесс-функции и Cloud Run.
- Анализировать и подделывать Workload Identity Federation.
- Читать иерархию организации и находить, где политика не применяется.

## Квиз

```quiz
- question: "Чем токен GCP из metadata отличается от AWS IMDS?"
  options:
    - "Это OAuth-токен, привязанный к сервисному аккаунту и scopes"
    - "Он не истекает никогда"
    - "Он работает только в консоли"
    - "Он не требует HTTP"
  answer: 0
  explanation: "GCP выдаёт OAuth2 access token для привязанного сервисного аккаунта с ограниченными scopes."
- question: "Зачем атакующему Workload Identity Federation?"
  options:
    - "Чтобы внешний IdP получил доступ к GCP без статических ключей"
    - "Чтобы ускорить сеть"
    - "Чтобы сменить регион"
    - "Чтобы включить биллинг"
  answer: 0
  explanation: "WIF позволяет внешней идентичности обменять свой токен на GCP-токен — при слабом условии доверия это вход."
- question: "Что задают org policies?"
  options:
    - "Ограничения на уровне организации, которые наследуются вниз"
    - "Пароли пользователей"
    - "Стоимость ресурсов"
    - "IP-адреса ВМ"
  answer: 0
  explanation: "Org policies — это guardrails, применяемые иерархически к проектам и папкам."
```

## Где пригодится

- **Пентест GCP:** захват сервисных аккаунтов и серверлесс.
- **Bug bounty:** облачные программы Google Cloud.
- **Red team:** атаки на CI/CD, доверяющий GCP через WIF.
- **Сертификация:** Google Professional Cloud Security Engineer.
