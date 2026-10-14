---
id: cloud-gcp-secrets-deep
title: "Модуль: GCP — секреты и Firebase"
category: cloud
parent: cloud-credential-hunting
difficulty: hard
order: 2
tags: [cloud, gcp, secret-manager, firebase, secrets, kms, module]
prerequisites: [cloud-gcp-deep, cloud-secrets-manager]
useful_for:
  - "Кража секретов из GCP"
  - "Пентест Firebase-приложений"
  - "Анализ утечек через аналитику и правила"
estimated_minutes: 16
summary: "Подмодуль GCP про секреты: Secret Manager и Firebase. Где лежат секреты, как их читать при слабых IAM-правах и как Firebase-мисконфиги открывают базы и хранилища."
---

Этот подмодуль — часть ветки «Основы облака → идентичность, секреты и логи». Он собирает два урока по местам, где в GCP реально лежат секреты: Secret Manager и Firebase.

## Что покрывает подмодуль

1. **Secret Manager** (`cloud-gcp-secret-manager`) — версии секретов, `secretmanager.versions.access`, IAM на уровне секрета, CMEK и audit-логи.
2. **Firebase** (`cloud-gcp-firebase`) — Realtime Database/Firestore rules, открытые конфиги, API-ключи и злоупотребление публичными правилами.

## Почему такой порядок

Secret Manager — централизованное хранилище: если у роли есть `secretmanager.versions.access`, весь проект открыт. Firebase идёт вторым как «клиентская» грань GCP: неверные security rules открывают базы и Storage без всякой аутентификации. Вместе они покрывают и серверные, и клиентские утечки секретов.

## Как проходить

- В примерах используйте `gcloud secrets` и REST-запросы к Firebase с `curl`.
- Запомните формат `projects/*/secrets/*/versions/latest`: он встречается в ошибках и логах.
- Не забывайте проверять audit-логи (`gcloud logging read`) — они показывают, кто читал секрет.

## Чему вы научитесь

- Перечислять секреты и читать версии при слабых IAM-правах.
- Находить Firebase-конфиги в JS-бандлах и проверять security rules.
- Извлекать данные из открытых Realtime Database/Firestore.

## Квиз

```quiz
- question: "Какое право даёт чтение значения секрета в Secret Manager?"
  options:
    - "secretmanager.versions.access"
    - "secretmanager.secrets.list"
    - "resourcemanager.projects.get"
    - "logging.logs.list"
  answer: 0
  explanation: "Именно versions.access раскрывает payload; list показывает только метаданные."
- question: "Чем опасны открытые Firebase security rules?"
  options:
    - "Позволяют читать/писать Realtime Database и Firestore без аутентификации"
    - "Меняют биллинг"
    - "Удаляют IAM"
    - "Выдают SSH-ключи"
  answer: 0
  explanation: "Правило вида allow read, write: if true открывает всю базу любому клиенту."
- question: "Где чаще всего находят Firebase-конфиг?"
  options:
    - "В JS-бандле клиентского приложения"
    - "В CloudTrail"
    - "В KMS"
    - "В VPC"
  answer: 0
  explanation: "Конфиг (apiKey, databaseURL, projectId) по дизайну публичен и вшит в клиент."
```

## Где пригодится

- **Пентест GCP:** кража секретов и анализ Firebase.
- **Bug bounty:** мобильные и веб-приложения на Firebase.
- **Red team:** получение долгоживущих секретов проекта.
- **Форензика:** аудит доступа к секретам по логам.
