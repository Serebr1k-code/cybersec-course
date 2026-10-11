---
id: cloud-gcp-data-deep
title: "Модуль: GCP — контейнеры и данные"
category: cloud
parent: cloud-foundations-services
difficulty: hard
order: 4
tags: [cloud, gcp, gke, gcs, bigquery, cloudsql, module]
prerequisites: [cloud-gcp-deep, cloud-containers-docker]
useful_for:
  - "Пентест Google Cloud Platform"
  - "Атаки на GKE и облачные данные"
  - "Подготовка к Google Professional Cloud Security Engineer"
estimated_minutes: 18
summary: "Подмодуль GCP про данные и контейнеры: GKE, Cloud Storage, BigQuery и Cloud SQL. Кластеры, бакеты, датасеты и базы — там, где живут данные и роли."
---

Этот подмодуль — часть ветки «Основы облака → сервисы». Он собирает четыре урока по сервисам GCP, которые держат данные и контейнерные нагрузки: GKE, Cloud Storage, BigQuery и Cloud SQL.

## Что покрывает подмодуль

1. **GKE** (`cloud-gcp-gke`) — Workload Identity, node SA, автоскалинг и захват метаданных пода.
2. **Cloud Storage (GCS)** (`cloud-gcp-storage`) — IAM vs ACL, публичные бакеты, signed URLs и `storage.objects` permissions.
3. **BigQuery** (`cloud-gcp-bigquery`) — датасеты, `bigquery.datasets.get`, публичные наборы, эксфильтрация через экспорт и SQL.
4. **Cloud SQL** (`cloud-gcp-cloudsql`) — публичный доступ, SSL, IAM database auth и снапшоты/бэкапы.

## Почему такой порядок

GKE — самая частая точка входа в GCP: метаданные пода выдают токен node service account. Cloud Storage идёт вторым как крупнейший источник утечек. BigQuery показывает, как из «безобидного» аналитического сервиса вытащить данные и секреты. Cloud SQL замыкает модуль: управляемые базы часто открыты публично и используют IAM-аутентификацию, которую можно злоупотребить.

## Как проходить

- Каждый урок заканчивается разобранным примером с `gcloud`, `gsutil` и `bq`, с реальным выводом.
- Проверяйте `gcloud auth list` и `gcloud config list`: в тестах удобно держать несколько конфигураций.
- Обращайте внимание на наследование IAM на уровне организации/папки/проекта — это ключ к эскалации.

## Чему вы научитесь

- Захватывать токен node service account из пода GKE.
- Находить публичные бакеты и злоупотреблять подписанными ссылками.
- Извлекать данные из BigQuery и экспортировать их в свой проект.
- Использовать публичный Cloud SQL и IAM database auth.

## Квиз

```quiz
- question: "Что чаще всего даёт первый токен атакующему в GKE?"
  options:
    - "Metadata-сервер пода, выдающий токен node service account"
    - "BigQuery"
    - "Cloud DNS"
    - "Firebase Hosting"
  answer: 0
  explanation: "Если Workload Identity не включён, под получает токен node SA — обычно широкий по правам."
- question: "В чём разница IAM и ACL в Cloud Storage?"
  options:
    - "IAM — роли на бакет/объект, ACL — per-object гранты"
    - "IAM работает только в Firebase"
    - "ACL всегда строже"
    - "Они идентичны"
  answer: 0
  explanation: "При uniform bucket-level access ACL отключены; иначе ACL могут открывать объекты в обход IAM."
- question: "Почему BigQuery интересен атакующему?"
  options:
    - "Датасеты могут быть публичными и содержать чувствительные данные"
    - "BigQuery выдаёт SSH-ключи"
    - "BigQuery меняет IAM"
    - "BigQuery шифрует трафик"
  answer: 0
  explanation: "Публичные датасеты и право bigquery.jobs.create позволяют читать и экспортировать данные."
```

## Где пригодится

- **Пентест GCP:** захват токенов из GKE и доступ к данным.
- **Bug bounty:** облачные программы с бакетами и BigQuery в scope.
- **Red team:** lateral movement от пода к проекту.
- **Сертификация:** Google Professional Cloud Security Engineer.
