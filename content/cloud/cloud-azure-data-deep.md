---
id: cloud-azure-data-deep
title: "Модуль: Azure — хранилища и DevOps"
category: cloud
parent: cloud-storage-s3
difficulty: hard
order: 4
tags: [cloud, azure, blob, storage, devops, pipelines, module]
prerequisites: [cloud-azure-deep, cloud-storage-s3]
useful_for:
  - "Пентест Azure Storage"
  - "Атаки на Azure DevOps и пайплайны"
  - "Кража секретов из сборок"
estimated_minutes: 14
summary: "Подмодуль Azure: глубокий разбор Blob/File/Queue/Table и Azure DevOps (Pipelines, service connections, agent pools) как источника кредов и кода."
---

Этот подмодуль — часть ветки «Основы облака → хранилища». Он собирает два урока по Azure-сервисам, которые держат данные и облачные креды: Azure Storage (Blob/File/Queue/Table) и Azure DevOps.

## Что покрывает подмодуль

1. **Azure Blob глубоко** (`cloud-azure-blob-deep`) — контейнеры, доступ на уровне аккаунта, immutable/versioning, SAS-типы и soft-delete.
2. **Azure DevOps** (`cloud-azure-devops`) — Pipelines, service connections, agent pools, PAT-токены и кража секретов сборки.

## Почему такой порядок

Blob — крупнейшее хранилище данных в Azure и частый источник утечек из-за неверных настроек доступа. Azure DevOps идёт вторым: service connections хранят креды к подпискам, а PAT-токены дают доступ ко всей организации.

## Как проходить

- В примерах используйте `az storage`, `az devops` и REST-запросы с SAS.
- Различайте account-level и container-level доступ: это определяет масштаб утечки.
- Проверяйте, какие service connections есть в проекте и какие права у их service principal.

## Чему вы научитесь

- Находить публичные контейнеры и злоупотреблять SAS разных типов.
- Восстанавливать удалённые blob'ы (soft-delete/versioning).
- Извлекать креды из Azure DevOps и использовать service connections.

## Квиз

```quiz
- question: "Чем account-level SAS отличается от service SAS?"
  options:
    - "Account SAS покрывает несколько сервисов аккаунта, service SAS — один ресурс"
    - "Account SAS только для чтения"
    - "Service SAS всегда admin"
    - "Они идентичны"
  answer: 0
  explanation: "Account SAS действует на уровне аккаунта и может затрагивать Blob/File/Queue/Table."
- question: "Что хранят Azure DevOps service connections?"
  options:
    - "Креды (service principal/секрет) для доступа к подпискам и сервисам"
    - "Только имена проектов"
    - "DNS-записи"
    - "Логи"
  answer: 0
  explanation: "Service connection содержит принципал с правами в целевой подписке — цель атаки."
- question: "Зачем проверять soft-delete и versioning в Blob?"
  options:
    - "Позволяют восстановить удалённые данные и историю объектов"
    - "Ускоряют скачивание"
    - "Меняют регион"
    - "Отключают логи"
  answer: 0
  explanation: "Версии и soft-deleted blob'ы могут содержать данные, которые «уже удалили»."
```

## Где пригодится

- **Пентест Azure:** аудит Storage и DevOps.
- **Red team:** кража service connections и захват подписки.
- **Bug bounty:** публичные контейнеры и SAS-утечки.
- **Cloud IR:** восстановление удалённых данных.
