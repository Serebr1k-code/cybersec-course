---
id: cloud-iac-deep
title: "Модуль: IaC глубоко — state, Bicep и шаблоны"
category: cloud
parent: cloud-iam-basics
difficulty: hard
order: 3
tags: [cloud, terraform, state, bicep, iac, module]
prerequisites: [cloud-terraform, cloud-cloudformation]
useful_for:
  - "Пентест Infrastructure as Code"
  - "Кража секретов из Terraform state"
  - "Анализ Azure-шаблонов"
estimated_minutes: 14
summary: "Подмодуль IaC: Terraform state/backend и Azure Bicep. Как из state достают секреты, как backend даёт доступ к инфраструктуре и как Bicep повторяет ошибки ARM."
---

Этот подмодуль — часть ветки «Основы облака → идентичность». Он собирает два урока по инфраструктуре как коду: Terraform (state и backend) и Azure Bicep.

## Что покрывает подмодуль

1. **Terraform state** (`cloud-terraform-state`) — backend S3/GCS/Azure, шифрование, секреты в открытом виде и `terraform state pull`.
2. **Bicep** (`cloud-bicep`) — компиляция в ARM, deployments и PassRole-эскалация на Azure.

## Почему такой порядок

Terraform — де-факто стандарт IaC: state содержит все атрибуты ресурсов, включая пароли и ключи. Bicep идёт вторым как «человеческий» ARM: он компилируется в те же deployments, где живёт классическая Azure-эскалация через managed identity.

## Как проходить

- В примерах используйте `terraform`, `az bicep` и `az deployment`.
- Запомните: `terraform show -json` и `state pull` — основные способы вытащить значения.
- Проверяйте backend-конфиг: где лежит state, кто имеет к нему доступ.

## Чему вы научитесь

- Читать Terraform state и извлекать из него секреты.
- Атаковать незащищённый backend (S3/GCS/Blob).
- Использовать Bicep/deployments для эскалации в Azure.

## Квиз

```quiz
- question: "Почему Terraform state — лакомая цель?"
  options:
    - "Он хранит атрибуты ресурсов, включая пароли и ключи, часто в открытом виде"
    - "Он содержит только имена ресурсов"
    - "Он зашифрован KMS всегда"
    - "Он публичен по умолчанию"
  answer: 0
  explanation: "State сериализует все атрибуты; без шифрования секреты лежат plaintext."
- question: "Чем Bicep отличается от ARM-шаблона?"
  options:
    - "Bicep компилируется в ARM и разворачивается тем же deployments-механизмом"
    - "Bicep — это CLI Kubernetes"
    - "Bicep заменяет Entra ID"
    - "Bicep не поддерживает роли"
  answer: 0
  explanation: "Bicep — DSL, транслируемый в ARM JSON; модель прав и PassRole та же."
- question: "Где обычно хранят Terraform backend?"
  options:
    - "В S3/GCS/Azure Blob"
    - "В DNS"
    - "В CloudTrail"
    - "В KMS-ключе"
  answer: 0
  explanation: "Remote backend в объектном хранилище; его доступность определяет, кто читает state."
```

## Где пригодится

- **Пентест IaC:** извлечение секретов из state.
- **Red team:** эскалация через deployments.
- **Cloud security review:** аудит backend и шаблонов.
- **DevSecOps:** внедрение шифрования state и сканеров.
