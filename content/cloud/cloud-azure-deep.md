---
id: cloud-azure-deep
title: "Модуль: Azure глубоко"
category: cloud
parent: cloud-provider-deep
difficulty: hard
order: 4
tags: [cloud, azure, storage, sas, app-service, key-vault, arm, module]
prerequisites: [cloud-provider-deep, cloud-azure-basics]
useful_for:
  - "Пентест Azure-подписок"
  - "Атаки на Storage, App Service и Key Vault"
  - "Подготовка к AZ-500"
estimated_minutes: 18
summary: "Подмодуль Azure: Storage SAS, App Service/Functions, Key Vault и ARM-развёртывания. От публичных токенов до эскалации через развёртывание."
---

Этот подмодуль — часть этапа «Модуль: провайдеры глубоко». Четыре урока по Azure: от утёкших SAS-токенов до злоупотребления ARM-развёртываниями и Key Vault.

## Что покрывает подмодуль

1. **Azure Storage и SAS** (`cloud-azure-storage-sas`) — SAS-токены, Blob/File/Queue, публичный доступ и захват данных.
2. **App Service и Functions** (`cloud-azure-appservice`) — SSRF, Kudu/SCM, захват managed identity.
3. **Key Vault** (`cloud-azure-keyvault`) — access policies, RBAC, purge/recovery и кража секретов.
4. **ARM-шаблоны и deployments** (`cloud-azure-arm`) — PassRole-эквивалент через deployment, экспорт секретов.

## Почему такой порядок

Storage — самая доступная поверхность: SAS-токены утекают в URL и логах. App Service даёт RCE/SSRF, через который крадётся managed identity. Key Vault — цель этих цепочек (там секреты и ключи). ARM завершает подмодуль: это механизм, которым атакующий с `Contributor` заставляет Azure действовать с чужими правами.

## Как проходить

- Используйте `az` и `az rest` для работы с ARM-эндпоинтом.
- Различайте Entra ID (идентичность) и Azure RBAC (права на ресурсы) — эта граница встречается в каждом уроке.
- В примерах показаны как `az`, так и прямые REST-вызовы: сравните их.

## Чему вы научитесь

- Находить и использовать утёкшие SAS-токены.
- Захватывать managed identity через App Service/Functions.
- Читать и злоупотреблять access policies Key Vault.
- Эскалировать через ARM-развёртывание с чужой ролью.

## Квиз

```quiz
- question: "Почему утёкший SAS-токен опасен?"
  options:
    - "Он даёт доступ к Storage в обход учётных данных Azure"
    - "Он ускоряет загрузку"
    - "Он меняет регион"
    - "Он создаёт подписку"
  answer: 0
  explanation: "SAS — это подписанный URL-токен, дающий делегированный доступ к ресурсу без входа в Entra ID."
- question: "Что даёт захват managed identity на App Service?"
  options:
    - "Токен ресурса, который можно использовать против Key Vault, ARM и Graph"
    - "Только логи приложения"
    - "Смену тарифного плана"
    - "Публичный IP"
  answer: 0
  explanation: "MI выдаёт OAuth-токен через IMDS; его права определяют, куда можно пройти."
- question: "Чем ARM-развёртывание полезно атакующему?"
  options:
    - "Оно исполняется от имени роли развёртывания, позволяя эскалировать"
    - "Оно только читает ресурсы"
    - "Оно отключает логи"
    - "Оно удаляет подписку"
  answer: 0
  explanation: "Если у атакующего есть право на deployment, он может заставить Azure действовать с более широкими правами."
```

## Где пригодится

- **Пентест Azure:** подписки, Entra ID, гибридные среды.
- **Bug bounty:** программы Microsoft Cloud.
- **Red team:** цепочки от публичного SAS до Key Vault.
- **Сертификация:** Microsoft Azure Security Engineer (AZ-500).
