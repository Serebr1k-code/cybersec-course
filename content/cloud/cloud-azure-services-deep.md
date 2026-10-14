---
id: cloud-azure-services-deep
title: 'Модуль: сервисы Azure глубоко — Cosmos, Synapse, Data Factory, AI, SQL MI'
category: cloud
parent: cloud-azure-deep
difficulty: hard
order: 5
tags: [cloud, azure, cosmos, synapse, data-factory, ai, sql, module]
prerequisites: [cloud-azure-arm]
useful_for:
  - 'Пентест Azure'
  - 'Кража данных и секретов из PaaS'
  - 'CTF cloud'
estimated_minutes: 18
summary: 'Подмодуль о платформенных сервисах Azure за пределами базовых (storage, app service, key vault): Cosmos DB (ключи и инъекции в API), Synapse и Data Factory (данные и managed identity), Azure AI (ключи и prompt injection) и Azure SQL/Managed Instance (firewall и AAD-auth). Общий мотив: у каждого сервиса есть свой ключ, своя роль и свой data-plane.'
---

Ты уже разобрал ARM, storage SAS, App Service и Key Vault. Но Azure — это ещё и десятки PaaS-сервисов, у каждого из которых своя плоскость данных, свои ключи и своя модель ролей. Компромисс одного сервиса часто даёт доступ к данным и к managed identity, а через неё — ко всему тенанту. Этот подмодуль закрывает четыре самых частых семейства: базы и аналитику (Cosmos, Synapse), конвейеры данных (Data Factory), AI-сервисы и Azure SQL.

## Что покрывает подмодуль

1. **Cosmos DB** (`cloud-azure-cosmos`) — ключи доступа, RBAC, инъекции в SQL/Gremlin-API.
2. **Synapse Analytics** (`cloud-azure-synapse`) — workspace, Spark-пулы, linked services и exfil через хранилище.
3. **Data Factory** (`cloud-azure-data-factory`) — pipelines, integration runtime, managed identity и её захват.
4. **Azure AI / Cognitive Services** (`cloud-azure-ai-services`) — ключи, endpoints, prompt injection и кража данных.
5. **Azure SQL / Managed Instance** (`cloud-azure-sql-mi`) — firewall, AAD-auth, exfil и эскалация через роли.

## Почему такой порядок

Идём от «данные в базе» к «данные в конвейере» и «данные в модели». Cosmos — это база с ключом, который сам по себе является полным доступом. Synapse — аналитика поверх хранилища, где права путают control-plane и data-plane. Data Factory — то, что двигает данные между сервисами, и потому держит identity ко всем сразу. Azure AI — новая поверхность, где ключ = деньги и данные. Azure SQL — классическая база в облаке, но с AAD-аутентификацией и managed identity.

## Как проходить подмодуль

Держи один вопрос: «какой ключ или роль открывает эту плоскость данных и что лежит за ней?». У Cosmos — primary key; у Synapse — роль workspace и доступ к ADLS; у Data Factory — managed identity; у Azure AI — ключ сервиса; у SQL — AAD-логин или SQL-логин. Поняв, чем сервис аутентифицируется в data-plane, ты находишь и точку атаки, и способ закрепиться.

## Квиз

Проверь себя.

```quiz
- question: "Что объединяет сервисы этого подмодуля?"
  options:
    - "У каждого своя плоскость данных, свой ключ и своя роль"
    - "Они все бесплатны"
    - "У них нет аутентификации"
    - "Они не пишут логи"
  answer: 0
  explanation: "Control-plane и data-plane у Azure разделены: ключ или роль сервиса открывает данные напрямую."
- question: "Почему managed identity сервисов так ценна?"
  options:
    - "Она даёт токен к другим ресурсам без пароля"
    - "Она отключает логи"
    - "Она удаляет firewall"
    - "Она только читает"
  answer: 0
  explanation: "Managed identity — это автоматически выдаваемый токен; компромисс сервиса часто даёт доступ к его правам."
- question: "Чем Cosmos primary key отличается от RBAC?"
  options:
    - "Ключ даёт полный доступ к данным без ролей"
    - "Ключ только для чтения"
    - "Ключ не работает по сети"
    - "Ключ это логин пользователя"
  answer: 0
  explanation: "Primary key обходит модель ролей и открывает весь аккаунт."
- question: "Почему Data Factory считают чувствительной точкой?"
  options:
    - "Его identity ходит в источники и приёмники данных"
    - "Он не имеет identity"
    - "Он не хранит данные"
    - "Он работает только локально"
  answer: 0
  explanation: "Конвейер данных держит доступ ко всем подключённым сервисам одновременно."
```

## Куда дальше

Дальше — Cosmos DB: база, где один ключ равен полному доступу к данным. А пока главное: у каждого сервиса Azure есть своя плоскость данных, и её открывает либо ключ, либо роль.

## Где пригодится

- Пентест Azure-тенантов.
- Кража данных и секретов из PaaS-сервисов.
- CTF-задачи категории cloud.
