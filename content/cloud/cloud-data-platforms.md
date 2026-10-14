---
id: cloud-data-platforms
title: "Модуль: Платформы данных: Snowflake, Databricks, lakehouse"
category: cloud
parent: cloud-data-analytics
difficulty: medium
order: 1
tags: [cloud, module, roadmap]
prerequisites: [cloud-data-analytics]
useful_for:
- Аудит облачных данных.
- Пентест SaaS-платформ.
- Red team в data-командах.
estimated_minutes: 10
summary: "Роли и shares snowflake, токены databricks, доступ через dbt/bi и права data lake"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Платформы данных: Snowflake, Databricks, lakehouse»: роли и shares Snowflake, токены Databricks, доступ через dbt/BI и права data lake.

- **cloud-snowflake** — Snowflake: роли, shares, external stages и exfiltration данных.
- **cloud-databricks** — Databricks: workspace, персональные токены, кластеры и exfil.
- **cloud-dbt-looker** — dbt / Looker / BI: доступ к данным через сервисные аккаунты.
- **cloud-data-lake** — Data lake / Lakehouse: каталоги, права и обход.

## Почему такой порядок

Платформы данных концентрируют самый чувствительный контент; сначала разбираем сами платформы, затем доступ через BI.

## Что вы сможете после этапа

- Оценивать модель прав Snowflake/Databricks.
- Искать путь к данным через сервисные аккаунты.

## Квиз

Проверь себя.

```quiz
- question: Чем опасны personal access tokens Databricks?
  options:
    - "Дают доступ к workspace в обход ролей"
    - "Ускоряют кластеры"
    - "Шифруют данные"
    - "Логируют запросы"
  answer: 0
  explanation: Токен действует от имени пользователя.
- question: Что такое Snowflake share?
  options:
    - "Способ предоставить доступ к данным другому аккаунту"
    - "Тип индекса"
    - "Резервная копия"
    - "Формат файла"
  answer: 0
  explanation: Share отдаёт базы/таблицы другому аккаунту Snowflake.
- question: Зачем смотреть на dbt/BI-аккаунты?
  options:
    - "Через них можно получить доступ к данным под сервисной учёткой"
    - "Они хранят пароли Wi-Fi"
    - "Они шифруют трафик"
    - "Они чистят логи"
  answer: 0
  explanation: BI-сервисы ходят в хранилище под сервисными правами.
```

## Где пригодится

- Аудит облачных данных.
- Пентест SaaS-платформ.
- Red team в data-командах.
