---
id: cloud-data-streaming
title: "Модуль: Стриминг и пайплайны: Kafka, Airflow, exfiltration"
category: cloud
parent: cloud-data-analytics
difficulty: medium
order: 2
tags: [cloud, module, roadmap]
prerequisites: [cloud-data-analytics]
useful_for:
- Аудит стриминговых платформ.
- Пентест data-пайплайнов.
- Red team.
estimated_minutes: 10
summary: "Acl и sasl в kafka/msk, инъекции в dag airflow и каналы утечки через managed-стриминг"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Стриминг и пайплайны: Kafka, Airflow, exfiltration»: ACL и SASL в Kafka/MSK, инъекции в DAG Airflow и каналы утечки через managed-стриминг.

- **cloud-kafka-msk** — Kafka / MSK / Confluent: ACL, SASL и инъекции в потоки.
- **cloud-airflow-dag** — Airflow / Dagster / Prefect: DAG-инъекции и кража соединений.
- **cloud-streaming-exfil** — Стриминговая exfiltration: каналы утечки через Kinesis/PubSub/EventHub.

## Почему такой порядок

Потоки данных требуют отдельного разбора: права на топики и код DAG дают свои примитивы атаки.

## Что вы сможете после этапа

- Оценивать права на топики Kafka.
- Искать инъекции в DAG и каналы exfil.

## Квиз

Проверь себя.

```quiz
- question: Что регулирует доступ к топикам Kafka?
  options:
    - "ACL"
    - "DNS"
    - "TLS-сертификат браузера"
    - "cron"
  answer: 0
  explanation: ACL задаёт, кто читает/пишет топик.
- question: Чем опасен DAG Airflow?
  options:
    - "Исполняет произвольный Python с правами сервиса"
    - "Хранит пароли в открытом виде всегда"
    - "Отключает сеть"
    - "Шифрует диск"
  answer: 0
  explanation: DAG — это код, который исполняется планировщиком.
- question: Что такое стриминговая exfiltration?
  options:
    - "Утечка данных через managed-потоки (Kinesis/PubSub/EventHub)"
    - "Шифрование трафика"
    - "Резервное копирование"
    - "Сжатие логов"
  answer: 0
  explanation: Данные выносят через легитимные стриминговые сервисы.
```

## Где пригодится

- Аудит стриминговых платформ.
- Пентест data-пайплайнов.
- Red team.
