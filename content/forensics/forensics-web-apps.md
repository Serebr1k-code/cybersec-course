---
id: forensics-web-apps
title: "Модуль: веб-приложения — CMS, Java, БД и поиск"
category: forensics
parent: forensics-web-forensics
difficulty: hard
order: 3
tags: [forensics, web, cms, java, elasticsearch, mongodb, roadmap]
prerequisites: [forensics-web-forensics]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ веб-серверов"
estimated_minutes: 13
summary: "Этап ветки «веб»: как расследовать серверные приложения — CMS, Java-серверы, Elasticsearch и NoSQL-БД."
---

Веб-инцидент почти всегда оставляет следы в серверных приложениях: логи, базы, кэши,
сессии. Этот модуль — про типовые компоненты, которые встречаются почти везде.

## Что покрывает этот модуль

- **CMS** — WordPress/Joomla/Drupal и их логи.
- **Java-серверы** — Tomcat/JBoss/WildFly.
- **Elasticsearch** — поисковый движок и его логи.
- **MongoDB/Redis** — NoSQL-хранилища.

## Рекомендуемый порядок изучения

1. `web-cms` — самый частый случай.
2. `web-java-appserver` — корпоративные приложения.
3. `web-elasticsearch` — утечки и логи.
4. `web-mongodb-redis` — NoSQL.

## Что вы будете уметь

- Читать логи CMS и находить веб-шеллы.
- Анализировать Java-приложения.
- Расследовать компромисс Elasticsearch.
- Работать с NoSQL-данными.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| access.log CMS | что запрашивали | `grep`, `awk` |
| Tomcat-логи | что выполнялось | `catalina.out` |
| Elasticsearch-лог | кто читал индексы | консоль |
| Mongo/Redis | что в хранилище | `mongosh`, `redis-cli` |

## Куда дальше

Открывай урок **«CMS-форензика»** — начнём с самого частого.
