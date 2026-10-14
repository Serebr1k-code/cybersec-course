---
id: cloud-provider-edge
title: 'Модуль: edge-платформы — Cloudflare Workers и serverless-БД'
category: cloud
parent: cloud-cdn-edge
difficulty: hard
order: 1
tags: [cloud, cloudflare, workers, supabase, edge, module]
prerequisites: [cloud-cdn-edge]
useful_for:
  - 'Пентест edge-приложений'
  - 'Bug bounty: edge-секреты'
  - 'CTF cloud'
estimated_minutes: 18
summary: 'Подмодуль об edge-платформах и serverless-базах: Cloudflare Workers/KV/R2/D1 и Supabase/PlanetScale. Где живут секреты и как утекают данные.'
---

Этот подмодуль продолжает урок `cloud-cdn-edge` о CDN и edge. Если CDN раздаёт статику, то edge-функции исполняют код у пользователя — а значит, хранят секреты и говорят с базами. Здесь мы разбираем два класса таких платформ: Cloudflare Workers и serverless-базы (Supabase, PlanetScale, Neon).

## Что покрывает подмодуль

1. **Cloudflare Workers/KV/R2/D1: edge-код, секреты и SSRF** (`cloud-cloudflare-workers`) — переменные окружения, биндинги, worker-роуты и запросы к внутренним сервисам.
2. **Supabase / PlanetScale / Neon: RLS, connection strings и анон-ключи** (`cloud-supabase-planetscale`) — публичные anon-ключи, Row Level Security и утечка данных.

## Почему такой порядок

Сначала код, который исполняется на edge, затем база, к которой он ходит. Это ровно тот путь, по которому идёт атакующий: нашёл anon-ключ в бандле фронтенда → проверил RLS → дотянулся до бакета или KV.

## Как проходить подмодуль

Пройдите оба урока подряд: они образуют одну сквозную цепочку edge-приложения. Заведите привычку: любой `NEXT_PUBLIC_` или `VITE_` префикс в фронтенде — это публичный секрет, а не секрет вообще.

## Квиз

Проверь себя.

```quiz
- question: "Почему ключ с префиксом NEXT_PUBLIC_ нельзя считать секретом?"
  options:
    - "Он попадает в клиентский бандл и виден любому пользователю"
    - "Он всегда короткий"
    - "Он не поддерживает шифрование"
    - "Он работает только на сервере"
  answer: 0
  explanation: "Префикс NEXT_PUBLIC_ (или VITE_) означает, что значение инлайнится в клиентский JS — его читает любой."
- question: "Что защищает данные в Supabase, если anon-ключ публичен?"
  options:
    - "Row Level Security (RLS) в PostgreSQL"
    - "Обфускация имён таблиц"
    - "Секретность URL проекта"
    - "IP-allowlist"
  answer: 0
  explanation: "Anon-ключ по дизайну публичен; доступ к строкам ограничивает именно RLS-политика на таблицах."
- question: "Что такое биндинг KV в Cloudflare Workers?"
  options:
    - "Key-value-хранилище, доступное worker-коду напрямую"
    - "Тип DNS-записи"
    - "Формат логов"
    - "Сетевой протокол"
  answer: 0
  explanation: "KV — глобальное key-value-хранилище, привязанное к worker как биндинг и доступное из кода."
```

## Куда дальше

Дальше — практика: утёкший anon-ключ и неверная RLS-политика. А пока запомни: edge-код исполняется близко к пользователю, но его секреты и права — обычные облачные креденшелы.

## Где пригодится

- Bug bounty на SaaS-приложениях (Next.js, Supabase).
- Аудит edge-функций и serverless-баз.
- CTF cloud/web.
