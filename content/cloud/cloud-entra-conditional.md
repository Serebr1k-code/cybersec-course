---
id: cloud-entra-conditional
title: 'Модуль: Entra ID — Conditional Access, PIM и Identity Protection'
category: cloud
parent: cloud-saas-identity-deep
difficulty: hard
order: 6
tags: [cloud, entra, azure, conditional-access, pim, identity-protection, module]
prerequisites: [cloud-saas-identity-deep]
useful_for:
  - 'Пентест привилегированного доступа в Entra ID'
  - 'Обход условного доступа'
  - 'CTF cloud'
estimated_minutes: 18
summary: 'Подмодуль о трёх механизмах контроля Entra ID: Conditional Access (условия входа), PIM (привилегированные роли по требованию) и Identity Protection (риск-детекции). Общая тема — где у контроля остаются слепые зоны.'
---

Этот подмодуль — про защитные механизмы Entra ID и про то, как их обходят. Conditional Access решает, при каких условиях пускать вход; PIM ограничивает привилегии во времени; Identity Protection считает риск. Каждый из них полезен, и у каждого есть слепые зоны — именно на них смотрит атакующий.

## Что покрывает подмодуль

1. **Conditional Access: обход политик и device compliance** (`cloud-entra-conditional-access`) — условия, исключения и legacy-пути.
2. **PIM: активация ролей, approval-обход и постоянные назначения** (`cloud-entra-pim`) — eligible/active и правила активации.
3. **Identity Protection: risky sign-ins и слепые зоны** (`cloud-entra-identity-protection`) — риск-детекции и границы их применимости.

## Почему такой порядок

Сначала — что пускает вход (CA), затем — что ограничивает права (PIM), потом — что замечает аномалии (Identity Protection). Это три слоя защиты, и обход каждого строится на одном вопросе: «какой случай не покрыт?».

## Как проходить подмодуль

После каждого урока выписывайте слепую зону: у CA — непокрытое приложение/протокол; у PIM — постоянные назначения и eligible без approval; у Identity Protection — тихие атаки и исключённые аккаунты.

## Квиз

Проверь себя.

```quiz
- question: "Что решает Conditional Access?"
  options:
    - "При каких условиях разрешён вход"
    - "Кто получает роль"
    - "Где хранятся логи"
    - "Как шифруется трафик"
  answer: 0
  explanation: "CA применяет controls (MFA, compliant device) на основе условий входа."
- question: "Чем опасно постоянное назначение роли в PIM?"
  options:
    - "Обходит модель активации по требованию"
    - "Ускоряет вход"
    - "Требует approval"
    - "Ничем"
  answer: 0
  explanation: "Active/permanent-роль не требует активации и обесценивает JIT."
- question: "Почему смена пароля не всегда выкидывает атакующего?"
  options:
    - "Нужно ещё отозвать сессии (revokeSignInSessions)"
    - "Пароль меняется медленно"
    - "MFA отключается"
    - "Сессии не существуют"
  answer: 0
  explanation: "Refresh-токены остаются валидными, пока сессии не отозваны явно."
```

## Куда дальше

После Entra-контроля логично вернуться к протоколам и посмотреть Golden SAML — подделку подписи SAML-токенов. А пока главное: любой контроль силён ровно настолько, насколько полон его охват.

## Где пригодится

- Пентест и аудит Entra ID.
- Разбор инцидентов с компрометацией аккаунтов.
- CTF-задачи категории cloud.
