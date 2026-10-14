---
id: cloud-entra-pim
title: 'Entra PIM: активация ролей, approval-обход и постоянные назначения'
category: cloud
parent: cloud-entra-conditional
difficulty: hard
order: 2
tags: [cloud, entra, azure, pim, privileged-role, approval, jit]
prerequisites: [cloud-entra-conditional-access]
useful_for:
  - 'Пентест привилегированных ролей Entra'
  - 'Захват Global Admin через PIM'
  - 'CTF cloud'
estimated_minutes: 45
summary: 'Entra PIM: eligible/active-назначения, активация ролей по требованию, правила approval/MFA/justification и пути обхода. Сквозной пример — выгрузка PIM-назначений и поиск роли, которую можно активировать без одобрения.'
lab:
  kind: shell
  title: 'Практика: разбор PIM-назначений'
  toolset: [core]
  workdir: /home/student/pim
  files: [task.md, pim-assignments.json, notes.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Изучи назначения: `cat pim-assignments.json`. Найди роль с постоянным (permanent) назначением.'
    - 'Определи, какая активация не требует approval.'
    - 'Флаг — в notes.md: найди строку `nto` и запиши её в found.txt.'
---

## Вопрос, с которого всё начинается

В организации привилегированные роли выдаются не постоянно, а «по требованию»: пользователь активирует Global Admin на час, обосновывает необходимость, иногда ждёт одобрения. Это PIM. Вопрос: делает ли PIM систему безопаснее — и если да, где остаются пути обхода? Ответ: PIM снижает риск, но его правила (approval, MFA, justification) и **постоянные назначения** оставляют лазейки. Разберём их.

## Что такое Entra PIM

PIM (Privileged Identity Management) — сервис Entra ID для управления привилегированными ролями. Вместо постоянного назначения роли используется схема **eligible → activate**:
- пользователю назначают роль как **eligible** (может активировать, но не имеет прав сейчас);
- при необходимости он **активирует** её на ограниченное время (обычно 1–8 часов);
- активация может требовать MFA, обоснования (justification), одобрения (approval) и тикет.

Идея — принцип наименьших привилегий во времени: права есть только когда нужны.

## Сквозной пример: выгрузка назначений

Смотрим выгрузку:
```
$ cat pim-assignments.json
{
  "roleAssignments": [
    {"role": "Global Administrator", "principal": "alice@acme.com",
     "assignmentType": "Eligible", "activation": {"requireApproval": false, "requireMfa": true}},
    {"role": "Privileged Role Administrator", "principal": "svc-backup",
     "assignmentType": "Active", "permanent": true}
  ]
}
```
Два факта. Первый: `alice` может активировать Global Admin **без одобрения** (requireApproval=false) — только MFA. Второй: сервисный аккаунт `svc-backup` имеет **постоянную активную** роль `Privileged Role Administrator` — то есть может управлять ролями, не активируя ничего. Оба факта — пути к захвату.

## Eligible без approval — быстрый путь

Если роль eligible и `requireApproval=false`, активация — один шаг: подтвердить MFA и нажать «активировать». Значит, компромисса пароля+MFA достаточно для получения Global Admin. При аудите ищи eligible-назначения на привилегированные роли, у которых не требуется approval: это фактически «постоянный доступ в два действия».

## Постоянные (permanent) назначения

PIM не мешает оставить роль **active/permanent** в обход всей модели. Администраторы делают это «на время» и забывают, или так настраивают сервисные аккаунты. Постоянная привилегированная роль — прямой захват без активации: пароль (или токен) = права. Особенно опасны постоянные роли у сервисных principals, у которых нет MFA.

## Обход approval

Даже если approval включён, есть пути:
- одобряющий — сам атакующий (если скомпрометирован и approver);
- настройка «approval not required for this role» для части ролей;
- апелляция через `Privileged Role Administrator` (если он скомпрометирован, он меняет правила PIM);
- автоматический approval по тикету, где тикеты создаются свободно.

`Privileged Role Administrator` — ключевая роль: она управляет настройками PIM, поэтому её компромисс обесценивает всю защиту.

## Justification и MFA как контроль

PIM может требовать MFA при активации и обоснование. MFA-требование повышает планку (нужен второй фактор), обоснование — детективный контроль. Но если у пользователя слабый фактор или он уже скомпрометирован (AiTM), требования проходятся. Поэтому PIM — это слой **снижения риска**, а не абсолютная защита.

## Связка с другими техниками

PIM редко атакуют в одиночку. Цепочка обычно такая: фишинг/кража токена → вход под пользователем с eligible-ролью → активация Global Admin → создание постоянного доступа (новое приложение, новый админ, новый ключ) → закрепление. На каждом шаге PIM может помешать — или не помешать, если правила слабые.

## Как проверить руками

```
$ az rest --method GET --url "https://graph.microsoft.com/v1.0/privilegedAccess/azureResources/roleAssignments"
$ az rest --method GET --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
```
Вывод покажет eligible/active-назначения. Дальше — сопоставление: какие привилегированные роли можно активировать без approval и какие назначены постоянно.

## Что мы теперь знаем

- PIM разделяет eligible и active; активация временна.
- Eligible без approval = быстрый путь к привилегиям (пароль+MFA).
- Постоянные назначения обходят всю модель PIM.
- Privileged Role Administrator управляет PIM — его компромисс критичен.
- MFA/justification снижают риск, но проходятся при компрометации.

## Квиз

Проверь себя.

```quiz
- question: "Чем eligible-назначение отличается от active?"
  options:
    - "Eligible нужно активировать; active действует постоянно"
    - "Eligible даёт больше прав"
    - "Это одно и то же"
    - "Active нельзя использовать"
  answer: 0
  explanation: "Eligible-роль активируется по требованию на ограниченное время; active-роль постоянна."
- question: "Почему eligible без approval опасна?"
  options:
    - "Права получаются в два действия: пароль + MFA"
    - "Она не даёт прав"
    - "Она требует тикет"
    - "Она блокирует вход"
  answer: 0
  explanation: "Без одобрения активация сводится к подтверждению MFA."
- question: "Чем плохи постоянные привилегированные назначения?"
  options:
    - "Обходят модель PIM: пароль/токен сразу даёт права"
    - "Они ускоряют работу"
    - "Они требуют MFA"
    - "Ничем"
  answer: 0
  explanation: "Permanent/active-назначение не требует активации и обесценивает JIT-модель."
- question: "Почему компромисс Privileged Role Administrator критичен?"
  options:
    - "Он управляет настройками PIM и может ослабить правила"
    - "Он читает почту"
    - "Он меняет DNS"
    - "Он только смотрит логи"
  answer: 0
  explanation: "Контроль над PIM позволяет менять approval/MFA-требования и выдавать роли."
- question: "Что снижает риск, но не устраняет его полностью?"
  options:
    - "Требование MFA и justification при активации"
    - "Пароль без MFA"
    - "Постоянные роли"
    - "Отключение логирования"
  answer: 0
  explanation: "MFA и обоснование повышают планку, но проходятся при компрометации пользователя."
```

## Куда дальше

В следующем уроке — Entra Identity Protection: risky sign-ins, риск-политики и их слепые зоны. А пока главное: PIM — это про время и одобрение; ищи eligible без approval и постоянные назначения.

## Где пригодится

- Пентест привилегированного доступа в Entra ID.
- Аудит конфигурации PIM.
- CTF-задачи категории cloud.
