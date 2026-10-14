---
id: forensics-google-workspace
title: 'Google Workspace: аудит и форензика'
category: forensics
parent: forensics-cloud-identity
difficulty: medium
order: 3
tags: [cloud, google, workspace, oauth, audit, admin, forensics]
prerequisites: [forensics-cloud-multi]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Cloud security'
estimated_minutes: 50
summary: 'Как устроены журналы Google Workspace (Admin audit, login, drive, token), как их читать через Reports API и BigQuery, и что они доказывают — от кражи OAuth-токенов до смены администратора и массовой выгрузки из Drive.'
lab:
  kind: shell
  title: 'Практика: разбор журнала Workspace'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, workspace.log]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Начни с `ls -la workspace.log` и `head workspace.log`.'
    - 'Поля: event_name, actor.email, ipAddress, type.'
    - 'Ищи события login, admin, token и drive.'
    - 'Флаг лежит в записи журнала: `grep nto workspace.log > found.txt`.'
---

## Вопрос, с которого всё начинается

Компания работает в Google Workspace. Сотрудник жалуется, что к его Google Drive
«прицепилось» незнакомое приложение. Через день из общего диска кто-то скачал документы.
Нужно понять, как это произошло. Источник — журналы Workspace.

## Что такое журналы Google Workspace

Workspace ведёт несколько **журналов аудита**, доступных администратору и через API:

- **login** — входы в аккаунты (успешные и неудачные);
- **admin** — действия администратора (создание пользователя, смена прав);
- **drive** — доступ к файлам и изменение прав;
- **token** — выдача и отзыв OAuth-токенов;
- **saml** — события входа через SSO;
- **user accounts** — изменения учётных записей.

Ключевые поля: **event_name** (что случилось), **actor.email** (кто), **ipAddress**
(откуда), **type** (категория журнала), **time**.

## Наш пример: журнал токенов и диска

```
$ ls -la
-rw-r--r-- 1 student student 5120 workspace.log
$ head -n 2 workspace.log
{"type":"login","event_name":"login_success","actor":{"email":"bob@corp.com"},"ipAddress":"203.0.113.9"}
{"type":"token","event_name":"authorize","actor":{"email":"bob@corp.com"},"ipAddress":"203.0.113.9"}
```

Второе событие — выдача **OAuth-токена** приложению. Смотрим дальше:

```
$ grep -Ei 'token|drive|admin|nto' workspace.log
{"type":"token","event_name":"authorize","app_name":"Docs Sync Tool","scopes":["drive.readonly","drive.file"]}
{"type":"drive","event_name":"download","actor":{"email":"bob@corp.com"},"doc_id":"1AbC"}
{"EVIDENCE":"nto{workspac3_0auth_t0k3n_gr4nt}"}
```

Видна связка: пользователь **авторизовал стороннее приложение** (`Docs Sync Tool`), и оно
получило доступ к Drive. Затем — скачивание документов. Это типичный сценарий кражи через
OAuth-согласие.

## Шаг 1: типичные сценарии атак

| event_name / type | Что означает | Почему подозрительно |
|-------------------|--------------|----------------------|
| `login_failure` (много) | неудачные входы | перебор пароля |
| `authorize` (token) | выдача OAuth-токена | сторонний доступ |
| `change_admin_setting` | смена настроек | ослабление защиты |
| `grant_delegated_admin` | делегированный админ | эскалация |
| `download` (drive, массово) | выгрузка файлов | кража данных |
| `change_password` | смена пароля | захват аккаунта |

Опасна **последовательность**: фишинг → авторизация приложения → массовые скачивания.

## Шаг 2: OAuth-токены и «app passwords»

Workspace выдаёт токены приложениям через OAuth. Злоумышленник может:

- уговорить пользователя авторизовать вредоносное приложение (consent phishing);
- использовать **app-specific passwords** (устаревший механизм) для доступа к почте;
- воспользоваться **service account** с domain-wide delegation.

В журнале `token` видно **имя приложения** и **scopes** — набор разрешений. Широкие scopes
(`drive`, `gmail.modify`) в сочетании с незнакомым приложением — красный флаг.

## Шаг 3: выгрузка журналов

Через Reports API:

```
$ curl -s -H "Authorization: Bearer ${TOKEN}" \
    "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/token?startTime=2026-03-10T00:00:00Z" \
    -o token.json
```

Через BigQuery — экспорт в датасеты `workspace_*` (например, `workspace_activity`), что
удобно для долгосрочного хранения и SQL-анализа. Портал Admin console даёт интерактивный
аудит.

Важно: **срок хранения** журналов ограничен (обычно 6 месяцев, дольше — при экспорте в
BigQuery). Поэтому выгрузку делают сразу.

## Шаг 4: разбор и корреляция

Сопоставляй **actor.email** и **ipAddress** между журналами: один IP во многих аккаунтах —
массовая атака. Событие `login_success` сразу после серии `login_failure` — подбор пароля.
`grant_delegated_admin` после входа с нового IP — эскалация.

Смотри **`drive`** на предмет массовых `download`/`change_user_access`: это выдача доступа
наружу или выкачивание данных.

## Шаг 5: реагирование

- отозвать OAuth-токен приложения (`tokens.revoke`);
- заблокировать приложение в настройках (allowlist);
- сменить пароль и включить 2FA;
- проверить delegated admins и service accounts;
- ограничить external sharing в Drive.

## Мини-практика: связать токен и скачивание

```
$ grep 'authorize' workspace.log
{"type":"token","event_name":"authorize","app_name":"Docs Sync Tool","actor":{"email":"bob@corp.com"}}
$ grep -c '"type":"drive"' workspace.log
42
```

Один `authorize` и 42 события Drive от того же пользователя за короткое время — картина
кражи через стороннее приложение. Дальше — отзыв токена и оценка ущерба.

## Частые ошибки и подводные камни

- **Не смотреть scopes.** Именно они показывают масштаб доступа.
- **Игнорировать `token`.** Выдача токена — точка входа для доступа без пароля.
- **Забыть про BigQuery.** Без экспорта старые события исчезнут.
- **Путать типы журналов.** login ≠ admin ≠ token — это разные потоки.
- **Не проверять delegated admin.** Делегированный админ может всё.

## Что мы теперь знаем

- Workspace ведёт журналы login/admin/drive/token/saml.
- OAuth-согласие (`authorize`) — путь к данным без пароля.
- Выгрузка — через Reports API или BigQuery; хранение ограничено.
- Коррелируй actor/IP между журналами.
- Реакция: отозвать токен, заблокировать приложение, сменить пароль.

## Что фиксировать в отчёте

| Что | Зачем |
|-----|-------|
| Список выданных токенов и scopes | масштаб доступа |
| Связка authorize → download | нарратив кражи |
| Делегированные админы | эскалация |
| Диапазон выгрузки | покрытие |
| Действия по устранению | реакция |

## Квиз

Проверь себя.

```quiz
- question: "Какой журнал Google Workspace показывает выдачу OAuth-токенов?"
  options:
    - "login"
    - "token"
    - "drive"
    - "saml"
  answer: 1
  explanation: "Журнал token фиксирует authorize/revoke OAuth-токенов и их scopes."
- question: "Что означают scopes при выдаче токена?"
  options:
    - "Имя пользователя"
    - "Набор разрешений приложения"
    - "IP-адрес"
    - "Размер файла"
  answer: 1
  explanation: "Scopes определяют, к каким данным и действиям приложение получает доступ."
- question: "Зачем экспортировать журналы Workspace в BigQuery?"
  options:
    - "Ускорить вход"
    - "Для долгосрочного хранения и SQL-анализа"
    - "Уменьшить размер пароля"
    - "Отключить 2FA"
  answer: 1
  explanation: "Хранение журналов ограничено; BigQuery даёт долгий срок и удобный анализ."
- question: "Какое событие подозрительно сразу после серии неудачных входов?"
  options:
    - "login_failure"
    - "login_success"
    - "logout"
    - "drive_view"
  answer: 1
  explanation: "Успешный вход после многих неудач — признак подбора пароля."
```

## Куда дальше

Мы разобрали Google Workspace. Дальше возьмём **Salesforce** — CRM с собственными Event Log
File и Setup Audit Trail. А пока главное запомни: **OAuth-токен — это доступ без пароля, и
его выдачу надо ловить в журнале token**.

## Где пригодится

- **CTF Forensics:** выгрузки журналов Workspace.
- **DFIR:** расследование consent-phishing и кражи из Drive.
- **Cloud security:** аудит OAuth-приложений и делегированных админов.
- **Threat hunting:** поиск массовых скачиваний и смен настроек.
