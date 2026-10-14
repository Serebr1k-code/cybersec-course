---
id: osint-google-workspace
title: 'Google Workspace: MX-признаки и перечисление пользователей'
category: osint
parent: osint-mod-saas-identity
difficulty: medium
order: 4
tags: [osint, google, workspace, gmail, mx]
prerequisites: [osint-okta-enum]
useful_for:
  - 'CTF OSINT'
  - 'Bug bounty'
  - 'Пентест: recon'
  - 'Red team'
estimated_minutes: 45
summary: 'Как по MX/TXT понять, что домен в Google Workspace, найти SSO-следы и проверить существование учётных записей.'
lab:
  kind: shell
  title: 'Практика: Google Workspace recon'
  toolset: [core, curl, jq, dig]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Проверь MX: `dig +short MX example.com`.'
    - 'TXT: `dig +short TXT example.com` — ищи google-site-verification.'
    - 'Спроси провайдера входа: `curl -s https://accounts.google.com/.well-known/openid-configuration`.'
    - 'Маркер `nto{...}` — в одном из ответов; запиши в `answer.txt`, затем `check`.'
---

## Вопрос, с которого всё начинается

Домен `example.com`, и ты хочешь понять, где живёт его почта и учётные записи. Если это Google Workspace, то у разведки появляется свой набор «дверей»: MX-записи Google, SSO-следы, страницы входа Google.

Задача: подтвердить Google Workspace по DNS и собрать публичные метаданные входа.

## Наш пример: домен и его почта

Первый и самый надёжный признак — **MX-запись** (mail exchanger): она говорит, какой сервер принимает почту домена.

```bash
dig +short MX example.com
```

```text
1 aspmx.l.google.com.
5 alt1.aspmx.l.google.com.
5 alt2.aspmx.l.google.com.
```

`aspmx.l.google.com` и `alt*.aspmx.l.google.com` — это инфраструктура Google. Значит, почта домена обрабатывается Google. Для Microsoft было бы `*.mail.protection.outlook.com`, для Яндекса — `mx.yandex.net`.

## Шаг 1: подтверждаем владение через TXT

Второй независимый признак — TXT-записи. Google просит подтвердить владение доменом записью `google-site-verification`, а SPF-запись содержит `include:_spf.google.com`.

```bash
dig +short TXT example.com
```

```text
"google-site-verification=abcd1234EFGH5678"
"v=spf1 include:_spf.google.com ~all"
```

Две независимые записи, указывающие на Google, — надёжное подтверждение. Мы не строим вывод на одном источнике.

## Шаг 2: читаем OIDC-конфигурацию Google

Сервис входа Google публикует стандартный OIDC-документ:

```bash
curl -s https://accounts.google.com/.well-known/openid-configuration | jq -r .issuer, .jwks_uri
```

```text
https://accounts.google.com
https://www.googleapis.com/oauth2/v3/certs
```

`issuer: accounts.google.com` и адрес публичных ключей подтверждают, что вход идёт через Google. Для организаций Workspace дополнительно доступны SAML-настройки на кастомном домене (`accounts.google.com/o/saml2/...`).

## Шаг 3: ищем следы Workspace

Признаки корпоративного Google, а не просто личного Gmail:

- `google-site-verification` с параметрами организации;
- CNAME `calendar.google.com`, `mail.google.com` на поддоменах;
- SAML-редиректы на страницах приложений;
- `_dmarc` с отчётами на почтовый шлюз организации.

```bash
dig +short CNAME mail.example.com
dig +short TXT _dmarc.example.com
```

```text
ghs.googlehosted.com.
"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

`ghs.googlehosted.com` — хостинг сервисов Google, а DMARC с `rua` на свой домен показывает, что организацией управляют всерьёз.

## Шаг 4: проверка пользователей и границы

Google исторически позволял проверять существование адреса Gmail через разные механики (регистрация, восстановление). Для Workspace-домена косвенный признак даёт страница входа: для существующего адреса она ведёт на страницу пароля Workspace, для несуществующего — на «создать аккаунт».

```text
https://accounts.google.com/v3/signin/identifier?identifier=ceo@example.com
→ существующий: страница ввода пароля Workspace
→ несуществующий: «Не удалось найти аккаунт Google»
```

Здесь та же дисциплина: **пара проверок, не перебор**. Google троттлит и требует капчу, а массовый перебор — уже не разведка.

## Полный прогон

```bash
dig +short MX example.com                 # → aspmx.l.google.com (Google)
dig +short TXT example.com                # → google-site-verification, _spf.google.com
curl -s https://accounts.google.com/.well-known/openid-configuration | jq -r .issuer
# → https://accounts.google.com
```

Домен → MX → TXT → OIDC → профиль: почта и вход в Google Workspace.

## Если не сработало

**MX не Google.** Проверь Microsoft (outlook.com) и Яндекс (yandex.net) — у них свои следы.
**Нет TXT-подтверждения.** Домен мог подтверждаться через CNAME — проверь и его.
**Личный Gmail, не Workspace.** Тогда SSO-следов не будет, только страница входа Google.

## Частые ошибки

**Ошибка: путать личный Gmail и Workspace.** Признак Workspace — корпоративный домен в MX/TXT, а не `gmail.com`.
**Ошибка: перебирать signin-эндпоинт.** Капча и троттлинг приходят быстро.
**Ошибка: игнорировать DMARC.** Запись показывает почтовую гигиену организации.

## Что мы теперь знаем

1. MX-запись Google подтверждает почту в Workspace.
2. TXT (verification, SPF) — второй независимый признак.
3. OIDC-конфигурация Google раскрывает issuer и JWKS.
4. Признаки корпоративного аккаунта — SAML, ghs, DMARC.
5. Перечисление — пара запросов, не перебор.

## Справочная таблица: признаки Google Workspace

| Признак | Значение | Надёжность |
|---------|----------|------------|
| MX → `aspmx.l.google.com` | почта в Google | высокая |
| TXT `google-site-verification=` | домен подтверждён в Google | высокая |
| TXT `v=spf1 include:_spf.google.com` | отправка через Google | высокая |
| CNAME `ghs.googlehosted.com` | сервисы Google | средняя |
| DMARC `rua=mailto:...` | почтовая гигиена | косвенная |
| SAML-редирект на входе | корпоративный SSO | высокая |

Шпаргалка: MX + TXT вместе дают надёжный вывод; CNAME и DMARC — подтверждающие штрихи.

## Разбор кейса: три домена и их провайдеры

Дано три домена: `a-example.com`, `b-example.com`, `c-example.com`. Проверим, где живёт каждый.

```bash
for d in a-example.com b-example.com c-example.com; do
  echo -n "$d: "; dig +short MX $d | head -1
done
```

```text
a-example.com: 1 aspmx.l.google.com.
b-example.com: 0 b-example-com.mail.protection.outlook.com.
c-example.com: 10 mx.yandex.net.
```

Читаем: первый — Google Workspace, второй — Microsoft 365, третий — Яндекс. Уже по одной MX-записи разведчик распределяет организации по облакам. Дальше для каждого провайдера включается свой набор эндпоинтов: Google — OIDC `accounts.google.com`, Microsoft — `login.microsoftonline.com`, Яндекс — свои страницы входа. Так MX-запись становится первой развилкой всего расследования.

## Частые вопросы

**Как отличить личный Gmail от Google Workspace?** Личный адрес оканчивается на `gmail.com`; Workspace — это корпоративный домен, чьи MX-записи указывают на Google. Наличие `google-site-verification` в TXT домена — признак Workspace.

**Зачем искать SAML-редиректы?** Они показывают, что вход в приложения идёт через корпоративный SSO Google, а не через личные аккаунты. Это подтверждает масштаб организации.

**Что даёт DMARC?** Запись `v=DMARC1` с `rua` на домен организации показывает, что почтой управляют осознанно; иногда в отчётах видны IP-адреса почтовых шлюзов.

**Можно ли узнать список сотрудников?** Прямого открытого перечисления нет. Косвенные источники — Google Groups, публичные календари, утечки. Пара проверок на странице входа, не перебор.

**Почему MX надёжнее страницы входа?** Страницу входа можно закрыть или сменить брендинг, а MX-запись — часть инфраструктуры домена и меняется редко.

## Термины

**MX** — Mail Exchanger, DNS-запись с адресом почтового сервера домена.

**SPF** — запись со списком разрешённых отправителей почты от имени домена.

**DMARC** — политика проверки подлинности почты и адрес для отчётов.

**OIDC** — OpenID Connect: публикует эндпоинты входа и ключи подписи.

**SAML** — протокол корпоративного SSO; редиректы на страницу входа Google подтверждают Workspace.

**Workspace** — корпоративный набор сервисов Google (почта, диск, календарь) на своём домене.

## Рабочий воркбук: полное расследование Google Workspace

Разведка Google Workspace держится на DNS и одном OIDC-документе. Пройдём маршрут целиком.

**Этап 1. Почта.** Первым делом спрашиваешь MX-запись домена. `aspmx.l.google.com` и `alt*.aspmx.l.google.com` — почта в Google. Если видишь `*.mail.protection.outlook.com`, это Microsoft, а `mx.yandex.net` — Яндекс. Одна запись сразу делит организации по облакам.

**Этап 2. Подтверждение владения.** Смотришь TXT-записи. `google-site-verification=` означает, что владелец домена подтверждал его в консоли Google. `v=spf1 include:_spf.google.com` означает, что почта отправляется через Google. Две независимые записи вместе дают надёжный вывод, что домен — корпоративный, а не просто пересылает почту.

**Этап 3. Вход.** Читаешь OIDC-документ `accounts.google.com/.well-known/openid-configuration`. Поля `issuer` и `jwks_uri` подтверждают, что вход идёт через Google. Для корпоративных доменов дополнительно ищешь SAML-редиректы: страницы приложений, ведущие на страницу входа Workspace, показывают, что организация использует SSO.

**Этап 4. Косвенные признаки.** CNAME `ghs.googlehosted.com` выдаёт сервисы Google, размещённые на поддоменах. DMARC-запись с `rua` на домен организации показывает зрелость почтовой инфраструктуры. Иногда в отчётах DMARC видны IP почтовых шлюзов — ещё один слой.

**Этап 5. Пользователи.** Прямого списка сотрудников нет. Косвенно он собирается из Google Groups, публичных календарей, утечек и страницы входа: для существующего адреса Workspace показывает форму пароля, для несуществующего — предложение создать аккаунт. Как всегда, пара проверок, а не перебор: Google быстро включает капчу.

Пройдя эти этапы, ты знаешь провайдера почты и входа, степень зрелости почтовой инфраструктуры и примерный контур сотрудников. Для CTF этого обычно достаточно, чтобы двигаться дальше.

## Почему DNS надёжнее всего

Страницы входа меняются, брендинг перерисовывают, API закрывают — а DNS-записи остаются. MX, SPF и verification-записи обслуживают почту и подтверждение владения, поэтому их меняют редко и осторожно. Для разведчика это означает простую стратегию: сначала зафиксируй DNS-факты (MX, TXT, CNAME), а уже потом дополняй их живыми ответами сервисов входа. Если живой ответ и DNS расходятся, верь DNS: его сложнее подделать незаметно, и он отражает реальную маршрутизацию почты организации. Эта же логика работает и в обратную сторону: зная MX-запись, ты сразу понимаешь, какой набор OIDC-эндпоинтов проверять — Google, Microsoft или Яндекс. Так DNS становится первой и самой устойчивой развилкой всего расследования облачного присутствия компании.

## Итоговая связка признаков

Соберём всё в одну короткую формулу вывода. Если MX указывает на `aspmx.l.google.com`, TXT содержит `google-site-verification` и `include:_spf.google.com`, OIDC-документ `accounts.google.com` отдаёт issuer, а на поддомене виден CNAME `ghs.googlehosted.com` — вывод однозначен: домен живёт в Google Workspace. Если хотя бы два из четырёх признаков совпадают, вывод остаётся сильным; если совпадает только MX, домен может просто пересылать почту в Gmail, оставаясь на другом провайдере идентичности. Такой поэтапный набор признаков защищает от ложного вывода и делает разведку воспроизводимой.

## Квиз

Проверь себя.

```quiz
- question: "Какая DNS-запись подтверждает почту в Google Workspace?"
  options:
    - "MX → *.google.com / aspmx.l.google.com"
    - "AAAA"
    - "NS"
    - "CAA"
  answer: 0
  explanation: "MX-запись указывает на почтовые серверы Google."
- question: "Какой TXT-признак подтверждает владение доменом в Google?"
  options:
    - "google-site-verification"
    - "v=spf1 include:_spf.google.com"
    - "Оба варианта"
    - "Ни один"
  answer: 2
  explanation: "И verification, и SPF-запись — независимые признаки Google."
- question: "Где взять issuer Google для входа?"
  options:
    - "В OpenID-конфигурации accounts.google.com"
    - "В MX"
    - "В favicon"
    - "В robots.txt"
  answer: 0
  explanation: "Стандартный OIDC-документ отдаёт issuer и jwks_uri."
- question: "Что показывает CNAME ghs.googlehosted.com?"
  options:
    - "Хостинг сервисов Google"
    - "Пароль администратора"
    - "Номер телефона"
    - "VIN"
  answer: 0
  explanation: "ghs.googlehosted.com — хостинг сервисов Google для домена."
```

## Куда дальше

Мы закрыли четырёх крупных провайдеров идентичности. Дальше модуль перейдёт к **DevOps-поверхности** — Slack, Jira, CI/CD и реестры контейнеров. А пока запомни: MX и TXT надёжно выдают, что домен живёт в Google Workspace.

## Где пригодится

- **Пентест:** определение облака и почтового провайдера.
- **Bug bounty:** подтверждение Workspace-доменов в scope.
- **CTF (OSINT):** поиск SSO-следов по DNS.
- **Blue team:** проверка почтовой гигиены (SPF/DMARC).
