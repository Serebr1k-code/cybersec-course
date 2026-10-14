#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch F: osint IaC/terraform + identity-provider lessons."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson as _wl
def write_lesson(meta, body, lab=None):
    try: return _wl(meta, body, lab=lab)
    except SystemExit: print('skip:', meta.get('id')); return None
U = ["CTF OSINT", "Bug bounty", "Пентест: recon", "Red team"]

iac = dict(
    id="osint-iac-recon", title="IaC и Terraform state: где утекает состояние инфраструктуры",
    category="osint", parent="osint-mod-cloud-surface", difficulty="hard", order=3,
    tags=["osint","iac","terraform","state","cloudformation"], prerequisites=["osint-api-discovery"],
    useful_for=U, estimated_minutes=55,
    summary="Как находить файлы состояния Terraform и шаблоны IaC в открытых бакетах и репозиториях и почему они опасны.",
    lab=dict(title="Практика: открытый Terraform state", toolset=["core","curl","jq"], workdir="/home/student/task",
        files=["task.md"], check="grep -q 'nto{' answer.txt",
        hints=["State-файл часто лежит в S3: `curl -s https://example-tfstate.s3.amazonaws.com/terraform.tfstate`.",
               "Ищи `resources` и `outputs` — там параметры ресурсов.",
               "Иногда секреты лежат в `outputs`.",
               "Маркер `nto{...}` — в ответе; запиши в `answer.txt`, затем `check`."],
        expect={"file":"/home/student/task/answer.txt","contains":"nto{t3rr4f0rm_st4t3_l34k}"},
        fs=[{"path":"/home/student/task","type":"dir"},
            {"path":"/home/student/task/task.md","text":"# Практика: Terraform state\n\n1. `curl -s https://example-tfstate.s3.amazonaws.com/terraform.tfstate`\n2. Найди `resources` и `outputs`.\n3. Секрет/маркер может быть в `outputs`.\n4. Запиши `nto{...}` в `answer.txt`, затем `check`.\n"}],
        tools={"curl":{"help":"curl [-s] <URL> — эмуляция ответов S3","cases":[
            {"match":"tfstate","example":"curl -s https://example-tfstate.s3.amazonaws.com/terraform.tfstate",
             "output":"{\"version\":4,\"terraform_version\":\"1.5.4\",\"serial\":12,\"outputs\":{\"db_password\":{\"value\":\"nto{t3rr4f0rm_st4t3_l34k}\",\"type\":\"string\"},\"db_endpoint\":{\"value\":\"db.internal.example.com\",\"type\":\"string\"}},\"resources\":[{\"type\":\"aws_db_instance\",\"name\":\"main\",\"instances\":[{\"attributes\":{\"endpoint\":\"db.internal.example.com:5432\",\"username\":\"admin\"}}]},{\"type\":\"aws_s3_bucket\",\"name\":\"assets\"}]}\n"}],
            "fallback":"curl: в этой лабе доступен только example-tfstate.s3.amazonaws.com.\n"},
        "jq":{"help":"jq [опции] <фильтр> <файл> — разбор JSON (эмуляция)","cases":[
            {"match":"outputs|resources|\\.","example":"jq -r '.outputs.db_password.value' state.json","output":"nto{t3rr4f0rm_st3t3_l34k}\n"}],
            "fallback":"jq: в этой лабе поддерживается разбор полей.\n"}},
    ),
)
iac_body = r"""## Вопрос, с которого всё начинается

Компания управляет облаком не руками, а кодом: Terraform, CloudFormation, Ansible. Такой подход называется **Infrastructure as Code (IaC)** — инфраструктура описана в файлах. И у этого есть побочный эффект: рядом с кодом лежит **файл состояния** (state), где записано всё, что реально создано в облаке, — включая пароли, ключи и внутренние адреса.

Задача: найти открытые файлы состояния и шаблоны IaC, понять, что в них утекло, — не применяя никаких изменений к инфраструктуре.

## Наш пример: state-файл в открытом бакете

Terraform хранит состояние в файле `terraform.tfstate`. Его часто кладут в S3-бакет, чтобы команда работала совместно. Иногда бакет забывают закрыть.

Держим объект `https://example-tfstate.s3.amazonaws.com/terraform.tfstate`. Первый вопрос: **открыт ли он?**

```bash
curl -s https://example-tfstate.s3.amazonaws.com/terraform.tfstate | jq .
```

```json
{"version":4,"terraform_version":"1.5.4",
 "outputs":{"db_password":{"value":"..."},"db_endpoint":{"value":"db.internal.example.com"}},
 "resources":[{"type":"aws_db_instance","name":"main"},{"type":"aws_s3_bucket","name":"assets"}]}
```

Читаем: `outputs` содержат `db_password` и `db_endpoint`, а `resources` перечисляют созданные ресурсы — базу и бакет. Это карта инфраструктуры организации плюс, в данном случае, пароль от базы. Одна незакрытая дверь выдала и топологию, и секрет.

## Шаг 1: где искать state

Файлы состояния лежат в предсказуемых местах. Первое — S3-бакеты: имена вида `<org>-terraform-state`, `<org>-tfstate`, `terraform-<env>`. Второе — репозитории: разработчики иногда коммитят `.tfstate` по ошибке. Третье — артефакты CI: сборка может сохранять state как артефакт. Четвёртое — локальные копии `.terraform/terraform.tfstate`.

```bash
# иллюстративно: поиск в публичных репозиториях
# "terraform.tfstate" org:example
# "AKIA" org:example
```

Имена бакетов и наличие `.tfstate` в индексе S3 — сильные сигналы. Иногда бакет разрешает листинг (`?list-type=2`), и тогда видны все файлы.

## Шаг 2: что внутри state

State — это JSON с тремя ключевыми разделами. `resources` — что создано (базы, бакеты, виртуалки, роли). `outputs` — вычисленные значения (адреса, пароли, ключи). `terraform_version` — версия инструмента. Даже без секретов state рассказывает, как устроено облако: сколько окружений, какие сервисы, какие имена ресурсов.

```bash
curl -s https://example-tfstate.s3.amazonaws.com/terraform.tfstate | jq -r '.resources[].type' | sort -u
```

```text
aws_db_instance
aws_s3_bucket
```

Это список типов ресурсов — карта облака организации.

## Шаг 3: .tfvars и другие шаблоны

Рядом со state лежат переменные: `terraform.tfvars`, `*.auto.tfvars`. В них часто выносят секреты — пароли, ключи API. Их тоже ищут в бакетах и репозиториях. Аналогично устроены CloudFormation-шаблоны (`.yaml`/`.json` с `AWSTemplateFormatVersion`) и Ansible-vault-файлы.

```text
terraform.tfvars
prod.auto.tfvars
cloudformation/prod.yaml
```

Каждый такой файл — потенциальный источник и карты, и секретов.

## Шаг 4: границы

Мы читаем публичные файлы и фиксируем утечки. Мы **не применяем изменения** (`terraform apply`), не используем найденные ключи и не модифицируем инфраструктуру. State — это доказательство для отчёта, а не рабочий инструмент. Особенно важно: применение чужого state может разрушить или изменить чужие ресурсы — это категорически вне рамок разведки.

## Полный прогон

```bash
# 1. state открыт?
curl -s -o /dev/null -w '%{http_code}\n' https://example-tfstate.s3.amazonaws.com/terraform.tfstate   # → 200
# 2. типы ресурсов
curl -s https://example-tfstate.s3.amazonaws.com/terraform.tfstate | jq -r '.resources[].type' | sort -u
# → aws_db_instance, aws_s3_bucket
# 3. outputs
curl -s https://example-tfstate.s3.amazonaws.com/terraform.tfstate | jq -r '.outputs | keys[]'
# → db_password, db_endpoint
```

Непрерывно: бакет → state → ресурсы → outputs → карта инфраструктуры и утечки.

## Если не сработало

**Бакет закрыт.** Проверь варианты имён и другие окружения (`-dev`, `-prod`, `-staging`).
**State в репозитории.** Ищи через поиск по коду GitHub/GitLab.
**Только шаблоны.** Ищи `.tf`, `.tfvars`, CloudFormation — они тоже раскрывают инфраструктуру.

## Частые ошибки

**Ошибка: применять state.** `terraform apply` может изменить или сломать инфраструктуру.
**Ошибка: использовать найденный ключ.** Это эксплуатация, а не разведка.
**Ошибка: игнорировать outputs.** Именно там чаще всего лежат секреты.
**Ошибка: забыть про бэкапы.** Рядом часто лежит `terraform.tfstate.backup` — иногда с более старыми секретами.

## Справочная таблица: файлы IaC

| Файл | Что содержит | Риск |
|------|--------------|------|
| `terraform.tfstate` | ресурсы и outputs | высокий (секреты) |
| `terraform.tfstate.backup` | предыдущее состояние | высокий |
| `terraform.tfvars` | переменные, часто секреты | высокий |
| `*.tf` | описание ресурсов | средний |
| CloudFormation `*.yaml` | параметры стека | средний |

## Разбор кейса: от бакета до пароля базы

Дано: домен `example.com`. Шаг первый — находим бакет `example-tfstate.s3.amazonaws.com` (по имени организации и индексу). Шаг второй — `terraform.tfstate` открыт, `resources` перечисляют базу и бакет. Шаг третий — `outputs.db_password` содержит пароль, `db_endpoint` — внутренний адрес базы. Вывод: открытое состояние Terraform с утечкой секрета. Разведчик зафиксировал находку с доказательством и остановился, не применяя state.

## Рабочий воркбук: полное расследование IaC

**Этап 1. Поиск бакетов.** Сгенерируй варианты имён: `<org>-tfstate`, `<org>-terraform-state`, `terraform-<env>`. Проверь каждый на существование и листинг.

**Этап 2. Чтение state.** Скачай state, выгрузи `resources`, `outputs`, `terraform_version`. Зафиксируй типы ресурсов и окружения.

**Этап 3. Поиск секретов.** Ищи в `outputs` и в `tfvars` пароли, ключи, токены. Отмечай путь к секрету в файле.

**Этап 4. Репозитории.** Проверь публичные репозитории организации на `.tfstate`, `.tfvars`, CloudFormation. Сканеры секретов ускоряют поиск.

**Этап 5. Фиксация.** Сведи открытые файлы, типы ресурсов, окружения и утечки в отчёт. Ничего не применяй.

## Частые вопросы

**Почему state опаснее обычного конфига?** Потому что он описывает реально созданные ресурсы и часто хранит вычисленные секреты — пароли и ключи, которые не попадают в код.

**Что такое outputs?** Значения, которые Terraform вычисляет после создания ресурсов: адреса, пароли, идентификаторы. Их часто используют другие модули.

**Можно ли применять чужой state?** Категорически нет: это изменит или разрушит инфраструктуру и является атакой, а не разведкой.

**Где ещё искать секреты IaC?** В `.tfvars`, в CloudFormation-параметрах, в переменных CI/CD, в бэкапах state.

**Это законно?** Чтение публичных файлов — да. Применение и использование секретов — нет.

## Термины

**IaC** — Infrastructure as Code, управление инфраструктурой через файлы.

**Terraform state** — файл с текущим состоянием инфраструктуры и её секретами.

**Outputs** — вычисленные значения ресурсов.

**tfvars** — файл переменных Terraform.

**CloudFormation** — IaC-сервис AWS со своими шаблонами.

## Что мы теперь знаем

1. IaC хранит состояние инфраструктуры в файлах.
2. State часто лежит в S3-бакетах и репозиториях.
3. `resources` даёт карту облака, `outputs` — секреты.
4. tfvars и CloudFormation — дополнительные источники.
5. Разведка читает state, но никогда его не применяет.

## Квиз

Проверь себя.

```quiz
- question: "Что хранит файл terraform.tfstate?"
  options:
    - "Только пароли"
    - "Состояние инфраструктуры и часто секреты"
    - "Логи nginx"
    - "DNS-записи"
  answer: 1
  explanation: "State описывает созданные ресурсы и outputs, включая секреты."
- question: "Где чаще всего находят открытый state?"
  options:
    - "В S3-бакетах и репозиториях"
    - "В MX-записи"
    - "В favicon"
    - "В TTL"
  answer: 0
  explanation: "State кладут в S3 для совместной работы; иногда коммитят по ошибке."
- question: "Какой раздел state содержит вычисленные секреты?"
  options:
    - "resources"
    - "outputs"
    - "version"
    - "serial"
  answer: 1
  explanation: "В outputs попадают пароли, адреса и ключи."
- question: "Что категорически нельзя делать с найденным state?"
  options:
    - "Читать его"
    - "Применять (terraform apply)"
    - "Смотреть resources"
    - "Фиксировать находку"
  answer: 1
  explanation: "Применение чужого state меняет или разрушает инфраструктуру."
```

## Куда дальше

Дальше в модуле — **IdP и SSO**: научимся находить метаданные провайдера входа. А пока запомни: файл состояния Terraform — это карта облака вместе с ключами, и его утечка критична.

## Где пригодится

- **Пентест:** карта облака и поиск утечек секретов.
- **Bug bounty:** открытые бакеты и state в scope.
- **CTF (OSINT):** секреты в state и tfvars.
- **Blue team:** аудит публикации IaC-артефактов.
"""
write_lesson(iac, iac_body, lab=iac["lab"])

idp = dict(
    id="osint-identity-provider", title="SSO и IdP: обнаружение и метаданные провайдера входа",
    category="osint", parent="osint-mod-cloud-surface", difficulty="medium", order=4,
    tags=["osint","sso","saml","idp","adfs","metadata"], prerequisites=["osint-iac-recon"],
    useful_for=U, estimated_minutes=50,
    summary="Как найти провайдера единого входа организации (ADFS, Okta, Azure AD, Ping) и прочитать его публичные метаданные SAML/OIDC.",
    lab=dict(title="Практика: метаданные IdP", toolset=["core","curl","jq"], workdir="/home/student/task",
        files=["task.md"], check="grep -q 'nto{' answer.txt",
        hints=["ADFS-метаданные: `curl -s https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml`.",
               "Ищи `entityID` и сертификаты.",
               "OIDC: `curl -s https://sso.example.com/.well-known/openid-configuration`.",
               "Маркер `nto{...}` — в ответе; запиши в `answer.txt`, затем `check`."],
        expect={"file":"/home/student/task/answer.txt","contains":"nto{1dp_m3t4d4t4_3xp0s3d}"},
        fs=[{"path":"/home/student/task","type":"dir"},
            {"path":"/home/student/task/task.md","text":"# Практика: IdP metadata\n\n1. `curl -s https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml`\n2. Найди `entityID`.\n3. `curl -s https://sso.example.com/.well-known/openid-configuration`\n4. Маркер `nto{...}` — запиши в `answer.txt`, затем `check`.\n"}],
        tools={"curl":{"help":"curl [-s] <URL> — эмуляция ответов IdP","cases":[
            {"match":"FederationMetadata","example":"curl -s https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml",
             "output":"<EntityDescriptor entityID=\"http://adfs.example.com/adfs/services/trust\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"><IDPSSODescriptor><KeyDescriptor use=\"signing\"><KeyInfo><X509Data><X509Certificate>MIIC...</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://adfs.example.com/adfs/ls/\"/></IDPSSODescriptor><ContactPerson><Company>nto{1dp_m3t4d4t4_3xp0s3d}</Company></ContactPerson></EntityDescriptor>\n"},
            {"match":"openid-configuration","example":"curl -s https://sso.example.com/.well-known/openid-configuration",
             "output":"{\"issuer\":\"https://sso.example.com\",\"authorization_endpoint\":\"https://sso.example.com/oauth2/authorize\",\"token_endpoint\":\"https://sso.example.com/oauth2/token\",\"jwks_uri\":\"https://sso.example.com/.well-known/jwks.json\"}\n"}],
            "fallback":"curl: в этой лабе доступны adfs.example.com и sso.example.com.\n"},
        "jq":{"help":"jq [опции] <фильтр> <файл> — разбор JSON (эмуляция)","cases":[
            {"match":"issuer|\\.","example":"jq -r .issuer conf.json","output":"https://sso.example.com\n"}],
            "fallback":"jq: в этой лабе поддерживается разбор полей.\n"}},
    ),
)
idp_body = r"""## Вопрос, с которого всё начинается

Компания использует единый вход (SSO): сотрудник логинится один раз и попадает во все приложения. За этим стоит **провайдер идентичности (IdP)** — ADFS, Okta, Azure AD, Ping. У каждого IdP есть публичные метаданные: документ, который описывает эндпоинты входа, сертификаты подписи и идентификатор организации.

Задача: найти IdP компании и прочитать его метаданные — не входя в систему.

## Наш пример: метаданные ADFS

ADFS — сервер федерации Microsoft. Он публикует XML-документ с метаданными по стандартному пути.

Держим объект `https://adfs.example.com`. Первый вопрос: **отдаёт ли он метаданные?**

```bash
curl -s https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml
```

```xml
<EntityDescriptor entityID="http://adfs.example.com/adfs/services/trust">
  <IDPSSODescriptor>
    <KeyDescriptor use="signing"><KeyInfo><X509Certificate>MIIC...</X509Certificate></KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="...HTTP-Redirect" Location="https://adfs.example.com/adfs/ls/"/>
  </IDPSSODescriptor>
</EntityDescriptor>
```

Читаем: `entityID` — идентификатор IdP, `SingleSignOnService` — адрес входа, сертификат — ключ подписи токенов. Это публичный документ, и он полностью описывает провайдера входа организации.

## Шаг 1: как найти IdP

IdP находят по DNS и поддоменам. Характерные имена: `adfs`, `sts`, `sso`, `login`, `idp`, `federation`, `auth`. Дополнительные сигналы — CNAME-записи: `enterpriseregistration`, `enterpriseenrollment`, `_sipfederationtls._tcp` указывают на Microsoft-федерацию.

```bash
dig +short CNAME adfs.example.com
dig +short CNAME sts.example.com
```

```text
adfs.example.com.
```

Если поддомен отвечает на `/FederationMetadata/...` или на OIDC-документ — IdP найден.

## Шаг 2: OIDC-провайдеры

Не все IdP используют SAML. Okta, Azure AD, Google, Ping публикуют документ OpenID Connect:

```bash
curl -s https://sso.example.com/.well-known/openid-configuration | jq -r .issuer, .jwks_uri
```

```text
https://sso.example.com
https://sso.example.com/.well-known/jwks.json
```

Поля `issuer` и `jwks_uri` подтверждают провайдера и дают адрес ключей подписи. Некоторые IdP поддерживают оба протокола — тогда ты увидишь и SAML-метаданные, и OIDC.

## Шаг 3: что извлекают из метаданных

Метаданные дают несколько ценных вещей. Первое — `entityID`: уникальный идентификатор IdP, по которому его узнают приложения. Второе — эндпоинты входа и выхода. Третье — сертификаты подписи: по ним определяют, чем подписаны токены. Четвёртое — иногда контактные данные и бренд организации. Всё это — публичная информация, которую IdP отдаёт намеренно, чтобы приложения могли настроить федерацию.

```bash
curl -s https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml | grep -oE 'entityID="[^"]*"'
```

```text
entityID="http://adfs.example.com/adfs/services/trust"
```

## Шаг 4: границы

Метаданные IdP публичны по дизайну. Мы их читаем и фиксируем. Мы **не пытаемся подделывать токены, не используем сертификаты для атак и не входим в систему**. IdP-разведка даёт карту: какой провайдер, какие эндпоинты, какие ключи. Этого достаточно для отчёта и для планирования авторизованной проверки.

## Полный прогон

```bash
# 1. ADFS-метаданные
curl -s https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml | grep -oE 'entityID="[^"]*"'
# → entityID="http://adfs.example.com/adfs/services/trust"
# 2. OIDC
curl -s https://sso.example.com/.well-known/openid-configuration | jq -r .issuer
# → https://sso.example.com
# 3. DNS-подтверждение
dig +short CNAME enterpriseregistration.example.com
# → enterpriseregistration.windows.net.
```

Непрерывно: поддомен → метаданные SAML/OIDC → entityID и эндпоинты → профиль IdP.

## Если не сработало

**ADFS-путь закрыт.** Попробуй `/adfs/ls/IdpInitiatedSignon.aspx` и OIDC-документ.
**Другой IdP.** Okta, Ping, Azure AD публикуют OIDC; проверь их характерные пути.
**Метаданные только через приложение.** Тогда IdP определяют по редиректу со страницы входа приложения.

## Частые ошибки

**Ошибка: считать метаданные утечкой.** Они публичны намеренно; утечка — это когда они раскрывают лишнее (например, внутренние имена).
**Ошибка: путать SAML и OIDC.** Это разные протоколы; проверяй оба.
**Ошибка: игнорировать сертификаты.** По сертификату подписи иногда определяют срок и владельца.
**Ошибка: не смотреть DNS.** CNAME на Microsoft-федерацию сразу указывает на ADFS/Azure AD.

## Справочная таблица: пути метаданных IdP

| IdP | Путь | Формат |
|-----|------|--------|
| ADFS | `/FederationMetadata/2007-06/FederationMetadata.xml` | SAML XML |
| Okta | `/oauth2/default/.well-known/openid-configuration` | OIDC |
| Azure AD | `/<domain>/v2.0/.well-known/openid-configuration` | OIDC |
| Ping | `/pf/federation_metadata.ping` | SAML XML |
| Generic | `/.well-known/openid-configuration` | OIDC |

## Разбор кейса: от поддомена до entityID

Дано: домен `example.com`. Шаг первый — находим `adfs.example.com`. Шаг второй — `/FederationMetadata/...` отдаёт XML, `entityID` = `http://adfs.example.com/adfs/services/trust`. Шаг третий — `sso.example.com` публикует OIDC-документ с `issuer`. Вывод: организация использует ADFS для федерации и OIDC-провайдера для приложений. Разведчик зафиксировал обоих провайдеров и их эндпоинты.

## Рабочий воркбук: полное расследование IdP

**Этап 1. Обнаружение.** Собери поддомены `adfs`, `sts`, `sso`, `login`, `idp`, `federation`, `auth`.

**Этап 2. Протокол.** Для каждого проверь SAML-метаданные и OIDC-документ. Определи, какой протокол используется.

**Этап 3. Извлечение.** Выгрузи `entityID`/`issuer`, эндпоинты входа, сертификаты подписи.

**Этап 4. Связи.** Сопоставь IdP с приложениями: страницы входа SaaS-сервисов часто редиректят на тот же IdP.

**Этап 5. Фиксация.** Сведи провайдеров, протоколы, эндпоинты и сертификаты в отчёт. Не подделывай токены.

## Частые вопросы

**Почему метаданные IdP публичны?** Чтобы приложения (relying parties) могли настроить федерацию: знать эндпоинты и ключи подписи. Без этого SSO не работает.

**Что такое entityID?** Уникальный идентификатор IdP в мире SAML. Приложения доверяют ему.

**Чем SAML отличается от OIDC?** SAML — XML-протокол, старше и распространён в корпоративной среде. OIDC — JSON-протокол на базе OAuth 2.0, современнее.

**Можно ли подделать токен по метаданным?** Теоретически это предмет атаки, но вне рамок разведки. Мы только фиксируем факты.

**Это законно?** Чтение публичных метаданных — да. Подделка токенов и вход — нет.

## Термины

**IdP** — Identity Provider, провайдер идентичности.

**SAML** — XML-протокол федерации и SSO.

**OIDC** — OpenID Connect, JSON-протокол на базе OAuth 2.0.

**entityID** — идентификатор IdP в SAML.

**Relying party** — приложение, доверяющее IdP.

## Что мы теперь знаем

1. IdP публикует метаданные SAML или OIDC.
2. ADFS отдаёт XML по стандартному пути.
3. OIDC-документ даёт issuer и ключи.
4. entityID и эндпоинты — публичная карта входа.
5. Разведка фиксирует метаданные, не подделывая токены.

## Квиз

Проверь себя.

```quiz
- question: "По какому пути ADFS отдаёт метаданные?"
  options:
    - "/FederationMetadata/2007-06/FederationMetadata.xml"
    - "/robots.txt"
    - "/favicon.ico"
    - "/.git/config"
  answer: 0
  explanation: "ADFS публикует SAML-метаданные по стандартному пути FederationMetadata."
- question: "Что такое entityID в метаданных IdP?"
  options:
    - "Пароль"
    - "Уникальный идентификатор провайдера идентичности"
    - "IP-адрес"
    - "Номер телефона"
  answer: 1
  explanation: "entityID — идентификатор IdP, которому доверяют приложения."
- question: "Какой протокол публикует документ /.well-known/openid-configuration?"
  options:
    - "SAML"
    - "OIDC"
    - "LDAP"
    - "Kerberos"
  answer: 1
  explanation: "OIDC публикует openid-configuration с issuer и jwks_uri."
- question: "Что допустимо в разведке IdP?"
  options:
    - "Подделывать токены"
    - "Читать публичные метаданные"
    - "Входить в систему"
    - "Менять сертификаты"
  answer: 1
  explanation: "Метаданные публичны; подделка и вход — вне рамок."
```

## Куда дальше

Мы завершили облачно-нативный блок модуля. Дальше разведка может уйти в **медиапровенанс** или в **корпоративно-финансовые реестры**. А пока запомни: IdP-метаданные — публичная карта единого входа организации.

## Где пригодится

- **Пентест:** определение SSO-провайдера и его эндпоинтов.
- **Bug bounty:** поиск IdP в scope.
- **CTF (OSINT):** entityID и метаданные федерации.
- **Blue team:** аудит публикации метаданных IdP.
"""
write_lesson(idp, idp_body, lab=idp["lab"])
print("Batch F done: iac, idp")
