#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Second expansion pass for osint-m365-enum and osint-azure-tenant."""
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def insert_before_quiz(path, block):
    t = open(path, encoding='utf-8').read()
    i = t.index('## Квиз')
    open(path, 'w', encoding='utf-8').write(t[:i] + block.strip() + '\n\n' + t[i:])

M365 = r"""
## Разбор кейса: три домена — один тенант

Представь, что у компании три домена: `example.com`, `example-corp.com` и бренд `example.net`. Задача — понять, живут ли они в одном тенанте Microsoft.

Первый шаг — спросить realm по каждому домену:

```bash
for d in example.com example-corp.com example.net; do
  echo -n "$d: "
  curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@$d&json=1" | jq -r .NameSpaceType
done
```

```text
example.com: Managed
example-corp.com: Managed
example.net: Managed
```

Все три управляемые — уже хороший знак, но это не доказывает один тенант. Второй шаг — достать tenant ID из OpenID каждого домена и сравнить GUID:

```bash
for d in example.com example-corp.com example.net; do
  curl -s "https://login.microsoftonline.com/$d/v2.0/.well-known/openid-configuration" \
    | jq -r .token_endpoint | grep -oE '[0-9a-f-]{36}'
done
```

```text
72f988bf-86f1-41af-91ab-2d7cd011db47
72f988bf-86f1-41af-91ab-2d7cd011db47
72f988bf-86f1-41af-91ab-2d7cd011db47
```

Одинаковый GUID трижды — значит, три домена принадлежат **одному тенанту**. Это вывод, ради которого стоило работать: разведчик получил полную карту доменов организации, а не один домен.

## На что смотреть дальше

- **Подтверждай второй раз.** Один ответ сервиса — гипотеза; GUID из двух источников — факт.
- **Следи за троттлингом.** Частые запросы GetCredentialType приводят к `ThrottleStatus` и заметны защите.
- **Разделяй разведку и атаку.** Перечисление пользователей — это карта, а не вход; подбор паролей — отдельный авторизуемый шаг.
- **Фиксируй источник и время.** Метаданные тенанта меняются; отмечай, когда получен факт.
"""

AZURE = r"""
## Полный прогон: один домен, четыре пути к GUID

Соберём всё в один маршрут на домене `example.com`.

```bash
# Путь 1: OpenID-конфигурация
curl -s 'https://login.microsoftonline.com/example.com/v2.0/.well-known/openid-configuration' \
  | jq -r .token_endpoint
# → https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token

# Путь 2: realm (тип тенанта)
curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login=a@example.com&json=1' \
  | jq -r .NameSpaceType
# → Managed

# Путь 3: DNS-подтверждение
dig +short CNAME enterpriseregistration.example.com
# → enterpriseregistration.windows.net.

# Путь 4: почта
dig +short MX example.com
# → example-com.mail.protection.outlook.com.
```

Четыре запроса — один профиль: GUID `72f988bf-...`, регион EU, управляемый тенант, подтверждение по DNS и почте. Если хотя бы два пути дают согласованный результат, вывод устойчив.

## Как это выглядит в отчёте

Разведчик фиксирует не «сырые» запросы, а сжатый вывод с источником и уверенностью:

```text
Организация: Example Corp
Облако: Microsoft 365 / Azure AD
Tenant ID: 72f988bf-86f1-41af-91ab-2d7cd011db47   [OpenID + iss, подтверждено]
Регион данных: EU
Тип тенанта: Managed (без федерации)
Домены: example.com, example-corp.com   [один GUID]
Источник: login.microsoftonline.com (публичные метаданные)
Ограничение: список пользователей не собирался
```

Такой блок сразу отвечает на вопросы: где организация, насколько она «облачная», какие домены связаны, что уже проверено. Дальше по этому профилю планируют авторизованную фазу.

## Мини-практика

Возьми любой домен из открытого списка компаний и определи: привязан ли он к Azure AD, каков его tenant ID и регион данных. Запиши результат в формате блока выше. Сравни два-три домена одной отрасли — увидишь, как GUID группирует организации.

## На что смотреть дальше

- **Кэш.** OpenID-документ может отдаваться из кэша; проверяй свежесть ответа.
- **Федерация.** При внешнем IdP GUID всё равно есть — ищи его в `iss` токена.
- **Связанные домены.** Собрав GUID, проверь по нему другие домены организации.
- **Юрисдикция.** `tenant_region_scope` — часть профиля, не игнорируй его.
"""

insert_before_quiz(os.path.join(ROOT, 'content/osint/osint-m365-enum.md'), M365)
insert_before_quiz(os.path.join(ROOT, 'content/osint/osint-azure-tenant.md'), AZURE)
print('patched pass 2')
