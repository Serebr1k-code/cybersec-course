#!/usr/bin/env python3
import re, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def insert(lid, additions, minutes=None):
    path = os.path.join(ROOT, "content", "web", lid + ".md")
    lesson = open(path, encoding="utf-8").read()
    add = additions.strip("\n")
    m = re.search(r"^## Квиз\s*$", lesson, re.MULTILINE)
    out = lesson[:m.start()] + add + "\n\n" + lesson[m.start():]
    if minutes:
        out = re.sub(r"^estimated_minutes:.*$", f"estimated_minutes: {minutes}",
                     out, count=1, flags=re.MULTILINE)
    open(path, "w", encoding="utf-8").write(out)
    print("topup2", lid)

insert("web-cms-enterprise", r"""
## Как выстроить работу с enterprise CMS по шагам

Практический порядок действий на незнакомой enterprise-платформе: сначала **идентификация** (заголовки, cookie, уникальные пути, вендорские метаданные), затем **точная версия** (только она определяет применимость CVE), потом **чтение security-бюллетеня вендора** (там указан диапазон версий и вектор), и лишь в конце — **минимальная безопасная проверка**. Пропуск любого шага ведёт к ложным выводам: «обновились» — не значит «пропатчены», а «сервер ответил 500» — не значит «RCE». Веди таблицу находок: платформа, версия, источник версии, CVE, статус проверки. Эта таблица станет основой отчёта и защитит от соблазна выдать догадку за факт.
""", 65)

insert("web-confluence", r"""
## Как использовать Confluence для движения дальше

Confluence редко стоит один — рядом Jira, Bitbucket, внутренний Git, артефакторий. У них общие учётные записи (Atlassian Crowd/SSO) и общие токены. Поэтому после компрометации Confluence первым делом ищи: (1) список пользователей через `/rest/api/user/list` или `/admin/users/view`, (2) страницы пространства с паролями и SSH-ключами (поиск по `password`, `key`, `token`, `prod`), (3) привязанные приложения в `/plugins/servlet/applinks/listApplicationLinks`. Часто в Confluence лежит документация по доступам к продовым серверам — это прямой маршрут к цели более высокого уровня. Все найденные креды фиксируй в engagement state и передавай координатору, а не используй вслепую.
""", 70)

insert("web-craftcms", r"""
## Почему Craft — растущая цель

Craft CMS популярен среди агентств и медиа: он быстрый, «дизайнерский» и часто держит API (GraphQL) и вебхуки. Это значит, что вместе с классическими CVE (десериализация, SSRF) он даёт **GraphQL-поверхность**: интроспекция (`{__schema{types{name}}}`), батчинг запросов для обхода лимитов, глубоко вложенные запросы для DoS. Проверяй интроспекцию первым делом — если открыта, ты получаешь полную карту API. Второй момент — GraphQL часто отдаёт больше полей, чем нужно интерфейсу (утечка email, внутренних ID). Фиксируй каждую утечку отдельной находкой: в отчёте она весит меньше RCE, но вместе они дают полную картину и высокий совокупный риск.
""", 60)

insert("web-devops-surfaces", r"""
## Практика: Prometheus и открытые метрики как разведка

Prometheus на `:9090` без аутентификации — это не только графики. Через `/api/v1/targets` виден **полный список целей** мониторинга: имена хостов, порты, пути. Через `/api/v1/query?query=...` можно вытащить метрики с метками, где иногда встречаются версии, имена сервисов и даже пароли (в метках `label`). Начни с `curl -s http://prometheus.target.example:9090/api/v1/targets | head -c 500` — это мгновенно даёт карту инфраструктуры. Затем `/api/v1/label/__name__/values` перечисляет все метрики. Экспортёр Node (`:9100`) через `/metrics` отдаёт список процессов и смонтированных ФС, а `/debug/pprof/` на Go-сервисах может дать heap-дамп. Так DevOps-панель становится картой сети, по которой строится вся дальнейшая атака.
""", 75)

insert("web-django", r"""
## Практика: GraphQL/DRF и утечка через API-схему

Современный Django почти всегда идёт с Django REST Framework (DRF) или Graphene. DRF отдаёт browsable API по умолчанию — `/api/` с формами и схемой. Если включён `DEFAULT_AUTHENTICATION_CLASSES` с `SessionAuthentication`, а `permission_classes` забыли, любой эндпоинт доступен анонимно. Проверяй так: `curl -s https://app.target.example/api/` — если видишь список маршрутов, это утечка. Graphene отдаёт интроспекцию (`{__schema{queryType{fields{name}}}}`) — полная карта API. Отдельно ищи `/api/schema/` и `/api/docs/` (drf-spectacular) — там описаны все поля и типы, включая внутренние ID. Это идеальная база для IDOR и mass-assignment: зная точные имена полей, ты отправляешь лишние (например, `is_staff: true`) и проверяешь, применит ли их сериализатор.
""", 65)
