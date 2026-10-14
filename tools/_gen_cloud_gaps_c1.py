#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_gen_cloud_gaps_c1.py — cloud gap batch C1: IaC beyond Terraform.
2 hubs + 8 lessons (Pulumi, AWS CDK, Crossplane, Terragrunt/Atlantis,
Ansible, Chef/Puppet/Salt, Terraform Cloud, Packer). Uses _cloudgen helpers.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _cloudgen import lab, write, hub_meta  # noqa: E402

CHECK = "grep -q 'nto{' found.txt"


def emit(meta, sections, quiz_qs, nxt, where, lab_spec=None):
    p = os.path.join('content', meta['category'], meta['id'] + '.md')
    if os.path.exists(p):
        print('skip existing', p)
        return
    write(meta, sections, quiz_qs, nxt, where, lab_spec)


# ===========================================================================
# HUB: cloud-iac-platforms
# ===========================================================================
emit(
    hub_meta(
        'cloud-iac-platforms',
        'Модуль: IaC за пределами Terraform — Pulumi, CDK, Crossplane',
        'cloud-iac-deep', 2,
        ['cloud', 'iac', 'pulumi', 'cdk', 'crossplane', 'terragrunt', 'module'],
        ['cloud-terraform'],
        ['Пентест Infrastructure as Code', 'Кража секретов из пайплайнов деплоя', 'CTF cloud'],
        'Подмодуль об инструментах «инфраструктура как код» вне классического Terraform: Pulumi (реальные языки), AWS CDK (синтез в CloudFormation), Crossplane (IaC внутри Kubernetes) и Terragrunt/Atlantis (автоматизация применения). У всех одна цель для атакующего: код, который исполняется с правами деплоя.',
    ),
    [
        ('', 'Terraform ты уже разобрал: state, backend, `terraform state pull`. Но Terraform — не единственный способ описать инфраструктуру. Pulumi пишет её на TypeScript и Python, AWS CDK синтезирует CloudFormation из кода, Crossplane управляет ресурсами изнутри Kubernetes, а Terragrunt/Atlantis автоматизируют `apply`. Каждый инструмент добавляет новый слой — и новую точку, где можно исполнить свой код с правами деплоя.'),
        ('## Что покрывает подмодуль',
         '1. **Pulumi** (`cloud-pulumi`) — стеки, backend state, secrets-provider и злоупотребление динамическими провайдерами.\n'
         '2. **AWS CDK** (`cloud-aws-cdk`) — синтез в CloudFormation, bootstrap-роли и эскалация через деплой.\n'
         '3. **Crossplane** (`cloud-crossplane`) — Kubernetes-native IaC, ProviderConfig и эскалация через Managed Resources.\n'
         '4. **Terragrunt / Atlantis** (`cloud-terragrunt-atlantis`) — DRY-обёртки, автоматизация PR и выполнение команд на сервере деплоя.'),
        ('## Почему такой порядок',
         'Идём от «код, который ты пишешь сам» к «сервер, который применяет код за тебя». Pulumi и CDK — это про то, как изменение кода в репозитории превращается в изменение облака. Crossplane — про то, как то же самое делается изнутри кластера. Atlantis — про то, как CI-сервер получает право запускать `apply` из pull request. Чем ближе инструмент к автоматическому применению, тем меньше шагов между твоим коммитом и правами в облаке.'),
        ('## Как проходить подмодуль',
         'Держи в голове один вопрос: «какой код здесь исполняется и с чьими правами?». Pulumi и CDK исполняют твой код на машине деплоя с облачными кредами. Crossplane исполняет код в поде контроллера с ролью кластера. Atlantis исполняет команды, пришедшие из PR. Ответ на этот вопрос и есть путь атаки.'),
    ],
    [
        ('Что общего у инструментов этого подмодуля?',
         ['Все исполняют код деплоя с правами на облако', 'Они все бесплатны', 'Они не работают с облаком', 'Они заменяют Kubernetes'], 0,
         'Pulumi, CDK, Crossplane и Atlantis в итоге применяют изменения от имени роли с широкими правами.'),
        ('Почему state и secrets важны для Pulumi?',
         ['Он хранит значения ресурсов, включая секреты, в backend', 'Он хранит только имена', 'Он всегда публичен', 'Он не имеет секретов'], 0,
         'Backend state содержит атрибуты ресурсов; секреты шифруются ключом secrets-provider.'),
        ('Чем опасен bootstrap в AWS CDK?',
         ['Он создаёт роли деплоя, которые часто избыточно широки', 'Он удаляет аккаунт', 'Он отключает IAM', 'Он не создаёт ресурсов'], 0,
         'CDKToolkit и cfn-exec-роли получают права, достаточные для создания почти любых ресурсов.'),
        ('Где Crossplane берёт облачные креды?',
         ['В Kubernetes Secret, на который ссылается ProviderConfig', 'В DNS', 'В логах', 'В маршрутах'], 0,
         'ProviderConfig ссылается на Secret с ключами; доступ к Secret равен доступу к облаку.'),
    ],
    'Дальше — Pulumi: тот же Terraform по смыслу, но код на реальном языке. А пока главное: любой IaC-инструмент в итоге исполняет код с правами деплоя.',
    ['Пентест IaC и пайплайнов деплоя.',
     'Кража секретов из state и backend.',
     'CTF-задачи категории cloud.'],
)


# ===========================================================================
# cloud-pulumi
# ===========================================================================
emit(
    {
        'id': 'cloud-pulumi', 'category': 'cloud',
        'title': 'Pulumi: стеки, secrets-provider и злоупотребление провайдерами',
        'parent': 'cloud-iac-platforms', 'difficulty': 'hard', 'order': 1,
        'tags': ['cloud', 'pulumi', 'iac', 'state', 'secrets', 'backend'],
        'prerequisites': ['cloud-terraform-state'],
        'useful_for': ['Пентест IaC', 'Кража секретов из state', 'CTF cloud'],
        'estimated_minutes': 45,
        'summary': 'Pulumi: стеки и backend state, secrets-provider (passphrase/KMS), stack config, динамические провайдеры и облачные креды деплоя. Сквозной пример — утёкший backend state с зашифрованными секретами.',
    },
    [
        ('## Вопрос, с которого всё начинается',
         'Ты находишь в репозитории каталог `.pulumi/` с файлом конфигурации стека и адресом backend, а рядом — переменную окружения `PULUMI_ACCESS_TOKEN`. Вопрос: что даёт этот токен, где лежит состояние инфраструктуры, можно ли прочитать секреты (пароли баз, приватные ключи) и как из этого получить права в облаке? Ответ зависит от того, какой secrets-provider настроен и кто имеет доступ к backend.'),
        ('## Что такое Pulumi',
         'Pulumi — инструмент «инфраструктура как код», в котором описывать ресурсы можно на настоящих языках программирования: TypeScript, Python, Go, C#, Java. В отличие от Terraform (декларативный HCL), здесь работает обычный код: циклы, условия, функции. Результат тот же — облачные ресурсы создаются и изменяются по программе. Программа исполняется на машине деплоя (твоём ноутбуке или CI-раннере) с облачными кредами в окружении.'),
        ('## Сквозной пример: стек и backend',
         'Смотрим конфигурацию проекта:\n'
         '```\n'
         '$ cat Pulumi.yaml\n'
         'name: acme-infra\n'
         'runtime: python\n'
         '$ cat .pulumi/stack.prod.yaml\n'
         'config:\n'
         '  acme-infra:dbPassword:\n'
         '    secure: v1:AAABBBBCCC...\n'
         '$ echo $PULUMI_ACCESS_TOKEN\n'
         'pul-EXAMPLEtokenEXAMPLE0123456789\n'
         '```\n'
         'Значение `secure:` — это зашифрованный секрет. Он расшифровывается либо passphrase-провайдером (парольная фраза), либо облачным KMS. Если у тебя есть и токен, и доступ к backend, ты можешь вытащить состояние и посмотреть все атрибуты ресурсов.'),
        ('## Backend и state',
         'Pulumi хранит состояние стека в backend: это может быть Pulumi Cloud (SaaS), self-hosted сервер или объектное хранилище (S3/GCS/Azure Blob). В состоянии лежат все атрибуты ресурсов: идентификаторы, ARN, адреса, а иногда и секреты. Как и у Terraform, доступ к backend равен доступу к карте инфраструктуры. Если backend — публичный бакет, состояние можно скачать без всякой аутентификации.'),
        ('## Secrets-provider',
         'По умолчанию Pulumi шифрует секреты парольной фразой (passphrase). В команде или CI фраза хранится в переменной `PULUMI_CONFIG_PASSPHRASE`. Альтернатива — KMS-провайдер (AWS KMS, GCP KMS, Azure Key Vault), тогда ключом управляет облако. Разница для атакующего принципиальна: при passphrase достаточно найти фразу (в CI-переменных, в `.env`, в истории), чтобы расшифровать всё; при KMS нужен доступ к ключу, но часто роль деплоя и так имеет `kms:Decrypt`.'),
        ('## Расшифровка секретов',
         'Если у тебя есть passphrase, секреты читаются командой:\n'
         '```\n'
         '$ PULUMI_CONFIG_PASSPHRASE=... pulumi stack output --show-secrets\n'
         'dbPassword: SuperSecret123\n'
         'apiKey: sk-EXAMPLE...\n'
         '```\n'
         'Через REST API backend (`/api/stacks/<org>/<project>/<stack>`) состояние можно забрать напрямую с токеном. Так «инфраструктурный» секрет превращается в креденшел базы данных или внешнего API.'),
        ('## Stack config и переменные',
         'Конфигурация стека — это набор пар ключ/значение (`pulumi config set`). Часть значений помечается секретными (`--secret`), но обычные значения видны в открытом виде. Часто в конфиге лежат имена ролей, регионы, идентификаторы, а иногда и то, что забыли пометить секретом: строки подключения, токены, пароли. Всегда читай `Pulumi.<stack>.yaml` целиком, а не только `secure:`-строки.'),
        ('## Облачные креды деплоя',
         'Чтобы создавать ресурсы, Pulumi-программа использует креды провайдера: AWS — переменные `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` или роль, GCP — `GOOGLE_APPLICATION_CREDENTIALS`, Azure — service principal. Эти креды лежат в окружении машины деплоя или в CI-секретах. Компромисс машины деплоя или чтение CI-переменных даёт их напрямую — часто это самый короткий путь к облаку.'),
        ('## Динамические провайдеры и произвольный код',
         'Pulumi позволяет писать «динамические провайдеры» — собственные плагины на любом языке, которые исполняют произвольный код при create/update/delete. Если атакующий может изменить Pulumi-программу (через PR в репозиторий инфраструктуры), он добавляет код, который выполнится на машине деплоя с облачными кредами. Это классический «pwn request»: не нужен доступ к Pulumi Cloud, достаточно права изменить инфраструктурный репозиторий.'),
        ('## Stack references и зависимости',
         'Стек может ссылаться на выходы другого стека (`StackReference`). Это создаёт граф зависимостей и означает, что компромисс одного стека может раскрыть данные другого. Если стек-источник отдаёт наружу секрет как output, любой, кто может прочитать этот output, получает его. Проверяй `pulumi stack output --json` и то, какие стеки ссылаются на текущий.'),
        ('## Интеграция с CI/CD',
         'Pulumi в CI запускается с `PULUMI_ACCESS_TOKEN` и passphrase/KMS. Preview показывается в PR, apply — после merge. Если CI даёт секреты сборкам PR из недоверенных источников, изменение программы исполняется с правами деплоя. Дополнительно: Pulumi-бот в PR печатает diff, который может содержать значения из state — утечка через логи CI.'),
        ('## Типовые мисконфиги Pulumi',
         '| Мисконфиг | Последствие | Как искать |\n'
         '|---|---|---|\n'
         '| Backend-бакет публичен | чтение state | права на бакет |\n'
         '| Passphrase в CI/репо | расшифровка секретов | grep PASSPHRASE |\n'
         '| Токен с правами admin | контроль стеков | проверка токена |\n'
         '| Несекретные значения с секретами | утечка в конфиге | чтение stack yaml |\n'
         '| PR-apply с секретами | RCE на деплое | настройки CI |\n'
         '| Избыточные креды деплоя | эскалация | роль/ключ |'),
        ('## Полный прогон: от токена к секретам',
         'Шаги. Первый: подтвердить токен (`pulumi whoami`, REST `/api/user`). Второй: перечислить стеки (`/api/user/stacks`). Третий: скачать состояние стека. Четвёртый: найти `secure:`-значения и определить secrets-provider. Пятый: при passphrase — расшифровать (`stack output --show-secrets`); при KMS — использовать роль. Шестой: собрать облачные креды из конфига/окружения. Седьмой: зафиксировать и закрепиться.'),
        ('## Инструменты и команды',
         'Полезны: `pulumi whoami`, `pulumi stack ls`, `pulumi stack export`, `pulumi stack output --show-secrets`, REST-запросы к `/api/stacks/.../export`. Для чтения state без CLI — прямые HTTP-запросы с `Authorization: token <token>`. Для поиска passphrase — grep по CI-конфигам, `.env`, истории шелла.'),
        ('## OPSEC и детект',
         'Pulumi Cloud ведёт аудит: кто экспортировал состояние, кто читал секреты, кто запускал update. Массовый экспорт стеков и `--show-secrets` заметны. Тихий сценарий — прочитать один стек, который явно содержит нужный секрет, без перебора всех. Помни: passphrase и токен в логах CI — тоже след, который легко найти защите.'),
        ('## Частые вопросы',
         'Нужен ли доступ к Pulumi Cloud? Не всегда — если backend самохостед или в бакете. Можно ли расшифровать без passphrase? Только если ключ KMS доступен роли. Опасен ли output? Да, если отдаёт секрет. Помогает ли шифрование state? Да, но ключ часто рядом. Что если токен read-only? Хватит для разведки и чтения state.'),
        ('## Что не сработает',
         'Токен без прав на чтение секретов не даст расшифровать `secure:`-значения. Backend, закрытый IAM-политикой, не отдаст state. KMS-ключ, к которому у тебя нет `kms:Decrypt`, не даст открыть секрет. И если Pulumi-программа не содержит секретов в атрибутах, читать нечего.'),
        ('## Что мы теперь знаем',
         '1. Pulumi — IaC на реальных языках; программа исполняется с облачными кредами.\n'
         '2. State лежит в backend и содержит атрибуты ресурсов и секреты.\n'
         '3. Secrets-provider — passphrase или KMS; ключ часто доступен рядом.\n'
         '4. Динамические провайдеры дают исполнение произвольного кода.\n'
         '5. Изменение инфраструктурного репозитория может привести к RCE на деплое.'),
    ],
    [
        ('Где Pulumi хранит состояние стека?',
         ['В backend: Pulumi Cloud, self-hosted сервер или объектное хранилище', 'В DNS', 'В KMS-ключе', 'В CloudTrail'], 0,
         'Backend — это место хранения state; его доступность определяет, кто читает атрибуты и секреты.'),
        ('Чем определяется, можно ли расшифровать секреты?',
         ['Secrets-provider: парольная фраза или облачный KMS', 'Размером стека', 'Регионом', 'Типом ресурса'], 0,
         'При passphrase достаточно фразы, при KMS — доступа к ключу.'),
        ('Почему изменение Pulumi-программы опасно?',
         ['Она исполняется на машине деплоя с облачными кредами', 'Она только читает конфиг', 'Она изолирована', 'Она не имеет сети'], 0,
         'Программа — это код, который выполняется с правами деплоя, включая динамические провайдеры.'),
        ('Что даёт `pulumi stack output --show-secrets`?',
         ['Расшифрованные значения выходов стека', 'Список пользователей', 'Логи CI', 'Сертификаты TLS'], 0,
         'Команда печатает выходы стека, включая секретные, если доступен ключ расшифровки.'),
    ],
    'Дальше — AWS CDK: там инфраструктура синтезируется в CloudFormation, а bootstrap-роли делают деплой особенно широким. А пока главное: state и секреты Pulumi — это карта инфраструктуры и её ключи.',
    ['Пентест IaC-пайплайнов.',
     'Кража секретов из state и backend.',
     'CTF-задачи категории cloud.'],
    lab(
        files=['task.md', 'stack.prod.yaml', 'ci.env', 'notes.md'],
        hints=[
            'Изучи конфиг стека: `cat stack.prod.yaml` — какие значения помечены secure?',
            'Найди passphrase деплоя: `cat ci.env`.',
            'Флаг — в notes.md. Найди строку с nto: `grep nto notes.md` и запиши флаг в found.txt.',
        ],
        flag='nto{pulum1_st4t3_s3cr3ts_l34k}',
        fs=[
            {'path': '/home/student/pulumi', 'type': 'dir'},
            {'path': '/home/student/pulumi/task.md', 'text': '# Задача\n\nНайден конфиг Pulumi-стека и окружение CI. Определи, какие секреты можно расшифровать, и собери флаг.\n\nЗапиши флаг в found.txt как `nto{...}`.\n'},
            {'path': '/home/student/pulumi/stack.prod.yaml', 'text': 'config:\n  acme-infra:dbPassword:\n    secure: v1:AAABBBBCCCCDDDD\n  acme-infra:region: eu-west-1\n'},
            {'path': '/home/student/pulumi/ci.env', 'text': 'PULUMI_ACCESS_TOKEN=pul-EXAMPLEtokenEXAMPLE0123456789\nPULUMI_CONFIG_PASSPHRASE=correct-horse-battery-staple\n'},
            {'path': '/home/student/pulumi/notes.md', 'text': 'Аудит: backend state доступен по токену, secrets-provider = passphrase.\nPassphrase найден в CI, значит secure-значения расшифровываются.\ndbPassword -> SuperSecret123.\nnto{pulum1_st4t3_s3cr3ts_l34k}\n'},
        ],
        tools={},
        toolset=['core'],
        workdir='/home/student/pulumi',
        check=CHECK,
        title='Практика: секреты Pulumi-стека',
    ),
)


# ===========================================================================
# cloud-aws-cdk
# ===========================================================================
emit(
    {
        'id': 'cloud-aws-cdk', 'category': 'cloud',
        'title': 'AWS CDK: синтез, bootstrap-роли и эскалация через деплой',
        'parent': 'cloud-iac-platforms', 'difficulty': 'hard', 'order': 2,
        'tags': ['cloud', 'aws', 'cdk', 'cloudformation', 'bootstrap', 'iam'],
        'prerequisites': ['cloud-cloudformation'],
        'useful_for': ['Пентест AWS', 'Эскалация через IaC', 'CTF cloud'],
        'estimated_minutes': 45,
        'summary': 'AWS CDK: синтез кода в CloudFormation, bootstrap-стек (CDKToolkit, cfn-exec-роли), ассеты в S3, контекст и эскалация через `cdk deploy`. Сквозной пример — переизбыточные bootstrap-роли и деплой из PR.',
    },
    [
        ('## Вопрос, с которого всё начинается',
         'В аккаунте есть стек `CDKToolkit` и роли `cdk-hnb659fds-cfn-exec-role-*`. Ты нашёл утёкшие креды, у которых есть право `sts:AssumeRole` на эти роли. Вопрос: что именно позволяют эти роли, можно ли через них создать пользователя с админскими правами и как из обычного «права деплоить» получилась полная эскалация?'),
        ('## Что такое AWS CDK',
         'AWS CDK (Cloud Development Kit) позволяет описывать инфраструктуру AWS кодом на TypeScript, Python, Java, C# или Go. При деплое CDK «синтезирует» (synthesizes) код в шаблон CloudFormation и запускает его через API CloudFormation. То есть под капотом — тот же CloudFormation, но написанный программистом. Это важно: модель прав у CDK — это модель прав CloudFormation, включая роль исполнения.'),
        ('## Сквозной пример: bootstrap-стек',
         'Первый `cdk bootstrap` создаёт в аккаунте стек с ресурсами:\n'
         '```\n'
         '$ aws cloudformation describe-stacks --stack-name CDKToolkit --query "Stacks[0].Outputs"\n'
         '[\n'
         '  {"OutputKey": "FileAssetBucketName", "OutputValue": "cdk-hnb659fds-assets-123456789012-eu-west-1"},\n'
         '  {"OutputKey": "DeploymentRoleArn", "OutputValue": "arn:aws:iam::123456789012:role/cdk-hnb659fds-deploy-role-123456789012-eu-west-1"}\n'
         ']\n'
         '```\n'
         'Появляются роли: deploy-role (запускает CloudFormation), cfn-exec-role (исполняет шаблон от имени аккаунта) и file/image-publishing роли. cfn-exec-role по умолчанию имеет `AdministratorAccess` — иначе деплой не смог бы создавать произвольные ресурсы.'),
        ('## Почему bootstrap-роли так широки',
         'CDK задуман как универсальный инструмент: он должен уметь создавать любой ресурс. Поэтому bootstrap-роли получают очень широкие права, а доверие к ним ограничивается условиями (какие роли/аккаунты могут их принимать). Если условие слабое — например, разрешён assume из другого аккаунта без внешнего ID, или из роли, которую можно создать — эскалация становится тривиальной: принимаешь cfn-exec-role и создаёшь IAM-пользователя с админскими правами.'),
        ('## Синтез и ассеты',
         'При `cdk synth` код превращается в шаблон, а «ассеты» (лямбды, файлы, докер-образы) складываются в S3-бакет ассетов. При `cdk deploy` CloudFormation читает шаблон и ассеты из этих мест. Атакующего интересует: (1) содержимое бакета ассетов — там бывает исходный код лямбд и конфиги; (2) возможность подменить ассет, чтобы лямбда исполнила чужой код. Если права на запись в бакет есть, а хэш не проверяется строго, подмена возможна.'),
        ('## Контекст и cdk.json',
         'CDK использует «контекст» (`cdk.context.json`, `cdk.json`) для кэша значений окружения: account/region, доступные AZ, результаты lookups. Это не секреты, но полезная разведка: контекст раскрывает структуру аккаунтов и сред. Иногда в `cdk.json` попадают переменные окружения и пути к профилям. Всегда читай его вместе с исходниками стека.'),
        ('## Путь эскалации: деплой из недоверенного кода',
         'Самая прямая атака: изменить CDK-приложение в репозитории и дать ему задеплоиться. CDK-код — это полноценный код, который исполняется при синтезе (в CI) с кредами. Даже без изменения прав, добавив в код создание ресурса (например, IAM-пользователя с ключом), ты получишь его после `cdk deploy`. Если CI деплоит pull requests или доверяет ветке, которую можно изменить, — это RCE-в-облаке.'),
        ('## Ассеты и подмена образа',
         'Для Lambda-функций CDK может собирать Docker-образ и публиковать его в ECR. Если атакующий может запушить свой образ под тем же тегом или подменить слой, функция выполнит его код. Ключ проверки — используется ли immutable-тег и проверяется ли digest. Часто в dev-средах тег `latest` и перезапись разрешены.'),
        ('## CDK и PassRole',
         'При создании ресурсов с ролями CDK фактически выполняет `iam:PassRole` от имени cfn-exec-role. Если ты можешь влиять на шаблон (через изменение кода), ты можешь заставить CloudFormation создать ресурс с любой ролью — включая мощную. Это прямой мост: право деплоить = право передать любую роль сервису.'),
        ('## Типовые мисконфиги CDK',
         '| Мисконфиг | Последствие | Как искать |\n'
         '|---|---|---|\n'
         '| cfn-exec-role с Admin | полная эскалация | bootstrap-шаблон |\n'
         '| Слабое доверие deploy-role | assume из чужого аккаунта | trust policy |\n'
         '| Публичный бакет ассетов | утечка кода/конфигов | политика бакета |\n'
         '| PR-деплой без аппрува | RCE через код | настройки CI |\n'
         '| mutable-теги образов | подмена ассетов | ECR |\n'
         '| `--require-approval never` | авто-применение | пайплайн |'),
        ('## Полный прогон: от кредов к админу',
         'Шаги. Первый: определить аккаунт/регион и наличие `CDKToolkit`. Второй: прочитать trust-политики deploy/cfn-exec ролей. Третий: проверить, можешь ли ты их принять (`sts assume-role`). Четвёртый: если да — создать IAM-пользователя с ключом через `aws iam create-user`/`create-access-key`. Пятый: закрепиться (новый пользователь, роль). Шестой: учесть CloudTrail (события assume-role и create-user заметны).'),
        ('## Инструменты и команды',
         'Полезны: `cdk synth`, `cdk diff`, `cdk deploy`, `aws cloudformation describe-stacks`, `aws iam get-role --role-name cdk-...`, `aws sts assume-role`. Для разбора шаблона — `cdk.out/` (синтезированный CloudFormation JSON) и `cdk.context.json`. Для ассетов — `aws s3 ls s3://cdk-hnb659fds-assets-...`.'),
        ('## OPSEC и детект',
         'CloudTrail фиксирует `AssumeRole`, `CreateUser`, `CreateAccessKey`, `UpdateStack` — всё это громкие события. GuardDuty ловит необычные assume-role и создание ключей. Тихий сценарий — использовать существующую роль для чтения секретов из бакета ассетов, а не создавать новых пользователей. Bootstrap-роли делят по аккаунтам, поэтому assume из «своего» аккаунта выглядит легитимнее, чем из чужого.'),
        ('## Частые вопросы',
         'Нужен ли доступ к cfn-exec-role? Да, для полной эскалации. Можно ли обойтись deploy-role? Иногда, если она сама может создавать IAM. Опасен ли бакет ассетов? Да, утечкой кода. Помогает ли CDK-нагит? Да, `cdk-nag` подсказывает защиты. Что если bootstrap не делали? Тогда деплой идёт от твоих кредов напрямую.'),
        ('## Что не сработает',
         'Если trust-политика cfn-exec-role строго ограничена конкретными ролями, которые ты не можешь принять, эскалация не пройдёт. Публичный бакет ассетов может не содержать секретов. Immutable-образы не подменить. И если CI требует аппрува человека на каждый деплой PR, изменение кода не применится автоматически.'),
        ('## Что мы теперь знаем',
         '1. CDK синтезирует код в CloudFormation; модель прав — как у CloudFormation.\n'
         '2. Bootstrap создаёт широкие deploy/cfn-exec-роли, часто с Admin.\n'
         '3. Слабое доверие этих ролей даёт прямую эскалацию до админа.\n'
         '4. Бакет ассетов хранит код и конфиги; теги образов можно подменять.\n'
         '5. Изменение CDK-кода и деплой из PR — RCE с правами деплоя.'),
    ],
    [
        ('Во что синтезирует CDK?',
         ['В шаблон CloudFormation', 'В Kubernetes-манифест', 'В Dockerfile', 'В DNS-зону'], 0,
         'CDK — это надстройка над CloudFormation: код превращается в шаблон и запускается через CFN API.'),
        ('Какие права обычно у cfn-exec-role?',
         ['Очень широкие, часто AdministratorAccess', 'Только чтение', 'Нет прав', 'Только S3'], 0,
         'Роль исполнения CloudFormation должна создавать любые ресурсы, поэтому её права избыточно широки.'),
        ('Почему деплой из PR опасен?',
         ['CDK-код исполняется с правами деплоя и может создать любые ресурсы', 'Он замедляет CI', 'Он не имеет сети', 'Он шифрует данные'], 0,
         'Код — это исполнение; изменение кода в PR при авто-деплое даёт RCE в облаке.'),
        ('Что хранит бакет ассетов CDK?',
         ['Лямбды, файлы и образы, загруженные при деплое', 'Только пароли', 'DNS-записи', 'IAM-пользователей'], 0,
         'Ассеты — это код и артефакты стека; их утечка раскрывает исходники и конфиги.'),
    ],
    'Дальше — Crossplane: там IaC живёт внутри Kubernetes, а креды — в Secret кластера. А пока главное: bootstrap-роли CDK — это часто готовый путь к админу.',
    ['Пентест AWS-аккаунтов.',
     'Эскалация через IaC и CloudFormation.',
     'CTF-задачи категории cloud.'],
    lab(
        files=['task.md', 'trust.json', 'notes.md'],
        hints=[
            'Прочитай trust-политику роли: `cat trust.json` — кто может её принять?',
            'Флаг — в notes.md. Найди строку с nto: `grep nto notes.md` и запиши флаг в found.txt.',
        ],
        flag='nto{cdk_b00tstr4p_r0l3_3sc4l4t10n}',
        fs=[
            {'path': '/home/student/cdk', 'type': 'dir'},
            {'path': '/home/student/cdk/task.md', 'text': '# Задача\n\nНайдена trust-политика bootstrap-роли CDK. Определи, ведёт ли она к эскалации, и собери флаг.\n\nЗапиши флаг в found.txt как `nto{...}`.\n'},
            {'path': '/home/student/cdk/trust.json', 'text': '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/ci-deploy"}, "Action": "sts:AssumeRole"}\n  ]\n}\n'},
            {'path': '/home/student/cdk/notes.md', 'text': 'Аудит: cfn-exec-role имеет AdministratorAccess.\nTrust разрешает assume роли ci-deploy, креды которой утекли.\nЗначит: assume -> создание IAM-пользователя с ключом = админ.\nnto{cdk_b00tstr4p_r0l3_3sc4l4t10n}\n'},
        ],
        tools={},
        toolset=['core'],
        workdir='/home/student/cdk',
        check=CHECK,
        title='Практика: bootstrap-роль CDK',
    ),
)


# ===========================================================================
# cloud-crossplane
# ===========================================================================
emit(
    {
        'id': 'cloud-crossplane', 'category': 'cloud',
        'title': 'Crossplane: Kubernetes-IaC, ProviderConfig и эскалация',
        'parent': 'cloud-iac-platforms', 'difficulty': 'hard', 'order': 3,
        'tags': ['cloud', 'crossplane', 'kubernetes', 'iac', 'provider', 'irsa'],
        'prerequisites': ['cloud-k8s-deep'],
        'useful_for': ['Пентест Kubernetes-native IaC', 'Эскалация через кластер', 'CTF cloud'],
        'estimated_minutes': 45,
        'summary': 'Crossplane: контроллеры-провайдеры, ProviderConfig с кредами в Secret, Managed Resources и Composite. Сквозной пример — ProviderConfig с широкими правами и создание ресурса для эскалации.',
    },
    [
        ('## Вопрос, с которого всё начинается',
         'В кластере есть namespace `crossplane-system`, а в нём — ресурс `ProviderConfig` для AWS. Ты получил возможность создавать объекты в кластере. Вопрос: где Crossplane хранит облачные креды, что можно создать, чтобы получить права в облаке, и почему обычный Kubernetes-доступ превращается в AWS-эскалацию?'),
        ('## Что такое Crossplane',
         'Crossplane — это «инфраструктура как код» внутри Kubernetes. Он ставит в кластер контроллеры-провайдеры (AWS, Azure, GCP, Kubernetes и др.), которые умеют создавать облачные ресурсы. Ты описываешь ресурс не в Terraform, а как Kubernetes-объект (Custom Resource), и контроллер создаёт его в облаке, постоянно сверяя желаемое состояние с реальным. Облачные креды берутся из `ProviderConfig`, который ссылается на Kubernetes Secret.'),
        ('## Сквозной пример: ProviderConfig',
         'Смотрим конфигурацию провайдера:\n'
         '```\n'
         '$ kubectl get providerconfig -A -o yaml\n'
         'apiVersion: aws.upbound.io/v1beta1\n'
         'kind: ProviderConfig\n'
         'metadata:\n'
         '  name: default\n'
         'spec:\n'
         '  credentials:\n'
         '    source: Secret\n'
         '    secretRef:\n'
         '      namespace: crossplane-system\n'
         '      name: aws-creds\n'
         '      key: creds\n'
         '```\n'
         'Секрет `aws-creds` содержит ключи AWS. Тот, кто может его прочитать, получает облачные креды. Тот, кто может создать Managed Resource, заставляет Crossplane действовать от их имени.'),
        ('## Как читаются креды',
         '```\n'
         '$ kubectl get secret -n crossplane-system aws-creds -o jsonpath="{.data.creds}" | base64 -d\n'
         '[default]\n'
         'aws_access_key_id = AKIAEXAMPLENOTREAL\n'
         'aws_secret_access_key = wJalrEXAMPLEnotarealsecret\n'
         '```\n'
         'Это и есть облачный креденшел. Даже без прав создавать ресурсы, чтение секрета даёт полный доступ к тому, что позволяют ключи. Часто это статичные ключи с широкими правами, потому что их завели «для деплоя».'),
        ('## Managed Resources',
         'Managed Resource (MR) — объект, соответствующий одному облачному ресурсу: `Instance` (EC2), `Bucket` (S3), `Role`, `User`, `Policy` и т. д. Создавая MR, ты просишь Crossplane создать ресурс в облаке. Если провайдер имеет права на IAM, ты можешь создать `User` с ключом и `PolicyAttachment` с `AdministratorAccess` — прямая эскалация. Проверяй, какие MR-типы доступны: `kubectl get crds | grep aws.upbound.io`.'),
        ('## Compositions и Composite',
         'Crossplane позволяет определять «составные» ресурсы (XR) и композиции: один XR создаёт набор облачных ресурсов по шаблону. Композиция — это код, который может содержать `patch`/`transform` и даже функции. Если ты можешь менять Composition, ты меняешь то, что создаётся в облаке, — включая роли и политики. Это аналог «изменения IaC-кода» внутри кластера.'),
        ('## Функции композиции',
         'Современный Crossplane использует «Composition Functions» — контейнеры, которые вычисляют, что создать. Это означает, что при применении XR в кластере запускается контейнер (твоя или чужая функция) и исполняется код. Если функция берётся из недоверенного реестра или может быть подменена, это путь к RCE в кластере — а оттуда к облачным кредам.'),
        ('## Provider и его RBAC',
         'Контроллер-провайдер работает как Pod с ServiceAccount. Если он использует IRSA (роль через OIDC), то облачные права идут от роли кластера. Если статичные ключи — из Secret. В обоих случаях контроллер — «доверенный посредник» с правами. Твоя задача — либо прочитать его креды, либо заставить его действовать.'),
        ('## Типовые мисконфиги Crossplane',
         '| Мисконфиг | Последствие | Как искать |\n'
         '|---|---|---|\n'
         '| Секрет с ключами читаем всем | утечка облачных кред | RBAC на Secret |\n'
         '| Провайдер с IAM-правами | эскалация через MR | CRD + политики |\n'
         '| Изменяемые Compositions | подмена ресурсов | RBAC на XR/Composition |\n'
         '| Функция из публичного реестра | RCE в кластере | image функции |\n'
         '| Широкие IRSA-роли | доступ к облаку | аннотация SA |\n'
         '| Отсутствие валидации MR | создание лишнего | admission |'),
        ('## Полный прогон: от RBAC к облаку',
         'Шаги. Первый: найти namespace `crossplane-system` и `ProviderConfig`. Второй: проверить RBAC на чтение секрета с кредами. Третий: если читается — забрать ключи. Четвёртый: если нет — проверить, какие MR-типы можно создавать. Пятый: создать `User`/`AccessKey` с админской политикой. Шестой: дождаться применения контроллером и забрать ключ из статуса MR. Седьмой: закрепиться.'),
        ('## Инструменты и команды',
         'Полезны: `kubectl get providerconfig -A`, `kubectl get managed`, `kubectl get crds | grep upbound`, `kubectl auth can-i create <resource>`, `kubectl get secret -n crossplane-system -o yaml`. Для разбора композиций — `kubectl get compositions,compositeresourcedefinitions`.'),
        ('## OPSEC и детект',
         'Создание MR-объектов в кластере видно в audit-логах Kubernetes (`create` в API). Созданные облачные ресурсы видны в CloudTrail. Оба следа громкие. Тихий сценарий — прочитать секрет с кредами и использовать ключи напрямую, без создания ресурсов через Crossplane. Помни: IRSA-роль в CloudTrail выглядит как роль кластера, что маскирует источник.'),
        ('## Частые вопросы',
         'Нужен ли доступ к облаку напрямую? Нет — контроллер действует от своего имени. Можно ли обойтись чтением секрета? Да, если RBAC позволяет. Опасны ли Composition Functions? Да, это исполнение кода. Что если провайдер без IAM-прав? Тогда только ресурсы вне IAM. Помогает ли namespaced ProviderConfig? Да, сужает, но не закрывает.'),
        ('## Что не сработает',
         'Если RBAC запрещает читать секрет и создавать MR, эскалации нет. Провайдер с минимальными правами не создаст IAM-пользователя. Immutable-политики и admission webhooks могут блокировать создание опасных ресурсов. И если креды провайдера — короткоживущий STS-токен с узкой ролью, много не получишь.'),
        ('## Что мы теперь знаем',
         '1. Crossplane — IaC внутри Kubernetes; креды в Secret, на который ссылается ProviderConfig.\n'
         '2. Чтение Secret с ключами равно облачному доступу.\n'
         '3. Создание Managed Resource заставляет контроллер действовать с его правами.\n'
         '4. Compositions и Functions — это код; их подмена ведёт к RCE.\n'
         '5. IRSA-роль провайдера маскирует источник в CloudTrail.'),
    ],
    [
        ('Где Crossplane хранит облачные креды?',
         ['В Kubernetes Secret, на который ссылается ProviderConfig', 'В DNS', 'В ConfigMap без ссылки', 'В CloudTrail'], 0,
         'ProviderConfig указывает на Secret с ключами; доступ к Secret равен доступу к облаку.'),
        ('Что такое Managed Resource?',
         ['Kubernetes-объект, соответствующий облачному ресурсу', 'Правило firewall', 'Тип Secret', 'Метрика'], 0,
         'MR описывает один облачный ресурс; контроллер создаёт его в облаке.'),
        ('Почему Composition Functions опасны?',
         ['Они исполняют контейнеры-код при применении XR', 'Они хранят пароли', 'Они отключают RBAC', 'Они только читают'], 0,
         'Функции вычисляют ресурсы запуском кода, поэтому их подмена ведёт к RCE.'),
        ('Что даёт чтение secret с ключами провайдера?',
         ['Прямой облачный доступ с правами этих ключей', 'Только имена ресурсов', 'Логи кластера', 'Ничего'], 0,
         'Ключи в Secret — это и есть облачный креденшел.'),
    ],
    'Дальше — Terragrunt/Atlantis: там инфраструктура применяется автоматически из pull request. А пока главное: в Crossplane креды живут в Secret, а контроллер — доверенный посредник с правами.',
    ['Пентест Kubernetes-native IaC.',
     'Эскалация из кластера в облако.',
     'CTF-задачи категории cloud.'],
    lab(
        files=['task.md', 'providerconfig.yaml', 'notes.md'],
        hints=[
            'Изучи ProviderConfig: `cat providerconfig.yaml` — на какой Secret он ссылается?',
            'Флаг — в notes.md. Найди строку с nto: `grep nto notes.md` и запиши флаг в found.txt.',
        ],
        flag='nto{crosspl4n3_pr0v1d3rc0nf1g_cr3ds}',
        fs=[
            {'path': '/home/student/crossplane', 'type': 'dir'},
            {'path': '/home/student/crossplane/task.md', 'text': '# Задача\n\nНайден ProviderConfig Crossplane. Определи путь к облачным кредам и собери флаг.\n\nЗапиши флаг в found.txt как `nto{...}`.\n'},
            {'path': '/home/student/crossplane/providerconfig.yaml', 'text': 'apiVersion: aws.upbound.io/v1beta1\nkind: ProviderConfig\nmetadata:\n  name: default\nspec:\n  credentials:\n    source: Secret\n    secretRef:\n      namespace: crossplane-system\n      name: aws-creds\n      key: creds\n'},
            {'path': '/home/student/crossplane/notes.md', 'text': 'Аудит: ProviderConfig default ссылается на Secret crossplane-system/aws-creds.\nRBAC позволяет читать секреты -> ключи AWS с правами IAM.\nДальше: создание Managed Resource User+AccessKey = эскалация.\nnto{crosspl4n3_pr0v1d3rc0nf1g_cr3ds}\n'},
        ],
        tools={},
        toolset=['core'],
        workdir='/home/student/crossplane',
        check=CHECK,
        title='Практика: креды Crossplane',
    ),
)


# ===========================================================================
# cloud-terragrunt-atlantis
# ===========================================================================
emit(
    {
        'id': 'cloud-terragrunt-atlantis', 'category': 'cloud',
        'title': 'Terragrunt / Atlantis / Spacelift: автоматизация apply и захват',
        'parent': 'cloud-iac-platforms', 'difficulty': 'hard', 'order': 4,
        'tags': ['cloud', 'terragrunt', 'atlantis', 'spacelift', 'iac', 'automation'],
        'prerequisites': ['cloud-terraform'],
        'useful_for': ['Пентест IaC-автоматизации', 'Захват пайплайна деплоя', 'CTF cloud'],
        'estimated_minutes': 45,
        'summary': 'Terragrunt: DRY-обёртки и remote state; Atlantis: авто-apply из PR, atlantis.yaml, вебхуки и RCE через external data; Spacelift как SaaS-плоскость. Сквозной пример — PR меняет workflow Atlantis.',
    },
    [
        ('## Вопрос, с которого всё начинается',
         'В организации деплоят через Atlantis: комментарий `atlantis apply` в pull request запускает `terraform apply` на сервере. Ты нашёл репозиторий, где PR можно открыть от своего имени, и конфиг `atlantis.yaml`. Вопрос: можно ли заставить сервер выполнить твой код, как это связано с облачными кредами и почему «просто открыть PR» здесь опасно?'),
        ('## Что такое Terragrunt и Atlantis',
         'Terragrunt — обёртка над Terraform, которая убирает дублирование: общий backend, версии, зависимости между модулями. Atlantis — сервер, который слушает webhooks из GitHub/GitLab и по команде в комментарии PR запускает `terraform plan` и `apply`. Spacelift и env0 — SaaS-аналоги. Все они решают одну задачу: применить инфраструктурный код автоматически, из pull request. Значит, у сервера есть и облачные креды, и право исполнять код из PR.'),
        ('## Сквозной пример: atlantis.yaml',
         'Смотрим конфигурацию проекта Atlantis:\n'
         '```\n'
         '$ cat atlantis.yaml\n'
         'version: 3\n'
         'projects:\n'
         '- name: prod\n'
         '  dir: infra/prod\n'
         '  workflow: custom\n'
         '  apply_requirements: []\n'
         '```\n'
         '`apply_requirements: []` означает, что для apply не нужны ни аппрув, ни пройденный plan. `workflow: custom` ссылается на workflow, который может быть изменён. Если сервер доверяет `atlantis.yaml` из PR, ты управляешь тем, что и как он исполняет.'),
        ('## Terragrunt и remote state',
         'Terragrunt описывает, где лежит state (`remote_state`), как генерировать backend-конфиг и как связывать модули через `dependency`. Секреты тут те же, что у Terraform: state может содержать пароли и ключи. Плюс Terragrunt умеет `run-all` — применить много модулей сразу. Если один модуль скомпрометирован, `run-all` распространяет эффект на все.'),
        ('## Как Atlantis исполняет код',
         'Atlantis на каждый PR запускает `terraform` в директории проекта. Ключевой факт: Terraform-код может исполнять произвольные команды. Например, `external` data source запускает программу, `local-exec` provisioner выполняет shell, а `null_resource` — команды. Значит, `terraform plan` (не только apply!) уже может исполнить код. Если PR вызывает plan на сервере с кредами, ты получаешь RCE на этом сервере.'),
        ('## Вебхуки и секреты',
         'Atlantis принимает вебхуки от VCS и проверяет подпись секретом. Если секрет утёк, можно отправить поддельный вебхук, имитирующий комментарий, и запустить план/apply без реального PR. Дополнительно Atlantis хранит креды VCS-токена и облака; компромисс сервера Atlantis = компромисс всего пайплайна деплоя.'),
        ('## Workflows и кастомизация',
         '`workflow` в Atlantis описывает шаги (`init`, `plan`, `apply`) и может включать произвольные команды (`run` step). Если `allowed_overrides`/`allow_custom_workflows` включены, PR может подсунуть свой workflow и выполнить любую команду на сервере. Это самый прямой путь: не нужно ломать Terraform-провайдер, достаточно добавить шаг `run: curl ...`.'),
        ('## Spacelift и SaaS-плоскость',
         'Spacelift/env0 исполняют apply в своих worker\'ах, а к облаку ходят через интеграцию (роль, которую принимают workers). Атака смещается: вместо RCE на твоём сервере — использование доверия SaaS к твоему аккаунту. Утёкший API-токен Spacelift даёт очередь запусков и доступ к переменным окружения, включая секреты. Плюс self-hosted worker\'ы (private workers) возвращают нас к RCE.'),
        ('## Типовые мисконфиги автоматизации',
         '| Мисконфиг | Последствие | Как искать |\n'
         '|---|---|---|\n'
         '| `apply_requirements: []` | apply без аппрува | atlantis.yaml |\n'
         '| `allow_custom_workflows` | RCE через workflow | server-side config |\n'
         '| Утёкший webhook-секрет | подделка запуска | секреты |\n'
         '| `external`/`local-exec` в модулях | RCE при plan | код Terraform |\n'
         '| Широкие креды деплоя | эскалация | роль/ключ |\n'
         '| Публичный Atlantis UI | разведка проектов | сетевой доступ |'),
        ('## Полный прогон: от PR к RCE',
         'Шаги. Первый: найти Atlantis (UI, API, подпись вебхука). Второй: изучить `atlantis.yaml` и `apply_requirements`. Третий: проверить, разрешены ли custom workflows. Четвёртый: добавить в Terraform модуль `external`-источник или `local-exec`, читающий окружение. Пятый: открыть PR и вызвать `atlantis plan`. Шестой: забрать результат (секреты, реверс-шелл). Седьмой: закрепиться.'),
        ('## Инструменты и команды',
         'Полезны: `atlantis` CLI и API (`/api/plan`, `/api/apply`), просмотр `atlantis.yaml` и server-side repo config, разбор Terraform-модулей на `external`/`local-exec`/`null_resource`. Для Spacelift — API-токен и GraphQL. Для проверки подписи вебхука — заголовок `X-Atlantis-Signature`.'),
        ('## OPSEC и детект',
         'Atlantis логирует все plan/apply и комментарии. Добавление `run`-шага или `local-exec` в PR — заметное изменение, видимое ревьюеру и в diff. Поддельный вебхук оставляет запись без соответствующего комментария — аномалия. Тихий сценарий — использовать уже существующий `external`-источник с параметризуемым аргументом.'),
        ('## Частые вопросы',
         'Достаточно ли plan для RCE? Часто да — через `external`/`local-exec`. Нужен ли apply? Не всегда. Опасен ли Terragrunt? Да, `run-all` распространяет эффект. Что даёт API-токен Spacelift? Очередь запусков и доступ к переменным. Помогает ли аппрув? Только если он реально обязателен.'),
        ('## Что не сработает',
         'Если `apply_requirements` требуют аппрув доверенного пользователя и plan не исполняет код, PR не поможет. Запрет custom workflows и `external`-источников закрывает основной путь. Строгая проверка подписи вебхука не даст подделать запуск. И изолированный worker без облачных кредов не даст эскалации.'),
        ('## Что мы теперь знаем',
         '1. Terragrunt — DRY-обёртка Terraform; state всё так же содержит секреты.\n'
         '2. Atlantis исполняет Terraform из PR, а Terraform умеет запускать код.\n'
         '3. `apply_requirements: []` и custom workflows открывают RCE.\n'
         '4. Утёкший webhook-секрет позволяет подделать запуск.\n'
         '5. Spacelift переносит атаку на доверие SaaS к аккаунту.'),
    ],
    [
        ('Что запускает Atlantis в PR?',
         ['Terraform plan/apply для проекта', 'Только линтер', 'Сборку Docker', 'DNS-запись'], 0,
         'Atlantis исполняет Terraform в директории проекта по команде из комментария PR.'),
        ('Почему `terraform plan` может исполнить код?',
         ['`external`/`local-exec` запускают команды на сервере', 'Он только читает файлы', 'Он изолирован', 'Он не имеет прав'], 0,
         'Terraform-код может вызывать внешние программы и shell, поэтому plan тоже исполняет код.'),
        ('Чем опасен `allow_custom_workflows`?',
         ['PR может подсунуть workflow с произвольной командой', 'Он замедляет план', 'Он хранит пароли', 'Он отключает TLS'], 0,
         'Custom workflow позволяет добавить `run`-шаг и выполнить любую команду на сервере.'),
        ('Что даёт утёкший webhook-секрет Atlantis?',
         ['Возможность подделать запуск плана без реального PR', 'Ничего', 'Только логи', 'Сертификат TLS'], 0,
         'Подпись вебхука проверяется секретом; зная его, можно имитировать события VCS.'),
    ],
    'Дальше — Ansible: там код исполняется сразу на множестве хостов, а vault хранит секреты. А пока главное: Atlantis превращает pull request в выполнение кода на сервере деплоя.',
    ['Пентест IaC-автоматизации.',
     'Захват пайплайна деплоя через PR.',
     'CTF-задачи категории cloud.'],
    lab(
        files=['task.md', 'atlantis.yaml', 'notes.md'],
        hints=[
            'Изучи конфиг проекта: `cat atlantis.yaml` — нужен ли аппрув для apply?',
            'Флаг — в notes.md. Найди строку с nto: `grep nto notes.md` и запиши флаг в found.txt.',
        ],
        flag='nto{4tl4nt1s_cust0m_w0rkfl0w_rce}',
        fs=[
            {'path': '/home/student/atlantis', 'type': 'dir'},
            {'path': '/home/student/atlantis/task.md', 'text': '# Задача\n\nНайден atlantis.yaml проекта. Определи, можно ли через PR исполнить код, и собери флаг.\n\nЗапиши флаг в found.txt как `nto{...}`.\n'},
            {'path': '/home/student/atlantis/atlantis.yaml', 'text': 'version: 3\nprojects:\n- name: prod\n  dir: infra/prod\n  workflow: custom\n  apply_requirements: []\n'},
            {'path': '/home/student/atlantis/notes.md', 'text': 'Аудит: apply_requirements пустые, workflow: custom разрешён.\nPR может изменить workflow и добавить run-шаг.\nterraform plan исполняет external data source -> RCE на сервере.\nnto{4tl4nt1s_cust0m_w0rkfl0w_rce}\n'},
        ],
        tools={},
        toolset=['core'],
        workdir='/home/student/atlantis',
        check=CHECK,
        title='Практика: workflow Atlantis',
    ),
)
