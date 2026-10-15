#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_topup_cloud_c.py — cloud batch C."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _topup_gap

C = {
    'cloud-oci-functions': [
        ('## OCI Functions: как устроены и где ломаются',
         'OCI Functions (Fn Project) — serverless: функции в контейнерах, запускаемые по '
         'событию (API Gateway, Events, cron). Поверхность: (1) application с недостаточными '
         'правами или, наоборот, с широкой dynamic group; (2) переменные окружения функции с '
         'секретами; (3) доступ к метаданным инстанса, если функция запущена на инстансе; '
         '(4) образ функции из публичного реестра (supply chain).\n\n'
         '```text\n'
         'function -> dynamic group -> policies -> resources\n'
         '```\n\n'
         'Ключевой риск: функция наследует права dynamic group, и если она широкая, вызов '
         'функции даёт эти права.'),
        ('## Практика: анализ и эксплуатация',
         'Что проверять: (1) список приложений и функций; (2) конфигурацию (env, image, '
         'timeout); (3) dynamic group и policies; (4) точки вызова (API Gateway, Events); '
         '(5) секреты в env. Инструменты: `oci fn`, `oci iam`, `oci ce`. Эксплуатация: если '
         'есть `InvokeFunction`, вызови функцию с контролируемым входом и посмотри, что она '
         'делает (инъекция, чтение ресурсов).\n\n'
         '```bash\n'
         'oci fn function list --application-id <id>\n'
         'oci fn function get --function-id <id>\n'
         '```\n\n'
         'Типичная находка — секреты в переменных окружения функции.'),
        ('## Защита',
         'Меры: минимальные dynamic group и policies, секреты в Vault (не в env), образы из '
         'доверенного реестра с фиксированными тегами, ограничение вызова функции, '
         'логирование. Для пентеста — чтение конфигурации; вызов — только в тестовом тенанте.'),
    ],
    'cloud-oci-iam': [
        ('## OCI IAM: модель и поверхность',
         'OCI IAM: users, groups, dynamic groups, policies. Политика — человекочитаемая '
         'строка: `Allow group Admins to manage all-resources in tenancy`. Ошибки: '
         '`manage all-resources` (полный доступ), dynamic group по широкому правилу '
         '(например, все инстансы компартмента), отсутствие compartment-ограничений, '
         'федерация без строгих условий.\n\n'
         '```text\n'
         'Allow <subject> to <verb> <resource> in <compartment> [where <condition>]\n'
         '```\n\n'
         'Аудит: собрать все политики, найти `manage all-resources`, проверить dynamic groups '
         'и их правила, проверить условия.'),
        ('## Практика: эскалация в OCI IAM',
         'Векторы: (1) dynamic group, которой можно стать (например, правило по тегу, '
         'который можно поставить), (2) политика, разрешающая `manage users`/`manage groups`, '
         '(3) `manage all-resources`, (4) федерация с доверием широкому IdP. Инструменты: '
         '`oci iam`.\n\n'
         '```bash\n'
         'oci iam policy list --compartment-id <tenancy>\n'
         'oci iam dynamic-group list --compartment-id <tenancy>\n'
         '```\n\n'
         'Строй граф: идентичность → политики → ресурсы → следующая идентичность. Цель — '
         'найти путь до `manage all-resources`.'),
        ('## Защита',
         'Меры: минимальные политики, compartment-ограничения, условия (`where`), строгие '
         'dynamic groups, MFA, мониторинг. Для пентеста — чтение политик и построение графа.'),
    ],
    'cloud-oci-object-storage': [
        ('## OCI Object Storage: доступ и находки',
         'Object Storage в OCI — бакеты с объектами. Доступ управляется IAM-политиками, '
         'pre-authenticated requests (PAR — ссылка с токеном), и visibility (public/private). '
         'Типичные ошибки: публичный бакет, PAR без срока/ограничений, широкие политики.\n\n'
         '```bash\n'
         'oci os bucket list --compartment-id <id>\n'
         'oci os object list --bucket-name <b> --namespace <ns>\n'
         '```\n\n'
         'PAR — особенно интересны: ссылка вида `https://objectstorage.../p/<token>/...` даёт '
         'доступ без аутентификации. Если PAR утёк (в логах, коде), доступ открыт.'),
        ('## Практика: PAR и публичные бакеты',
         'Что искать: публичные бакеты (анонимный листинг), PAR (в коде/логах/URL), объекты с '
         'секретами, широкие политики. Проверка публичного бакета: `curl '
         'https://objectstorage.<region>.oraclecloud.com/n/<ns>/b/<bucket>/o/`. Инструменты: '
         '`oci os`, `curl`, `cloud_enum`.\n\n'
         '```bash\n'
         'curl "https://objectstorage.us-ashburn-1.oraclecloud.com/n/<ns>/b/<bucket>/o/"\n'
         '```\n\n'
         'Типичная находка — PAR без ограничений, дающий доступ ко всему бакету.'),
        ('## Защита',
         'Меры: приватные бакеты, PAR с коротким сроком и ограниченным доступом, шифрование, '
         'мониторинг, аудит публичных бакетов и PAR. Для пентеста — перечисление и чтение '
         'публичного; модификация — с разрешения.'),
    ],
    'cloud-oci-vcn': [
        ('## OCI VCN: сеть и её поверхность',
         'VCN (Virtual Cloud Network) — изолированная сеть OCI: подсети, security lists, '
         'network security groups (NSG), route tables, internet/nat/service gateways. Ошибки: '
         'security list с `0.0.0.0/0` на чувствительные порты, отсутствие сегментации, '
         'публичные подсети для внутренних сервисов, открытые сервисные шлюзы.\n\n'
         '```text\n'
         'VCN -> subnets -> security lists / NSG -> instances\n'
         '```\n\n'
         'Аудит: инвентаризация VCN, подсетей, правил; поиск `0.0.0.0/0`; проверка '
         'маршрутизации (куда ведут gateway).'),
        ('## Практика: анализ сети',
         'Что проверять: (1) security lists и NSG (входящие/исходящие правила); (2) '
         'публичные vs приватные подсети; (3) route tables (интернет/nat/peering); (4) '
         'VCN peering (связи между VCN); (5) VPN/FastConnect. Инструменты: `oci network`, '
         '`nmap`.\n\n'
         '```bash\n'
         'oci network security-list list --compartment-id <id> --vcn-id <vcn>\n'
         'oci network subnet list --compartment-id <id> --vcn-id <vcn>\n'
         '```\n\n'
         'Типичная находка — публичная подсеть с SSH/RDP из интернета и отсутствием '
         'сегментации между окружениями.'),
        ('## Защита',
         'Меры: приватные подсети, минимальные NSG, bastion/VPN для доступа, сегментация по '
         'окружениям, мониторинг flow logs. Для пентеста — чтение конфигурации и проверка '
         'доступности портов (без нагрузки).'),
    ],
    'cloud-okta-privesc': [
        ('## Okta: роли и поверхность',
         'Okta — IdP с ролями (Super Admin, Org Admin, App Admin, Group Admin и др.). Роли '
         'выдаются пользователям и группам, приложения подключаются через SAML/OIDC. '
         'Поверхность: (1) широкая роль у сервисного аккаунта, (2) API-токен Okta с большими '
         'правами, (3) OIDC-приложение с `client_secret` в открытом виде, (4) SAML без '
         'подписи (подделка assertion).\n\n'
         '```text\n'
         'role -> permissions -> apps/users -> escalation\n'
         '```\n\n'
         'Ключевая цель — API-токен или роль, дающая управление пользователями/приложениями.'),
        ('## Практика: эскалация в Okta',
         'Векторы: (1) `Group Admin` может менять членство групп → добавить себя в '
         'привилегированную группу; (2) `App Admin` может изменить SAML-приложение → '
         'инъекция атрибутов; (3) API-токен с `okta.users.manage` → создание/изменение '
         'пользователей; (4) weak SAML (без подписи) → подделка assertion. Инструменты: Okta '
         'API, `aws sso`-подобные.\n\n'
         '```bash\n'
         'curl -H "Authorization: SSWS <token>" https://<org>.okta.com/api/v1/users\n'
         '```\n\n'
         'Типичная находка — сервисный аккаунт с широкой ролью и токеном в открытом виде.'),
        ('## Защита',
         'Меры: минимальные роли, ротация API-токенов, подпись SAML, ограничение admin-'
         'приложений, MFA для админов, мониторинг (Okta System Log). Для пентеста — чтение '
         'конфигурации; изменение — только с разрешения.'),
    ],
    'cloud-vercel-netlify': [
        ('## Vercel/Netlify: что это и поверхность',
         'Vercel и Netlify — платформы для деплоя фронтенда/serverless. Поверхность: (1) '
         'переменные окружения (env) с секретами; (2) deploy hooks и build-логи; (3) '
         'serverless-функции (`/api`); (4) preview-деплои (часто без защиты); (5) доступ к '
         'Git-репозиторию через интеграцию.\n\n'
         '```text\n'
         'git push -> build (env available) -> deploy -> preview/prod\n'
         '```\n\n'
         'Ключевой риск — preview-деплои без аутентификации, раскрывающие неготовый функционал '
         'и данные.'),
        ('## Практика: находки',
         'Что проверять: (1) env-переменные (через `_next/static` или serverless-ошибки); '
         '(2) preview-URL (перебор имён/через Git); (3) serverless-функции (SSRF, инъекции); '
         '(4) build-логи (секреты); (5) source maps (исходники). Инструменты: `curl`, '
         'анализ JS, `gobuster`.\n\n'
         '```bash\n'
         'curl https://<project>.vercel.app/_next/static/.../pages/...js.map\n'
         '```\n\n'
         'Типичная находка — source maps, раскрывающие исходный код, и env-секреты, '
         'попавшие в клиентский бандл.'),
        ('## Защита',
         'Меры: защита preview-деплоев (пароль/SSO), не класть секреты в клиентский код, '
         'отключить source maps в проде, ротация секретов, ограничение доступа к '
         'build-логам. Для пентеста — проверка preview и бандла.'),
    ],
    'cloud-vultr-objectstorage': [
        ('## Vultr Object Storage: доступ и находки',
         'Vultr Object Storage — S3-совместимое хранилище. Доступ через API-ключ и S3-'
         'совместимые креды. Типичные ошибки: публичный бакет, ключ в открытом виде, '
         'широкие права.\n\n'
         '```bash\n'
         'aws --endpoint-url https://<region>.vultrobjects.com s3 ls\n'
         'curl https://<bucket>.<region>.vultrobjects.com/   # анонимно\n'
         '```\n\n'
         'Проверка анонимного листинга — первый шаг. Дальше — объекты с секретами.'),
        ('## Практика: от ключа к данным',
         'Что искать: публичные бакеты, креды (в CI/конфигах), объекты с секретами, широкие '
         'API-ключи. Эскалация: получив креды, использовать S3 API для доступа к другим '
         'бакетам. Инструменты: `aws s3`, `s3cmd`, `rclone`, `nmap`.\n\n'
         '```bash\n'
         'aws --endpoint-url https://<region>.vultrobjects.com s3 cp s3://<b>/.env .\n'
         '```\n\n'
         'Типичная находка — публичный бакет или ключ с полным доступом к аккаунту Vultr.'),
        ('## Защита',
         'Меры: приватные бакеты, минимальные API-ключи, ротация, шифрование, мониторинг. '
         'Для пентеста — перечисление и чтение публичного; модификация — с разрешения.'),
    ],
}

if __name__ == '__main__':
    _topup_gap.apply(C, 'cloud')
