---
id: hardware-tpm-deep
title: "TPM 2.0 глубоко: иерархии, NV-индексы, ключи и tpm2-tools"
category: hardware
parent: hardware-tpm
difficulty: hard
order: 1
tags: [tpm2, tpm2-tools, hierarchies, nvram, endorsement, sealed, attestation]
prerequisites: [hardware-tpm]
useful_for:
  - "CTF-задачи категории Hardware"
  - "Аудит доверенной платформы"
  - "Реверс firmware и secure element"
estimated_minutes: 55
summary: "Глубокое погружение в TPM 2.0: иерархии, primary keys, NV-индексы, политики, sealed objects, attestation и полный набор команд tpm2-tools."
---

TPM 2.0 — сложная криптосистема с собственной объектной моделью. Чтобы уверенно атаковать и защищать доверенную платформу, нужно понимать иерархии, типы ключей, NV-индексы и политики (policy). Этот урок — практическое погружение через `tpm2-tools`: от `tpm2_getcap` до запечатывания объектов с политикой и подписи attestation.

## Иерархии TPM 2.0

TPM 2.0 имеет четыре иерархии, каждая со своим seed:

| Иерархия | Назначение | Активируется |
|----------|-----------|--------------|
| Owner | пользовательские ключи | owner auth |
| Endorsement (EK) | идентичность платформы | всегда |
| Platform | firmware/измерения | platform auth |
| Null | эфемерные ключи | без auth |

Каждая иерархия порождает **primary key** из seed + шаблона. Смена иерархии (например, `clear`) уничтожает все ключи, выведенные из неё. Понимание этого критично: запечатанный под owner объект не восстановить после `clear`.

```bash
# Возможности и алгоритмы TPM
tpm2_getcap algorithms
tpm2_getcap properties-fixed
tpm2_getcap handles-persistent
tpm2_getcap pcrs
```

## Primary keys и шаблоны

Primary key создаётся детерминированно из seed иерархии и шаблона. Одинаковый seed + шаблон → одинаковый primary. Это позволяет «восстанавливать» primary без сохранения, если известен шаблон.

```bash
# Создать primary в owner-иерархии (RSA2048, restricted decrypt)
tpm2_createprimary -C o -G rsa2048 -g sha256 -c primary.ctx
# Создать дочерний ключ (шифрование данных)
tpm2_create -C primary.ctx -G aes256 -u child.pub -r child.priv
tpm2_load -C primary.ctx -u child.pub -r child.priv -c child.ctx
# Сохранить контекст для переиспользования
tpm2_flushcontext -t
```

Флаги `-G` (алгоритм ключа), `-g` (хэш), `-a` (атрибуты: fixedtpm, fixedparent, sensitivedataorigin) определяют, где может жить ключ и что с ним можно делать.

## NV-индексы

**NV (non-volatile) storage** — небольшие области во флеше TPM для сертификатов, счётчиков, конфигурации. NV-индекс имеет атрибуты (read/write, ownerread, policy, counter, bits) и размер.

```bash
# Определить NV-индекс (например, сертификат EK)
tpm2_nvdefine 0x1500000 -C o -s 32 -a "ownerread|ownerwrite"
echo -n "0123456789abcdef0123456789abcdef" | tpm2_nvwrite 0x1500000 -C o -i-
tpm2_nvread 0x1500000 -C o
# Список NV-индексов
tpm2_getcap handles-nv-index
```

NV-индексы часто хранят **сертификат EK** (Endorsement Key) и настройки BitLocker. Атакующий может читать их, если политика позволяет, или искать там чувствительные данные.

## Политики (policy) и авторизация

TPM 2.0 поддерживает сложные политики: `policyPCR`, `policyCommandCode`, `policyAuthValue`, `policyOR`, `policyNV`, `policySigned`. Политика — это условие, при выполнении которого объект доступен.

```bash
# Политика: доступ только при определённых PCR
tpm2_startauthsession -S session.ctx
tpm2_policypcr -S session.ctx -l sha256:0,7 -L pcr.policy
tpm2_flushcontext session.ctx

# Создать объект с этой политикой
tpm2_create -C primary.ctx -G aes256 -u key.pub -r key.priv -L pcr.policy -i secret.bin
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx

# Использовать: сначала восстановить сессию политики
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policypcr -S session.ctx -l sha256:0,7
tpm2_unseal -c key.ctx -p session:session.ctx
```

Если PCR не совпадают — политика не выполняется, unseal отклонён. Так работает защита секретов в измеряемой загрузке.

## Attestation: quote и certify

**Quote** — подпись набора PCR ключом AK; **certify** — подпись публичной части ключа. Это ядро remote attestation.

```bash
# Создать AK (restricted signing key)
tpm2_createprimary -C e -G rsa2048 -c ek.ctx
tpm2_create -C ek.ctx -G rsa2048 -u ak.pub -r ak.priv -a "sign|restricted" -c ak.ctx
# Получить quote по PCR
tpm2_quote -c ak.ctx -l sha256:0,1,2,3,4,7 -q nonce.bin -m quote.msg -s quote.sig -o pcr.bin
# Проверить подпись (openssl/tsd)
```

Проверяющая сторона сверяет nonce (защита от replay), подпись AK и значения PCR с эталоном. Подделка требует компрометации AK или самого TPM.

## Разобранный пример: восстановление доступа к запечатанному секрету

```bash
# 1. Осмотреть иерархии и persistent handles
tpm2_getcap handles-persistent
tpm2_getcap properties-variable | grep -i hierarchy
# 2. Проверить, не создан ли ключ с пустым/слабым auth
tpm2_getcap handles-transient
# 3. Если объект привязан к PCR и PCR изменились — unseal не сработает:
tpm2_unseal -c 0x81010001 -p pcr:sha256:7
# ERROR: tpm:session(1):the policy digest is not correct
# 4. Варианты: восстановить PCR (перезагрузка в нормальном состоянии),
#    либо атаковать TPM (fault injection/cold-boot), либо искать recovery.
```

## Безопасность и атаки на уровень TPM 2.0

- **Weak authorization**: пустой или дефолтный auth у NV/ключей.
- **Policy bypass**: `policyOR` с выполнимым всегда условием (например, `policyCommandCode` без ограничений).
- **dictionary attack protection**: TPM блокируется после N неверных auth (lockout). Это ограничивает брутфорс.
- **Fault injection**: glitch при проверке auth/policy.
- **Firmware bugs**: уязвимости в fTPM (например, ошибки в AMD fTPM, Intel PTT).
- **Interposer**: MITM между CPU и TPM для replay/подмены (сложно, но известно).

## Таблица команд tpm2-tools

| Команда | Назначение |
|---------|-----------|
| `tpm2_getcap` | возможности/алгоритмы/handles |
| `tpm2_createprimary` | создать primary |
| `tpm2_create` / `tpm2_load` | дочерний ключ |
| `tpm2_nvdefine`/`read`/`write` | NV-индекс |
| `tpm2_policypcr` | политика по PCR |
| `tpm2_unseal` | распечатать объект |
| `tpm2_quote` | attestation |
| `tpm2_pcrread`/`extend` | PCR |
| `tpm2_clear` | сброс иерархий |

## Частые ошибки и подводные камни

- **Забыли flushcontext**: сессии/транзитные handles исчерпываются, команды падают.
- **Неверная иерархия**: ключ под endorsement не загрузится под owner.
- **Auth string vs policy**: `-p` (пароль) и `-p session:` (политика) — разные вещи.
- **NV-индекс read-only**: определить с `ownerwrite` заранее, иначе запись отклонена.
- **PCR меняются при обновлении**: запечатанные секреты «отвязываются» после прошивки.

## Атрибуты объектов: где живёт ключ

Каждый объект TPM имеет атрибуты, определяющие его поведение. Ключевые:

| Атрибут | Значение |
|---------|----------|
| `fixedtpm` | ключ нельзя продублировать (не покидает TPM) |
| `fixedparent` | привязан к родителю |
| `sensitivedataorigin` | sensitive-часть создана внутри TPM |
| `userwithauth` | доступ по auth value |
| `adminwithpolicy` | доступ по policy |
| `restricted` | ограничен (только подпись/расшифрование хэшей) |
| `decrypt` / `sign` | назначение ключа |

Если у ключа нет `fixedtpm`, его можно **duplicate** (выгрузить в зашифрованном виде) на другой TPM. Это используется для миграции, но и для атак: если удалось получить дубликат, ключ можно перенести и использовать офлайн. Атрибут `sensitivedataorigin` показывает, что sensitive-часть не «импортирована» извне — импортированные ключи (`tpm2_import`) не имеют этого флага, и это нормально для загрузки внешних ключей.

## Dictionary attack и lockout на практике

TPM защищает от подбора auth: после нескольких неверных попыток (обычно 3) наступает **lockout** — TPM отказывается принимать auth до сброса (перезагрузка или ожидание recovery-таймаута). Это важно при брутфорсе:

```bash
# Посмотреть счётчик неудач и параметры lockout
tpm2_getcap properties-variable | grep -iA2 lockout
# Пример:
#   TPM2_PT_LOCKOUT_COUNTER: 0
#   TPM2_PT_MAX_AUTH_FAIL: 3
#   TPM2_PT_LOCKOUT_INTERVAL: 7200
#   TPM2_PT_LOCKOUT_RECOVERY: 86400
```

`LOCKOUT_INTERVAL` — окно, в котором считаются неудачи; `LOCKOUT_RECOVERY` — сколько ждать после блокировки. Поэтому онлайн-брутфорс TPM практически невыгоден, и атакующие предпочитают обход (fault injection) или кражу ключей. Защитнику же эти значения показывают, насколько устойчива конфигурация к подбору.

## Провижининг: EK, сертификаты и идентичность

У каждой платформы есть **Endorsement Key (EK)** — уникальная пара, вшитая производителем, и **сертификат EK**, подписанный вендором. Он хранится в NV-индексе (обычно `0x01C00002`) и позволяет доказать, что перед нами «настоящий» TPM конкретной модели. Это основа device identity: сервер доверяет платформе, потому что верит цепочке сертификатов вендора.

```bash
# Найти и прочитать сертификат EK
tpm2_getcap handles-nv-index
tpm2_nvread 0x01c00002 -C 0x01c0000a | openssl x509 -inform der -text -noout
```

Практические аспекты:

- **EK нельзя дублировать** (нет `fixedtpm`-снятия) — это якорь идентичности.
- **AK создаётся на базе EK** и подписывает attestation; привязка AK↔EK доказывается `tpm2_certify`.
- **Provisioning** — процесс разворачивания EK/AK на устройстве; ошибки здесь (например, общий EK для партии) ломают идентичность.
- **Атака**: если вендорский сертификат EK скомпрометирован или ключ вендора утёк, доверие ко всей партии устройств рушится.

## Что дальше / решение

- Нужна измеряемая загрузка целиком → `hardware-measured-boot`.
- Нужен обход Secure Boot → `hardware-secure-boot`.
- Нужны glitch-атаки → `hardware-fault-injection`.
- Нужен базовый обзор → `hardware-tpm`.

## Квиз

```quiz
- question: "Сколько иерархий у TPM 2.0?"
  options:
    - "2"
    - "4 (owner, endorsement, platform, null)"
    - "8"
    - "1"
  answer: 1
  explanation: "Owner, endorsement, platform и null."
- question: "Что задаёт policyPCR?"
  options:
    - "Размер NV"
    - "Условие доступа, зависящее от состояния PCR"
    - "Тип ключа"
    - "Скорость TPM"
  answer: 1
  explanation: "Политика выполняется только при совпадении PCR."
- question: "Что подписывает tpm2_quote?"
  options:
    - "MAC-адрес"
    - "Набор PCR ключом AK"
    - "Пароль"
    - "NV-индекс"
  answer: 1
  explanation: "Quote — подпись измерений для attestation."
- question: "Что произойдёт с ключами после tpm2_clear?"
  options:
    - "Сохранятся"
    - "Будут уничтожены (иерархии сброшены)"
    - "Скопируются в NV"
    - "Останутся в endorsement"
  answer: 1
  explanation: "clear сбрасывает иерархии и уничтожает выведенные ключи."
- question: "Зачем TPM использует lockout?"
  options:
    - "Экономить питание"
    - "Ограничить брутфорс auth (dictionary attack protection)"
    - "Ускорять ключи"
    - "Хранить PCR"
  answer: 1
  explanation: "После N неудач TPM блокирует попытки."
```

## Где пригодится

- **CTF:** Hardware-задачи на TPM и secure element.
- **Аудит:** проверка политик, NV и конфигурации TPM.
- **Пентест:** анализ привязки BitLocker и измеряемой загрузки.
- **Реверс:** понимание firmware-TPM и его уязвимостей.
- **Дальше по дереву:** `hardware-tpm`, `hardware-measured-boot`.
