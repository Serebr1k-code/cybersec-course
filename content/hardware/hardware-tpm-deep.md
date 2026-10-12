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

## Вопрос, с которого всё начинается

В прошлом уроке мы поняли, зачем нужен TPM. Но чтобы реально им пользоваться — запечатать секрет, прочитать сертификат, подписать измерения — нужно понимать его **объектную модель**: где живут ключи, что такое иерархии и как задаются условия доступа.

Вопрос урока: как на практике работать с TPM 2.0 через `tpm2-tools` — от первичного ключа до запечатанного секрета с политикой?

## Наш пример: Linux-машина с TPM 2.0

У нас есть ноутбук с Linux и встроенным TPM 2.0 (в системе он виден как `/dev/tpm0`). Мы хотим запечатать секрет так, чтобы он открывался только при «правильном» состоянии загрузки, и попутно разобраться в устройстве модуля.

## Шаг 1: иерархии — четыре «корня» TPM

У TPM 2.0 есть четыре иерархии, каждая со своим **seed** (первичным зерном):

| Иерархия | Назначение | Активируется |
|----------|-----------|--------------|
| Owner | пользовательские ключи | owner auth |
| Endorsement (EK) | идентичность платформы | всегда |
| Platform | firmware/измерения | platform auth |
| Null | эфемерные ключи | без auth |

Каждая иерархия детерминированно порождает **primary key** из seed и шаблона. Важное следствие: команда `clear` уничтожает все ключи, выведенные из иерархии. Значит, запечатанный под owner объект после `clear` не восстановить.

Посмотрим, что умеет наш TPM:

```bash
$ tpm2_getcap properties-fixed | head
TPM2_PT_FAMILY_INDICATOR:
  raw: 0x322E3000
  value: "2.0"
$ tpm2_getcap handles-persistent
$ tpm2_getcap pcrs
```

## Шаг 2: создаём первичный и дочерний ключ

**Primary key** создаётся детерминированно: одинаковый seed + шаблон → одинаковый ключ. Это позволяет «восстанавливать» его без сохранения. Создаём primary в owner-иерархии:

```bash
$ tpm2_createprimary -C o -G rsa2048 -g sha256 -c primary.ctx
```

Флаги: `-C o` — иерархия owner, `-G rsa2048` — алгоритм ключа, `-g sha256` — хэш, `-c primary.ctx` — файл контекста. Теперь создаём дочерний ключ для шифрования данных:

```bash
$ tpm2_create -C primary.ctx -G aes256 -u child.pub -r child.priv
$ tpm2_load -C primary.ctx -u child.pub -r child.priv -c child.ctx
```

`-u` и `-r` — публичная и приватная части. Когда работа закончена, транзитные объекты стоит сбрасывать:

```bash
$ tpm2_flushcontext -t
```

## Шаг 3: NV-индексы — флеш внутри TPM

**NV (non-volatile) storage** — небольшие области во флеше TPM: сертификаты, счётчики, конфигурация. NV-индекс имеет атрибуты (`ownerread`, `ownerwrite`, `counter`, `bits`) и размер. Определим свой:

```bash
$ tpm2_nvdefine 0x1500000 -C o -s 32 -a "ownerread|ownerwrite"
$ echo -n "0123456789abcdef0123456789abcdef" | tpm2_nvwrite 0x1500000 -C o -i-
$ tpm2_nvread 0x1500000 -C o
```

Часто в NV лежит **сертификат EK** — «паспорт» платформы от вендора. Его индекс обычно `0x01C00002`:

```bash
$ tpm2_getcap handles-nv-index
$ tpm2_nvread 0x01c00002 -C 0x01c0000a | openssl x509 -inform der -text -noout
```

## Шаг 4: политики — условия доступа

TPM 2.0 поддерживает сложные условия (**policy**): `policyPCR`, `policyCommandCode`, `policyAuthValue`, `policyOR`, `policyNV`. Политика — это набор условий, при выполнении которых объект доступен. Соберём политику «доступ только при определённых PCR»:

```bash
$ tpm2_startauthsession -S session.ctx
$ tpm2_policypcr -S session.ctx -l sha256:0,7 -L pcr.policy
$ tpm2_flushcontext session.ctx
```

Теперь создадим объект с этой политикой и запечатаем в него секрет:

```bash
$ tpm2_create -C primary.ctx -G aes256 -u key.pub -r key.priv -L pcr.policy -i secret.bin
$ tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
```

Чтобы распечатать, нужно **восстановить** ту же сессию политики:

```bash
$ tpm2_startauthsession -S session.ctx --policy-session
$ tpm2_policypcr -S session.ctx -l sha256:0,7
$ tpm2_unseal -c key.ctx -p session:session.ctx
```

Если PCR не совпадут, `unseal` вернёт ошибку вида `the policy digest is not correct`. Так работают секреты измеряемой загрузки.

## Шаг 5: аттестация — quote

**Quote** — подпись набора PCR ключом **AK** (Attestation Key); это ядро remote attestation. Создадим AK и получим quote:

```bash
$ tpm2_createprimary -C e -G rsa2048 -c ek.ctx
$ tpm2_create -C ek.ctx -G rsa2048 -u ak.pub -r ak.priv -a "sign|restricted" -c ak.ctx
$ tpm2_quote -c ak.ctx -l sha256:0,1,2,3,4,7 -q nonce.bin -m quote.msg -s quote.sig -o pcr.bin
```

Проверяющая сторона сверяет **nonce** (защита от повтора), подпись AK и значения PCR с эталоном. Подделать quote можно только скомпрометировав AK или сам TPM.

## Шаг 6: атрибуты объектов — где живёт ключ

Каждый объект имеет атрибуты, определяющие его поведение:

| Атрибут | Значение |
|---------|----------|
| `fixedtpm` | ключ нельзя продублировать (не покидает TPM) |
| `fixedparent` | привязан к родителю |
| `sensitivedataorigin` | sensitive-часть создана внутри TPM |
| `restricted` | только подпись/расшифрование хэшей |
| `decrypt` / `sign` | назначение ключа |

Если у ключа нет `fixedtpm`, его можно **duplicate** (выгрузить в зашифрованном виде) на другой TPM. Это нужно для миграции — но и для атак: получив дубликат, ключ можно перенести и использовать офлайн.

## Шаг 7: dictionary attack и lockout

TPM защищает auth от подбора. После нескольких неудач (обычно 3) наступает **lockout**. Посмотрим параметры:

```bash
$ tpm2_getcap properties-variable | grep -iA2 lockout
TPM2_PT_LOCKOUT_COUNTER: 0
TPM2_PT_MAX_AUTH_FAIL: 3
TPM2_PT_LOCKOUT_INTERVAL: 7200
TPM2_PT_LOCKOUT_RECOVERY: 86400
```

`LOCKOUT_RECOVERY: 86400` — сутки ожидания после блокировки. Поэтому онлайн-брутфорс TPM невыгоден: атакующие предпочитают fault injection или кражу ключей.

## Шаг 8: разбор ошибки на реальном примере

Попробуем распечатать объект, привязанный к PCR, когда PCR изменились:

```bash
$ tpm2_unseal -c 0x81010001 -p pcr:sha256:7
ERROR: tpm:session(1):the policy digest is not correct
```

Что делать:
1. Проверить persistent handles: `tpm2_getcap handles-persistent`.
2. Проверить транзитные: `tpm2_getcap handles-transient`.
3. Варианты: перезагрузиться в «нормальном» состоянии (восстановить PCR), атаковать TPM (fault injection/cold-boot) или искать recovery.

## Что мы теперь знаем

1. У TPM 2.0 четыре иерархии; `clear` уничтожает выведенные из них ключи.
2. Primary key детерминирован (seed + шаблон); дочерние создаются через `tpm2_create`/`load`.
3. NV-индексы хранят сертификаты и конфигурацию; EK лежит по индексу `0x01C00002`.
4. Политики (`policyPCR` и др.) задают условия доступа; несовпадение PCR блокирует `unseal`.
5. `tpm2_quote` подписывает PCR ключом AK — это основа attestation.
6. `lockout` делает онлайн-брутфорс auth невыгодным.

## На что смотреть дальше

- **Забыли `flushcontext`** — сессии и транзитные handles исчерпываются, команды падают.
- **Неверная иерархия** — ключ под endorsement не загрузится под owner.
- **Auth string vs policy** — `-p` (пароль) и `-p session:` (политика) — разные вещи.
- **NV-индекс read-only** — определяйте с `ownerwrite` заранее, иначе запись отклонена.
- **PCR меняются при обновлении прошивки** — запечатанные секреты «отвязываются».

## Квиз

Проверь себя.

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

## Куда дальше

Мы освоили инструмент. В следующем уроке применим его к полной картине — измеряемой загрузке: как PCR заполняются по шагам от прошивки до ядра, чем отличается от Secure Boot и как читать журнал измерений. А пока главное: **TPM 2.0 — это маленькая криптосистема с иерархиями и политиками, и `tpm2-tools` даёт к ней полный доступ.**

## Где пригодится

- **CTF:** Hardware-задачи на TPM и secure element.
- **Аудит:** проверка политик, NV и конфигурации TPM.
- **Пентест:** анализ привязки BitLocker и измеряемой загрузки.
- **Реверс:** понимание firmware-TPM и его уязвимостей.
- **Дальше по дереву:** `hardware-measured-boot`, `hardware-tpm`.
