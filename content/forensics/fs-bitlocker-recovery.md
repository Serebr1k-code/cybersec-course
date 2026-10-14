---
id: fs-bitlocker-recovery
title: 'BitLocker: recovery-ключ, TPM и метаданные FVE'
category: forensics
parent: forensics-img-encryption
difficulty: hard
order: 4
tags: [bitlocker, fve, tpm, recovery-key, vmk, dislocker, forensics]
prerequisites: [forensics-disk-encryption, forensics-luks-header]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Windows data recovery'
estimated_minutes: 55
summary: 'Как устроен BitLocker: метаданные FVE, VMK и протекторы (TPM, recovery-пароль, startup key), где искать recovery-ключ при расследовании и как открывать образы инструментами dislocker и bdemount.'
lab:
  kind: shell
  title: 'Практика: метаданные BitLocker'
  toolset: [core, grep, hex]
  workdir: /home/student/task
  files: [task.md, fve.meta]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Начни с `ls -la fve.meta` и `file fve.meta`.'
    - 'BitLocker подписывает метаданные строкой -FVE-FS- — ищи её.'
    - 'Ищи VMK, protector и recovery password.'
    - 'Флаг лежит в текстовой метке: `strings fve.meta | grep nto > found.txt`.'
---

## Вопрос, с которого всё начинается

Ты снял образ зашифрованного Windows-диска. Данные не читаются, а в начале диска — некая
служебная область. Это **BitLocker**. В отличие от VeraCrypt, у него есть опознаваемая
подпись, но ключ защищён и TPM, и recovery-паролем. Как понять, как именно защищён том, и
где искать ключ при расследовании?

## Что такое BitLocker

**BitLocker (BitLocker Drive Encryption)** — встроенное шифрование дисков Windows. Весь
том шифруется **Full Volume Encryption Key (FVEK)**, а FVEK, в свою очередь, шифруется
**Volume Master Key (VMK)**. VMK хранится в метаданных в зашифрованном виде, и развернуть
его можно через один или несколько **протекторов (protectors)**:

- **TPM** — модуль доверенной платформы на материнской плате; ключ «запечатан» в нём;
- **Recovery password** — 48-значный числовой код (8 групп по 6 цифр);
- **Startup key** — файл на USB, вставляемый при загрузке;
- **Password / PIN** — пользовательский секрет.

Ключевая идея: **том открывается любым доступным протектором**. Значит, для расследования
важно найти **хоть один** — чаще всего recovery-ключ.

## Наш пример: метаданные FVE

```
$ ls -la
-rw-r--r-- 1 student student 8388608 bl.img
$ file bl.img
bl.img: data
```

`file` не распознаёт — но BitLocker прячет метаданные не в самом начале, а в служебной
области. Ищем подпись:

```
$ strings bl.img | grep -Ei 'FVE|VMK|protector|recovery|nto'
-FVE-FS- signature at offset 0x0
VMK present, protected by TPM + recovery
recovery password protector present
EVIDENCE: nto{b1tl0ck3r_vmk_r3c0v3ry}
```

Мы видим подпись `-FVE-FS-`, VMK и список протекторов: TPM и recovery. Последний — самое
ценное: если recovery-пароль есть, том откроется.

## Шаг 1: структура метаданных BitLocker

| Область | Назначение |
|---------|-----------|
| Boot sector | загрузочный сектор (с подписью `-FVE-FS-`) |
| FVE metadata (header) | VMK, протекторы, метод шифрования, GUID |
| Metadata backup | резервная копия заголовка |
| Encrypted volume | собственно шифрованные данные |

Метаданные содержат:

- **метод шифрования** (AES-CBC + Elephant diffuser в старых версиях, AES-XTS в новых);
- **VMK** в зашифрованном виде;
- **протекторы**: TPM (с PCR-политикой), recovery password, startup key, PIN;
- **GUID тома** и счётчики.

## Шаг 2: протекторы и что они значат

| Протектор | Как разворачивается | Слабость при расследовании |
|-----------|--------------------|----------------------------|
| TPM | автоматически при загрузке | нужен тот же TPM / снимок его состояния |
| Recovery password | ввод 48 цифр | часто лежит в AD / файле / реестре |
| Startup key | USB-файл | файл может быть найден |
| Password/PIN | пользователь | подбор |

Ключевой вывод: **TPM-защита без recovery-пароля почти не берётся**, если только нет
доступа к самому TPM (или его состояния). Поэтому в реальных инцидентах recovery-ключ —
главная цель.

## Шаг 3: где искать recovery-ключ

Recovery-пароль хранится в нескольких местах:

- **Active Directory** (атрибут `msFVE-RecoveryPassword` объекта компьютера) — самое
  частое в корпоративной среде;
- **файл-распечатка** `BitLocker Recovery Key *.txt` в профиле пользователя;
- **Microsoft Account** (для домашних ПК) — в облаке;
- **реестр / WMI** на самом хосте;
- **Azure AD** (ключи Intune).

При форензике ищут по всей системе: `grep -ri 'Recovery Key'`, проверяют AD, смотрят
`manage-bde -protectors -get C:`.

## Шаг 4: работа с образом

Если ключ есть:

```
$ dislocker -V bl.img -p 123456-234567-345678-456789-567890-678901-789012-890123 -u -- /mnt/bl
$ ls /mnt/bl/dislocker-file
dislocker-file
$ sudo mount -o ro /mnt/bl/dislocker-file /mnt/plain
```

`dislocker` умеет открывать BitLocker по recovery-паролю, пользовательскому паролю или
BEK-файлу. Есть также **`bdemount`** (из libbde) для монтирования образов и **`bdeinfo`**
для чтения метаданных без ключа:

```
$ bdeinfo bl.img | grep -Ei 'Encryption|Protector|Recovery'
Encryption Method: AES-XTS 256
Protector: Recovery Password
```

## Шаг 5: что можно узнать без ключа

Даже без recovery-пароля метаданные дают много:

- **метод шифрования** — важно для корректной расшифровки;
- **список протекторов** — как защищён том;
- **GUID** — сопоставление с записями AD;
- **версия BitLocker** — старые версии имели уязвимости (например, в CBC-режиме).

Это позволяет понять, реально ли вообще открыть том, и куда идти за ключом.

## Мини-практика: от подписи к протектору

```
$ strings bl.img | grep -Ei 'FVE|protector|recovery'
-FVE-FS- signature at offset 0x0
recovery password protector present
$ bdeinfo bl.img | grep -i protector
Protector: TPM, Recovery Password
```

Два протектора, один из них recovery. Дальше ищем 48-значный пароль в AD/профиле/облаке.
Наличие recovery-протектора — хорошая новость: том открываем.

## Частые ошибки и подводные камни

- **Искать подпись в самом начале.** Метаданные FVE могут быть не по offset 0.
- **Путать VMK и FVEK.** VMK разворачивается протектором, FVEK — уже из VMK.
- **Забыть про резервные метаданные.** Есть копия заголовка — она спасает при повреждении.
- **Считать TPM непреодолимым.** При наличии recovery-ключа TPM обходится.
- **Монтировать с записью.** Только `-o ro`.

## Что мы теперь знаем

- BitLocker опознаётся по подписи `-FVE-FS-`.
- FVEK шифрует том, VMK шифрует FVEK, протекторы защищают VMK.
- Протекторы: TPM, recovery password (48 цифр), startup key, PIN.
- Recovery-ключ ищут в AD, профиле, MSA, Azure AD.
- Инструменты: `dislocker`, `bdemount`/`bdeinfo`, `manage-bde`.

## Что фиксировать в отчёте

| Что | Зачем |
|-----|-------|
| Метод шифрования | корректная расшифровка |
| Список протекторов | путь к ключу |
| GUID тома | сопоставление с AD |
| Найденный recovery-ключ (источник) | открытие тома |
| Метод монтирования (readonly) | сохранность |

## BitLocker To Go и съёмные носители

**BitLocker To Go** — режим для съёмных носителей (USB, внешние диски). Технически это тот
же BitLocker, но с нюансами:

- чаще используется **пароль** или **смарт-карта**, а не TPM (на съёмном носителе TPM нет);
- заголовок FVE хранится на носителе, поэтому образ внешнего диска самодостаточен;
- **авторазблокировка** (`manage-bde -autounlock`) может быть настроена — тогда ключ
  хранится на связанном ПК, и его можно найти там;
- в корпоративной среде ключи могут лежать в AD/Intune.

При расследовании важно понять **тип протектора**: если это пароль, нужен подбор; если
авторазблокировка — ищи связанный компьютер. Съёмные носители часто содержат копию
recovery-ключа в скрытом файле `BitLocker Recovery Key *.txt`.

## Сопоставление с AD и Intune

В домене recovery-пароли централизованы, и это сильно упрощает работу:

- **Active Directory**: атрибут `msFVE-RecoveryPassword` у объекта **компьютера**;
- **Azure AD / Intune**: ключи в разделе устройств (BitLocker keys);
- **запрос через PowerShell**:

```
PS> Get-ADObject -Filter 'objectClass -eq "computer" -and Name -eq "PC01"' `
      -Properties msFVE-RecoveryPassword | Select msFVE-RecoveryPassword
```

Получив 48-значный код, сопоставь его с **GUID тома** из метаданных FVE: ключей может быть
несколько, и нужно выбрать тот, что относится именно к этому тому. Это важно, потому что
устройство могло быть перешифровано, и старый ключ не подойдёт. Всегда сверяй GUID.

## Что делать, если ключа нет

Иногда ни recovery-пароля, ни TPM, ни startup key в наличии нет. Тогда:

- **проверь все места хранения** ещё раз (AD, Azure AD, MSA, профили, печатные копии);
- **поищи дамп памяти** работающей системы — при загруженном томе ключи могут быть в RAM;
- **проверь hiberfil.sys / pagefile.sys** — туда попадают расшифрованные страницы;
- **оцени версию BitLocker**: старые реализации (AES-CBC + Elephant) имели известные
  атаки, новее — устойчивы;
- **зафиксируй невозможность** доступа как вывод, если ключа нет.

Важно не выдавать «не смог открыть» за «данных нет». В отчёте формулируй точно: «том
зашифрован, протектор — TPM без recovery; доступ без ключа невозможен». Это честный и
корректный результат.

## Квиз

Проверь себя.

```quiz
- question: "Какой подписью опознаются метаданные BitLocker?"
  options:
    - "LUKS"
    - "-FVE-FS-"
    - "_BHRfS_M"
    - "ZFS"
  answer: 1
  explanation: "Boot sector BitLocker содержит подпись -FVE-FS-."
- question: "Что защищают протекторы BitLocker?"
  options:
    - "FVEK напрямую"
    - "VMK (Volume Master Key)"
    - "Таблицу разделов"
    - "Реестр"
  answer: 1
  explanation: "Протекторы (TPM, recovery, startup key) разворачивают VMK, а тот — FVEK."
- question: "Сколько цифр в recovery-пароле BitLocker?"
  options:
    - "16"
    - "32"
    - "48"
    - "64"
  answer: 2
  explanation: "Recovery password — 48 цифр (8 групп по 6)."
- question: "Где чаще всего ищут recovery-ключ в корпоративной среде?"
  options:
    - "В $MFT"
    - "В Active Directory (msFVE-RecoveryPassword)"
    - "В BIOS"
    - "В jbd2"
  answer: 1
  explanation: "В домене recovery-пароли хранятся в AD в атрибуте msFVE-RecoveryPassword объекта компьютера."
```

## Куда дальше

Мы завершили блок шифрования дисков. Дальше перейдём к **облачной форензике** — журналам
M365, Okta и Google Workspace: там ключи и события живут не на диске, а в API провайдера.
А пока главное запомни: **BitLocker открывается протектором, и recovery-ключ — самый
доступный из них**.

## Где пригодится

- **CTF Forensics:** образы Windows с BitLocker.
- **DFIR:** извлечение recovery-ключей из AD и облака.
- **Data recovery:** открытие томов при повреждённом TPM.
- **Пентест:** понимание, как шифрование влияет на вывоз данных.
