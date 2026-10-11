---
id: hardware-measured-boot
title: "Измеряемая загрузка: цепочка доверия, PCR и UEFI Secure Boot"
category: hardware
parent: hardware-tpm
difficulty: hard
order: 2
tags: [measured-boot, secure-boot, uefi, pcr, chain-of-trust, tboot, grub]
prerequisites: [hardware-tpm, hardware-uefi]
useful_for:
  - "CTF-задачи категории Hardware"
  - "Аудит доверенной загрузки"
  - "Пентест: обход защит загрузки"
estimated_minutes: 50
summary: "Как строится цепочка доверия: UEFI Secure Boot, измеряемая загрузка, PCR и проверка целостности, а также практические способы обхода и защита."
---

**Измеряемая загрузка (measured boot)** — механизм, при котором каждый компонент цепочки загрузки хэшируется в PCR TPM ещё до исполнения. В отличие от **Secure Boot**, который *блокирует* загрузку недоверенных компонентов, измеряемая загрузка только *фиксирует* их состояние. Вместе они образуют **chain of trust**: firmware → bootloader → ядро → initramfs → ОС. Этот урок — про то, как это устроено и где ломается.

## Разница между Secure Boot и measured boot

| Свойство | Secure Boot | Measured Boot |
|----------|-------------|---------------|
| Что делает | проверяет подпись, блокирует | хэширует в PCR, не блокирует |
| Основа | ключи подписи (db/dbx) | TPM + PCR |
| Результат | загрузка разрешена/запрещена | состояние платформы в PCR |
| Обход | shim, ключи, dbx | спуфинг измерений, TPM-атаки |

Их комбинируют: Secure Boot обеспечивает, что грузится только подписанное, а measured boot даёт доказательство состояния для remote attestation.

## Цепочка доверия UEFI

1. **Root of Trust for Measurement (RTM)** — неизменяемый код (CRTM) в firmware, который первым измеряет firmware.
2. **Firmware (UEFI)** измеряет конфигурацию и передаёт управление загрузчику.
3. **Загрузчик** (Windows Boot Manager, GRUB с TPM-модулем, systemd-boot) измеряет ядро и cmdline.
4. **Ядро** измеряет initramfs/initrd.
5. **ОС** продолжает измерения (IMA/EVM на Linux).

Каждый шаг extend'ит PCR. Если хотя бы один компонент изменён — PCR другие.

## PCR при загрузке Linux

При загрузке с TPM измеряются:

- **PCR 4**: загрузочный код (bootloader stage).
- **PCR 7**: состояние Secure Boot (включён/выключен, ключи).
- **PCR 8**: GRUB — команды и конфиг (если GRUB с TPM).
- **PCR 9**: файлы, загруженные GRUB.
- **PCR 12–14**: ОС-специфичные (systemd-stub измеряет kernel/initrd/cmdline).

```bash
# Считать PCR после загрузки
sudo tpm2_pcrread sha256:4,7,8,9,12
# Пример вывода
# sha256:
#   4 : 0x9A1B...
#   7 : 0x3C5D...
```

Для проверки целостности нужно знать **эталонные** значения (good-known-values). Любое расхождение — сигнал о модификации.

## systemd-boot и systemd-stub

Современные Linux используют **systemd-stub**: kernel image — это PE-бинарник, который сам измеряет kernel/initrd/cmdline в PCR 12. Это упрощает measured boot без отдельного TPM-модуля GRUB. Команда `systemd-analyze` и `tpm2_pcrread` помогают увидеть результат.

## Проверка целостности и remote attestation

Сервер проверяет клиента так: клиент посылает **quote** (подпись PCR ключом AK) и nonce; сервер сверяет подпись, nonce и PCR с эталоном. Если PCR «правильные» — платформа считается доверенной. Это основа zero-trust и device identity.

```bash
# Сгенерировать quote и сохранить
echo -n "$(head -c16 /dev/urandom | xxd -p)" > nonce.bin
tpm2_quote -c ak.ctx -l sha256:0,4,7,12 -q nonce.bin -m q.msg -s q.sig -o q.pcr
# На сервере: проверить q.sig (AK), q.msg (PCR+nonce) с эталоном
```

## Обход measured boot и Secure Boot

- **Отключение Secure Boot**: меняет PCR 7 → привязка BitLocker к PCR 7 «сломается», но иногда восстановление секретов возможно.
- **shim + MOK**: загрузка неподписанного ядра через подписанный shim и Machine Owner Key (если MOK разрешён).
- **dbx-обход**: использование отозванных, но всё ещё загружаемых бинарей; эксплуатация неполного dbx.
- **TOCTOU в измерении**: изменение компонента после измерения, но до исполнения (гонка).
- **TPM-атаки**: cold-boot, fault injection, bus sniffing — обходятся дороже.
- **Кража recovery-ключа**: часто проще найти ключ BitLocker в AD/Entra ID, чем ломать TPM.

## Разобранный пример: анализ состояния загрузки

```bash
# 1. Проверить Secure Boot
mokutil --sb-state
# SecureBoot enabled
# 2. Считать PCR 7 (policy)
sudo tpm2_pcrread sha256:7
# 3. Проверить, к чему привязан BitLocker (если Windows рядом)
#    manage-bde -protectors -get C:
# 4. Посмотреть события измерений (если есть TCG log)
ls /sys/kernel/security/tpm0/binary_bios_measurements 2>/dev/null
# Разбор лога через tpm2_eventlog
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements | head
```

TCG log — это журнал измерений: он показывает, **что именно** и в какой PCR попало. Это ключ к диагностике «почему PCR не совпали».

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `tpm2_pcrread` | чтение PCR |
| `tpm2_eventlog` | разбор TCG log |
| `mokutil` | состояние Secure Boot/MOK |
| `tboot` | измеряемая загрузка для Linux (Intel TXT) |
| `systemd-analyze` | проверка измерений systemd |
| `manage-bde` | привязка BitLocker |
| `sbctl` | управление ключами Secure Boot |

## Частые ошибки и подводные камни

- **Обновление прошивки меняет PCR 0/1** → секреты, привязанные к ним, недоступны.
- **Отключённый Secure Boot меняет PCR 7** → BitLocker запросит recovery.
- **TCG log не включён**: без него сложно понять, что изменилось.
- **fTPM vs discrete**: разные значения PCR и разная устойчивость к атакам.
- **MOK enrollment**: если MOK разрешён, Secure Boot можно «обойти» легально — это конфигурационная слабость.

## Intel TXT, AMD SKINIT и DRTM

Классическая измеряемая загрузка измеряет **снизу вверх** (SRTM): сначала firmware, потом загрузчик. У неё есть слабость — если скомпрометирован ранний код (firmware/BIOS), измерения можно подделать. **Dynamic Root of Trust for Measurement (DRTM)** решает это: CPU запускает небольшой проверенный код (**tboot** для Intel TXT, **SKINIT** для AMD) в изолированной среде, который **перезапускает** измерения в отдельные PCR (17–22). Это даёт «чистую» точку доверия уже после загрузки, не доверяя BIOS.

```bash
# Intel TXT: проверка поддержки и запуск через tboot
grep -o 'txt' /proc/cpuinfo | head -1
tboot /boot/vmlinuz ...    # обычно через GRUB-запись с tboot
# PCR 17-22 отражают DRTM-измерения
sudo tpm2_pcrread sha256:17,18,19
```

DRTM устойчивее к компрометации firmware, но сложнее в настройке и требует поддержки CPU/чипсета. В атаках на DRTM известны уязвимости реализации (например, в ранних версиях SINIT AC-модулей).

## Практика: hardening измеряемой загрузки

Чтобы measured boot реально защищала, недостаточно её «включить». Хорошая конфигурация:

- **Secure Boot включён**, dbx актуален, MOK не разрешён без нужды.
- **BitLocker/шифрование привязано к PCR 7 + 11**, а не только к TPM без PIN (защита от cold-boot).
- **TCG event log сохраняется** и мониторится SIEM.
- **Remote attestation настроена** и проверяет PCR с эталоном, а не «любую подпись».
- **Обновления прошивки** контролируются: смена firmware меняет PCR, надо обновлять эталон.
- **Firmware защищён паролем**, flash-дескриптор залочен от записи.

Проверить базовые вещи:

```bash
mokutil --sb-state
sudo tpm2_pcrread sha256:7
# Windows
# manage-bde -protectors -get C:
```

Пентест-вывод: даже с measured boot и Secure Boot «дыры» обычно не в криптографии, а в конфигурации (MOK, отсутствие PIN, слабый пароль firmware) и в физическом доступе (fault injection, SPI-дамп).

## Логи и мониторинг измерений

Чтобы measured boot приносила пользу, измерения надо **наблюдать**. На Linux TCG event log лежит в securityfs; его можно парсить и отправлять в SIEM. Любое изменение набора измерений — сигнал.

```bash
# Расположение лога
ls -l /sys/kernel/security/tpm0/binary_bios_measurements
# Человекочитаемый разбор
tpm2_eventlog --eventlog-version=2 /sys/kernel/security/tpm0/binary_bios_measurements | less
# Только события измерений PCR 4 (bootloader)
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements | grep -A3 'PCR 4'
```

На Windows аналог — события **TPM-WMI** и **Microsoft-Windows-TPM-WMI** в Event Log, плюс отчёты `tpmtool`. В корпоративной среде эталонные значения PCR хранят централизованно (например, через Microsoft Intune или собственный сервер attestation) и сравнивают при каждой загрузке.

Практический совет пентестеру: если есть доступ к TCG log, вы быстро поймёте, **какой именно** компонент изменился — например, подменённый GRUB (`PCR 8/9`) или выключенный Secure Boot (`PCR 7`). Это экономит часы диагностики и помогает обосновать находку в отчёте.

## Что дальше / решение

- Нужен базовый обзор TPM → `hardware-tpm`.
- Нужен глубокий TPM 2.0 → `hardware-tpm-deep`.
- Нужен разбор UEFI → `hardware-uefi`.
- Нужны glitch-атаки на проверки → `hardware-fault-injection`.

## Квиз

```quiz
- question: "Чем measured boot отличается от Secure Boot?"
  options:
    - "Он блокирует загрузку"
    - "Он только измеряет и записывает в PCR, не блокируя"
    - "Он шифрует диск"
    - "Он быстрее"
  answer: 1
  explanation: "Measured boot фиксирует состояние, Secure Boot — блокирует."
- question: "Что измеряется в PCR 7?"
  options:
    - "Ядро Linux"
    - "Состояние Secure Boot (политика)"
    - "MBR"
    - "initramfs"
  answer: 1
  explanation: "PCR 7 отражает Secure Boot policy."
- question: "Зачем нужен TCG event log?"
  options:
    - "Ускорить загрузку"
    - "Показать, что именно измерялось и в какой PCR"
    - "Шифровать PCR"
    - "Хранить пароли"
  answer: 1
  explanation: "Event log детализирует измерения для диагностики."
- question: "Что происходит с PCR 7 при отключении Secure Boot?"
  options:
    - "Не меняется"
    - "Меняется, ломая привязку BitLocker к PCR 7"
    - "Сбрасывается в ноль"
    - "Удаляется"
  answer: 1
  explanation: "Изменение policy меняет PCR 7."
- question: "Что такое shim в контексте Secure Boot?"
  options:
    - "Аппаратный чип"
    - "Подписанный загрузчик, позволяющий грузить ядра через MOK"
    - "Модуль TPM"
    - "Раздел диска"
  answer: 1
  explanation: "shim — мост для загрузки сторонних подписанных ядер."
```

## Где пригодится

- **CTF:** Hardware-задачи на цепочку доверия.
- **Аудит:** проверка конфигурации Secure Boot и измеряемой загрузки.
- **Пентест:** обход защит загрузки, анализ BitLocker.
- **Работа:** проектирование доверенной загрузки, remote attestation.
- **Дальше по дереву:** `hardware-tpm`, `hardware-tpm-deep`, `hardware-uefi`.
