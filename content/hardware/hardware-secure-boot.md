---
id: hardware-secure-boot
title: "Обход secure boot: U-Boot, verified boot, цепочка доверия"
category: hardware
parent: hardware-firmware-emulation
difficulty: hard
order: 3
tags: [secure-boot, uboot, verified-boot, dm-verity, chain-of-trust, signed-firmware]
prerequisites: [hardware-firmware-emulation, hardware-firmware-extract]
useful_for:
  - "CTF-задачи категории Hardware"
  - "Пентест IoT и мобильных устройств"
  - "Аппаратная безопасность"
estimated_minutes: 45
summary: "Как устроена цепочка доверия от BootROM до ядра и где её ломают: перехват U-Boot, подмена образов, dm-verity, откат версий и fault injection."
---

Secure boot — механизм, при котором каждый этап загрузки проверяет подпись следующего. Идея: BootROM проверяет загрузчик, загрузчик — ядро, ядро — rootfs. На практике цепочка часто имеет разрывы: незащищённая консоль, слабая проверка, откат версий, обход через fault injection. Этот урок показывает, где искать слабое звено.

## Теория

Цепочка доверия (chain of trust):

```
BootROM (неизменяемый, доверенный корень)
   │ проверяет подпись
   ▼
SPL / первый загрузчик (подписан ключом вендора)
   │ проверяет подпись
   ▼
U-Boot / второй загрузчик
   │ проверяет подпись (fitImage, dm-verity)
   ▼
Ядро Linux
   │ проверяет rootfs (dm-verity, AVB)
   ▼
Rootfs / система
```

Типовые слабости:

| Слабость | Где встречается | Как эксплуатировать |
|----------|-----------------|---------------------|
| Открытая консоль U-Boot | IoT-роутеры, камеры | прервать автозагрузку, получить shell |
| `bootargs` не защищены | U-Boot | добавить `init=/bin/sh`, `single` |
| Нет проверки подписи ядра | дешёвые устройства | подменить ядро/initramfs |
| Откат версий (no anti-rollback) | Android, IoT | залить уязвимую старую прошивку |
| Ключ в образе/на флеш | слабая реализация | извлечь ключ и подписать свой образ |
| dm-verity выключен | dev-сборки | править rootfs напрямую |
| AVB с `disable-verity` | Android dev | `fastboot --disable-verity` |
| BootROM уязвим к glitch | многие SoC | fault injection для пропуска проверки |

## Инструменты и команды

- **UART-консоль** — главный путь в U-Boot.
- **`uboot` команды**: `printenv`, `setenv`, `saveenv`, `bootm`, `fatload`, `tftpboot`.
- **binwalk, dumpimage, mkimage** — разбор образов U-Boot/ядра.
- **avbtool** — Android Verified Boot.
- **veritysetup** — dm-verity.
- **fastboot** — режимы загрузки Android-устройств.

```bash
# Разбор образа U-Boot / ядра
binwalk firmware.bin
dumpimage -l uImage          # список компонентов FIT/uImage
# Извлечь и проверить подпись
dumpimage -T flat_dt -p 0 -o kernel.fit uImage

# Android Verified Boot: посмотреть параметры
avbtool info_image --image vbmeta.img

# dm-verity: собрать таблицу хэшей
veritysetup format rootfs.img rootfs.hash
veritysetup open rootfs.img root rootfs.hash
```

```text
# Типовые команды в консоли U-Boot:
printenv                 # посмотреть окружение
setenv bootargs 'console=ttyS0,115200 init=/bin/sh'
boot                     # попытка загрузиться в shell
# или прервать автозагрузку и загрузить своё ядро по TFTP:
tftpboot 0x80000000 mykernel.bin
bootm 0x80000000
```

## Разобранный пример: обход secure boot на роутере

**Дано:** роутер с U-Boot на UART, secure boot включён, но консоль не заблокирована.

**Шаг 1 — получить консоль.** Подключаемся к UART (см. `hardware-pcb-reversing`), ловим лог U-Boot, жмём клавишу для прерывания автозагрузки.

**Шаг 2 — inspect окружения.** `printenv`. Видим `bootargs`, `bootcmd`, переменные с адресами. Проверяем, есть ли `init=/bin/sh` или возможность изменить `bootargs`.

**Шаг 3 — попытка изменить bootargs.** Пробуем `setenv bootargs '... init=/bin/sh'`. Если подпись проверяет только ядро, а не bootargs — система загрузится в shell. Если U-Boot проверяет целостность окружения — не сработает.

**Шаг 4 — загрузка своего ядра.** Если подпись ядра не проверяется (или ключ извлечён), собираем простой initramfs, грузим по TFTP:

```bash
tftpboot 0x82000000 kernel.itb
bootm 0x82000000
```

**Шаг 5 — если проверка подписи есть.** Анализируем, чем она реализована (FIT-подпись, отдельный верификатор). Ищем:
- ключ в открытом виде в образе (`strings`, `binwalk`);
- ошибку в логике проверки (сравнение без constant-time, отключение при флаге);
- уязвимость к fault injection (см. `hardware-fault-injection`).

**Шаг 6 — откат версий.** Если anti-rollback отсутствует, заливаем старую уязвимую прошивку с известным багом и эксплуатируем его.

## Частые ошибки

- **Сразу glitch.** Сначала исчерпайте программные пути: консоль, bootargs, откат. Fault injection — последнее средство.
- **Правка ядра без подписи.** Если ядро подписано, изменённое ядро не загрузится. Сначала проверьте, что подпись не валидируется.
- **Забыли про dm-verity.** Правка rootfs при включённом dm-verity = ошибка целостности при монтировании.
- **Затирание критичных разделов.** Не перезаписывайте BootROM/bootloader без бэкапа — получите «кирпич».
- **Неверные адреса загрузки.** `tftpboot` в неправильный адрес = зависание. Сверяйтесь с `printenv`/даташитом.
- **Правовые рамки.** Обход secure boot на чужом устройстве (ТВ-приставки, банковские терминалы) — вне рамок авторизации.

## Теория: цепочка доверия

Secure boot строит цепочку: ROM → загрузчик → ядро → rootfs, где каждый этап проверяет подпись следующего. В embedded: U-Boot проверяет ядро (fitImage с подписью), ядро проверяет dm-verity rootfs (хэш-дерево), иногда есть TPM для измерения. Корень доверия — в ROM или eFuse (неизменяемый ключ). Если хотя бы одно звено не проверяется, цепочка рвётся.

## Инструменты и команды

```bash
# извлечь и проверить fitImage
dumpimage -l fitImage
# проверить подпись
uboot-mkimage -l fitImage
# dm-verity
veritysetup verify rootfs.img rootfs.hash <root_hash>
# анализ U-Boot
binwalk -Me uboot.bin
strings uboot.bin | grep -iE 'bootcmd|bootargs|verify'
```

## Обходы

| Обход | Условие |
|-------|---------|
| Отключить проверку в U-Boot | доступ к консоли + запись флеш |
| Сменить bootargs | консоль U-Boot |
| Откат на старый подписанный образ | нет anti-rollback |
| Уязвимый загрузчик | конкретная версия |
| Fault injection | физический доступ |
| Запись модифицированного rootfs | dm-verity не включён |

## Практика

Распакуйте образ роутера, найдите U-Boot и fitImage, определите, проверяется ли подпись. Проверьте наличие dm-verity (`veritysetup`, fstab). Если проверки нет — модифицируйте rootfs и добейтесь загрузки. Это демонстрирует разрыв цепочки доверия.

## dm-verity: целостность rootfs

dm-verity строит хэш-дерево (Merkle) над блоками rootfs; корневой хэш хранится в подписанном месте (kernel cmdline/TPM). При чтении каждый блок проверяется по дереву — модификация rootfs обнаруживается. Без dm-verity можно изменить файлы, сохранив загрузку. Проверка:

```bash
veritysetup verify rootfs.img rootfs.hash <root_hash>
cat /proc/cmdline | tr ' ' '\n' | grep verity
dmsetup table
```

## Практика 2

Соберите образ с dm-verity, измените блок rootfs и убедитесь, что система не загружается (или падает). Затем уберите dm-verity из cmdline и повторите — модификация проходит. Это демонстрирует роль каждого звена цепочки доверия и почему отключение проверки в загрузчике равносильно её отсутствию.

## Быстрая проверка

```bash
dumpimage -l fitImage
cat /proc/cmdline | tr ' ' '\n' | grep verity
veritysetup verify rootfs.img rootfs.hash <root_hash>
strings uboot.bin | grep -iE 'verify|bootargs'
```

Проверьте: подписан ли fitImage, включён ли dm-verity, есть ли проверка в U-Boot. Отсутствие любого звена — разрыв цепочки доверия.

## Итог

Secure boot — это цепочка: ROM → загрузчик → ядро → rootfs. Разрыв любого звена (нет подписи fitImage, нет dm-verity, отключена проверка в U-Boot) обнуляет защиту. Проверяйте всю цепочку, а не только наличие Secure Boot. Для защиты — подпись на каждом этапе, anti-rollback и write-protect флеш.

## Квиз

```quiz
- question: "Что проверяет каждый этап secure boot?"
  options:
    - "Подпись следующего этапа цепочки доверия"
    - "Цвет корпуса устройства"
    - "Напряжение питания"
    - "Скорость интернета"
  answer: 0
- question: "Как чаще всего прерывают загрузку U-Boot?"
  options:
    - "Нажатием клавиши в UART-консоли до таймаута автозагрузки"
    - "Выключением питания на 1 секунду"
    - "Сменой SIM-карты"
    - "Подключением по Wi-Fi"
  answer: 0
- question: "Что такое anti-rollback?"
  options:
    - "Защита от установки более старой (уязвимой) версии прошивки"
    - "Откат драйверов"
    - "Сброс настроек сети"
    - "Возврат денег за устройство"
  answer: 0
- question: "Чем проверяется целостность rootfs в Android?"
  options:
    - "dm-verity / Android Verified Boot (avb)"
    - "MD5 в имени файла"
    - "Паролем пользователя"
    - "Контролем температуры"
  answer: 0
- question: "Когда уместен fault injection для обхода secure boot?"
  options:
    - "Когда программные пути исчерпаны, а BootROM проверяет подпись"
    - "Всегда, вместо анализа консоли"
    - "Только на устройствах без процессора"
    - "Никогда"
  answer: 0
```

## Где пригодится

- **CTF:** Hardware-задачи с обходом подписанной загрузки.
- **Пентест IoT/Android:** получение root/консоли на защищённых устройствах.
- **Аппаратная безопасность:** оценка стойкости цепочки доверия.
- **Работа:** разработка безопасного загрузчика, сертификация.
- **Дальше по дереву:** `hardware-fault-injection`, `hardware-uefi`, `hardware-rtos`.
