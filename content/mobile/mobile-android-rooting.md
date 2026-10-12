---
id: mobile-android-rooting
title: "Root на Android: Magisk, KernelSU, Xposed и LSPosed"
category: mobile
parent: mobile-android-root
difficulty: hard
order: 3
tags: [android, root, magisk, kernelsu, apatch, xposed, lsposed, boot.img, fastboot]
prerequisites: [mobile-platforms]
useful_for:
  - "Пентест мобильных приложений"
  - "Анализ малвари"
  - "Bug bounty (обход root-детекта)"
estimated_minutes: 55
summary: "Практическое получение root: разблокировка загрузчика, патч boot.img через Magisk, KernelSU/APatch, установка Xposed/LSPosed и проверка результата."
---

## Вопрос, с которого всё начинается

Ты запускаешь тестовое приложение на своём телефоне — и оно сразу пишет «Root detected!» и закрывается. Ему не нравится, что устройство модифицировано. А тебе, наоборот, root нужен: без него не прочитать чужую песочницу, не установить системный CA, не прицепить Frida к защищённому процессу.

Как получить root на своём устройстве — и почему приложение вообще об этом узнаёт?

## Наш пример: uncrack1.apk и его детект

Снова возьмём `uncrack1.apk`. Декомпилируем его через `jadx` и посмотрим на точку входа:

```java
protected void onCreate(Bundle bundle) {
    if (c.a() || c.b() || c.c()) {
        a("Root detected!");
    }
    if (b.a(getApplicationContext())) {
        a("App is debuggable!");
    }
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
}
```

Здесь `c.a()`, `c.b()`, `c.c()` — три проверки root, а `b.a(...)` — проверка debuggable. Найдём класс `c` и посмотрим, что именно он проверяет:

```java
public static boolean a() {
    for (String str : System.getenv("PATH").split(":")) {
        if (new File(str, "su").exists()) return true;
    }
    return false;
}
public static boolean b() {
    return new File("/system/app/Superuser.apk").exists();
}
public static boolean c() {
    return new File("/system/xbin/daemonsu").exists() ||
           new File("/system/xbin/su").exists();
}
```

Вот и ответ: приложение ищет бинарь `su` в `PATH`, файл Superuser и `su` в системных каталогах. Всё это — **следы root**. Чтобы понять, откуда они берутся, нужно разобраться, как root вообще устроен.

## Шаг 1: что именно ломает root

Android — это «слоёный пирог» защиты. Root пробивает каждый слой аккуратно, не ломая загрузку системы.

| Слой | Назначение | Что даёт root |
|------|-----------|----------------|
| Sandbox (UID) | изоляция данных | чтение `/data/data/*` |
| SELinux | мандатный контроль | политики `su` |
| dm-verity | целостность system | обход через overlay |
| Verified Boot | подпись загрузки | разблокировка загрузчика |
| Keystore/TEE | аппаратные ключи | частично |

Важно различать три вещи: **bootloader unlock** (разрешение прошивать неофициальные образы), **root** (UID 0 и бинарь `su`) и **systemless-модификации** (Magisk). Unlock — это предпосылка: без него нельзя прошить patched boot.

## Шаг 2: разблокируем загрузчик

Загрузчик (`bootloader`) проверяет подпись загрузочных образов по Verified Boot. Чтобы прошить свой образ, его сначала разблокируют. У Pixel это делается через `fastboot`:

```
$ adb reboot bootloader
$ fastboot flashing unlock
OKAY [ 12.345s]
Finished. Total time: 12.345s
```

Внимание: эта команда **стирает все данные** (wipe) — это часть защиты. Проверяем состояние:

```
$ adb shell getprop ro.boot.verifiedbootstate
orange
$ adb shell getprop ro.boot.flash.locked
0
```

`orange` — разблокированный загрузчик. Многие банковские приложения детектят именно это (см. `mobile-root-detection`). У Samsung разблокировка — через `OEM unlock` в Developer Options и режим Download, у Xiaomi — с привязкой аккаунта и ожиданием.

## Шаг 3: systemless root через Magisk

Раньше root писали прямо в `/system` (SuperSU). Это ломало dm-verity и мешало обновлениям. Современный стандарт — **Magisk**: он не трогает `/system` физически, а патчит **boot-образ** и подмешивает изменения на этапе загрузки через ramdisk. Поэтому dm-verity остаётся валидным.

Установка выглядит так:

```
# 1. вытаскиваем boot.img своей сборки (или берём из OTA)
$ adb shell su -c "dd if=/dev/block/by-name/boot of=/sdcard/boot.img"   # если root уже есть
# 2. в приложении Magisk: Install -> Patch a file -> выбираем boot.img
# 3. возвращаем патченный образ
$ adb pull /sdcard/Download/magisk_patched-XXXX.img
$ adb reboot bootloader
$ fastboot flash boot magisk_patched-XXXX.img
$ fastboot reboot
```

После перезагрузки проверяем:

```
$ adb shell su -c id
uid=0(root) gid=0(root) context=u:r:magisk:s0
```

`uid=0(root)` — root есть. Внутри `/data/adb/magisk` живут файлы Magisk, а `/data/adb/modules/` — модули.

## Шаг 4: почему детект срабатывает

Теперь вернёмся к `uncrack1`. Проверки ищут `su` в `PATH` и файлы Superuser. Magisk умеет **скрывать** эти следы: у него есть **DenyList** (список приложений, которым не видно root) и модули вроде Play Integrity Fix. Но `su` как таковой нужен — поэтому просто «спрятать всё» не всегда выходит.

Есть и более скрытные решения:

| Решение | Принцип | Скрытность |
|---------|---------|-----------|
| Magisk | ramdisk + overlay | средняя |
| KernelSU | патч ядра (GKI) | высокая |
| APatch | ядро + KPM | очень высокая |

**KernelSU** работает на уровне ядра, поэтому его сложнее заметить из userspace. **APatch** — ещё более скрытный. Для пентеста обычно достаточно Magisk.

## Шаг 5: альтернатива — эмулятор

Не всегда хочется рисковать личным телефоном. **Эмулятор** (`AVD`, Android Virtual Device) — это виртуальное устройство, где root включается без разблокировки загрузчика. Образы Google APIs (`google_apis`) дают `adb root` из коробки:

```
$ adb root
restarting adbd as root
$ adb shell id
uid=0(root)
```

Плюсы эмулятора: воспроизводимость, снапшоты, изоляция от личных данных. Минусы: некоторые приложения детектят эмулятор (см. `mobile-emulator-detection`). Для большинства задач тестирования эмулятор — решение по умолчанию.

## Шаг 6: риски

Root снижает защиту устройства: вредоносное приложение, запросившее `su`, получит полный доступ, если пользователь подтвердит. Поэтому для работы используют отдельное устройство или эмулятор, не хранят там личные токены и делают снапшоты. Также важно согласовывать версию прошивки и патча Magisk — иначе можно получить «кирпич».

## Шаг 7: проверка состояния загрузчика

Прежде чем шить что-либо, посмотри, разблокирован ли загрузчик и цел ли system. Это системные свойства, и приложение видит ровно те же значения через `getprop`. Ключевых три:

- `ro.boot.verifiedbootstate` — `green` при подписанной штатной загрузке, `orange` при разблокированном загрузчике, `yellow`/`red` — нестандартная или кастомная загрузка;
- `ro.boot.flash.locked` — `1`, если загрузчик заблокирован;
- `ro.boot.veritymode` — `enforcing`, если dm-verity включён, `disabled` — если выключен.

Именно по этим свойствам банковские приложения вычисляют root-устройство: `orange` или `flash.locked=0` уже выдаёт разблокированный загрузчик ещё до установки Magisk, а `veritymode=disabled` — побочный эффект старых методов root. Запомни эту тройку: проверять их проще и надёжнее, чем искать бинарь `su`.

## Что мы теперь знаем

- Root — это UID 0 и бинарь `su`; он пробивает песочницу, SELinux и dm-verity.
- Bootloader unlock — предпосылка; он стирает данные и меняет verified boot state на `orange`.
- Magisk патчит boot-образ и работает systemless, не трогая `/system`.
- KernelSU/APatch скрытнее, потому что работают на уровне ядра.
- Детект root ищет `su` в `PATH` и системные файлы; Magisk умеет это скрывать.
- Эмулятор — безопасная альтернатива с root «из коробки».

## Квиз

Проверь себя.

```quiz
- question: Что ищет типовая проверка root вроде `new File(str, 'su').exists()`?
  options:
    - "Файл с паролем"
    - "Бинарь `su` в каталогах из PATH"
    - "Настройки Wi-Fi"
    - "Ключ API"
  answer: 1
  explanation: "Наличие `su` в PATH — классический маркер установленного root."
- question: Чем systemless root (Magisk) лучше записи в `/system`?
  options:
    - "Он быстрее"
    - "Не ломает dm-verity и OTA-обновления, подменяя /system на этапе загрузки"
    - "Не требует загрузчика"
    - "Работает без устройства"
  answer: 1
  explanation: "Magisk патчит boot-образ и подмешивает overlay, оставляя раздел system нетронутым."
- question: Что произойдёт при `fastboot flashing unlock`?
  options:
    - "Ничего"
    - "Все пользовательские данные будут стёрты (wipe)"
    - "Установится root"
    - "Удалится bootloader"
  answer: 1
  explanation: "Wipe — часть защиты при разблокировке загрузчика."
- question: Какой prop указывает на разблокированный загрузчик?
  options:
    - "ro.debuggable"
    - "ro.boot.verifiedbootstate=orange"
    - "ro.secure"
    - "ro.product.model"
  answer: 1
  explanation: "orange — разблокированный загрузчик; green — штатная подпись."
- question: Почему KernelSU сложнее заметить из приложения?
  options:
    - "Он не требует root"
    - "Работает на уровне ядра, а не через userspace-бинарь"
    - "Он скрывает манифест"
    - "Он отключает SELinux"
  answer: 1
  explanation: "KernelSU — патч ядра (GKI), поэтому следы в userspace минимальны."
```

## Куда дальше

Root получен. Дальше логично разобраться с **модулями Magisk и Zygisk** — именно они позволяют прятать root от конкретных приложений, подменять системные свойства и запускать код внутри Zygote. Об этом — следующий урок. А пока главное запомни: root — это не «взлом телефона», а легальная модификация собственного устройства, которая открывает доступ к данным и инструментам.

## Где пригодится

- **Пентест:** подготовка устройства для динамического анализа и MITM.
- **Bug bounty:** обход root- и integrity-детекта для доступа к функционалу.
- **Анализ малвари:** изоляция образца и перехват его поведения.
- **CTF:** Mobile-задачи, где нужен доступ к закрытым данным приложения.
