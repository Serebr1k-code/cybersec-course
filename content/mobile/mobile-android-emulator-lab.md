---
id: mobile-android-emulator-lab
title: "Тестовая лаборатория Android: AVD, Genymotion, docker-android"
category: mobile
parent: mobile-platform-integration
difficulty: medium
order: 1
tags: [mobile, android, emulator, avd, genymotion, docker, lab]
prerequisites: [mobile-android-analysis]
useful_for:
  - "Пентест: воспроизводимая среда тестирования"
  - "CTF: быстрый запуск Android-приложения"
estimated_minutes: 40
summary: "Как поднять воспроизводимую лабораторию для теста Android-приложений: AVD и Genymotion, root-образы, установка пользовательского CA, прокси Burp/mitmproxy, docker-android и автоматизация с adb."
---

## Зачем своя лаборатория

Тестировать приложение на личном телефоне неудобно: нет root, нельзя ставить системный CA, а провал можно «словить» на боевом устройстве. Лаборатория решает три задачи: **изоляция** (подозрительное APK не угрожает основному устройству), **контроль** (root, системный CA, отладка) и **воспроизводимость** (одна и та же среда на любой машине). Для CTF это ещё и скорость: поднять эмулятор быстрее, чем искать физическое устройство.

## AVD: штатный эмулятор Android

Android Studio и `avdmanager` позволяют создать виртуальное устройство:

```bash
# список доступных образов
sdkmanager --list | grep "system-images"
# установить образ с Google APIs (нужен для многих приложений)
sdkmanager "system-images;android-34;google_apis;x86_64"
# создать AVD
avdmanager create avd -n test34 -k "system-images;android-34;google_apis;x86_64" -d pixel_6
# запустить
emulator -avd test34 -writable-system -no-snapshot &
```

Флаг `-writable-system` критичен: он позволяет перемонтировать `/system` в read-write и установить системный CA или запушить frida-server.

Root на AVD: образы `google_apis` не имеют root, но `adb root` работает на `-writable-system` эмуляторах (userdebug). Для полного root используйте образы `AOSP` или патчите через Magisk.

## Системный CA и перехват TLS

Начиная с Android 7, приложения по умолчанию доверяют только системным CA, а не пользовательским. Чтобы перехватить трафик приложения, установите CA в системный store:

```bash
# 1) получить сертификат Burp/mitmproxy (DER)
# Burp: Proxy > Options > Export CA certificate > DER
# 2) вычислить hash имени
HASH=$(openssl x509 -inform DER -in cacert.der -subject_hash_old -noout)
# 3) перемонтировать system и положить сертификат
adb root && adb remount
openssl x509 -inform DER -in cacert.der -out /tmp/ca.pem
adb push /tmp/ca.pem /system/etc/security/cacerts/$HASH.0
adb shell chmod 644 /system/etc/security/cacerts/$HASH.0
adb reboot
```

Теперь трафик приложений виден в прокси. Если приложение пинит сертификат — см. `mobile-cert-pinning-deep`.

Настройка прокси:

```bash
adb shell settings put global http_proxy 10.0.2.2:8080   # 10.0.2.2 = хост
# или в настройках Wi-Fi: proxy вручную
```

`10.0.2.2` — специальный адрес хоста из эмулятора Android. Для Genymotion это `10.0.3.2`.

## Genymotion

Genymotion — коммерческий эмулятор на базе VirtualBox, быстрее и удобнее для тестов. Плюсы: готовые root-образы, простой проброс сертификатов, snapshots. Минус — лицензия для части функций.

```bash
# установка через gmtool
gmtool admin create "Pixel_API_34" "Google Pixel 6" "Android 14"
gmtool admin start "Pixel_API_34"
adb connect 192.168.56.101:5555
```

Genymotion имеет встроенную поддержку установки сертификатов (`adb shell` + суперпользователь) и проброс портов.

## docker-android и облачные фермы

Для CI и воспроизводимости удобны контейнеры:

```bash
docker run -d --name android \
  -p 5555:5555 -p 6080:6080 \
  budtmo/docker-android-x86-11.0
# внутри — эмулятор с noVNC на 6080
adb connect localhost:5555
```

Такой контейнер поднимает эмулятор в headless-режиме с VNC-доступом. Плюс: одинаково на любой машине, легко масштабировать. Минус: ограниченная производительность и не все образы поддерживают Google APIs.

Облачные фермы (BrowserStack, Sauce Labs, Firebase Test Lab) дают реальные устройства по API, но не дают root и требуют загрузки APK — для глубокого пентеста не подходят, для smoke-тестов — да.

## Установка инструментов внутрь эмулятора

Frida-server под архитектуру эмулятора:

```bash
# определить архитектуру
adb shell getprop ro.product.cpu.abi   # x86_64
# скачать frida-server для android-x86_64 нужной версии
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
# проверить
frida-ps -U
```

Для ARM-приложений на x86-эмуляторе нужен ARM-транслятор (см. `mobile-arm-x86-translation`), иначе нативные библиотеки не запустятся.

## Автоматизация лаборатории

Скрипт полного цикла «поднять — установить — настроить»:

```bash
#!/usr/bin/env bash
set -e
emulator -avd test34 -writable-system -no-window -no-audio &
sleep 25
adb wait-for-device
adb root && adb remount
HASH=$(openssl x509 -inform DER -in cacert.der -subject_hash_old -noout)
adb push cacert.pem /system/etc/security/cacerts/$HASH.0
adb shell chmod 644 /system/etc/security/cacerts/$HASH.0
adb shell settings put global http_proxy 10.0.2.2:8080
adb install app.apk
echo "lab ready"
```

Такой скрипт экономит часы при повторяющихся тестах.

## Частые ошибки и подводные камни

- **Приложение не видит прокси** — http_proxy не работает для некоторых сетевых стеков; настройте прокси на уровне Wi-Fi или используйте iptables-редирект.
- **CA не действует** — сертификат не в системном store или неверный hash.
- **Нативный код падает** — ARM-библиотека на x86-эмуляторе.
- **`adb root` недоступен** — образ не userdebug; используйте Google APIs с `-writable-system`.
- **Эмулятор тормозит** — включите KVM (`-accel on`) и выделите больше RAM.
- **SafetyNet/Play Integrity падает** — эмулятор не проходит проверки; это ожидаемо, см. `mobile-integrity`.

## Справочная таблица

| Среда | Root | Системный CA | Скорость | Годится для |
|-------|------|--------------|----------|-------------|
| AVD (google_apis) | частично | да (writable-system) | средне | общий тест |
| AVD (AOSP) | да | да | средне | deep-тест |
| Genymotion | да | да | быстро | быстрый старт |
| docker-android | да | да | медленно | CI |
| физ. устройство | зависит | нужен root | быстро | финальная проверка |

## Что дальше / решение

Поднимите AVD с `-writable-system`, установите системный CA, настройте прокси — и у вас есть базовая лаборатория. Для ARM-приложений добавьте транслятор, для автоматизации — скрипт. Дальше — `mobile-mitm-burp` (перехват трафика) и `mobile-frida-tooling` (инструментация).

## Практический сценарий: перехват трафика банковского приложения

Полный цикл на чистом AVD:

```bash
# 1) запуск с writable system
emulator -avd test34 -writable-system -no-window &
adb wait-for-device
# 2) root и remount
adb root && adb remount
# 3) установка системного CA (Burp DER)
HASH=$(openssl x509 -inform DER -in burp.der -subject_hash_old -noout)
openssl x509 -inform DER -in burp.der -out /tmp/burp.pem
adb push /tmp/burp.pem /system/etc/security/cacerts/$HASH.0
adb shell chmod 644 /system/etc/security/cacerts/$HASH.0
# 4) прокси
adb shell settings put global http_proxy 10.0.2.2:8080
# 5) перезапуск
adb reboot && adb wait-for-device
# 6) установка и запуск приложения
adb install bank.apk
adb shell monkey -p com.bank.app -c android.intent.category.LAUNCHER 1
```

Теперь в Burp виден трафик. Если приложение пинит сертификат, соединения будут рваться — переходите к `mobile-cert-pinning-deep`.

## Работа с эмулятором: полезные команды

```bash
adb devices                     # список устройств
adb -s emulator-5554 shell ...  # выбрать конкретный
adb shell input text "hello"    # ввод текста
adb shell input tap 540 1200    # тап по координатам
adb shell input swipe 900 1500 100 1500 300
adb shell screencap -p /sdcard/s.png && adb pull /sdcard/s.png
adb shell screenrecord /sdcard/r.mp4 --time-limit 20
adb shell dumpsys activity activities | grep mResumedActivity
adb shell am start -n com.app/.MainActivity
adb shell pm list packages -3    # сторонние приложения
```

Автоматизация UI — через `monkey` (случайные события) или `uiautomator`/Appium (сценарные тесты). Для прогрева приложения перед дампом/анализом `monkey` часто достаточно:

```bash
adb shell monkey -p com.target.app --throttle 300 -v 1000
```

## Снапшоты и откат состояния

Эмулятор позволяет сохранять состояние, что бесценно при тесте, который «палит» устройство:

```bash
adb emu avd snapshot save clean_state
adb emu avd snapshot load clean_state
```

Для Genymotion — снапшоты через GUI. Для AVD — `emulator -avd test34 -snapshot clean_state`. Сохраняйте чистое состояние с установленным CA и прокси: тогда между экспериментами вы откатываетесь за секунды, а не пересобираете среду.

## Проблемы производительности и KVM

Если эмулятор тормозит, проверьте ускорение:

```bash
emulator -avd test34 -accel-check
# на Linux нужен KVM
ls -l /dev/kvm
# при отсутствии KVM используйте -accel off (медленно) или облако
```

Выделите больше RAM (`-memory 4096`) и ядер (`-cores 4`). Для тяжёлых приложений (игры, банки) x86-эмулятор с ARM-трансляцией будет медленным — это ожидаемо.

## Чек-лист готовности лаборатории

- [ ] AVD/Genymotion запускается и `adb` видит устройство.
- [ ] `adb root` работает (userdebug/AOSP).
- [ ] `/system` перемонтируем (`-writable-system`).
- [ ] Системный CA установлен, hash корректен.
- [ ] Прокси настроен и трафик виден в Burp.
- [ ] frida-server запущен, `frida-ps -U` работает.
- [ ] Снапшот чистого состояния сохранён.

Этот чек-лист экономит время: если что-то не работает на этапе настройки, вы будете искать причину в приложении, а не в среде.

## Заключение по лаборатории

Правильно собранная лаборатория — фундамент всего мобильного теста. Три кирпича: изолированное устройство (эмулятор или отдельный физический аппарат), прозрачный перехват трафика (системный CA + прокси) и инструментация (frida-server, root). Если хотя бы один из них отсутствует, вы либо тестируете вслепую, либо рискуете основным устройством. Потратьте час на автоматизацию настройки и снапшот чистого состояния — это окупится на каждом следующем приложении. Дальше переходите к перехвату трафика и инструментации: без готовой среды они превращаются в борьбу с окружением вместо анализа приложения.

## Квиз

```quiz
- question: "Почему на Android 7+ недостаточно установить пользовательский CA?"
  options:
    - "Приложения доверяют только системным CA по умолчанию"
    - "Android не поддерживает TLS"
    - "CA ставится только на iOS"
    - "Прокси не работает"
  answer: 0
- question: "Какой адрес хоста доступен из эмулятора Android?"
  options:
    - "10.0.2.2"
    - "127.0.0.1"
    - "192.168.0.1"
    - "10.0.3.2 (это Genymotion)"
  answer: 0
- question: "Зачем флаг -writable-system при запуске эмулятора?"
  options:
    - "Чтобы перемонтировать /system и установить системный CA/frida"
    - "Чтобы ускорить эмулятор"
    - "Чтобы включить Bluetooth"
    - "Чтобы сменить язык"
  answer: 0
- question: "Почему облачные фермы устройств не подходят для глубокого пентеста?"
  options:
    - "Они не дают root и полный контроль над устройством"
    - "Они слишком быстрые"
    - "Они не поддерживают APK"
    - "Они дорогие"
  answer: 0
```

## Где пригодится

- **Пентест:** воспроизводимая среда для теста приложений и трафика.
- **CTF:** быстрый запуск Android-задач.
- **Работа:** CI-тесты мобильного приложения в контейнере.
