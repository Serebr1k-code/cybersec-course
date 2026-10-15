---
id: mobile-network-security-config
title: "Network Security Config: атаки и обход доверия"
category: mobile
parent: mobile-network-security
difficulty: hard
order: 2
tags: [android, network-security-config, nsc, cleartext, trust-anchors, mitm, pinning, xml]
prerequisites: [mobile-ssl-pinning, mobile-static-analysis]
useful_for:
  - "Пентест мобильных приложений (Android)"
  - "Bug bounty Android"
  - "Анализ трафика"
estimated_minutes: 50
summary: "Как читать Network Security Config, почему пользовательский CA не работает, как обходить trust-anchors, cleartext-политику и config-level pinning."
lab:
  kind: shell
  title: "Практика: Network Security Config"
  toolset: [core, xml]
  workdir: /home/student/task
  files: [task.md, network_security_config.xml]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Найди блоки с `cleartextTrafficPermitted=\"true\"`: `grep -n cleartext network_security_config.xml`."
    - "Определи, для каких доменов разрешён plain HTTP."
    - "Флаг оставлен в комментарии `TODO(sec)`. `grep nto{ network_security_config.xml`."
---

## Вопрос, с которого всё начинается

Прокси настроен, CA установлен, но приложение не пускает трафик через посредника. Всё дело в одном XML-файле внутри APK — **Network Security Config**. Он определяет, каким сертификатам приложение доверяет и разрешён ли незашифрованный трафик. Как его прочитать и что в нём важно для тестировщика?

## Наш пример: реальный NSC

Возьмём настоящий APK и извлечём его конфигурацию. После `apktool d` файл лежит в ресурсах:

```
$ apktool d app.apk -o dec
$ find dec/res -name 'network_security_config*'
dec/res/xml/network_security_config.xml
```

Содержимое (реальный файл открытого приложения):

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
        <certificateTransparency enabled="false" />
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <certificateTransparency enabled="false" />
        <domain includeSubdomains="true">onion</domain>
    </domain-config>
    <domain-config cleartextTrafficPermitted="false">
        <certificateTransparency enabled="true" />
        <domain includeSubdomains="true">amazonaws.com</domain>
        <domain includeSubdomains="true">f-droid.org</domain>
        <domain includeSubdomains="true">github.com</domain>
    </domain-config>
</network-security-config>
```

Разберём его по частям — это ключ ко всему уроку.

## Шаг 1: что такое Network Security Config

**Network Security Config (NSC)** — это настройка TLS и сетевого поведения приложения, заданная в XML. Android применяет её ко всем соединениям приложения. В ней описано:

- каким **доверенным сертификатам** (trust anchors) приложение верит;
- разрешён ли **cleartext** (незашифрованный HTTP);
- включён ли **Certificate Transparency**;
- можно ли задать **pin** (config-level pinning).

Если NSC нет, действуют настройки по умолчанию: на Android 7+ доверяются только системные CA, cleartext запрещён на новых версиях.

## Шаг 2: читаем base-config и trust-anchors

Верхний блок `<base-config>` задаёт поведение по умолчанию. Главное для нас:

```xml
<trust-anchors>
    <certificates src="system" />
    <certificates src="user" />
</trust-anchors>
```

`src="user"` означает: приложение **доверяет пользовательским сертификатам**. Это то, что нужно тестировщику — достаточно установить CA прокси как пользовательский, и перехват заработает **без root**. Помните, что на Android 7+ это не по умолчанию, а именно потому, что разработчик явно разрешил.

Если бы здесь было только `<certificates src="system" />`, пользовательский CA игнорировался бы, и понадобился бы системный (root) или обход.

## Шаг 3: cleartext-политика

Атрибут `cleartextTrafficPermitted` решает, разрешён ли незашифрованный трафик:

- `true` — приложение может ходить по `http://`;
- `false` — только HTTPS.

В нашем файле `base-config` разрешает cleartext (`true`), а для конкретных доменов (`amazonaws.com`, `f-droid.org`, `github.com`) — запрещает. То есть по умолчанию приложение допускает HTTP, но к важным доменам — только HTTPS.

Для тестировщика `cleartextTrafficPermitted="true"` — это находка: незашифрованный трафик можно читать и менять без всякого MITM-сертификата.

## Шаг 4: domain-config и исключения

Блок `<domain-config>` переопределяет настройки для конкретных доменов. В примере:

- `onion` — cleartext разрешён (Tor-адреса работают по HTTP);
- `amazonaws.com`, `f-droid.org`, `github.com` — cleartext запрещён, CT включён.

Так разработчики точечно ослабляют или усиливают политику. Читая NSC, ищите домены с **ослабленными** настройками — они и есть точки интереса.

## Шаг 5: config-level pinning

В NSC можно задать **pin** — ожидаемый хэш открытого ключа:

```xml
<domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set expiration="2027-01-01">
        <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
    </pin-set>
</domain-config>
```

Если такой блок есть, приложение проверяет ключ сервера по хэшу — и обычный прокси с любым CA не поможет. Обход — тот же, что для пиннинга: хук проверки, патч NSC или удаление `pin-set` из ресурсов и переупаковка.

## Шаг 6: обход и что искать

Алгоритм работы с NSC:

1. **Извлеките файл** (`apktool`) и прочитайте `trust-anchors`.
2. **Проверьте `src="user"`** — если есть, хватит пользовательского CA.
3. **Посмотрите `cleartextTrafficPermitted`** — где разрешён HTTP, там перехват тривиален.
4. **Ищите `pin-set`** — это config-level pinning, требующий обхода.
5. **Если доверие только системное** — нужен root/системный CA или патч NSC.

Патч NSC — простой путь: убрать `pin-set`, добавить `src="user"`, пересобрать APK и подписать. Минус — проверка подписи (см. `mobile-integrity`).

## Шаг 7: Certificate Transparency

В нашем файле есть атрибут `certificateTransparency`. Это механизм, при котором выпущенные сертификаты публикуются в открытых логах, и клиент может проверить, что сертификат сервера там зарегистрирован. Для тестировщика важно другое: CT добавляет ещё одну проверку, из-за которой сертификат прокси (не зарегистрированный в логах) может быть отвергнут.

В примере для важных доменов CT включён (`enabled="true"`), а для `onion` — выключен. Если приложение включает CT, самодельный сертификат прокси не пройдёт, даже если CA доверенный. В таких случаях помогает хук, отключающий проверку CT, или работа с уже зарегистрированным сертификатом.

## Шаг 8: как проверить NSC в рантайме

Иногда NSC в ресурсах не виден (обфускация, динамическая подстановка). Тогда конфигурацию смотрят в работающем приложении: перехватывают создание сетевого стека и выводят активную политику. Практически достаточно понять три вещи:

- доверяются ли пользовательские CA;
- разрешён ли cleartext;
- есть ли активный pin-set.

Если в ресурсах ничего не нашлось, а трафик всё равно не перехватывается — смотрите на нативный TLS-стек: пиннинг может быть реализован не через NSC, а в `.so`.

Полезно также понимать приоритет: `domain-config` перекрывает `base-config` для указанного домена. Поэтому приложение может разрешать cleartext везде, кроме конкретных адресов, — и наоборот. Читая файл, всегда ищите наиболее специфичное правило для интересующего домена, а не только верхний блок.

Ещё одна деталь — `<debug-overrides>`. Этот блок позволяет доверять пользовательским CA **только в отладочной сборке**. В релизе он не действует. Если приложение собрано в debug-режиме (проверьте `android:debuggable`), такой блок даёт лёгкий перехват без root. Полезно проверить и флаг `debuggable` в манифесте — отладочная сборка вообще многое упрощает при анализе.

## Шаг 9: разбираем NSC скриптом

NSC — это XML, и его удобно разбирать программно, а не глазами:

```
$ python3 -c "import xml.etree.ElementTree as ET; r=ET.parse('network_security_config.xml').getroot(); b=r.find('base-config'); print('base cleartext =', b.get('cleartextTrafficPermitted')); print('debug-overrides =', r.find('debug-overrides') is not None)"
base cleartext = false
debug-overrides = True
```

`base cleartext = false` — хороший знак: по умолчанию HTTP запрещён. А `debug-overrides = True` — важная находка: блок `<debug-overrides>` разрешает доверять пользовательским CA, но **только** в debug-сборке. Если приложение собрано в debug (или проверка `android:debuggable` слабая), этот блок открывает путь для MITM без установки системного CA. Всегда проверяй наличие `debug-overrides` и `cleartextTrafficPermitted` на доменах-исключениях.

## Что мы теперь знаем

По-простому:

1. NSC задаёт доверие к сертификатам, политику cleartext и пины для доменов.
2. `<certificates src="user" />` разрешает пользовательский CA — перехват без root.
3. `cleartextTrafficPermitted="true"` допускает HTTP — данные читаемы без MITM.
4. `pin-set` — config-level pinning, обходится хуком или патчем.
5. Без `src="user"` нужен системный CA или патч NSC.

## На что смотреть дальше

- **NSC — первое, что читают.** Он сразу говорит, возможен ли лёгкий перехват.
- **Ищите `src="user"`.** Это самая частая «поблажка» разработчика.
- **`cleartext=true` — находка.** Незашифрованные данные не нуждаются в обходе.
- **`pin-set` — препятствие.** Готовьтесь к обходу пиннинга.

## Справочная таблица: атрибуты NSC и их обход

Network Security Config читается по атрибутам. Сведём, что означает каждый и как его обойти:

| Атрибут / блок | Значение | Обход для MITM |
|----------------|----------|----------------|
| `trust-anchors src="user"` | доверие пользовательским CA | ничего не нужно — ставим CA |
| `trust-anchors src="system"` | только системные CA | root/системный CA или патч NSC |
| `cleartextTrafficPermitted="true"` | разрешён HTTP | читаем трафик без сертификата |
| `<pin-set>` | config-level pinning | хук проверки или удаление `pin-set` |
| `certificateTransparency enabled="true"` | проверка CT | хук CT или сертификат из логов |
| `<debug-overrides>` | доверие user CA в debug | нужна debug-сборка |

Приоритет: `domain-config` перекрывает `base-config` для своего домена. Всегда ищите самое специфичное правило для интересующего домена, а не только верхний блок.

## Патч NSC: пошагово

Самый прямой обход — изменить NSC и пересобрать APK. Алгоритм:

1. Декодировать: `apktool d app.apk -o dec`.
2. Открыть `dec/res/xml/network_security_config.xml`, добавить `<certificates src="user"/>` в `trust-anchors` и удалить блоки `<pin-set>`.
3. Пересобрать: `apktool b dec -o app_patched.apk`.
4. Подписать: `apksigner sign --ks my.keystore app_patched.apk`.
5. Установить: `adb install -r app_patched.apk`.

После этого пользовательский CA прокси принимается, и перехват работает без root. Минус — проверка подписи: если приложение сверяет подпись с оригинальной, патч не запустится (см. `mobile-integrity`). Тогда NSC правят в рантайме хуком, а не в файле.

## Ограничения метода

NSC описывает только сетевой стек Java/OkHttp. Если пиннинг реализован в нативном коде (`.so`), патч XML его не снимет — ищите проверки в библиотеке или хукайте нативные функции. Отсутствие NSC не означает отсутствие защиты: на Android 7+ по умолчанию доверяются только системные CA, а cleartext запрещён, поэтому «нет файла» — это строгие настройки, а не открытость. Не путайте `debug-overrides` с рабочей конфигурацией: он действует только в debug-сборке, и в релизе перехват через него невозможен. И помните про Certificate Transparency: даже с доверенным CA самодельный сертификат может быть отвергнут, если CT включён и проверка настоящая. Наконец, если в ресурсах NSC не виден (обфускация, динамическая подстановка), проверяйте активную политику в рантайме, а не делайте вывод по отсутствию файла.

## Квиз

Проверь себя.

```quiz
- question: "Что означает certificates src='user' в Network Security Config?"
  options:
    - "Приложение доверяет пользовательским CA — перехват без root"
    - "Приложение запрещает TLS"
    - "Приложение работает только офлайн"
    - "Приложение использует QUIC"
  answer: 0
- question: "Что задаёт атрибут cleartextTrafficPermitted='true'?"
  options:
    - "Разрешает незашифрованный HTTP-трафик"
    - "Включает VPN"
    - "Отключает сертификаты"
    - "Ускоряет сеть"
  answer: 0
- question: "Где в APK лежит Network Security Config?"
  options:
    - "res/xml/network_security_config.xml"
    - "assets/config.json"
    - "lib/<abi>/nsc.so"
    - "classes.dex"
  answer: 0
- question: "Что задаёт блок pin-set в NSC?"
  options:
    - "Ожидаемый хэш открытого ключа (config-level pinning)"
    - "Список Wi-Fi сетей"
    - "Версию Android"
    - "Разрешения приложения"
  answer: 0
- question: "Почему на Android 7+ пользовательский CA обычно не работает?"
  options:
    - "Приложения по умолчанию доверяют только системным CA"
    - "Пользовательские CA запрещены"
    - "Нужен iOS"
    - "CA нельзя установить"
  answer: 0
```

## Куда дальше

Мы разобрали, как приложение управляет доверием к сертификатам. В следующем уроке разберём обход другого типа защиты — детекта эмулятора. А пока главное: Network Security Config — это «паспорт доверия» приложения, и чтение этого файла сразу показывает, возможен ли лёгкий перехват или придётся обходить пиннинг.

## Где пригодится

- **Пентест Android:** быстрая оценка возможности перехвата трафика.
- **Bug bounty:** поиск доменов с ослабленной политикой.
- **Анализ трафика:** понимание, почему прокси работает или нет.
- **Работа:** рекомендации разработчикам по настройке TLS.
