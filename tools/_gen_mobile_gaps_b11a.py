#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MOB-GAP-11a: Binder / bound-service deep batch.

New module hub:
  * mobile-android-ipc-binder — bound services, AIDL, Messenger (parent mobile-android-ipc-runtime)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _gen_mobile_gaps_b10lib import write_lesson, quiz, lab, seed_dir, task_md, seed  # noqa: E402


def mk(m, body, lab_bundle):
    path = os.path.join('content', 'mobile', m['id'] + '.md')
    if os.path.exists(path):
        print('skip (exists):', m['id'])
        return
    write_lesson(m, body, lab=lab_bundle)
    print('wrote:', m['id'])


# ============================================================ hub: ipc-binder
m = dict(
    id='mobile-android-ipc-binder',
    title='Модуль: Binder и bound-сервисы Android',
    category='mobile', parent='mobile-android-ipc-runtime', difficulty='hard', order=6,
    tags=['android', 'binder', 'service', 'aidl', 'messenger', 'ipc', 'module'],
    prerequisites=['mobile-android-ipc-deep'],
    useful_for=['Пентест Android-приложений', 'Аудит IPC', 'CTF Mobile'],
    estimated_minutes=14,
    summary='Навигационный модуль: как Android-приложения общаются через Binder — bound-сервисы, AIDL и Messenger — и где в этом канале появляется дыра.',
)
body = '''## Зачем вообще лезть в Binder

До этого мы смотрели на IPC «снаружи»: интенты, экспортированные Activity, перехват
deep-link. Но у Android есть второй, более низкий слой общения между приложениями —
**Binder**. Через него система отдаёт приложению почти всё: доступ к камере, к
геолокации, к контактам. И если приложение выставляет наружу свой собственный
bound-сервис без проверки прав, через Binder его можно дёрнуть напрямую — в обход
интерфейса, в обход валидации на экране.

Этот модуль — про три способа описать такой канал и про то, как каждый из них ломают.

## Что покрывает модуль

1. **Bound-сервисы** — сервис, к которому клиент *подключается* и вызывает методы,
   а не просто запускает. Разбираем, что такое Binder-мост и почему экспортированный
   bound-сервис без разрешения — это открытая дверь.
2. **AIDL** — язык описания интерфейса, из которого Android генерирует код
   маршалинга. Смотрим контракт, `Parcel`, и как подделанный вызов обходит проверки.
3. **Messenger** — обмен сообщениями через `Handler` вместо прямых вызовов. Разбираем
   подделку и повтор сообщений.

## Почему такой порядок

Сначала — базовая механика (как клиент находит сервис и вызывает метод), потом —
формальный контракт (AIDL), потом — асинхронный вариант (Messenger). Так новичок
видит одну и ту же идею «вызов через границу процесса» в трёх обличиях.

## Как проходить

Держи под рукой реальное APK с экспортированным сервисом. Каждый урок — это разбор
одного объекта от манифеста до вызова метода. Проверяй вывод команд на своём образце.

## Квиз

Проверь себя.

```quiz
- question: Что делает клиент с bound-сервисом?
  options:
    - Запускает его и уходит
    - Подключается через bindService и вызывает методы
    - Перезагружает устройство
    - Отправляет SMS
  answer: 1
  explanation: Bound-сервис живёт, пока к нему подключён хотя бы один клиент, и отдаёт интерфейс вызовов.
- question: Что такое Binder?
  options:
    - Формат картинок
    - Механизм IPC в ядре Android для вызовов между процессами
    - База данных
    - Компилятор Java
  answer: 1
  explanation: Binder — драйвер и протокол, через который процессы вызывают методы друг друга.
- question: Где искать экспортированный сервис?
  options:
    - В strings.xml
    - В AndroidManifest.xml, атрибут android:exported
    - В build.gradle
    - В proguard-rules
  answer: 1
  explanation: Доступность компонента снаружи задаётся атрибутом android:exported в манифесте.
```

## Куда дальше

В следующем уроке мы возьмём конкретный bound-сервис из манифеста и вызовем его метод
из собственного приложения. А пока главное запомни: **bound-сервис без permission —
это Binder-метод, доступный любому процессу на устройстве**.

## Где пригодится

- **Пентест:** Android, аудит IPC
- **CTF:** Mobile
- **Работа:** AppSec, ревью экспортированных компонентов
'''
lab_bundle = lab(
    'Практика: найди экспортированный bound-сервис',
    ['task.md', 'decoded/AndroidManifest.xml'],
    ['`decoded/AndroidManifest.xml` — распакованный манифест приложения.',
     'Ищи `<service>` с `android:exported="true"`.',
     'У открытого сервиса в `meta-data` лежит секрет — найди `nto{` и запиши в `found.txt`.'],
    'nto{b0und_s3rv1c3_exp0rt3d_n0_p3rm}',
    [seed_dir(), task_md(
        '# Задача: аудит bound-сервиса\n\n'
        '## Повторение (mobile-android-ipc-deep)\n\n'
        'Сначала осмотри артефакт: `ls -la` и `head decoded/AndroidManifest.xml`.\n\n'
        'Найди экспортированный `<service>`, посмотри его `meta-data` и выпиши секрет.\n'
        'Запиши флаг в `found.txt` и набери `check`.\n'),
     seed('decoded/AndroidManifest.xml',
          '<manifest package="com.example.bank">\n'
          '  <application>\n'
          '    <service android:name=".SyncService" android:exported="true">\n'
          '      <intent-filter><action android:name="com.example.bank.SYNC"/></intent-filter>\n'
          '      <meta-data android:name="debug.secret" android:value="nto{b0und_s3rv1c3_exp0rt3d_n0_p3rm}"/>\n'
          '    </service>\n'
          '    <service android:name=".Internal" android:exported="false"/>\n'
          '  </application>\n'
          '</manifest>\n')],
)
mk(m, body, lab_bundle)


# ============================================================ bound-service
m = dict(
    id='mobile-android-bound-service',
    title='Bound-сервисы Android: Binder-мост и его эксплуатация',
    category='mobile', parent='mobile-android-ipc-binder', difficulty='hard', order=1,
    tags=['android', 'binder', 'service', 'bound', 'exported', 'ipc'],
    prerequisites=['mobile-service-hijacking'],
    useful_for=['Пентест Android-приложений', 'Аудит IPC', 'CTF Mobile'],
    estimated_minutes=44,
    summary='Как найти экспортированный bound-сервис, понять его Binder-интерфейс и вызвать его методы из чужого приложения — в обход UI.',
)
body = '''## Вопрос, с которого всё начинается

Банковское приложение показывает баланс только после входа по отпечатку. Но в его
манифесте есть сервис с `android:exported="true"`, который называется `BalanceService`.
Логичный вопрос: **может ли другое приложение на том же телефоне просто вызвать его
метод `getBalance()` — минуя экран входа?**

Чтобы ответить, нужно понять, что такое bound-сервис и как через него вообще ходят
вызовы. Этим и займёмся.

## Наш пример: BalanceService из банковского приложения

У нас есть APK `bank.apk`. Сначала распакуем манифест и посмотрим на объявления
сервисов.

```bash
$ apktool d bank.apk -o bank
I: Copying assets and libs...
$ grep -A3 '<service' bank/AndroidManifest.xml
<service android:name=".BalanceService" android:exported="true">
    <intent-filter>
        <action android:name="com.example.bank.BALANCE"/>
    </intent-filter>
</service>
```

Мы видим сервис с флагом `android:exported="true"`. Это значит: система разрешает
**другим приложениям** обращаться к нему. Само по себе это не баг — так работают
плагины и SDK. Баг появится, если внутри нет проверки, кто именно обращается.

## Шаг 1: чем bound-сервис отличается от started

Есть два вида сервисов, и разница принципиальна.

* **Started** — его запускают командой `startService`, и он работает сам по себе, пока
  его не остановят. Клиент ему не нужен.
* **Bound** — клиент вызывает `bindService`, получает объект-мост и **вызывает методы**
  сервиса как обычные функции. Пока есть хотя бы один клиент, сервис жив.

Именно bound-сервисы дают доступ к коду, поэтому они и интересны: это не «запустил и
забыл», а «получил ручку управления».

## Шаг 2: что такое Binder

**Binder** — это механизм, через который один процесс на Android вызывает метод в
другом. Ядро предоставляет драйвер `/dev/binder`; он копирует данные вызова туда и
обратно, а идентификаторы объектов превращает в числа (дескрипторы).

Клиент никогда не держит указатель на чужой объект — между процессами указатели
бессмысленны. Вместо этого он получает `IBinder` — «ручку». Вызов метода на этой ручке
ядро превращает в сообщение и передаёт процессу-владельцу. Тот выполняет код и
возвращает результат.

Данные для передачи упаковываются в **Parcel** — плоский бинарный буфер. Кто угодно,
кто умеет собрать такой буфер, может отправить сервису произвольный вызов.

## Шаг 3: смотрим, что сервис умеет

Интерфейс bound-сервиса обычно описан в AIDL и попадает в код как абстрактный класс.
Найдём его в декомпилированном APK:

```bash
$ grep -rl "interface IBalance" bank/smali* | head
bank/smali/com/example/bank/IBalance$Stub.smali
$ sed -n '1,20p' bank/smali/com/example/bank/IBalance.smali
.class public interface abstract Lcom/example/bank/IBalance;
.method public abstract getBalance()I
.method public abstract transfer(ILjava/lang/String;)Z
```

Мы видим два метода: `getBalance` и `transfer`. Вот и ручка управления: если её можно
получить снаружи, то и перевод можно инициировать без UI.

## Шаг 4: вызываем чужой сервис

Соберём маленькое приложение-клиент. В нём — тот же AIDL-контракт и код подключения:

```java
Intent i = new Intent();
i.setComponent(new ComponentName("com.example.bank", "com.example.bank.BalanceService"));
bindService(i, conn, BIND_AUTO_CREATE);
// в onServiceConnected:
IBalance svc = IBalance.Stub.asInterface(service);
int bal = svc.getBalance();     // вернул 999999
svc.transfer(100, "attacker");  // вернул true
```

Ключевой момент — `IBalance.Stub.asInterface`. Мы взяли Binder-ручку, которую нам
вернула система, и превратили её в объект с методами. Никакого экрана входа не было:
мы общаемся с сервисом напрямую.

## Шаг 5: почему это вообще сработало

Система пустила нас, потому что сервис экспортирован. Дальше всё решил код сервиса:
если в `onBind` или в каждом методе нет проверки `checkCallingPermission(...)`, то
сервис не отличает наш процесс от собственного UI приложения.

Частая ошибка — проверка «вошёл ли пользователь» живёт в Activity, а сервис про неё
не знает. Приложение считает, что раз экран защищён, то и данные защищены. Но Binder
идёт в обход Activity.

## Что мы теперь знаем

- Bound-сервис отдаёт клиенту **методы**, а не просто «запускается».
- Вызовы идут через Binder и упаковываются в `Parcel`; клиенту нужен только контракт.
- `android:exported="true"` без `permission` открывает сервис любому приложению.
- Защита должна стоять **в самом сервисе** (проверка вызывающего), а не в UI.

## Квиз

Проверь себя.

```quiz
- question: Чем bound-сервис принципиально отличается от started?
  options:
    - Он быстрее
    - Клиент подключается и вызывает его методы
    - Он не может быть экспортирован
    - Он работает только в фоне
  answer: 1
  explanation: Bound-сервис отдаёт клиенту интерфейс вызовов через bindService.
- question: Что передаётся между процессами вместо указателя на объект?
  options:
    - Файл
    - IBinder-ручка и Parcel с данными вызова
    - Сокет TCP
    - SharedPreferences
  answer: 1
  explanation: Между процессами указатели бессмысленны; используется Binder-ручка и Parcel.
- question: Где должна стоять проверка прав вызывающего?
  options:
    - В Activity перед показом экрана
    - В самом сервисе при каждом вызове
    - В манифесте в виде комментария
    - В build.gradle
  answer: 1
  explanation: Binder-вызов идёт в обход Activity, поэтому проверять надо в сервисе.
- question: Что означает android:exported="true" у сервиса?
  options:
    - Он запускается при загрузке
    - К нему могут обращаться другие приложения
    - Он системный
    - Он шифрует данные
  answer: 1
  explanation: Экспортированный компонент доступен снаружи, другим приложениям.
- question: Как из Binder-ручки получить объект с методами?
  options:
    - Через new IBinder()
    - Через IBalance.Stub.asInterface(service)
    - Через Class.forName
    - Через SharedPreferences
  answer: 1
  explanation: Сгенерированный Stub.asInterface оборачивает Binder в прокси-объект контракта.
```

## Куда дальше

Теперь мы знаем, что за ручкой стоят методы. В следующем уроке разберём, откуда берётся
сам контракт — **AIDL** — и как подделанный `Parcel` обходит проверки внутри сервиса.
А пока запомни: **экспортированный bound-сервис без проверки вызывающего — это
удалённый вызов метода для любого приложения на устройстве**.

## Где пригодится

- **Пентест:** Android, аудит межпроцессного взаимодействия
- **CTF:** Mobile
- **Работа:** AppSec, ревью экспортированных компонентов
'''
lab_bundle = lab(
    'Практика: разбери Binder-контракт сервиса',
    ['task.md', 'IBalance.aidl', 'manifest_snippet.txt'],
    ['Сначала осмотри файлы: `ls -la`, `cat IBalance.aidl`.',
     'Найди метод, который двигает деньги.',
     'Рядом с уязвимым методом в логе лежит флаг — запиши его в `found.txt`.'],
    'nto{b1nd3r_tr4nsf3r_w1th0ut_p3rm}',
    [seed_dir(), task_md(
        '# Задача: аудит Binder-контракта\n\n'
        '## Повторение (mobile-android-ipc-deep)\n\n'
        'Осмотри артефакты: `ls -la`, затем `cat IBalance.aidl` и `head manifest_snippet.txt`.\n\n'
        'Определи, какой метод опасен без проверки прав, и найди рядом флаг.\n'
        'Запиши флаг в `found.txt` и набери `check`.\n'),
     seed('IBalance.aidl',
          'package com.example.bank;\n\n'
          'interface IBalance {\n'
          '    int getBalance();\n'
          '    boolean transfer(int amount, String to);\n'
          '}\n'),
     seed('manifest_snippet.txt',
          '<service android:name=".BalanceService" android:exported="true"/>\n'
          '# audit note: transfer() has no checkCallingPermission ->\n'
          '# nto{b1nd3r_tr4nsf3r_w1th0ut_p3rm}\n')],
)
mk(m, body, lab_bundle)


# ============================================================ aidl
m = dict(
    id='mobile-android-aidl',
    title='AIDL-интерфейсы Android: контракт, Parcel и подделка вызова',
    category='mobile', parent='mobile-android-ipc-binder', difficulty='hard', order=2,
    tags=['android', 'aidl', 'parcel', 'binder', 'marshalling', 'ipc'],
    prerequisites=['mobile-android-bound-service'],
    useful_for=['Пентест Android-приложений', 'Аудит IPC', 'CTF Mobile'],
    estimated_minutes=42,
    summary='Что генерирует AIDL, как данные превращаются в Parcel и как подделанный вызов обходит проверки на стороне сервиса.',
)
body = '''## Вопрос, с которого всё начинается

В прошлом уроке мы вызвали `transfer()` на чужом сервисе. Но откуда клиент знает, в
каком порядке упаковать аргументы и как их прочитать? Ответ — **AIDL**. И тут же
возникает вопрос посложнее: если данные вызова собирает сам клиент, **можно ли собрать
их так, чтобы сервис повёл себя неожиданно?**

## Наш пример: интерфейс из двух методов

Вернёмся к `IBalance`. Разработчик описал его так:

```java
// IBalance.aidl
package com.example.bank;

interface IBalance {
    int getBalance();
    boolean transfer(int amount, String to);
}
```

Это обычное текстовое описание. Никакого кода тут нет — только контракт: имена методов
и типы аргументов. Сборка превращает его в настоящий код.

## Шаг 1: что AIDL генерирует

Компилятор AIDL создаёт файл `IBalance.java` с двумя вложенными классами: `Stub`
(сторона сервиса) и `Proxy` (сторона клиента).

```java
public interface IBalance extends android.os.IInterface {
  public static abstract class Stub extends Binder implements IBalance { ... }
  private static class Proxy implements IBalance {
    public int getBalance() {
      Parcel _data = Parcel.obtain();
      Parcel _reply = Parcel.obtain();
      _data.writeInterfaceToken(DESCRIPTOR);
      mRemote.transact(TRANSACTION_getBalance, _data, _reply, 0);
      int _result = _reply.readInt();
      return _result;
    }
  }
}
```

Видно главное: клиент сам упаковывает аргументы в `Parcel` (`_data`), вызывает
`transact` с номером метода и читает ответ из `_reply`. Контракт — это просто
договорённость о формате буфера.

## Шаг 2: как устроен Parcel

**Parcel** — плоский буфер байт. У него нет схемы: значения пишутся подряд, в том
порядке, в каком их пишет код. `writeInt` кладёт 4 байта, `writeString` — длину и
байты строки. Читающая сторона обязана читать в **точно том же порядке**.

Отсюда два свойства, важных для атаки:

* если клиент прочитал на один `int` меньше — все следующие значения «съедут»;
* `writeInterfaceToken` кладёт имя интерфейса; сервис проверяет его в `onTransact`.

## Шаг 3: сторона сервиса — onTransact

Когда вызов приходит, Binder вызывает `onTransact(code, data, reply, flags)`. Код,
сгенерированный из AIDL, выглядит так:

```java
@Override
public boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
  switch (code) {
    case TRANSACTION_getBalance: {
      data.enforceInterface(DESCRIPTOR);
      int _result = this.getBalance();
      reply.writeInt(_result);
      return true;
    }
    case TRANSACTION_transfer: {
      data.enforceInterface(DESCRIPTOR);
      int amount = data.readInt();
      String to = data.readString();
      boolean _result = this.transfer(amount, to);
      reply.writeBoolean(_result);
      return true;
    }
  }
}
```

`enforceInterface` — та самая проверка имени интерфейса. Она защищает от вызова метода
«не того» интерфейса, но **не проверяет, кто вызывает**. Поэтому любой процесс,
знающий номер транзакции и формат, может отправить свой `Parcel`.

## Шаг 4: собираем вызов вручную

Не будем писать клиент на Java — отправим вызов прямо через `service call`. Это
системная команда, которая сама формирует `transact`:

```bash
$ adb shell service list | grep bank
7   com.example.bank.balance: [com.example.bank.IBalance]
$ adb shell service call com.example.bank.balance 1 i32 100 s16 attacker
Result: Parcel(00000000 00000001   '........')
```

Первый аргумент после имени сервиса — номер транзакции (`1` = `transfer`), дальше —
аргументы в формате `i32`/`s16`. Мы только что инициировали перевод, не имея кода
приложения вообще.

## Шаг 5: подделка типа (type confusion)

Теперь тонкий момент. В `onTransact` для `transfer` ожидается `int`, затем `String`.
Что, если отправить не `int`, а, скажем, число со знаком минус?

```bash
$ adb shell service call com.example.bank.balance 1 i32 -1 s16 attacker
Result: Parcel(00000000 00000001   '........')
```

Отрицательная сумма может означать «списать» вместо «зачислить» — зависит от того, как
написан сервис. Схема буфера не защищает от семантики: AIDL гарантирует порядок байт,
но не то, что значения осмысленны. Проверка диапазона — обязанность сервиса, и её
часто забывают, потому что «UI и так не даёт ввести минус».

## Что мы теперь знаем

- AIDL — это контракт; из него генерируются `Stub` (сервис) и `Proxy` (клиент).
- Данные идут через `Parcel` — плоский буфер без схемы; порядок чтения критичен.
- `enforceInterface` проверяет имя интерфейса, но не личность вызывающего.
- `service call` позволяет собрать вызов руками, без кода приложения.
- Валидация значений (диапазоны, знаки) — на стороне сервиса, не в UI.

## Квиз

Проверь себя.

```quiz
- question: Что описывает файл .aidl?
  options:
    - Реализацию методов
    - Контракт интерфейса: имена методов и типы аргументов
    - Разрешения приложения
    - Список Activity
  answer: 1
  explanation: AIDL — только контракт; код генерируется компилятором.
- question: Что такое Parcel?
  options:
    - Схема базы данных
    - Плоский бинарный буфер без схемы
    - Формат картинок
    - Сетевой пакет
  answer: 1
  explanation: Parcel хранит значения подряд, без описания структуры.
- question: Что проверяет enforceInterface?
  options:
    - Пароль пользователя
    - Имя интерфейса в буфере
    - Размер файла
    - Уровень заряда
  answer: 1
  explanation: Это проверка interface token, а не личности вызывающего.
- question: Чем опасна подделка типа (type confusion)?
  options:
    - Замедляет приложение
    - Значения могут обойти проверки, рассчитанные на UI
    - Ломает экран
    - Меняет иконку
  answer: 1
  explanation: Схема не гарантирует осмысленность; валидация должна быть в сервисе.
- question: Какая команда собирает Binder-вызов вручную?
  options:
    - adb shell am start
    - adb shell service call
    - adb shell pm list
    - adb shell input tap
  answer: 1
  explanation: service call формирует transact с указанными аргументами.
```

## Куда дальше

Мы научились собирать синхронный вызов вручную. В следующем уроке разберём
**Messenger** — асинхронный Binder, где вместо методов ходят `Message`, и увидим, чем
опасны подделка и повтор сообщений. А пока запомни: **AIDL задаёт формат, но не
доверие — доверие должен обеспечить код сервиса**.

## Где пригодится

- **Пентест:** Android, аудит Binder-интерфейсов
- **CTF:** Mobile
- **Работа:** AppSec, ревью AIDL-контрактов
'''
lab_bundle = lab(
    'Практика: разбери Parcel-контракт',
    ['task.md', 'IBalance.aidl', 'onTransact.txt'],
    ['Осмотри файлы: `ls -la`, `cat onTransact.txt`.',
     'Сопоставь номер транзакции с методом и его аргументами.',
     'Найди флаг рядом с описанием подделанного вызова.'],
    'nto{4idl_p4rcel_c0nfus10n}',
    [seed_dir(), task_md(
        '# Задача: подделка AIDL-вызова\n\n'
        '## Повторение (mobile-android-bound-service)\n\n'
        'Осмотри артефакты: `ls -la` и `cat onTransact.txt`.\n\n'
        'Определи, какой номер транзакции отвечает за `transfer`, и какой аргумент\n'
        'можно подделать. Рядом в комментарии лежит флаг — запиши в `found.txt`.\n'),
     seed('IBalance.aidl',
          'package com.example.bank;\n\n'
          'interface IBalance {\n'
          '    int getBalance();\n'
          '    boolean transfer(int amount, String to);\n'
          '}\n'),
     seed('onTransact.txt',
          'case 0: getBalance()\n'
          'case 1: amount=data.readInt(); to=data.readString(); transfer(amount,to)\n'
          '# negative amount bypasses UI check ->\n'
          '# nto{4idl_p4rcel_c0nfus10n}\n')],
)
mk(m, body, lab_bundle)


# ============================================================ messenger-ipc
m = dict(
    id='mobile-android-messenger-ipc',
    title='Messenger/Binder-обмен в Android: подделка и повтор сообщений',
    category='mobile', parent='mobile-android-ipc-binder', difficulty='hard', order=3,
    tags=['android', 'messenger', 'handler', 'message', 'binder', 'replay'],
    prerequisites=['mobile-android-aidl'],
    useful_for=['Пентест Android-приложений', 'Аудит IPC', 'CTF Mobile'],
    estimated_minutes=40,
    summary='Как сервис общается с клиентом через Messenger и Handler, и почему подделка или повтор Message может обойти логику приложения.',
)
body = '''## Вопрос, с которого всё начинается

Иногда сервису неудобно отдавать методы напрямую: он хочет общаться **сообщениями** —
асинхронно, как в очереди. Для этого в Android есть `Messenger`. Но если сообщения
может послать любой клиент, то **что мешает послать чужое сообщение или повторить
уже отправленное?** Разберёмся на живом примере.

## Наш пример: сервис синхронизации с Messenger

Приложение держит `SyncService`, который принимает команды через `Messenger`. В
декомпилированном коде видим:

```java
public class SyncService extends Service {
  static final int MSG_SYNC = 1;
  static final int MSG_SET_TOKEN = 2;

  class IncomingHandler extends Handler {
    public void handleMessage(Message msg) {
      switch (msg.what) {
        case MSG_SET_TOKEN:
          token = msg.getData().getString("token");
          break;
        case MSG_SYNC:
          doSync();
          break;
      }
    }
  }
  Messenger messenger = new Messenger(new IncomingHandler());
  public IBinder onBind(Intent i) { return messenger.getBinder(); }
}
```

Сервис принимает два вида сообщений: установку токена и запуск синхронизации. Метода
`onBind` возвращает `messenger.getBinder()` — то есть наружу отдаётся Binder для
отправки сообщений.

## Шаг 1: что такое Message и Messenger

**Message** — это контейнер: поле `what` (номер команды), `arg1`/`arg2` (числа) и
`Bundle data` (произвольные значения). **Messenger** — обёртка над Binder, которая
превращает `send(Message)` в Binder-транзакцию, а на той стороне — в вызов
`Handler.handleMessage`.

Получается мост: клиент шлёт `Message` → Binder → `Handler` сервиса разбирает его в
`switch`. Никаких AIDL-методов вручную писать не нужно — весь маршалинг делает
система.

## Шаг 2: клиент и его conn

Клиент подключается так же, как к любому bound-сервису:

```java
ServiceConnection conn = new ServiceConnection() {
  public void onServiceConnected(ComponentName c, IBinder b) {
    Messenger svc = new Messenger(b);
    Message m = Message.obtain(null, SyncService.MSG_SET_TOKEN);
    Bundle d = new Bundle();
    d.putString("token", "attacker-token");
    m.setData(d);
    try { svc.send(m); } catch (RemoteException e) {}
  }
  public void onServiceDisconnected(ComponentName c) {}
};
```

Мы создали `Message`, положили в `Bundle` свой токен и отправили. Сервис его примет и
запишет как свой. Если у него нет проверки, кто прислал сообщение, — токен подменён.

## Шаг 3: почему это проходит

Обрати внимание: `MSG_SET_TOKEN` меняет состояние сервиса. В коде `handleMessage` нет
ни одной проверки вызывающего — ни `checkCallingPermission`, ни `Binder.getCallingUid`.
Сервис считает, что раз он экспортирован «для своего приложения», то и сообщения
приходят только от него.

Но Binder не различает «своих» и «чужих»: раз `onBind` вернул Binder, его получит
любой клиент, который смог подключиться.

## Шаг 4: повтор сообщения (replay)

Даже если сервис проверяет токен, у Messenger есть вторая слабость — **повтор**. В
сообщении нет встроенного счётчика или nonce. Поэтому перехваченное (или ранее
записанное) сообщение можно отправить ещё раз:

```java
// отправили MSG_SYNC сто раз
for (int i = 0; i < 100; i++) svc.send(Message.obtain(null, SyncService.MSG_SYNC));
```

Если синхронизация запускает операцию со побочным эффектом (списание, отправка), её
повтор — уже атака. Защита здесь та же, что в сетевых протоколах: одноразовое значение
в `Bundle`, которое сервис проверяет и «гасит» после использования.

## Шаг 5: как искать такое в реальном APK

Маркеры Messenger-сервиса ищутся по коду:

```bash
$ grep -rn "new Messenger" bank/smali* | head
bank/smali/com/example/bank/SyncService.smali
$ grep -n "getCallingUid\\|checkCalling" bank/smali/com/example/bank/SyncService.smali
(пусто)
```

Пустой второй grep — тревожный знак: сервис не проверяет вызывающего. Дальше смотрим,
какие `MSG_*` меняют состояние, и пробуем их отправить.

## Что мы теперь знаем

- `Messenger` превращает `send(Message)` в Binder-вызов `Handler.handleMessage`.
- Поле `what` — номер команды; `Bundle` несёт произвольные данные.
- Если `handleMessage` не проверяет вызывающего, состояние сервиса можно подменить.
- В сообщении нет счётчика, поэтому replay — отдельный вектор.
- Ищем `new Messenger` и отсутствие `checkCallingPermission` в декомпилированном коде.

## Квиз

Проверь себя.

```quiz
- question: Что делает Messenger.send(Message)?
  options:
    - Пишет в лог
    - Отправляет Binder-транзакцию, превращающуюся в handleMessage
    - Открывает Activity
    - Читает файл
  answer: 1
  explanation: Messenger — обёртка над Binder: сообщение доходит до Handler получателя.
- question: Где живёт номер команды в Message?
  options:
    - В поле what
    - В Bundle
    - В arg1
    - В replyTo
  answer: 0
  explanation: what — целочисленный код команды, по нему идёт switch.
- question: Почему подделка сообщения возможна?
  options:
    - Messenger медленный
    - Сервис не проверяет вызывающего
    - Binder шифруется
    - Bundle сжат
  answer: 1
  explanation: Если нет checkCallingUid/Permission, любой подключившийся клиент шлёт свои сообщения.
- question: Чем опасен replay в Messenger?
  options:
    - Расходует батарею
    - Повторяет побочный эффект команды
    - Ломает Binder
    - Меняет тему
  answer: 1
  explanation: Без nonce/счётчика перехваченное сообщение можно воспроизвести повторно.
- question: Что искать в декомпилированном коде?
  options:
    - new Messenger и отсутствие проверки вызывающего
    - Только строки
    - Иконки
    - Размер APK
  answer: 0
  explanation: Messenger + пустой grep по checkCalling — типичный признак незащищённого IPC.
```

## Куда дальше

Мы закрыли Binder-триаду: bound-сервис, AIDL, Messenger. Дальше логично вернуться к
поверхностям данных и посмотреть, что ещё приложение отдаёт наружу — `ContentProvider`
и гранты URI. А пока запомни: **Messenger — это те же Binder-вызовы; если в
`handleMessage` нет проверки вызывающего, состояние сервиса принадлежит атакующему**.

## Где пригодится

- **Пентест:** Android, аудит IPC
- **CTF:** Mobile
- **Работа:** AppSec, ревью сервисов
'''
lab_bundle = lab(
    'Практика: аудит Messenger-обработчика',
    ['task.md', 'SyncService.txt'],
    ['Осмотри файл: `ls -la`, затем `cat SyncService.txt`.',
     'Найди команду, которая меняет состояние без проверки вызывающего.',
     'Рядом с ней в логе лежит флаг — запиши его в `found.txt`.'],
    'nto{m3ss3ng3r_n0_c4ll3r_ch3ck}',
    [seed_dir(), task_md(
        '# Задача: аудит Messenger-сервиса\n\n'
        '## Повторение (mobile-android-aidl)\n\n'
        'Осмотри артефакт: `ls -la` и `cat SyncService.txt`.\n\n'
        'Найди сообщение, меняющее токен без проверки вызывающего, и флаг рядом с ним.\n'
        'Запиши флаг в `found.txt` и набери `check`.\n'),
     seed('SyncService.txt',
          'MSG_SYNC=1      -> doSync()\n'
          'MSG_SET_TOKEN=2 -> token = msg.getData().getString("token")\n'
          'handleMessage: no Binder.getCallingUid() check\n'
          'audit: any bound client can set token -> nto{m3ss3ng3r_n0_c4ll3r_ch3ck}\n')],
)
mk(m, body, lab_bundle)

print('ipc-binder batch done')
