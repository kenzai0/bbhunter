"""
Yerlesik template'ler (non-destructive tespit imzalari).

Hepsi yalnizca "acik mi / sizmis mi" kontrolu yapar; somurme icermez.
Harici JSON template'ler ayni formatta --templates ile eklenebilir.
"""

from __future__ import annotations

BUILTIN_TEMPLATES: list[dict] = [
    {
        "id": "exposed-git-config",
        "name": "Acik .git/config dosyasi",
        "severity": "high",
        "reference": ["https://owasp.org/www-community/attacks/Source_code_disclosure"],
        "requests": [{
            "method": "GET", "path": "/.git/config",
            "matchers_condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "word", "part": "body",
                 "words": ["[core]", "repositoryformatversion"], "condition": "or"},
            ],
        }],
    },
    {
        "id": "exposed-env-file",
        "name": "Acik .env ortam dosyasi",
        "severity": "high",
        "requests": [{
            "method": "GET", "path": "/.env",
            "matchers_condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "regex", "part": "body",
                 "patterns": ["(?m)^[A-Z0-9_]+=", "APP_KEY=", "DB_PASSWORD=", "SECRET"],
                 "condition": "or"},
                {"type": "word", "part": "header", "words": ["text/html"], "negative": True},
            ],
        }],
    },
    {
        "id": "ds-store-exposed",
        "name": "Acik .DS_Store dosyasi",
        "severity": "low",
        "requests": [{
            "method": "GET", "path": "/.DS_Store",
            "matchers_condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "regex", "part": "body", "pattern": "Bud1|\\x00\\x00\\x00\\x01Bud1"},
            ],
        }],
    },
    {
        "id": "directory-listing",
        "name": "Acik dizin listeleme",
        "severity": "low",
        "requests": [{
            "method": "GET", "path": "/",
            "matchers_condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "word", "part": "body",
                 "words": ["Index of /", "<title>Index of", "Directory listing for"],
                 "condition": "or"},
            ],
        }],
    },
    {
        "id": "phpinfo-exposed",
        "name": "Acik phpinfo() sayfasi",
        "severity": "medium",
        "requests": [{
            "method": "GET", "path": "/phpinfo.php",
            "matchers_condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "word", "part": "body",
                 "words": ["PHP Version", "php.ini", "Configuration"], "condition": "and"},
            ],
        }],
    },
    {
        "id": "swagger-ui-exposed",
        "name": "Acik Swagger / OpenAPI UI",
        "severity": "info",
        "requests": [{
            "method": "GET", "path": "/swagger-ui.html",
            "matchers_condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "word", "part": "body",
                 "words": ["swagger-ui", "Swagger UI"], "condition": "or"},
            ],
        }],
    },
    {
        "id": "spring-actuator-env",
        "name": "Acik Spring Boot Actuator /env",
        "severity": "high",
        "requests": [{
            "method": "GET", "path": "/actuator/env",
            "matchers_condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "word", "part": "body",
                 "words": ["propertySources", "activeProfiles", "systemProperties"],
                 "condition": "or"},
                {"type": "word", "part": "header", "words": ["application/json", "application/vnd.spring-boot"], "condition": "or"},
            ],
        }],
    },
    {
        "id": "graphql-introspection",
        "name": "GraphQL introspection acik",
        "severity": "low",
        "requests": [{
            "method": "POST", "path": "/graphql",
            "headers": {"Content-Type": "application/json"},
            "body": "{\"query\":\"{__schema{queryType{name}}}\"}",
            "matchers_condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "word", "part": "body", "words": ["__schema", "queryType"], "condition": "and"},
            ],
        }],
    },
    {
        "id": "cors-origin-reflection",
        "name": "CORS yanlis yapilandirma (origin yansimasi + credentials)",
        "severity": "medium",
        "reference": ["https://portswigger.net/web-security/cors"],
        "requests": [{
            "method": "GET", "path": "/",
            "headers": {"Origin": "https://bbhunter-cors-probe.example"},
            "matchers_condition": "and",
            "matchers": [
                {"type": "header", "name": "Access-Control-Allow-Origin",
                 "regex": "bbhunter-cors-probe\\.example"},
                {"type": "header", "name": "Access-Control-Allow-Credentials", "value": "true"},
            ],
        }],
    },
    {
        "id": "missing-security-headers",
        "name": "Eksik guvenlik basliklari",
        "severity": "info",
        "requests": [{
            "method": "GET", "path": "/",
            "matchers_condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "header", "name": "Content-Security-Policy", "negative": True},
                {"type": "header", "name": "X-Frame-Options", "negative": True},
            ],
        }],
    },
    {
        "id": "server-error-disclosure",
        "name": "Sunucu hata/iz (stack trace) ifsasi",
        "severity": "low",
        "requests": [{
            "method": "GET", "path": "/'",
            "matchers_condition": "or",
            "matchers": [
                {"type": "word", "part": "body",
                 "words": ["Traceback (most recent call last)", "Fatal error:",
                           "java.lang.", "System.Web.", "ORA-", "SQLSTATE["],
                 "condition": "or"},
            ],
        }],
    },
    {
        "id": "backup-archive-exposed",
        "name": "Acik yedek arsivi",
        "severity": "medium",
        "requests": [{
            "method": "GET", "path": "/backup.zip",
            "matchers_condition": "and",
            "matchers": [
                {"type": "status", "values": [200]},
                {"type": "header", "name": "Content-Type",
                 "regex": "application/(zip|octet-stream|x-zip)"},
            ],
        }],
    },
]
