"""
Content discovery (dizin/endpoint fuzzing).

Wordlist tabanli. Yanlis pozitifleri azaltmak icin once bir "baseline" alinir:
var olmayan rastgele bir yol istenir; sunucunun 404 yerine 200 dondurdugu
(soft-404) durumlar bu baseline ile tespit edilip elenir.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field

from ..http_client import HttpClient, OutOfScopeError
from ..util import good, info, parallel_map, warn


@dataclass
class Hit:
    url: str
    status: int
    length: int
    content_type: str = ""
    redirect_to: str = ""


@dataclass
class Baseline:
    status: int
    length: int


INTERESTING = {200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403, 405, 500}


def _baseline(client: HttpClient, base: str) -> Baseline:
    rand = "".join(random.choices(string.ascii_lowercase, k=24))
    resp = client.get(f"{base.rstrip('/')}/{rand}")
    if resp is None:
        return Baseline(status=404, length=0)
    return Baseline(status=resp.status, length=resp.length)


def load_wordlist(path: str | None) -> list[str]:
    if not path:
        return BUILTIN_PATHS
    from pathlib import Path

    out = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip().lstrip("/")
        if s and not s.startswith("#"):
            out.append(s)
    return out


def fuzz(
    client: HttpClient,
    base_url: str,
    *,
    wordlist: list[str] | None = None,
    extensions: list[str] | None = None,
    threads: int = 30,
) -> list[Hit]:
    base_url = base_url.rstrip("/")
    words = wordlist or BUILTIN_PATHS
    exts = extensions or [""]

    try:
        base = _baseline(client, base_url)
    except OutOfScopeError:
        warn(f"Kapsam disi, atlaniyor: {base_url}")
        return []

    info(f"Content discovery: {base_url} ({len(words)} yol, baseline={base.status}/{base.length})")

    paths = []
    for w in words:
        for ext in exts:
            paths.append(f"{w}{ext}" if ext else w)

    def _probe(path: str) -> Hit | None:
        url = f"{base_url}/{path.lstrip('/')}"
        try:
            resp = client.get(url, allow_redirects=False)
        except OutOfScopeError:
            return None
        if resp is None:
            return None
        if resp.status not in INTERESTING:
            return None
        # soft-404 elemesi: baseline ile ayni status + yakin uzunluk
        if resp.status == base.status and abs(resp.length - base.length) <= 32:
            return None
        return Hit(
            url=url,
            status=resp.status,
            length=resp.length,
            content_type=resp.headers.get("Content-Type", ""),
            redirect_to=resp.headers.get("Location", ""),
        )

    hits = [h for h in parallel_map(_probe, paths, threads=threads) if h]
    hits.sort(key=lambda h: (h.status, h.url))
    for h in hits:
        extra = f" -> {h.redirect_to}" if h.redirect_to else ""
        good(f"{h.status} [{h.length}b] {h.url}{extra}")
    return hits


BUILTIN_PATHS = [
    ".git/config", ".git/HEAD", ".svn/entries", ".env", ".env.local",
    ".env.production", ".DS_Store", ".htaccess", ".htpasswd", "config.php",
    "config.php.bak", "wp-config.php", "wp-config.php.bak", "web.config",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "security.txt", ".well-known/security.txt", "humans.txt", "admin",
    "administrator", "admin/login", "login", "signin", "logout", "register",
    "dashboard", "panel", "cpanel", "phpmyadmin", "pma", "adminer.php",
    "server-status", "server-info", "status", "health", "healthz", "ping",
    "metrics", "actuator", "actuator/health", "actuator/env", "actuator/mappings",
    "api", "api/v1", "api/v2", "api/docs", "swagger", "swagger-ui.html",
    "swagger/index.html", "openapi.json", "api-docs", "graphql", "graphiql",
    "console", "debug", "test", "tests", "dev", "staging", "backup", "backups",
    "bak", "old", "tmp", "temp", "uploads", "upload", "files", "download",
    "static", "assets", "public", "private", "internal", "config", "configs",
    "settings", "setup", "install", "installer", "readme.md", "README.md",
    "CHANGELOG.md", "changelog", "license", "LICENSE", "composer.json",
    "package.json", "yarn.lock", "composer.lock", "Dockerfile", "docker-compose.yml",
    ".dockerignore", ".gitignore", "Gemfile", "requirements.txt", "info.php",
    "phpinfo.php", "test.php", "shell.php", "cmd.php", "upload.php", "index.php.bak",
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "dump.sql", "database.sql",
    "www.zip", "site.zip", "web.zip", "app.zip", "logs", "log", "error.log",
    "access.log", "debug.log", ".aws/credentials", ".ssh/id_rsa", "credentials",
    "secret", "secrets", "token", "tokens", "key", "keys", "apikey", "v1", "v2",
    "user", "users", "account", "accounts", "profile", "search", "upload-file",
    "wp-admin", "wp-login.php", "wp-json", "wp-json/wp/v2/users", "xmlrpc.php",
]
