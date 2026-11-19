"""
Scope-farkinda, rate-limitli HTTP client.

Onemli: Bu client'tan gecen HER istek, verilen Scope nesnesine karsi dogrulanir.
Kapsam disi bir host'a istek atilmaya calisilirsa OutOfScopeError firlatilir.
Boylece hicbir modul yanlislikla yetkisiz bir hedefe dokunamaz.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError as e:  # pragma: no cover
    raise SystemExit(
        "requests gerekli: pip install requests\n(orijinal hata: %s)" % e
    )

from .config import Config
from .scope import Scope


class OutOfScopeError(Exception):
    """Kapsam disi bir hedefe istek engellendiginde firlatilir."""


class RateLimiter:
    """Basit token-bucket; global saniye-basi-istek siniri."""

    def __init__(self, rate_per_sec: float):
        self.rate = max(rate_per_sec, 0.0)
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        if self.rate <= 0:
            return
        interval = 1.0 / self.rate
        with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                sleep_for = self._next_allowed - now
            else:
                sleep_for = 0.0
            self._next_allowed = max(now, self._next_allowed) + interval
        if sleep_for > 0:
            time.sleep(sleep_for)


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    body: bytes
    elapsed: float
    final_url: str
    history: list
    # Kapsam disi bir adrese yonlendirme engellendiyse o adres (yoksa "")
    blocked_redirect: str = ""

    @property
    def text(self) -> str:
        enc = self.headers.get("Content-Type", "")
        charset = "utf-8"
        if "charset=" in enc:
            charset = enc.split("charset=")[-1].split(";")[0].strip() or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except (LookupError, TypeError):
            return self.body.decode("utf-8", errors="replace")

    @property
    def length(self) -> int:
        return len(self.body)


class HttpClient:
    def __init__(self, config: Config, scope: Scope):
        self.config = config
        self.scope = scope
        self.limiter = RateLimiter(config.rate_limit)
        self._local = threading.local()

    def _session(self) -> requests.Session:
        """Thread-basi session (requests Session thread-safe degildir)."""
        sess = getattr(self._local, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.headers.update({"User-Agent": self.config.user_agent})
            if self.config.extra_headers:
                # program kimlik header'i gibi ozel header'lar (tum isteklere)
                sess.headers.update(self.config.extra_headers)
            retry = Retry(
                total=self.config.retries,
                backoff_factor=0.3,
                status_forcelist=(502, 503, 504),
                allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
            )
            adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
            sess.mount("http://", adapter)
            sess.mount("https://", adapter)
            self._local.session = sess
        return sess

    def request(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: bool | None = None,
        **kwargs,
    ) -> Response | None:
        host = urlparse(url).hostname or ""
        if not self.scope.in_scope(host):
            raise OutOfScopeError(f"Kapsam disi hedef engellendi: {host} ({url})")

        if self.config.dry_run:
            return None

        self.limiter.wait()
        if self.config.delay_jitter > 0:
            time.sleep(random.uniform(0, self.config.delay_jitter))

        if allow_redirects is None:
            allow_redirects = self.config.follow_redirects

        # Yonlendirmeler requests'e BIRAKILMAZ: her adimda hedef host yeniden
        # kapsam kontrolunden gecer. Kapsam disina giden bir yonlendirme
        # izlenmez; son (3xx) yanit blocked_redirect ile isaretlenip dondurulur.
        sess = self._session()
        start = time.monotonic()
        history: list[int] = []
        current_url, current_method = url, method.upper()
        blocked = ""
        while True:
            try:
                resp = sess.request(
                    current_method,
                    current_url,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                    allow_redirects=False,
                    **kwargs,
                )
            except requests.RequestException:
                return None

            location = resp.headers.get("Location")
            if not (allow_redirects and resp.is_redirect and location):
                break
            if len(history) >= self.config.max_redirects:
                break

            next_url = urljoin(current_url, location)
            next_host = urlparse(next_url).hostname or ""
            if not self.scope.in_scope(next_host):
                blocked = next_url
                break

            history.append(resp.status_code)
            # 303 her zaman, 301/302 ise POST icin GET'e doner (tarayici davranisi)
            if resp.status_code == 303 or (
                resp.status_code in (301, 302) and current_method == "POST"
            ):
                current_method = "GET"
                kwargs.pop("data", None)
                kwargs.pop("json", None)
            current_url = next_url
            self.limiter.wait()
        elapsed = time.monotonic() - start

        return Response(
            url=url,
            status=resp.status_code,
            headers=dict(resp.headers),
            body=resp.content or b"",
            elapsed=elapsed,
            final_url=current_url,
            history=history,
            blocked_redirect=blocked,
        )

    def get(self, url: str, **kwargs) -> Response | None:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> Response | None:
        return self.request("HEAD", url, **kwargs)
