"""
Calisma zamani konfigurasyonu. CLI argumanlari ve varsayilanlar burada birlesir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_UA = (
    "bbhunter/0.1 (+authorized-bugbounty-recon; respects-scope-and-ratelimit)"
)


@dataclass
class Config:
    # cikti
    out_dir: Path = field(default_factory=lambda: Path("bbhunter_out"))

    # hiz / nezaket
    threads: int = 20
    rate_limit: float = 10.0      # saniyede maksimum istek (global)
    timeout: float = 10.0         # istek timeout (sn)
    retries: int = 1
    user_agent: str = DEFAULT_UA

    # davranis
    verify_tls: bool = False      # bug bounty hedeflerinde sertifika sorunlari olagandir
    follow_redirects: bool = True
    max_redirects: int = 5
    delay_jitter: float = 0.0     # istekler arasi rastgele gecikme ust siniri

    # Tum isteklere eklenecek ozel header'lar (orn. program kimlik header'i:
    # {"X-HackerOne-Research": "kullaniciadi"}).
    extra_headers: dict = field(default_factory=dict)

    # ozellik bayraklari
    verbose: bool = False
    dry_run: bool = False         # scope filtrelemeyi gosterir, istek atmaz

    def ensure_out(self) -> Path:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        return self.out_dir
