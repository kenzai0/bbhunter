"""
Program kurallari: bir bug bounty programinin test kurallarini scope dosyasinda
tutar ve araca UYGULATIR. Boylece "hiz limitini girmeyi unuttum" ya da
"bu program fuzzing'i yasakliyordu" turu kural ihlalleri teknik olarak engellenir.

Scope dosyasinda '@' ile baslayan satirlar kuraldir:

    @program   Acme VDP
    @platform  hackerone
    @url       https://hackerone.com/acme
    @rate      5                      # saniyede en fazla istek
    @threads   5                      # en fazla paralel is parcacigi
    @header    X-HackerOne-Research: kullaniciadi
    @forbid    fuzz, ports            # yasak asamalar (tekrarlanabilir)
    @note      Otomatik tarama icin hesap basina 5 req/s siniri var.

Yasaklanabilecek asamalar (FORBIDDABLE):
    brute     subdomain DNS brute-force
    ports     port taramasi
    fuzz      dizin/dosya fuzzing
    probe     reflected-param problari (XSS/open-redirect)
    vuln      template tabanli zafiyet taramasi
    takeover  subdomain takeover kontrolu
    js        JS dosyasi indirip analiz etme
    active    hedefe istek atan HER SEY (yalnizca pasif kaynaklar: crt.sh, Wayback)
"""

from __future__ import annotations

from dataclasses import dataclass, field

FORBIDDABLE = {"brute", "ports", "fuzz", "probe", "vuln", "takeover", "js", "active"}

# 'active' yasaksa bu asamalarin hepsi de yasaktir
_ACTIVE_STAGES = {"brute", "ports", "fuzz", "probe", "vuln", "takeover", "js", "live"}


class RuleError(ValueError):
    """Scope dosyasindaki gecersiz kural satiri."""


@dataclass
class ProgramRules:
    program: str = ""
    platform: str = ""
    url: str = ""
    rate: float | None = None
    threads: int | None = None
    headers: dict = field(default_factory=dict)
    forbid: set = field(default_factory=set)
    notes: list = field(default_factory=list)

    def parse_line(self, line: str) -> None:
        """'@anahtar deger' satirini isler."""
        body = line[1:].strip()
        key, _, value = body.partition(" ")
        key, value = key.lower().strip(), value.strip()
        if not value:
            raise RuleError(f"Kural degeri bos: {line!r}")
        if key == "program":
            self.program = value
        elif key == "platform":
            self.platform = value.lower()
        elif key == "url":
            self.url = value
        elif key == "rate":
            try:
                self.rate = float(value)
            except ValueError:
                raise RuleError(f"@rate sayi olmali: {line!r}") from None
            if self.rate <= 0:
                raise RuleError(f"@rate 0'dan buyuk olmali: {line!r}")
        elif key == "threads":
            try:
                self.threads = int(value)
            except ValueError:
                raise RuleError(f"@threads tam sayi olmali: {line!r}") from None
            if self.threads < 1:
                raise RuleError(f"@threads en az 1 olmali: {line!r}")
        elif key == "header":
            name, sep, val = value.partition(":")
            if not sep or not name.strip():
                raise RuleError(f"@header 'Ad: deger' biciminde olmali: {line!r}")
            self.headers[name.strip()] = val.strip()
        elif key == "forbid":
            for item in value.replace(",", " ").split():
                item = item.lower()
                if item not in FORBIDDABLE:
                    raise RuleError(
                        f"Bilinmeyen @forbid degeri {item!r}. "
                        f"Gecerli: {', '.join(sorted(FORBIDDABLE))}")
                self.forbid.add(item)
        elif key == "note":
            self.notes.append(value)
        else:
            raise RuleError(f"Bilinmeyen kural: @{key}")

    def allows(self, stage: str) -> bool:
        """Bu asama program kurallarina gore calistirilabilir mi?"""
        if stage in self.forbid:
            return False
        if "active" in self.forbid and stage in _ACTIVE_STAGES:
            return False
        return True

    def is_empty(self) -> bool:
        return not (self.program or self.platform or self.url or self.rate
                    or self.threads or self.headers or self.forbid or self.notes)

    def summary(self) -> str:
        if self.is_empty():
            return "kurallar: (tanimli degil - program kurallarini @ satirlariyla ekle)"
        lines = ["kurallar:"]
        if self.program:
            lines.append(f"  program : {self.program}")
        if self.platform:
            lines.append(f"  platform: {self.platform}")
        if self.url:
            lines.append(f"  url     : {self.url}")
        if self.rate:
            lines.append(f"  rate    : en fazla {self.rate:g} istek/sn")
        if self.threads:
            lines.append(f"  threads : en fazla {self.threads}")
        for k, v in self.headers.items():
            lines.append(f"  header  : {k}: {v}")
        if self.forbid:
            lines.append(f"  yasak   : {', '.join(sorted(self.forbid))}")
        for n in self.notes:
            lines.append(f"  not     : {n}")
        return "\n".join(lines)
