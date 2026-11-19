"""
Bulgu degerlendirme (triage): otomatik bir bulgunun RAPORLANABILIR olup
olmadigina dair ilk degerlendirmeyi yapar.

Amac N/A (gecersiz) raporlari onceden elemek. N/A ve Informative kapanan
raporlar platformdaki itibar (signal/reputation) puanini dusurur; ilk raporun
onaylanmasi icin yalnizca dogrulanmis, etkisi gosterilebilen bulgular
gonderilmelidir.

Karar degerleri:
    promising   Guclu aday. Yine de ELLE dogrula ve etkisini goster.
    verify      Belirsiz. Raporlamadan once mutlaka elle dogrulanmali.
    likely-na   Tek basina genelde N/A / Informative kapanir. Zincirlemeden raporlama.
    info        Bulgu degil, kesif bilgisi (teknoloji, dizin vb.).

Bu kurallar genel deneyime dayanir; HER ZAMAN programin kendi politikasi
(ozellikle "out of scope / not accepted" listesi) onceliklidir.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ORDER = {"promising": 0, "verify": 1, "likely-na": 2, "info": 3}
LABELS = {
    "promising": "Guclu aday",
    "verify": "Elle dogrula",
    "likely-na": "Muhtemelen N/A",
    "info": "Kesif bilgisi",
}


# Pazarlama/izleme parametreleri: degerleri URL gibi gorunse de sunucu bunlara istek atmaz
_NOISE_PARAMS = {"ref", "src", "dom", "source", "referrer", "campaign", "gclid",
                 "fbclid", "mc_cid", "mc_eid", "session_hint", "lang", "locale"}


@dataclass
class Verdict:
    status: str
    reason: str
    next_steps: list = field(default_factory=list)


def _secret(f: dict) -> Verdict:
    name = f.get("name", "")
    target = f.get("target", "")
    if "Google API Key" in name:
        return Verdict(
            "likely-na",
            "On yuz JS'inde gorunen Google API anahtarlari (Maps vb.) cogu programda "
            "kapsam disidir; anahtar zaten tarayiciya gonderilmek icin tasarlanmistir.",
            ["Programin politikasinda 'leaked API keys' / 'Google Maps keys' kapsam disi mi bak.",
             "Yalnizca anahtarin KISITLAMASIZ oldugu ve ucretli bir API'de kotuye "
             "kullanilabildigi gosterilirse deger tasir; bunu programin izin verdigi "
             "olcude test et.",
             ],
        )
    if "JWT" in name:
        return Verdict(
            "verify",
            "JS icindeki JWT'ler cogunlukla ornek/anonim token'dir.",
            ["Token'i jwt.io yerine yerelde coz (base64) - payload'da kullanici/rol var mi?",
             "Suresi dolmamis ve yetki veren bir token mi? Degilse raporlama.",
             ],
        )
    if "Private Key" in name:
        detail = (f.get("detail") or "").strip()
        if detail.endswith("PRIVATE KEY-----"):
            # Eski surum yalnizca basligi yakaliyordu: kripto kutuphanelerinde
            # PEM ayristirmak icin duz metin olarak bulunur, gercek anahtar degildir.
            return Verdict(
                "likely-na",
                "Yalnizca PEM basligi var, anahtar govdesi yok. Buyuk ihtimalle "
                "bir kripto kutuphanesinin (oidc-client, jsrsasign, forge...) kodu.",
                ["Dosyayi acip basligin ardindan gercek bir base64 govde gelip "
                 "gelmedigine bak; gelmiyorsa yanlis alarmdir."],
            )
        return Verdict(
            "promising",
            "Govdesiyle birlikte bir ozel anahtar bloku bulundu.",
            ["Anahtarin bir test/ornek anahtari olmadigini kontrol et (yorumlar, "
             "dosya adi, 'example', 'test' ifadeleri).",
             "Anahtarin neye ait oldugunu (TLS, JWT imzalama, SSH) belirle; KULLANMA, "
             "yalnizca varligini ve konumunu raporla.",
             ],
        )
    if any(x in name for x in ("AWS", "Stripe Live", "GitHub Token", "Slack Token")):
        return Verdict(
            "promising",
            "Dogrudan yetki veren bir kimlik bilgisi imzasi.",
            ["Anahtarin gecerli olup olmadigini yalnizca programin izin verdigi, "
             "zararsiz ve salt-okunur bir cagriyla (orn. AWS 'sts get-caller-identity') kontrol et.",
             "Veriye erisme, degisiklik yapma. Bulgunun konumunu ve gecerliligini raporla.",
             ],
        )
    return Verdict(
        "verify",
        f"Genel anahtar imzasi ({target}). Yanlis alarm orani yuksek.",
        ["Degerin gercek bir sir mi, yoksa herkese acik bir istemci kimligi mi oldugunu incele."],
    )


def assess(f: dict) -> Verdict:
    cat = (f.get("category") or "").lower()
    name = (f.get("name") or "").lower()
    sev = (f.get("severity") or "").lower()

    if cat == "secret":
        return _secret(f)

    if cat == "subdomain-takeover":
        if sev in ("high", "critical"):
            return Verdict(
                "promising",
                "CNAME bir servise isaret ediyor ve sahipsiz kaynak imzasi eslesti.",
                ["dig/nslookup ile CNAME'i tekrar dogrula; servis imzalari zamanla degisir.",
                 "Programin takeover politikasini oku. Cogu program kaynagi ALMANI "
                 "(claim) yalnizca zararsiz bir PoC sayfasiyla ve gizli yolla ister; "
                 "bazilari hic almamani ister.",
                 ],
            )
        return Verdict(
            "verify",
            "Zayif takeover sinyali (yalnizca imza ya da yalnizca CNAME).",
            ["CNAME zincirini ve servisin kaydi alinabilir olup olmadigini elle kontrol et."],
        )

    if cat == "reflected-xss":
        return Verdict(
            "verify",
            "Ozel karakterler kodlanmadan yansiyor; bu henuz calisan bir XSS degil.",
            ["Yansimanin baglamini bul (HTML govdesi, attribute, <script> ici).",
             "Tarayicida GERCEKTEN calisan zararsiz bir PoC (orn. alert(document.domain)) goster.",
             "Yalnizca kendi oturumunda tetiklenen (self-XSS) ya da CSP ile engellenen "
             "durumlar genelde N/A'dir.",
             ],
        )

    if cat == "open-redirect":
        return Verdict(
            "likely-na",
            "Tek basina open redirect cogu programda dusuk/kapsam disi kabul edilir.",
            ["Programin politikasinda open redirect kabul ediliyor mu bak.",
             "OAuth/SSO akisinda token sizdirmaya zincirlenebiliyorsa deger kazanir.",
             ],
        )

    if cat == "ssrf-candidate":
        param = str((f.get("data") or {}).get("param", "")).lower()
        if param in _NOISE_PARAMS or param.startswith("utm_"):
            return Verdict(
                "info",
                f"'{param}' izleme/kimlik parametresi; sunucu buraya istek atmaz.", [])
        if param in ("iss", "issuer", "loginurl", "returnurl", "return_to",
                     "redirect_uri", "next", "continue"):
            return Verdict(
                "likely-na",
                f"'{param}' SSO/yonlendirme parametresi; SSRF degil, en fazla "
                "open redirect adayi (o da ayrica kanit ister).",
                ["Open redirect olarak elle test et; tek basina genelde dusuk degerlidir."],
            )
        return Verdict(
            "verify",
            "Parametre URL/host aliyor gibi; bu yalnizca bir isaret, SSRF kaniti degil.",
            ["Parametrenin sunucu tarafinda istek atip atmadigini, programin izin verdigi "
             "bir OOB yontemiyle (Burp Collaborator, interactsh) kontrol et.",
             "Ic aga/metadata servisine istek atma girisimlerini programin kurallari "
             "acikca izin vermiyorsa YAPMA.",
             ],
        )

    if "cors" in name:
        return Verdict(
            "verify",
            "Origin yansimasi + credentials gorundu; etkisi henuz gosterilmedi.",
            ["Oturum acmis bir test hesabiyla, kimlik dogrulamasi gerektiren HASSAS bir "
             "API yanitinin baska bir origin'den okunabildigini goster.",
             "Yanit herkese acik bir HTML sayfasiysa ya da hassas veri yoksa N/A'dir.",
             ],
        )

    if any(x in name for x in ("stack trace", "hata/iz", "version", "surum", "header eksik",
                               "missing", "security header", "banner", "clickjacking")):
        return Verdict(
            "likely-na",
            "Bilgi ifsasi / eksik header bulgulari genelde Informative kapanir.",
            ["Yalnizca hassas bir veri (kimlik bilgisi, ic yol + istismar edilebilir surum) "
             "iceriyorsa raporlamayi dusun."],
        )

    if cat in ("tech", "content") and sev == "info":
        return Verdict("info", "Kesif bilgisi; dogrudan bir zafiyet degil.", [])

    if cat == "content":
        return Verdict(
            "verify",
            "Ilginc dosya/yol bulundu (.git, .env, yedek vb. olabilir).",
            ["Dosyanin gercekten hassas icerik dondurdugunu kontrol et (soft-404 olmasin).",
             "Icerigi indirmekle yetin; icindeki kimlik bilgilerini KULLANMA.",
             ],
        )

    if sev == "info":
        return Verdict("info", "Kesif bilgisi.", [])
    return Verdict(
        "verify",
        "Otomatik sablon eslesmesi; yanlis pozitif olabilir.",
        ["Istegi Burp'te elle tekrarla ve etkisini dogrula."],
    )


def triage(findings: list[dict]) -> list[tuple[dict, Verdict]]:
    out = [(f, assess(f)) for f in findings]
    out.sort(key=lambda fv: (ORDER.get(fv[1].status, 9), fv[0].get("target", "")))
    return out


def write_markdown(findings: list[dict], path, program: str = "") -> str:
    from pathlib import Path

    rows = triage(findings)
    lines = [f"# Bulgu Degerlendirmesi{(' - ' + program) if program else ''}", ""]
    lines.append("> Otomatik ilk degerlendirme. Programin politikasi her zaman onceliklidir; "
                 "hicbir bulguyu elle dogrulamadan raporlama.")
    lines.append("")
    counts: dict[str, int] = {}
    for _, v in rows:
        counts[v.status] = counts.get(v.status, 0) + 1
    lines.append("| Karar | Adet |")
    lines.append("|---|---|")
    for st in ORDER:
        if st in counts:
            lines.append(f"| {LABELS[st]} | {counts[st]} |")
    lines.append("")
    for st in ("promising", "verify", "likely-na"):
        group = [(f, v) for f, v in rows if v.status == st]
        if not group:
            continue
        lines.append(f"## {LABELS[st]} ({len(group)})")
        lines.append("")
        for f, v in group:
            lines.append(f"### [{f.get('severity')}] {f.get('name')}")
            lines.append(f"- **Hedef:** `{f.get('target')}`")
            if f.get("detail"):
                lines.append(f"- **Detay:** `{str(f.get('detail'))[:200]}`")
            lines.append(f"- **Neden:** {v.reason}")
            for step in v.next_steps:
                lines.append(f"  - [ ] {step}")
            lines.append("")
    if counts.get("info"):
        lines.append(f"_{counts['info']} kesif bilgisi (teknoloji, dizin vb.) listelenmedi._")
    text = "\n".join(lines) + "\n"
    Path(path).write_text(text, encoding="utf-8")
    return text
