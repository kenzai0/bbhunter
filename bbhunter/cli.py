"""
bbhunter komut satiri arayuzu.

Kullanim ornekleri:
    python -m bbhunter scope   --scope program.scope
    python -m bbhunter recon    example.com --scope program.scope
    python -m bbhunter discover example.com --scope program.scope
    python -m bbhunter vuln     https://app.example.com --scope program.scope
    python -m bbhunter full     example.com --scope program.scope --ports
    python -m bbhunter report   --out bbhunter_out

Scope verilmezse, komut satirinda verilen domainler in-scope kabul edilir
(apex + tum subdomainler).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import Config, DEFAULT_UA
from .scope import Scope
from .pipeline import Pipeline
from .report.store import Store
from .report import report as reporter
from .report import html as html_reporter
from .util import banner, err, good, info, warn


def build_scope(args) -> Scope:
    if args.scope:
        scope = Scope.from_file(args.scope)
    else:
        if not getattr(args, "domains", None):
            err("Scope dosyasi ya da en az bir domain gerekli.")
            sys.exit(2)
        scope = Scope.from_lists(include=args.domains, exclude=args.exclude or [])
    return scope


def build_config(args) -> Config:
    cfg = Config()
    cfg.out_dir = Path(args.out)
    cfg.threads = args.threads
    cfg.rate_limit = args.rate
    cfg.timeout = args.timeout
    cfg.verify_tls = args.verify_tls
    cfg.dry_run = getattr(args, "dry_run", False)
    cfg.delay_jitter = args.jitter
    if args.user_agent:
        cfg.user_agent = args.user_agent
    for h in getattr(args, "header", None) or []:
        if ":" in h:
            name, _, val = h.partition(":")
            cfg.extra_headers[name.strip()] = val.strip()
    cfg.ensure_out()
    return cfg


def _open_store(cfg: Config) -> Store:
    return Store(cfg.out_dir / "bbhunter.db")


def _emit_reports(store: Store, cfg: Config, program: str = "") -> None:
    md = reporter.write_markdown(store, cfg.out_dir / "report.md", program=program)
    js = reporter.write_json(store, cfg.out_dir / "report.json")
    htmlf = html_reporter.write_html(store, cfg.out_dir / "report.html", program=program)
    good(f"Rapor: {md}")
    good(f"JSON:  {js}")
    good(f"HTML:  {htmlf}")


def cmd_scope(args) -> None:
    scope = build_scope(args)
    banner("SCOPE")
    print(scope.summary())
    if args.test:
        print("\nTest sonuclari:")
        for t in args.test:
            mark = "IN " if scope.in_scope(t) else "OUT"
            print(f"  [{mark}] {t}")


def cmd_recon(args) -> None:
    scope = build_scope(args)
    cfg = build_config(args)
    store = _open_store(cfg)
    pipe = Pipeline(cfg, scope, store)
    domains = scope.filter(args.domains)
    sub_wl = None
    if args.sub_wordlist:
        from .recon.subdomains import load_wordlist
        sub_wl = load_wordlist(args.sub_wordlist)
    pipe.recon(domains, sub_wordlist=sub_wl, do_ports=args.ports,
               passive_only=args.passive, probe_only=args.probe_only)
    _emit_reports(store, cfg)
    store.close()


def cmd_discover(args) -> None:
    scope = build_scope(args)
    cfg = build_config(args)
    store = _open_store(cfg)
    pipe = Pipeline(cfg, scope, store)
    domains = scope.filter(args.domains)
    # mevcut canli URL'leri store'dan al
    live_urls = [a["value"] for a in store.assets("url") if a["data"].get("status")]
    pipe.discover(domains, live_urls, do_fuzz=not args.no_fuzz)
    _emit_reports(store, cfg)
    store.close()


def cmd_vuln(args) -> None:
    scope = build_scope(args)
    cfg = build_config(args)
    store = _open_store(cfg)
    pipe = Pipeline(cfg, scope, store)
    targets = args.targets or [a["value"] for a in store.assets("url")]
    pipe.vuln(targets, template_paths=args.templates, min_severity=args.min_severity)
    _emit_reports(store, cfg)
    store.close()


def cmd_probe(args) -> None:
    scope = build_scope(args)
    cfg = build_config(args)
    store = _open_store(cfg)
    pipe = Pipeline(cfg, scope, store)
    # hedefler: verilen URL'ler veya store'daki parametreli URL'ler
    if args.targets:
        param_urls = args.targets
    else:
        from urllib.parse import urlparse
        param_urls = [a["value"] for a in store.assets("url")
                      if "=" in urlparse(a["value"]).query]
    pipe.probe(param_urls, only_hinted_redirect=not args.all_redirect_params)
    _emit_reports(store, cfg)
    store.close()


def cmd_full(args) -> None:
    scope = build_scope(args)
    cfg = build_config(args)
    store = _open_store(cfg)
    pipe = Pipeline(cfg, scope, store)
    domains = scope.filter(args.domains)
    pipe.resume = args.resume
    if args.fresh:
        sig = Pipeline.signature(domains)
        n = store.clear_stages(sig)
        if n:
            info(f"--fresh: {n} asama isareti temizlendi, bastan calisilacak")
    sub_wl = None
    if args.sub_wordlist:
        from .recon.subdomains import load_wordlist
        sub_wl = load_wordlist(args.sub_wordlist)
    pipe.run_full(
        domains,
        sub_wordlist=sub_wl,
        do_ports=args.ports,
        template_paths=args.templates,
        min_severity=args.min_severity,
        do_discover=not args.no_discover,
        do_vuln=not args.no_vuln,
        do_probe=not args.no_probe,
    )
    _emit_reports(store, cfg, program=args.program or "")
    store.close()


def cmd_takeover(args) -> None:
    from .recon import takeover as m_takeover

    scope = build_scope(args)
    cfg = build_config(args)
    store = _open_store(cfg)
    pipe = Pipeline(cfg, scope, store)
    hosts = scope.filter(args.hosts) if args.hosts else \
        [a["value"] for a in store.assets("subdomain")]
    if not hosts:
        warn("Host yok. Once 'recon' calistir ya da host(lar) ver.")
        store.close()
        return
    findings = m_takeover.detect(pipe.client, pipe.resolver, hosts, threads=cfg.threads)
    for t in findings:
        store.add_finding(
            "subdomain-takeover", f"Subdomain takeover adayi ({t.service})",
            t.severity, t.host,
            detail=f"{t.reason} | CNAME={t.cname or '-'} | imza='{t.evidence}'",
            data={"service": t.service, "cname": t.cname,
                  "confidence": t.confidence, "evidence": t.evidence},
        )
    _emit_reports(store, cfg)
    store.close()


def cmd_nuclei_import(args) -> None:
    from .vuln import nuclei

    templates, skipped = nuclei.import_path(args.paths)
    out = Path(args.save)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(templates, indent=2, ensure_ascii=False), encoding="utf-8")
    good(f"{len(templates)} template kaydedildi -> {out}")
    if skipped:
        warn(f"{len(skipped)} template atlandi (ilk 15):")
        for tid, reason in skipped[:15]:
            info(f"  [{tid}] {reason}")
    good(f"Kullanim: python -m bbhunter vuln <hedef> --templates {out}")


def cmd_report(args) -> None:
    cfg = Config(out_dir=Path(args.out))
    cfg.ensure_out()
    store = _open_store(cfg)
    _emit_reports(store, cfg, program=args.program or "")
    store.close()


def _add_common(p: argparse.ArgumentParser, with_domains=True) -> None:
    if with_domains:
        p.add_argument("domains", nargs="*", help="Kok domain(ler), orn. example.com")
    p.add_argument("--scope", help="Scope dosyasi (in/out-of-scope girdileri)")
    p.add_argument("--exclude", nargs="*", help="Ek out-of-scope girdileri")
    p.add_argument("--out", default="bbhunter_out", help="Cikti dizini")
    p.add_argument("--threads", type=int, default=20)
    p.add_argument("--rate", type=float, default=10.0, help="Saniyede maks istek")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--jitter", type=float, default=0.0, help="Istekler arasi rastgele gecikme (sn)")
    p.add_argument("--verify-tls", action="store_true", help="TLS sertifikasini dogrula")
    p.add_argument("--user-agent", default=DEFAULT_UA)
    p.add_argument("--header", action="append", default=[], metavar="NAME:VALUE",
                   help="Tum isteklere eklenecek ozel header (tekrarlanabilir), "
                        "orn. --header 'X-HackerOne-Research:kullaniciadi'")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="bbhunter",
        description="Scope-first bug bounty recon & otomasyon framework'u "
                    "(yalnizca yetkili/in-scope hedefler icin).",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scope", help="Scope'u yukle ve dogrula")
    _add_common(p)
    p.add_argument("--test", nargs="*", help="Bu hedefleri scope'a karsi test et")
    p.set_defaults(func=cmd_scope)

    p = sub.add_parser("recon", help="Subdomain + canli host + fingerprint")
    _add_common(p)
    p.add_argument("--sub-wordlist", help="Subdomain brute-force wordlist")
    p.add_argument("--ports", action="store_true", help="Port taramasi da yap")
    p.add_argument("--passive", action="store_true",
                   help="Yalnizca pasif subdomain toplama (crt.sh); hedefe HIC istek atma")
    p.add_argument("--probe-only", action="store_true",
                   help="Subdomain toplamayi atla; store'daki subdomainleri canli-probe et")
    p.set_defaults(func=cmd_recon)

    p = sub.add_parser("discover", help="Wayback + param + JS + dizin fuzzing")
    _add_common(p)
    p.add_argument("--no-fuzz", action="store_true",
                   help="Dizin fuzzing'i atla (yalnizca wayback + param + JS)")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("takeover", help="Subdomain takeover adaylarini tespit et")
    _add_common(p, with_domains=False)
    p.add_argument("hosts", nargs="*", help="Host(lar) (bos ise store'daki subdomainler)")
    p.set_defaults(func=cmd_takeover)

    p = sub.add_parser("vuln", help="Template tabanli zafiyet taramasi")
    _add_common(p, with_domains=False)
    p.add_argument("targets", nargs="*", help="Hedef URL'ler (bos ise store'daki canli URL'ler)")
    p.add_argument("--templates", nargs="*", help="Ek JSON template dizini/dosyasi")
    p.add_argument("--min-severity", default="info",
                   choices=["info", "low", "medium", "high", "critical"])
    p.set_defaults(func=cmd_vuln)

    p = sub.add_parser("probe", help="Reflected-param problari (XSS/open-redirect/SSRF-aday)")
    _add_common(p, with_domains=False)
    p.add_argument("targets", nargs="*",
                   help="Parametreli URL'ler (bos ise store'daki parametreli URL'ler)")
    p.add_argument("--all-redirect-params", action="store_true",
                   help="Open-redirect'i yalnizca ipucu parametrelerinde degil, hepsinde dene")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("full", help="Tam boru hatti (recon+discover+probe+vuln+rapor)")
    _add_common(p)
    p.add_argument("--program", help="Program adi (raporda gorunur)")
    p.add_argument("--sub-wordlist")
    p.add_argument("--ports", action="store_true")
    p.add_argument("--templates", nargs="*")
    p.add_argument("--min-severity", default="info",
                   choices=["info", "low", "medium", "high", "critical"])
    p.add_argument("--no-discover", action="store_true")
    p.add_argument("--no-vuln", action="store_true")
    p.add_argument("--no-probe", action="store_true")
    p.add_argument("--resume", action="store_true",
                   help="Daha once tamamlanmis asamalari atla (store'dan devam et)")
    p.add_argument("--fresh", action="store_true",
                   help="Asama isaretlerini temizle ve her seyi bastan calistir")
    p.set_defaults(func=cmd_full)

    p = sub.add_parser("nuclei-import",
                       help="Nuclei YAML template'lerini engine JSON formatina cevir")
    p.add_argument("paths", nargs="+", help="YAML dosya(lari) veya dizin(ler)")
    p.add_argument("--save", default="bbhunter_out/nuclei_templates.json",
                   help="Cikti JSON dosyasi")
    p.set_defaults(func=cmd_nuclei_import)

    p = sub.add_parser("report", help="Store'dan raporu yeniden uret")
    p.add_argument("--out", default="bbhunter_out")
    p.add_argument("--program")
    p.set_defaults(func=cmd_report)

    return ap


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        warn("Kullanici tarafindan durduruldu.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
