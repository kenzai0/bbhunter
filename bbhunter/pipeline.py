"""
Orkestrasyon: modulleri scope-farkinda bir boru hattinda birlestirir.
Her asama sonuclari Store'a yazar; sonunda rapor uretilir.
"""

from __future__ import annotations

import hashlib
from urllib.parse import urlparse

from .config import Config
from .http_client import HttpClient
from .scope import Scope
from .report.store import Store
from .util import banner, dim, good, info, warn

from .recon import subdomains as m_subs
from .recon.dns import Resolver
from .recon import ports as m_ports
from .recon import livehosts as m_live
from .recon import fingerprint as m_fp
from .recon import takeover as m_takeover
from .discovery import wayback as m_wb
from .discovery import params as m_params
from .discovery import jsanalyze as m_js
from .discovery import content as m_content
from .probe import reflected as m_probe
from .vuln import engine as m_vuln


class Pipeline:
    def __init__(self, config: Config, scope: Scope, store: Store):
        self.cfg = config
        self.scope = scope
        self.store = store
        self.client = HttpClient(config, scope)
        self.resolver = Resolver(timeout=config.timeout)
        self.resume = False   # True ise tamamlanmis asamalar atlanir

    @staticmethod
    def signature(domains: list[str]) -> str:
        """Kapsamin domain kumesine gore kararli bir imza (resume anahtari)."""
        joined = ",".join(sorted(set(domains)))
        return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:12]

    def _pending(self, stage: str, sig: str) -> bool:
        """Asama calistirilmali mi? (resume kapali ise her zaman evet)"""
        if self.resume and self.store.is_stage_done(stage, sig):
            info(f"[resume] '{stage}' asamasi daha once tamamlanmis, atlaniyor")
            return False
        return True

    # --- asamalar ---
    def recon(
        self,
        domains: list[str],
        *,
        sub_wordlist=None,
        do_passive=True,
        do_brute=True,
        do_ports=False,
        port_list=None,
        passive_only=False,
        probe_only=False,
    ) -> list[m_live.LiveHost]:
        banner("RECON")
        # probe_only: subdomain toplamayi ATLA; store'daki subdomainleri canli-probe et
        if probe_only:
            all_subs = sorted(a["value"] for a in self.store.assets("subdomain"))
            info(f"probe-only: store'dan {len(all_subs)} subdomain yuklendi "
                 f"(yeniden toplama yapilmadi)")
        else:
            # passive_only: hedefe HIC istek atmadan yalnizca crt.sh'tan subdomain topla
            effective_brute = do_brute and not passive_only
            all_subs = []
            for d in domains:
                subs = m_subs.enumerate_subdomains(
                    d, self.scope, self.resolver,
                    wordlist=sub_wordlist, do_passive=do_passive,
                    do_brute=effective_brute, threads=self.cfg.threads * 2,
                )
                all_subs += subs
            all_subs = sorted(set(all_subs))
            self.store.add_assets("subdomain", all_subs)

        if passive_only:
            good(f"Pasif mod: {len(all_subs)} subdomain toplandi. "
                 f"Hedefe hic istek atilmadi (yalnizca crt.sh).")
            return []

        if do_ports:
            # subdomainleri IP'ye cevirip port tara
            hosts = [s for s in all_subs if self.resolver.resolve(s).resolves]
            hp = m_ports.scan(hosts, self.scope, ports=port_list, threads=self.cfg.threads)
            for h in hp:
                self.store.add_asset("port", f"{h.host}:{h.open_ports}")

        live = m_live.probe(self.client, all_subs, threads=self.cfg.threads)
        for lh in live:
            self.store.add_asset("url", lh.final_url or lh.url, {
                "status": lh.status, "title": lh.title, "server": lh.server,
            })

        # fingerprint
        fps = m_fp.fingerprint(self.client, [lh.url for lh in live], threads=self.cfg.threads)
        for fp in fps:
            self.store.add_finding(
                "tech", "Teknoloji tespiti", "info", fp.url,
                detail=", ".join(fp.technologies),
                data={"technologies": fp.technologies, "server": fp.server},
            )

        # subdomain takeover (TUM subdomainler uzerinde; adaylar genelde "canli" degildir)
        tos = [] if probe_only else m_takeover.detect(
            self.client, self.resolver, all_subs, threads=self.cfg.threads)
        for t in tos:
            self.store.add_finding(
                "subdomain-takeover", f"Subdomain takeover adayi ({t.service})",
                t.severity, t.host,
                detail=f"{t.reason} | CNAME={t.cname or '-'} | imza='{t.evidence}'",
                data={"service": t.service, "cname": t.cname,
                      "confidence": t.confidence, "evidence": t.evidence},
            )
        return live

    def discover(self, domains: list[str], live_urls: list[str],
                 *, do_fuzz: bool = True, js_limit: int = 400) -> None:
        banner("CONTENT DISCOVERY")
        archive_urls: list[str] = []
        for d in domains:
            archive_urls += m_wb.fetch_urls(d, self.scope)
        self.store.add_assets("url", archive_urls[:5000])

        # parametreler
        params = m_params.discover(archive_urls)
        self.store.add_assets("param", params)

        # JS analizi (arsivdeki .js; naziklik icin js_limit ile sinirli)
        js_urls = [u for u in archive_urls if u.split("?")[0].endswith(".js")][:js_limit]
        js_findings = m_js.analyze(self.client, js_urls, threads=self.cfg.threads)
        for jf in js_findings:
            self.store.add_assets("endpoint", jf.endpoints)
            for name, snippet in jf.secrets:
                self.store.add_finding(
                    "secret", f"Olasi sir: {name}", "high", jf.source,
                    detail=snippet, data={"source": jf.source},
                )

        # dizin fuzzing (canli hostlar uzerinde) - opsiyonel (agir olabilir)
        if not do_fuzz:
            dim("Dizin fuzzing atlandi (--no-fuzz).")
            return
        banner("DIRECTORY FUZZING")
        for url in live_urls:
            hits = m_content.fuzz(self.client, url, threads=self.cfg.threads)
            for h in hits:
                sev = "info"
                if any(x in h.url for x in (".git", ".env", ".sql", "backup", "config", ".ssh", "credentials")):
                    sev = "medium"
                self.store.add_finding(
                    "content", "Ilginc yol/dosya", sev, url,
                    detail=f"{h.status} {h.url}",
                    data={"status": h.status, "length": h.length, "matched_at": h.url},
                )

    def vuln(self, targets: list[str], template_paths=None, min_severity="info") -> None:
        banner("VULN SCAN")
        templates = m_vuln.load_templates(template_paths)
        findings = m_vuln.scan(
            self.client, targets, templates,
            min_severity=min_severity, threads=self.cfg.threads,
        )
        for f in findings:
            self.store.add_finding(
                f.template_id, f.name, f.severity, f.url,
                detail=f.evidence,
                data={"matched_at": f.matched_at, "reference": f.reference},
            )

    def probe(self, param_urls: list[str], *, only_hinted_redirect: bool = True) -> None:
        """Reflected-parametre guvenli problari (XSS adayi, open-redirect, SSRF-aday)."""
        banner("REFLECTED-PARAM PROBE")
        param_urls = [u for u in param_urls if "=" in urlparse(u).query]
        if not param_urls:
            dim("Parametreli URL bulunamadi (once discover calistir).")
            return

        # XSS adaylari
        for rf in m_probe.test_reflection(self.client, param_urls, threads=self.cfg.threads):
            if rf.is_candidate:
                self.store.add_finding(
                    "reflected-xss", "Reflected XSS adayi", rf.severity, rf.url,
                    detail=f"param={rf.param} encode'suz={''.join(rf.reflected_chars)}",
                    data={"param": rf.param, "reflected_chars": rf.reflected_chars},
                )

        # Open-redirect adaylari
        for orf in m_probe.test_open_redirect(
            self.client, param_urls, threads=self.cfg.threads,
            only_hinted=only_hinted_redirect,
        ):
            self.store.add_finding(
                "open-redirect", "Open-redirect adayi", orf.severity, orf.url,
                detail=f"param={orf.param} -> {orf.location} ({orf.kind})",
                data={"param": orf.param, "location": orf.location, "kind": orf.kind},
            )

        # SSRF adaylari (pasif isaretleme)
        for sc in m_probe.classify_ssrf_candidates(param_urls):
            self.store.add_finding(
                "ssrf-candidate", "SSRF inceleme adayi (manuel)", sc.severity, sc.url,
                detail=f"param={sc.param}: {sc.reason}",
                data={"param": sc.param, "reason": sc.reason},
            )

    # --- tam boru hatti ---
    def run_full(
        self, domains: list[str], *,
        sub_wordlist=None, do_ports=False, port_list=None,
        template_paths=None, min_severity="info",
        do_discover=True, do_vuln=True, do_probe=True,
    ) -> None:
        in_scope = self.scope.filter(domains)
        if not in_scope:
            warn("Verilen domainlerin hicbiri kapsamda degil. Scope'u kontrol et.")
            return
        info(f"Kapsam ici kok domainler: {', '.join(in_scope)}")

        sig = self.signature(in_scope)

        # RECON
        if self._pending("recon", sig):
            live = self.recon(
                in_scope, sub_wordlist=sub_wordlist,
                do_ports=do_ports, port_list=port_list,
            )
            live_urls = [lh.url for lh in live]
            self.store.mark_stage("recon", sig, {"domains": in_scope})
        else:
            # atlandi: canli URL'leri store'dan al (recon bunlari 'status' ile isaretler;
            # arsiv/discover URL'lerinde boyle bir alan yoktur)
            live_urls = [a["value"] for a in self.store.assets("url")
                         if a["data"].get("status")]
            info(f"[resume] {len(live_urls)} canli URL store'dan yuklendi")

        # DISCOVERY
        if do_discover and self._pending("discover", sig):
            self.discover(in_scope, live_urls)
            self.store.mark_stage("discover", sig)

        # REFLECTED-PARAM PROBE
        if do_probe and self._pending("probe", sig):
            param_urls = [a["value"] for a in self.store.assets("url")
                          if "=" in urlparse(a["value"]).query]
            self.probe(param_urls)
            self.store.mark_stage("probe", sig)

        # VULN
        if do_vuln and self._pending("vuln", sig):
            self.vuln(live_urls, template_paths=template_paths, min_severity=min_severity)
            self.store.mark_stage("vuln", sig)

        banner("OZET")
        stats = self.store.stats()
        good(f"Varliklar: {stats['assets']}")
        good(f"Bulgular: {stats['findings']}")
        done = [s["stage"] for s in self.store.stages() if s["signature"] == sig]
        if done:
            good(f"Tamamlanan asamalar: {', '.join(done)} "
                 f"(tekrar icin --resume, bastan icin --fresh)")
