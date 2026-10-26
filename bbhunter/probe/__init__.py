"""
Aktif ama NON-DESTRUCTIVE parametre problari.

Bu paket, kesfedilen parametrelerin zafiyet ADAYI olup olmadigini belirler;
calisan bir exploit uretmez veya veri degistirmez:

  - reflection : zararsiz bir canary enjekte edip yansimayi ve hangi ozel
                 karakterlerin encode'lanmadan dondugunu olcer (XSS adayi).
  - open-redirect : url/next/redirect gibi parametrelere zararsiz, cozulmeyen
                 bir ornek host koyup yonlendirme olup olmadigina bakar.
  - ssrf-aday : URL/host alan gorunen parametreleri yalnizca MANUEL inceleme
                icin isaretler; aktif SSRF testi (OOB) yapmaz.

Dogrulama ve somurme her zaman arastirmaciya birakilir.
"""
