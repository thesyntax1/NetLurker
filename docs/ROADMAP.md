# NetLurker Yol Haritası

Sürümler `MAJOR.MINOR` düzeninde ilerler; her sürüm tek yürütülebilir
Windows uygulaması olarak derlenir (C++17 + Win32, harici bağımlılık yok).

## Tamamlanan — v6 (mevcut)

| Alan | Durum |
|---|---|
| Çoklu dil (i18n) — EN varsayılan, TR/ES/DE/FR/JA/ZH/PT; arayüz, hatalar, risk açıklamaları, sütunlar, araç ipuçları, AI istemleri, raporlar, tarihler | ✅ `lang/*.ini`, `src/i18n.*` |
| Ürün konumlandırması: "Real-time Windows Network Intelligence" | ✅ README + iniş sayfası |
| İlk açılış deneyimi (Hızlı Başlangıç + gizlilik notu) | ✅ Hoş geldin kartı |
| Demo Modu (API anahtarsız örnek veri seti) | ✅ `Ctrl+D`, Özet sekmesinde "DEMO ENVIRONMENT" bandı + tek tık çıkış |
| Dışa aktarma: JSON / CSV / HTML rapor / TXT | ✅ `Ctrl+E` |
| Arama + filtreler + sıralama | ✅ tıklanabilir filtre çipleri (All/Connected/Internet/Listening/Suspicious/HTTPS/Unsigned/Unknown/New/TCP/UDP) + 25 sütun sıralama |
| Bağlantı detay paneli | ✅ |
| Yapılandırılmış AI analisti (karar/güven/neden/endişe/öneri/adımlar) | ✅ |
| AI takip soruları: "Neden şüpheli?" / "Ne yapmalıyım?" / "Normalden sapma?" (temel çizgi karşılaştırması) | ✅ |
| Gizlilik Merkezi (uygulama içi + README) | ✅ |
| UAC / yönetici gerekçe diyaloğu | ✅ özel koyu tema diyaloğu (Continue as administrator / Continue without elevation) |
| Sürüm altyapısı (zip + SHA256SUMS + sürümleme) | ✅ Actions + `make_release.ps1` |
| Kod imzalama | ✅ `sign_release.ps1` (EV sertifikası alınınca çalışır) |
| README yapısı | ✅ |
| İniş sayfası | ✅ `docs/landing/index.html` (Pages'e hazır) |
| 30 saniyelik video | ✅ storyboard + kayıt kılavuzu (`docs/video/`) |
| Eklenti/sağlayıcı sistemi | ✅ `plugins/*.json` (stdin IP → stdout JSON) |
| Ağ grafiği görünümü | ✅ 5. sekme |
| Davranışsal anomali tespiti | ✅ süreç başına temel çizgi (EMA+3σ) |

## v7 — Algılama derinliği

- [ ] **ETW/ETLW sensörü:** `Microsoft-Windows-Kernel-Network` sağlayıcısından
      bağlantı oluşturma/kapanma olayları; mevcut polling yerine olay tabanlı gerçek
      zamanlılık ve DNS isteklerinin süreçle eşleştirilmesi.
- [ ] **Süreç başına trafik geçmişi:** ESTATS verilerinin dairesel tamponu;
      uygulama sekmesinde 60 dakikalık geriye dönük grafik.
- [ ] **Kural editörü:** kullanıcı tanımlı uyarı kuralları (süreç/port/IP/ülke
      desenleri + eşikler), `rules.json` ile kalıcı.
- [ ] **Syslog / dosya aktarımı:** bulguların `syslog://` veya yerel JSONL
      günlüğüne akışı (SIEM beslemesi).

## v8 — Kurumsal ölçek

- [ ] **Çekirdek izleme:** ETW'nin yetersiz kaldığı senaryolar için KMDF
      (sürücü tabanlı) soket olayları — imzalı sürücü ve ayrı yükleyici gerektirir.
- [ ] **MITRE ATT&CK taktik eşlemesi:** her risk nedeni → taktik/teknik kimliği
      (T1071, T1547, T1571, T1041…) ve raporda ATT&CK bölümü.
- [ ] **Toplu karşılaştırma:** aynı ağdaki NetLurker istemcilerinin
      (opsiyonel, yerel ağ) ortak temel çizgisi; yayılma tespiti.
- [ ] **Kural paketleri:** YARA benzeri imza dosyaları ile süreç/bellek taraması.

## Dış engelli maddeler

Bu üç madde dış kaynak gerektirdiği için yerine eşdeğer teslimatlar kondu:

| Madde | Engel | Eşdeğer teslimat |
|---|---|---|
| Kod imzalama (EV sertifikası) | Ücretli sertifika + kimlik doğrulama | `tools/sign_release.ps1` + `docs/RELEASES.md` (imzalama + doğrulama rehberi) |
| İniş sayfası alan adı | Alan adı satın alma | `docs/landing/index.html` — Pages'e hazır bağımsız HTML |
| 30 saniyelik video | Video üretimi/çekimi | `docs/video/STORYBOARD.md` — sahne sahne senaryo + kayıt kılavuzu |
