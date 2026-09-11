# NetLurker — Gercek zamanli Windows ag istihbarati

[English README](README.md)

**Hangi uygulama internete baglaniyor, nereye baglaniyor ve bu hedefler supheli mi —
hepsini tek pencerede gorun.**

NetLurker, Windows'un ham soket tablolarini eyleme donusebilir ag istihbaratina cevirir:
surec eslestirme, dijital imza, cografya, tehdit beslemeleri, TLS denetimi ve davranissal
temel cizgiler — tek, koyu temali, klavyeyle surulen, bagimsiz bir pencerede.

Saf **C++17 + Win32**, tek taşınabilir x64 yürütülebilir. Kurulum gerekmez.
Veri toplamaz, telemetri göndermez, hesap istemez.

![NetLurker](docs/preview.png)

---

## Why NetLurker?

Antivirüs size "dosya" hakkında karar verir; NetLurker size **"ağ"** hakkında kanıt
gösterir: hangi süreç nereye bağlanıyor, dosya imzalı mı, hedef veri merkezi mi,
DNS kara listesinde mi, sertifikası sağlam mı, normalden fazla mı konuşuyor.
Kanıtlar tek tıkla **yapılandırılmış bir analist raporuna** dönüşür.

## Features

- **Real-time Connections** — TCP/TCP6/UDP/UDP6 soketleri süreçleriyle eşlenir;
  durum, hız (KB/s), RTT, toplam bayt ve servis adı anlık akar.
- **Process Intelligence** — Authenticode imza, yayıncı, komut satırı, kullanıcı,
  üst süreç, svchost servisi, sahip DLL, SHA-256, bütünlük seviyesi.
- **Threat Intelligence** — AbuseIPDB, 5 DNS kara listesi, CIRCL pasif DNS,
  RDAP sahiplik, VirusTotal (anahtar isteğe bağlı), HTTP banner/EOL.
- **DNS · TLS · RDAP Analysis** — DNS önbellek/hosts eşlemesi, el yapımı
  ClientHello ile TLS sertifika denetimi (self-signed, süresi dolmuş, rDNS
  uyuşmazlığı), ağ sahipliği ve abuse iletişimi.
- **AI-assisted Investigation** — `Enter` ile kanıtlar **KARAR / GÜVEN / NEDEN /
  ENDİŞELER / ÖNERİ / ADIMLAR** formatında yapılandırılmış rapora dönüşür;
  anahtarsız yerel sezgisel motor da aynı formatta çalışır. Rapor altında üç
  takip aksiyonu: **"Neden şüpheli?"**, **"Ne yapmalıyım?"** ve
  **"Normalden sapma?"** (sürecin davranışsal temel çizgisiyle karşılaştırma).
- **Network Graph** — süreç ↔ hedef grafiği: risk renkli düğümler, kalınlık =
  veri akışı, ülke etiketleri.
- **Behavioral Anomaly Detection** — süreç başına bağlantı temel çizgisi
  (EMA + varyans); 3σ üzeri sapma → uyarı + bildirim + rapora kayıt.
- **Search, Filter, Sort** — serbest metin araması, filtre çipleri
  (All / Connected / Internet / Listening / Suspicious / HTTPS / Unsigned /
  Unknown / New / TCP / UDP) ve 25 sütunda sıralama.
- **Exports** — `Ctrl+E`: **JSON, CSV, HTML Security Report, TXT** — güncel
  dilde, KPI özeti ve anomali bölümüyle.
- **8 languages** — English (default), Türkçe, Español, Deutsch, Français,
  日本語, 中文, Português. Arayüz, hatalar, risk gerekçeleri, sütunlar, araç
  ipuçları, AI istemleri, raporlar ve tarih biçimleri dahil.

## Screenshots

Gerçek uygulama ekran görüntüsü (çalışan programdan alınmıştır):

![NetLurker dashboard](docs/preview.png)

> **Dürüstlük notu:** `docs/landing/hero.png` bir **UI konsept görselidir**
> (çizim), ekran görüntüsü değildir; iniş sayfasında yalnızca görsel amaçla
> kullanılır ve orada açıkça etiketlenmiştir. Uygulamanın ürettiği tüm veriler
> gerçek sistem verisidir; Demo Modu verileri ise her yerde "DEMO" olarak
> işaretlenir. GIF/video kaydı için kılavuz →
> [docs/video/STORYBOARD.md](docs/video/STORYBOARD.md).

## Demo

**Demo Mode** (`Ctrl+D`): API anahtarı olmadan, 30 saniyede programın tamamını
deneyin. 8 bağlantılı gerçekçi veri seti — imzalı tarayıcılar, DNS, Windows Update
ve şüpheli örnekler (imzasız `updater.exe` → veri merkezi 88/100, C2 beacon deseni,
hosts yönlendirme). Özet sekmesinde **DEMO ENVIRONMENT** bandı; tek tıkla çıkış.

## Installation

| | |
|---|---|
| İşletim sistemi | Windows 7 SP1+ / Windows 10 / Windows 11 (x64) |
| İndirme | [Releases](https://github.com/thesyntax11/NetLurker/releases) → `NetLurker-vX.Y.Z-win64.zip` |
| Kurulum | Gerekmez (taşınabilir). İsteyenler için Inno Setup betiği: `installer/NetLurker.iss` |
| Gereksinim | ~2 MB disk, internet bağlantısı (çevrimdışı da çalışır; zenginleştirme olmaz) |
| Dil paketleri | `NetLurker.exe` yanındaki `lang\` klasörü (zip içinde hazır) |

### Build from source

Tek yürütülebilir, üç araç zinciriyle derlenir:

| Yöntem | Komut | Gereksinim |
|---|---|---|
| MSVC | `build.bat` ("x64 Native Tools" içinde) | Visual Studio 2019+ |
| MinGW-w64 | `build_mingw.bat` | MSYS2 `mingw-w64-x86_64-toolchain` |
| Zig (çapraz) | `ZIG=zig ./tools/build_zig.sh` | Zig 0.14+ / `pip install ziglang` |

Dil kataloğunu yeniden üretmek için: `python3 tools/gen_lang.py`

## Configuration

Ayarlar penceresi (`Ctrl+S`) veya `%APPDATA%\NetLurker\config.ini`:

| Ayar | Açıklama |
|---|---|
| `[ai] endpoint/model/api_key` | OpenAI uyumlu API (boşsa yerel sezgisel analiz) |
| `[ui] lang` | `en` (varsayılan), `tr`, `es`, `de`, `fr`, `ja`, `zh`, `pt`, `system` |
| `[ui] interval` | Yenileme aralığı (×100 ms) |
| `[ui] geo/threat/rdap/banner` | Dış sorgu anahtarları (gizlilik merkeziyle eşleşir) |
| `[threat] abusekey` / `[threat] vtkey` | İsteğe bağlı API anahtarları |

Eklenti sağlayıcıları: `plugins\*.json` → [docs/PLUGINS.md](docs/PLUGINS.md)

## Privacy

| Söz | Durum |
|---|---|
| Ağ verileri yerel olarak işlenir | ✅ Cihaz dışına çıkmaz |
| Telemetri / analitik / reklam | ✅ Yok |
| Hesap veya kayıt | ✅ Gerekmez |

Dış servisler **yalnızca siz etkinleştirdiğinizde** sorgulanır; uygulama içi
**Privacy Center** servis servis durum gösterir:

| Sağlayıcı | Ne zaman | Tür |
|---|---|---|
| ip-api.com | Coğrafya/ASN/organizasyon | ✓ yerleşik |
| DNS kara listeleri (Spamhaus, Blocklist.de, Sorbs, Barracuda, UCEPROTECT) | Tehdit puanı | ✓ yerleşik |
| CIRCL pasif DNS | IP geçmişi | ✓ yerleşik |
| rdap.org | Ağ sahipliği | ✓ yerleşik |
| AbuseIPDB | Kötüye kullanım puanı | ○ anahtar isteğe bağlı |
| VirusTotal | Topluluk tespitleri | ○ anahtar isteğe bağlı |
| TLS ClientHello / HTTP HEAD | Hedefe tek istek | ✓ yerleşik |
| **plugins/\*.json** | Kendi kaynağınız | ○ siz tanımlarsınız |

## Why does it ask for administrator rights?

NetLurker normal kullanıcı olarak da çalışır. Yükseltme yalnızca Windows'un
koruduğu API'ler içindir: bağlantı başına hız/RTT, süreç sonlandırma, güvenlik
duvarı IP engelleme, tüm sistem süreçlerinin TCP tablosu. NetLurker yükseltmeyi
veri toplamak için kullanmaz ve ağ yapılandırmanızı değiştirmez. Durum çubuğundaki
sarı uyarı tıklandığında bu gerekçe iki seçenekle gösterilir:
**Continue as administrator** / **Continue without elevation**.

## Releases & integrity

- Her `vX.Y.Z` etiketi için GitHub Actions derlemesi, zip + `SHA256SUMS`.
  (Workflow: `tools/release.workflow.yml` → `.github/workflows/release.yml`)
- Bütünlük doğrulama:
  ```powershell
  Get-FileHash .\NetLurker.exe -Algorithm SHA256
  ```
- Kod imzalama yardımcısı: `tools/sign_release.ps1` (signtool + doğrulama).
  Ayrıntılar: [docs/RELEASES.md](docs/RELEASES.md)

**Güncel derleme SHA-256** (bu depodaki `dist/NetLurker.exe`):

```
b8d6c2b83bd1855f1a6bf2c2b19f29266621f548cb8abf26eb53eacb5db3168d
```

## Architecture

```
src/
├── main.cpp      pencere, sekmeler, çizim, filtre/arama, dışa aktarma,
│                 demo modu, grafik, anomali, gizlilik merkezi
├── netmon.cpp    TCP/UDP tabloları, süreç eşleme, risk motoru (0–100, MITRE)
├── procinfo.cpp  imza/yayıncı/servis/kullanıcı/modül/kaynak izleme
├── threat.cpp    AbuseIPDB + DNSBL + CIRCL + RDAP + VirusTotal işçileri
├── plugins.cpp   dış JSON sağlayıcı eklentileri (stdin IP → stdout JSON)
├── cert.cpp      TLS sertifika analizi (el yapımı ClientHello)
├── dns.cpp       DNS önbelleği + hosts yönlendirme tespiti
├── geo.cpp       ip-api toplu coğrafya sorgusu + disk önbelleği
├── banner.cpp    HTTP banner / EOL tespiti
├── history.cpp   kapanan bağlantı geçmişi
├── ai.cpp        OpenAI uyumlu istemci + yerel sezgisel analiz
├── i18n.cpp      sıfır bağımlılık çoklu dil sözlüğü (lang/*.ini)
├── wifi.cpp      kablosuz ağ bilgisi (WLAN API, koşullu yükleme)
└── ui_draw.cpp   GDI+ tabanlı koyu tema çizim katmanı
```

İşçi modeli: her sağlayıcı kendi iş parçacığında kuyruktan beslenir; sonuçlar
diskte önbelleklenir (geoip 14 gün, threat 7 gün). Ağır işler (imza, SHA-256,
AI) UI iş parçacığını bloklamaz.

## Roadmap

→ [docs/ROADMAP.md](docs/ROADMAP.md)

- **v6 (şu an):** 8 dil i18n, ilk açılış deneyimi, Demo Mode, ağ grafiği,
  davranışsal anomali, HTML/TXT rapor, eklenti sistemi, gizlilik merkezi,
  sürüm/imzalama altyapısı, iniş sayfası.
- **v7:** ETW sensörü, süreç başına trafik geçmişi, kural editörü, syslog aktarımı.
- **v8:** KMDF sürücü izleme, MITRE ATT&CK taktik eşlemesi, kural paketleri.

## FAQ

**Windows Defender / SmartScreen uyardı?** Açık kaynak imzasız bir exe için
olağandır. SHA-256'yı doğrulayın; imzalı sürüm için
[docs/RELEASES.md](docs/RELEASES.md) imzalama adımları hazırdır.

**Verilerim nereye gidiyor?** Hiçbir yere. `%APPDATA%\NetLurker\` altında yalnızca
yerel önbellekler ve ayarlar tutulur.

**AI anahtarı şart mı?** Hayır. Anahtar yoksa aynı yapılandırılmış formatla yerel
sezgisel analiz çalışır.

**Bağlantı hızları "n/a" görünüyor?** Bağlantı bazlı hızlar için yönetici modu
gerekir (gerekçe diyaloğu açıklar). Sistem geneli grafik her zaman çalışır.

## Contributing

1. Çatallayın, `main`'den dal açın.
2. Yeni bir arayüz metni eklediyseniz `Tr(L"...")` ile sarın ve
   `python3 tools/gen_lang.py` ile kataloğu yenileyin.
3. Üç derleme yolundan biriyle derleyin; PR açın.

Eklenti yazmak katkı vermenin en kolay yolu: [docs/PLUGINS.md](docs/PLUGINS.md)

## License

[MIT](LICENSE) — kullan, değiştir, dağıt. Ağ izleme aracını yalnızca yetkili
olduğun sistemlerde çalıştır.

---

*NetLurker sezgisel kurallara dayanır; kesin hüküm değildir. Şüpheli bulguları
her zaman bağlamıyla değerlendirin.*
