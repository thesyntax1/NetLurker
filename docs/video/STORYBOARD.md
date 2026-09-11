# NetLurker — 30 Saniyelik Tanıtım Videosu

Hedef: "İndir, çalıştır, 30 saniyede şüpheli bağlantıyı yakala." hikayesi.
Süre: 30 sn. Çözünürlük: 1920×1080, 30 fps. Ses: opsiyonel altyazı (TR + EN).

## Sahne planı (saniye saniye)

| Zaman | Sahne | Görüntü | Metin / Altyazı |
|---|---|---|---|
| 0:00–0:03 | **Hook** | Koyu arka planda NETLURKER logosu + slogan belirir | "Real-time Windows Network Intelligence" |
| 0:03–0:06 | **Açılış** | `NetLurker.exe` çift tıklanır → Hızlı Başlangıç kartı açılır | "No installer. No account. No telemetry." |
| 0:06–0:09 | **Demo Modu** | `DEMO MODU` düğmesine tıklanır; tablo 8 örnek bağlantıyla dolar (chrome, svchost, şüpheli updater.exe) | "Try the demo — no API keys needed" |
| 0:09–0:14 | **Zenginleştirme** | İmleç sütunların üzerinde gezer: Uygulama, İmza, Ülke, Org, Tehdit, RDAP, VirusTotal, Banner | "Every socket, enriched: signature, geo, ASN, RDAP, VT, TLS" |
| 0:14–0:17 | **Şüpheli satır** | Kırmızı `updater.exe → 45.155.205.86:4444` satırı seçilir; detay paneli açılır; gerekçeler görünür (imzasız, kalıcılık, spamhaus, VT 9/94) | "88/100 CRITICAL — here's why" |
| 0:17–0:21 | **AI analizi** | `Enter`'a basılır → yapılandırılmış analist raporu: Karar, Güven %, Neden, Endişeler, Öneri, Adımlar | "One keypress: a structured analyst verdict" |
| 0:21–0:24 | **Ağ grafiği** | `5` sekmesine geçilir; süreç↔hedef grafiği akar; risk renkleri görünür | "See the whole picture as a graph" |
| 0:24–0:27 | **Anomali + dışa aktarma** | Özet sekmesinde "⚠ anomali" kartı; `Ctrl+E` ile HTML raporu kaydedilir | "Anomaly alerts. One-click HTML report." |
| 0:27–0:30 | **Kapanış** | Logo + GitHub adresi + "İndir" | "github.com/thesyntax11/NetLurker — Free, MIT" |

## Kayıt kılavuzu

### Kurulum

1. **OBS Studio** (ücretsiz): `Display Capture` yerine `Window Capture` kullanın;
   pencere boyutu 1280×800'de sabit tutun (DPI tutarlılığı için).
2. Windows ölçeklemesini %100'e alın (Ekran Ayarları → Ölçek) — NetLurker DPI uyumludur
   ama kayıtta en keskin sonucu %100 verir.
3. Uygulamayı **Demo Modu** ile kaydedin (`Ctrl+D`): gerçek makinede kişisel veri
   görünmez, sahneler tekrarlanabilir olur.
4. İmleç vurgusu için OBS'de "yakala imleci" açık kalsın; tıklama vurgulaması için
   `PointerFocus` benzeri hafif bir katman kullanın.

### Sahneler için uygulama adımları

| Sahne | Uygulamada yapılacak |
|---|---|
| Açılış kartı | `config.ini` içinde `[ui] welcome=1` yapıp uygulamayı açın (veya ilk çalıştırma) |
| Demo doldurma | Hoş geldin kartında **DEMO MODU** düğmesi |
| Sütun gezintisi | Bağlantılar sekmesinde imleci yavaşça sütun başlıklarında gezdirin |
| Kritik satır | Demo verisinde `updater.exe` (88/100) her zaman üsttedir |
| AI analizi | Satırı seçip `Enter` (anahtarsız yerel analiz de çalışır) |
| Grafik | `5` tuşu; demo bağlantıları grafiği anında doldurur |
| Anomali | Özet sekmesinde "⚠ anomali" kartı demo verisinde görünür |
| HTML raporu | `Ctrl+E` → `NetLurker-rapor.html` adıyla masaüstüne kaydet; dosyayı tarayıcıda aç |

### Post-prodüksiyon

- Kurgu: DaVinci Resolve (ücretsiz) — sahne başına 0,5 sn çapraz geçiş.
- Altyazı: `docs/video/subtitles.srt` şablonu (TR + EN iki kanal).
- Ses: Kısa, nötr bir telif hakkı gerektirmeyen fon müziği (ör. YouTube Audio Library);
  uygulama sesi (bildirim "uyarı sesi") senkron bırakılabilir.
- Final: 1080p H.264, `NetLurker-promo-30s.mp4`, GitHub release varlığı olarak ekle.

### Yayınlanacak kanallar

1. GitHub README + release sayfası (mp4 gömülü)
2. `docs/landing/index.html` içine `<video>` etiketi
3. YouTube (açıklamada SHA256SUMS doğrulama adımına bağlantı)
