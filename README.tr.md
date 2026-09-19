# NetLurker

[![Build](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml/badge.svg)](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml)
[![MIT](https://img.shields.io/badge/lisans-MIT-blue.svg)](LICENSE)

[English](README.md) · [İndir](https://github.com/thesyntax1/NetLurker/releases) · [Derleme](#derleme) · [İletişim](#iletisim)

NetLurker, C++17 ve Win32 ile yazılmış bir Windows ağ izleme uygulamasıdır. TCP/UDP
bağlantılarını ilgili süreçlerle birlikte listeler; hedef adresleri, süreç bilgilerini
ve risk işaretlerini incelemenizi sağlar. Kotlin ve Compose ile yazılmış Android
uygulaması ise cihazın ağ bilgilerini gösterir ve girdiğiniz adresleri sorgular.

Proje geliştirme aşamasında. Yayımlanmış paketler
[Releases](https://github.com/thesyntax1/NetLurker/releases) sayfasında bulunur;
Actions dosyaları, henüz yayın incelemesinden geçmemiş geliştirme derlemeleridir.

## Özellikler

- Windows'ta bağlantı–süreç eşleştirmesi, arama, filtreleme ve sıralama.
- Ayarlara ve sağlayıcı erişimine bağlı IP konumu, RDAP, DNSBL, AbuseIPDB,
  VirusTotal, TLS ve HTTP başlık sorguları.
- Gerekçeleriyle gösterilen kural tabanlı risk puanları. OpenAI uyumlu bir servisle
  isteğe bağlı AI analizi; anahtar olmadan çalışan yerel raporlar.
- JSON, CSV, HTML ve metin olarak dışa aktarma.
- English, Türkçe, Español, Deutsch, Français, 日本語, 中文 ve Português.
- Taşınabilir Windows sürümü ve arayüzü denemek için etiketli demo verileri.

## İndirme

| Platform | Dosya |
|---|---|
| Windows yükleyicisi | Sürümün Assets bölümündeki `NetLurker-v…-setup.exe` |
| Windows taşınabilir | `NetLurker-v…-win64.zip`; `lang/` dahil arşivin tamamını çıkarın |
| Android geliştirme sürümü | Başarılı bir [Build çalışmasındaki](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml) `NetLurker-debug-apk` |

Henüz yayın yoksa başarılı bir Build çalışmasını kullanabilir veya aşağıdaki adımlarla
derleyebilirsiniz. Actions dosyaları için GitHub girişi gerekebilir. Otomatik eklenen
“Source code” arşivleri derlenmiş uygulama değildir.

İndirdiğiniz yayın dosyalarını `SHA256SUMS.txt` ile karşılaştırın. Windows paketleri
imzasız olabilir; sürümdeki imza bilgisini kontrol edin ve çalıştırmak için güvenlik
korumasını kapatmayın. Android üretim yayını varsayılan olarak kapalıdır. Debug APK
test içindir; imzasız release APK, imzalı ve kurulabilir bir sürümün yerine geçmez.

## Kullanım

1. `NetLurker.exe` dosyasını açın. Taşınabilir sürümde `lang/` aynı dizinde olmalı.
   Bazı süreç bilgileri ve TCP sayaçları yönetici yetkisi ister; arayüzü açmak için
   yönetici olarak çalıştırmak gerekmez.
2. `Ctrl+S` ile ayarları açın. **IP zenginleştirme varsayılan olarak açıktır ve sorgulanan
   adresler sağlayıcılara gönderilir.** Hassas ağlarda önce [Gizlilik](PRIVACY.md)
   belgesini okuyun.
3. İlk açılış İngilizcedir. Ayarların en üstündeki Language alanından Türkçe'yi seçip
   Kaydet'e basın. İptal, kaydedilmiş dil seçimini değiştirmez.
4. `Ctrl+F` ile bir süreç arayın ve incelemek için bağlantısını seçin. Canlı modda
   `Enter` analizi açar; `Ctrl+E` bulguları dışa aktarır. Paylaşmadan önce raporlardaki
   özel adresleri, dosya yollarını ve anahtarları temizleyin.
5. `Ctrl+D` ile sentetik demo verisine geçebilir ve geri dönebilirsiniz. Demo modunda
   AI, süreç kontrolü ve uzak sorgu işlemleri kapalıdır. Kısayolları `F1` ile açabilirsiniz.

Tablo boşsa arama filtresini temizleyip bir uygulama bağlantı kurarken tekrar bakın.
“Erişilemiyor” ifadesi ölçümün veya sorgunun alınamadığını belirtir; sıfır trafik ya da
tehdit bulunmadığı anlamına gelmez.

## Platform sınırları

Windows sürümü işletim sisteminin soket tablolarını okur. Kısa bağlantılar iki örnekleme
arasında kaçabilir; süreç trafiği ölçümleri TCP EStats desteğine ve yetkilere bağlıdır.

Android sürümünde **VPN yakalama, root ile veri toplama, uygulama–soket eşleştirmesi ve
güvenlik duvarı kontrolü yoktur**. Güncel Android sürümlerinde diğer uygulamaların canlı
UID sayaçları genellikle okunamaz. Cihaz toplamları ve elle girilen hedef sorguları,
uygulama başına ölçüm değildir. Ayrıntılar: [Android rehberi](android/README-android.md).

0–100 puanı kural tabanlı bir inceleme önceliğidir; zararlı yazılım olasılığı değildir.
Sağlayıcı hataları, eksik veriler ve normal VPN/bulut kullanımı sonuçları etkileyebilir.
TLS incelemesi tam zincir veya iptal doğrulaması yapmaz; sunucu başlığı taklit edilebilir,
AI çıktısı da kontrol gerektirir. Kaynaklar ve doğrulama kuralları
[Veri doğruluğu](docs/DATA-ACCURACY.md) belgesinde açıklanmıştır.

## Derleme

### Windows x64

Visual Studio'nun **C++ ile masaüstü geliştirme** araçlarını ve Windows SDK'yı kurun.
Depo kökünde **x64 Native Tools Command Prompt** açın:

```bat
python tools\gen_lang.py --check
build.bat
build\NetLurker.exe
```

Alternatifler: `build_mingw.bat`, Windows üzerinde CMake ve çapraz derleme için
`tools/build_zig.sh`. Çapraz derlenen dosyanın ayrıca Windows'ta çalıştırılarak
kontrol edilmesi gerekir.

### Android

JDK 17, Android SDK 35 ve Gradle bağımlılıkları için internet erişimi gerekir.

```sh
cd android
./gradlew testDebugUnitTest lintDebug assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
./gradlew connectedDebugAndroidTest  # bağlı cihaz veya emülatör gerekir
```

### Depo kontrolleri

```sh
python3 tools/gen_lang.py --check
python3 android/tools/gen_strings.py --check
python3 android/tools/check_symbols.py
python3 -m unittest discover -s tests -p 'test_*.py'
```

Yayın otomasyonu varsayılan olarak Windows ZIP ve yükleyici paketlerini hazırlar.
Android yayını ayrıca açılmalı ve üretim imzası doğrulanmalıdır. Geliştirici ayarları
[Yayın rehberi](docs/RELEASES.md) ve [kontrol listesinde](docs/RELEASE-CHECKLIST.md)
bulunur. CI kontrolleri cihaz testinin yerine geçmez.

## Katkı

Hata bildirimleri, çeviri düzeltmeleri ve küçük pull request'ler gönderebilirsiniz.
[Issue açarken](https://github.com/thesyntax1/NetLurker/issues/new/choose) sürümü, işletim
sistemini ve sorunu tekrar oluşturma adımlarını yazın. Arayüz değişikliklerinde çalışan
uygulamanın özel bilgileri temizlenmiş ekran görüntüsünü ekleyin; sentetik veri varsa
DEMO işaretini koruyun. Eski görseller güncel ekran görüntüsü değildir:
[görsel notları](docs/VISUAL-PROVENANCE.md).

[Katkı rehberi](CONTRIBUTING.md) · [Arayüz kontrolleri](docs/UI-REGRESSION-CHECKS.md) · [Yol haritası](docs/ROADMAP.md)

<a id="iletisim"></a>

## İletişim

Geliştiriciye ulaşmak için:

- TikTok: [szoboszlai2113](https://tiktok.com/szoboszlai2113)
- E-posta: [user2102392109@proton.me](mailto:user2102392109@proton.me)

Hata ve özellik isteklerini takip edebilmek için GitHub issue kullanın. Güvenlik
bildirimlerini herkese açık issue veya sosyal medya yorumlarına değil,
[SECURITY.md](SECURITY.md) içindeki özel iletişim kanallarına gönderin.

## Lisans

[MIT](LICENSE).
