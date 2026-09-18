# NetLurker

**Windows'ta hangi süreç dışarı bağlanıyor? Risk işaretlerinin arkasındaki kanıtı inceleyin.**

[![Build](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml/badge.svg)](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml)
[![MIT](https://img.shields.io/badge/lisans-MIT-blue.svg)](LICENSE)

[English](README.md) · [Veri doğruluğu](docs/DATA-ACCURACY.md) · [Gizlilik](PRIVACY.md) · [Yayın kontrol listesi](docs/RELEASE-CHECKLIST.md)

NetLurker; soket–süreç eşlemesini, süreç bilgilerini, IP sorgularını, TLS incelemesini ve
kurallara dayalı risk işaretlerini tek bir yerel arayüzde toplar. AI anahtarı olmadan da
çalışır: yerel kuralların ürettiği raporlar kullanılabilir.

**Durum: ilk yayın öncesi sağlamlaştırma.** CI dosyaları geliştirme derlemeleridir;
imzalanmış ve cihazda doğrulanmış genel sürüm anlamına gelmez. Hazır sürümler olduğunda
[Releases](https://github.com/thesyntax1/NetLurker/releases) sayfasında bulunacak.
Kaynak klasörlerindeki eski EXE/ZIP dosyaları dağıtım yolu değildir.

## Hangisini indireyim?

| İstediğim | İndireceğim dosya |
|---|---|
| Windows'a kurmak | [Releases](https://github.com/thesyntax1/NetLurker/releases) → Assets → `NetLurker-v…-setup.exe` |
| Kurmadan denemek | `NetLurker-v…-win64.zip`; arşivin **tamamını** çıkarın |
| Android yardımcı uygulamasını denemek | Başarılı bir [Build çalışmasındaki](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml) `NetLurker-debug-apk`; yalnızca geliştirme/test sürümü |

Henüz yayın dosyası yoksa başarılı Build çalışmasını veya aşağıdaki kaynak derleme
adımlarını kullanın. **“Source code (zip)” uygulama değildir.** CI dosyalarını indirmek
GitHub girişi gerektirebilir. Genel sürüm dosyalarını `SHA256SUMS.txt` ile karşılaştırın.

**Denemek için hesap, abonelik veya AI anahtarı gerekmez.** İmza ayarları geliştirici
ayarlarıdır; kullanıcı kurulumu için doldurulmaz. Varsayılan yayın Windows içindir;
Android üretim yayını açıkça etkinleştirilmedikçe geliştirme/test aşamasında kalır.

## Neden denemeli?

- Bir IP listesinden değil, **uygulamadan başlayın**: bağlantı, hedef, imza ve süreç bağlamı.
- Kırmızı bir puanı körü körüne kabul etmeyin; **hangi kuralın neden çalıştığını görün**.
- Bulguları JSON, CSV, TXT veya HTML olarak dışa aktarın. Paylaşmadan önce özel bilgileri silin.
- Ücretli AI zorunlu değil. Uzak AI analizi yalnızca kullanıcı işlemiyle çalışır ve hata yapabilir.
- Windows'ta C++17 + Win32; Android yardımcı uygulamasında Kotlin + Compose.
- İlk açılış İngilizce; Türkçe dahil sekiz dil ayarlardan seçilir ve seçim saklanır.

## Windows ile Android aynı şeyi ölçmez

| Özellik | Windows | Android yardımcı uygulama |
|---|---|---|
| Canlı bağlantı → süreç | Windows soket tabloları | VPN yakalama/root yok; **sunulmaz** |
| Cihaz toplam trafiği | Ağ arabirimi sayaçları | Destekleniyorsa `TrafficStats` |
| Süreç/uygulama canlı hızı | Kullanılabiliyorsa TCP EStats; yetki/protokol kısıtları var | Modern Android'de çağıran UID; diğer uygulamalar için **erişilemiyor** |
| Kimlik bilgisi | Yol, yayıncı, Authenticode | Paket ve APK imza bilgisi; güvenlik garantisi değil |
| Hedef inceleme | Gözlenen genel IP'ler | Kullanıcının girdiği adres/alan adı |
| Süreç sonlandırma / IP engelleme | Açık kullanıcı işlemi; yetki gerekebilir | Yok |
| Demo | `Ctrl+D`, sentetik olarak işaretli | Sentetik veri yok |

[Android ayrıntıları](android/README-android.md)

## Üç dakikada deneyin

1. Yukarıdan Windows yükleyicisini veya taşınabilir ZIP'i seçin. Henüz yayın yoksa
   başarılı bir Build çalışmasını ya da aşağıdaki kaynak derleme adımlarını kullanın.
2. `NetLurker.exe` ile `lang/` klasörünü aynı dizinde tutun.
3. `Ctrl+S` ile dış sorguları inceleyin. **IP zenginleştirme varsayılan olarak açıktır ve
   sorgulanan IP'ler hizmet sağlayıcılara gönderilir.** Hassas ağlarda önce [gizliliği](PRIVACY.md) okuyun.
4. `Ctrl+D` ile açıkça işaretlenmiş demo verisini deneyin veya `Ctrl+F` ile bir süreç arayın.
5. `Enter` ile rapor, `Ctrl+E` ile dışa aktarım. Kanıtı kontrol etmeden süreç sonlandırmayın.

Demo, kullanım deneyimini gösterir; canlı veri kaynağının doğru çalıştığını kanıtlamaz.

## İlk kullanımda takılırsanız

- **Türkçe yapmak:** `Ctrl+S` → en üstteki Language alanı → Türkçe → Kaydet.
  İlk açılış İngilizcedir; İptal, önizlenen dil seçimini kaydetmez.
- **Tablo boş:** Arama filtresini temizleyin, bir uygulama bağlantı kurarken tekrar
  bakın veya `Ctrl+D` ile etiketli sentetik demoyu açın. Boş tablo sistemin güvenli
  olduğunu kanıtlamaz. Kısayollar için `F1` kullanın.
- **Bir bilgiye erişilemiyor:** Ölçüm/sorgu tamamlanmamış veya erişim sınırlı olabilir.
  Bu, sıfır trafik, temiz sonuç veya tehdit anlamına gelmez; kaynak ayarlarını inceleyin.
- **Windows güvenlik uyarısı:** Korumanızı kapatmayın. Dosyanın kaynağını ve özetini
  doğrulayın veya kaynak kodundan derleyin. İmzasız dosyalar açıkça belirtilir.
- **Hata buldunuz:** [Bildirim açın](https://github.com/thesyntax1/NetLurker/issues/new/choose);
  sürümü, işletim sistemini ve tekrar üretme adımlarını yazın. Ekran görüntüsü/rapordan
  özel adresleri, API anahtarlarını ve kişisel bilgileri silin.

## Puan ne anlama geliyor?

0–100 puanı bir **inceleme önceliği işaretidir; zararlı yazılım olasılığı değildir**.
Düşük puan güvenli olduğunu, yüksek puan zararlı olduğunu kanıtlamaz.

- VPN, veri merkezi ve yüksek yükleme trafiği normal kullanım olabilir.
- DNSBL hata kodları kara liste kaydı değildir.
- Başarısız veya kapalı bir sorgu, temiz sonuç sayılamaz.
- TLS incelemesi tam zincir güveni/iptal denetimi değildir.
- Sunucu başlığı taklit edilebilir; sürüm eşlemesi zafiyet taraması değildir.
- AI çıktısı yanılabilir; dış kaynak metinlerinden etkilenebilir.

## Derleme

**Windows:** Visual Studio 2022 C++ masaüstü araçları ve Windows SDK.
Depo kökünde x64 Native Tools Command Prompt:

```bat
python tools\gen_lang.py --check
build.bat
build\NetLurker.exe
```

**Android:** JDK 17 + Android SDK 35:

```sh
cd android
./gradlew testDebugUnitTest lintDebug assembleDebug
# app/build/outputs/apk/debug/app-debug.apk
./gradlew connectedDebugAndroidTest  # bağlı cihaz/emülatör gerekir
```

Debug APK değerlendirme içindir. İmzasız release APK, normal bir yayın olarak kurulamaz.

## Güven ve katkı

Releases’te `v6.0.1` gibi bir tag ile **Publish release** seçildiğinde test edilmiş Windows
ZIP’i ve yükleyici otomatik eklenir. Android APK’sı yalnızca üretim yayını açıkça etkinleştirilip imza doğrulaması
geçtiğinde eklenir. Yayımlamadan hazırlık modu da vardır: [kurulum ve kullanım](docs/RELEASES.md).

Yayın adayları taze derleme, kaynak revizyonu ve SHA-256 özetiyle hazırlanır. Özet dosyası
kod imzasının veya güvenlik denetiminin yerini tutmaz. SmartScreen uyarısı alırsanız güvenlik
korumasını kapatmayın; dosyanın kaynağını doğrulayın veya kendiniz derleyin.

Eski tanıtım görselleri mevcut sürümün doğrulanmış ekran görüntüsü değildir. Gerçek veri
kanıtı gibi sunulmuyor. [Görsel kaydı](docs/VISUAL-PROVENANCE.md)

En değerli katkılar: yeniden üretilebilir hata bildirimleri, yanlış pozitif örnekleri,
çeviri düzeltmeleri ve gerçek cihaz testleri. İşinize yaradıysa bir star keşfedilmesine
katkı sağlar; doğruluğu artıran bir hata bildirimi de en az onun kadar değerlidir.

[Katkı rehberi](CONTRIBUTING.md) · [Hata bildir](https://github.com/thesyntax1/NetLurker/issues/new/choose) · [Güvenlik](SECURITY.md) · [MIT](LICENSE)
