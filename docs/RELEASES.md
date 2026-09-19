# GitHub Releases: sürüm hazırlama ve otomatik yayın

## Basit kullanım: şifre/anahtar doldurmadan Windows yayını

Varsayılan yayın **Windows ZIP + kurulum EXE’si + doğrulama dosyalarıdır**.
Android imzası kurmak, parola üretmek veya boş secret alanları açmak gerekmez.
`REQUIRE_ANDROID_RELEASE` tanımsız ya da `false` olduğunda Android imza kayıtları
kullanılmaz; yarım bırakılmış Android ayarları Windows yayınını durdurmaz. Android
kaynak kodu ve geliştirme APK’sı korunur; debug APK genel sürüm gibi yayımlanmaz.
Windows sertifikası yoksa paket açıkça **UNSIGNED** olarak işaretlenir.

Daha önce yalnızca denemek için boş/örnek kayıtlar açtıysanız GitHub'da
**Settings → Secrets and variables → Actions** altında bunları silebilirsiniz.
Gerçek bir uygulamada kullanılmış anahtarları veya yedeklerini silmeyin.
Android'i kapalı tutmak için `REQUIRE_ANDROID_RELEASE` değişkenini kaldırın veya
`false` yapın; diğer imza alanlarını doldurmanız gerekmez.

## Kullanım: Releases’ten sürüm yayımla

Önce bu otomasyon değişikliklerini varsayılan dala (`main`) birleştirin. Etiketlenecek
commit de yeni workflow ve araçları içermeli; eski bir etikete yeni dosyalar ekleyerek
sürüm kimliğini değiştirmeyin.

1. **Releases → Draft a new release** ekranını açın.
2. **Choose a tag** alanına örneğin `v6.0.1` yazın ve hedef commit/dalı seçin.
   `Release title` yalnızca başlıktır; **derlenen sürümü tag belirler**.
3. Notları yazın veya **Generate release notes** kullanın. Aday sürüm için
   `v6.0.1-rc.1` gibi bir tag ve **Set as a pre-release** seçin.
4. [Yayın kontrol listesindeki](RELEASE-CHECKLIST.md) manuel incelemeyi tamamlayıp
   **Publish release** düğmesine basın.
5. **Actions → Release** akışı testleri ve derlemeleri çalıştırır, paketleri hazırlayıp
   **aynı release’in Assets bölümüne** yükler. Notlarınıza kurulum, imza durumu,
   kaynak SHA’sı ve doğrulama bölümü eklenir; yazdığınız notlar korunur.

Taslak kaydetmek veya yalnızca başlığı değiştirmek yayın başlatmaz. Bu akış tag/release
oluşturmaz, tag taşımaz ve uygulamaların içinde otomatik güncelleyici kurmaz.
GitHub’ın otomatik eklediği “Source code” arşivleri, derlenmiş uygulama değildir.

> Release sayfası Publish’a basınca görünür; dosyalar derleme bittikçe değil, tüm gerekli
> paketler hazırlandıktan sonra yüklenmeye başlar. GitHub çoklu dosya yüklemesi atomik
> değildir. Actions yeşil olmadan, yönetilen doğrulama bölümü görünmeden ve tüm
> `SHA256SUMS.txt` girdileri mevcut olmadan yayını tamamlanmış saymayın.

## Üretilen dosyalar

| Dosya | İçerik |
|---|---|
| `NetLurker-v6.0.1-win64.zip` | Windows x64 EXE, sekiz dil, lisans, gizlilik/güvenlik belgeleri, kaynak bilgisi ve iç dosya özetleri |
| `NetLurker-v6.0.1-setup.exe` | Varsayılan olarak kullanıcı başına kurulum, kısayollar ve kaldırıcı |
| `NetLurker-v6.0.1-android.apk` | **Yalnızca Android yayını açık ve üretim imzası doğrulanmışsa**; normal uygulama kimliğiyle doğrulanmış APK |
| `windows-signatures.json` | EXE ve yükleyicinin gerçek Authenticode durumu, dosya ve sertifika SHA-256’ları |
| `android-signature.json` | APK varsa imza sertifikası ve dosya SHA-256’sı |
| `RELEASE-MANIFEST.json` | Ortak sürüm, Android versionCode, kaynak commit’i, Actions bağlantısı, dosya özetleri ve imza raporları |
| `SHA256SUMS.txt` | Manifest dahil dağıtılan bütün dosyaların SHA-256 özeti (kendisi hariç) |

ZIP’i tamamen çıkarın: `NetLurker.exe` ile `lang/` aynı konumda kalmalı.
Kurulum programı aynı uygulama kimliğini korur. Sessiz kaldırma ayar/cache silme
sorusu açmaz ve kullanıcı verisini silmez. Gerçek kurulum/yükseltme testi yine gereklidir.

## Bir kez yapılacak GitHub ayarları

**Settings → Actions → General** altında Actions’ın çalışmasına ve yayın işinin
`contents: write` iznine kurum/depo politikasının izin verdiğinden emin olun.
Yalnızca dosya yükleyen `publish` işi bu yazma iznini ister. Kişisel erişim token’ı
(PAT) gerekmez; yerleşik `GITHUB_TOKEN` kullanılır. Workflow’lar üçüncü taraf
aksiyonları commit SHA’sına sabitler; Dependabot bunları PR ile günceller.

**Aşağıdaki imza ayarları isteğe bağlıdır; Windows yayını için doldurmayın.**
İleride imzalı yayın istediğinizde **Settings → Secrets and variables → Actions** bölümünü kullanın.
Sırları issue, sohbet, kaynak kodu, build log’u veya release notlarına yazmayın.

### İleri kullanım — Android: kurulabilir ve güncellenebilir APK

Android imzası **ilk yayımdan itibaren aynı anahtarla** yapılmalı. Kaybolan/değiştirilen
anahtar mevcut kurulumların normal güncellenmesini engeller. Anahtarı güvenli,
çevrimdışı yedekleyin. Workflow kendiliğinden yeni anahtar oluşturmaz.

| Tür | Ad | İçerik |
|---|---|---|
| Secret | `ANDROID_KEYSTORE_BASE64` | Üretim JKS/PKCS12 dosyasının Base64 içeriği |
| Secret | `ANDROID_KEYSTORE_PASSWORD` | Keystore parolası |
| Secret | `ANDROID_KEY_ALIAS` | Üretim anahtarının alias’ı |
| Secret | `ANDROID_KEY_PASSWORD` | Anahtar parolası |
| Variable | `ANDROID_SIGNING_CERT_SHA256` | Beklenen üretim sertifikasının 64 haneli SHA-256 parmak izi; `:` ayraçları kabul edilir |

Parmak izini yerel olarak, parolayı komuta yazmadan inceleyebilirsiniz:

```sh
keytool -list -v -keystore /secure/location/netlurker-release.jks -alias netlurker
```

Workflow keystore’u geçici dizinde açar; parolaları `apksigner`a ortam değişkeniyle
aktarır. APK zipalign, imza, sertifika parmak izi, uygulama kimliği, sürüm ve debug
bayrağı kontrollerinden geçer. Geçici anahtar temizlenir; artifact olarak yüklenmez.
Normal CI/PR işlerine üretim imza sırları verilmez. CI aynı imzalama yolunu geçici
bir test anahtarıyla da çalıştırır; bu test APK’sı/anahtarı dağıtılmaz ve üretim imzası
doğrulanmış gibi sunulmaz.

- Android yayını **varsayılan olarak kapalıdır**. Anahtarlar mevcut olsa bile
  yalnızca bunları eklemek APK yayını başlatmaz.
- Android'i yayımlamak istediğinizde yukarıdaki ayarları tamamlayıp Variable
  **`REQUIRE_ANDROID_RELEASE=true`** yapın. Bu, Android'i hem açar hem zorunlu kılar.
- Açıkken eksik/yarım ayar, yanlış parmak izi veya imza doğrulama hatası yayını
  durdurur. Debug/imzasız APK hiçbir zaman onun yerine konulmaz.

### Windows: isteğe bağlı Authenticode

| Tür | Ad | İçerik |
|---|---|---|
| Secret | `WINDOWS_CERT_BASE64` | Dışa aktarılabilir kod imzalama PFX dosyası, Base64 |
| Secret | `WINDOWS_CERT_PASSWORD` | PFX parolası |

İkisi de varsa EXE **paketlenmeden önce**, yükleyici de oluşturulduktan sonra
zaman damgalı olarak imzalanır ve doğrulanır. İmza hatası yayını durdurur. İkisi de
yoksa dosyalar **UNSIGNED** olarak açıkça etiketlenir; imzalı gibi sunulmaz.
Sadece birinin tanımlı olması yapılandırma hatasıdır.

Variable **`REQUIRE_WINDOWS_SIGNATURE=true`** ile imzasız yayını tamamen engelleyebilirsiniz.
Donanım/HSM veya bulut tabanlı imza hizmetiniz varsa bu PFX yolu doğrudan uygun
olmayabilir; sağlayıcının imza adımını ayrıca entegre edin. Kod imzası SmartScreen
uyarısının kesinlikle görünmeyeceğini garanti etmez; korumaları kapatmayın.

## Yayımlamadan deneme / kurtarma

**Actions → Release → Run workflow**:

- **Branch:** denenecek kaynak dalı.
- **tag:** ör. `v6.0.1-rc.1`.
- **publish:** **kapalı** (varsayılan).
- **run-emulator:** yalnızca istediğinizde açık; ek runner süresi kullanır.

Bu hazırlık modu seçtiğiniz dalın commit’ini sürümlendirir ve aynı paketleme/imza
kontrollerini çalıştırır. Tag’in mevcut olması gerekmez. `NetLurker-release-assets`
artifact’ini üretir; release/tag oluşturmaz veya değiştirmez. Windows imza sırları yapılandırılmışsa
aday Windows paketi de imzalanır. Android ayrıca açıkça etkinleştirilmiş olmalıdır. Otomatik release’lerde emülatörü zorunlu yapmak için
Variable **`RELEASE_RUN_EMULATOR=true`** kullanın. Kapalıyken UI testleri derlenir,
çalıştırılmış gibi raporlanmaz. Fiziksel cihaz kontrolü ayrıca yapılmalıdır.

Yüklemede ağ hatası olursa **Re-run failed jobs** kullanın: hazırlanmış **aynı baytlar**
yeniden kullanılır. Özeti aynı olan mevcut dosyalar atlanır; farklı veya yarım dosya
üzerine yazılmaz. Başarısız iş açık hata verir. Yarım bir GitHub asset’i varsa önce
manuel inceleyin; sadece gerçekten başarısız yüklemeyi temizledikten sonra yeniden
deneyin. İndirilmeye başlanmış sürümün dosyalarını yeni derlemeyle sessizce değiştirmeyin.

`publish` açık manuel çalıştırma yalnızca **mevcut, yayımlanmış** release’i hedefler;
başka bir branch’in son commit’ini değil, belirtilen tag’in commit’ini derler. Tam
akışı yeniden başlatmak deterministik olmayan derleme baytlarını değiştirebilir;
çakışmada yükleme reddedilir. Yeni içerik için yeni sürüm/tag kullanın. Tag’in
kaynağı ve release kimliği derlemenin başında ve yükleme sırasında yeniden denetlenir.

## Sürüm politikası

Kaynak ağacının varsayılanı `version.json` dosyasıdır. Android Gradle bu dosyayı okur;
Windows `VERSIONINFO` aynı araçla güncellenir. Yayın sırasında tag’deki sürüm çalışma
kopyasına **derlemeden önce** uygulanır; kaynak tag’i/commit’i değiştirilmez. Manifest
bu dönüşümü açıkça kaydeder.

Desteklenen biçimler: `vMAJOR.MINOR.PATCH`, `-alpha.N`, `-beta.N`, `-rc.N`.
Baştaki sıfırlar, `+build` ve serbest metin kabul edilmez. Sınırlar:
major 0–209, minor/patch 0–99, aday sıra numarası 1–199.

Android kodu `major×10000000 + minor×100000 + patch×1000 + aşama`dır:
alpha `N`, beta `200+N`, rc `400+N`, kararlı `999`.
Böylece alpha → beta → rc → kararlı → sonraki yama yükseltmeleri artan versionCode
alır; en büyük değer Android’in 2.100.000.000 sınırının altındadır.
Önceden dağıttığınız bir APK varsa ilk yeni sürümün kodunun ondan yüksek olduğunu
ve sertifikasının aynı olduğunu ayrıca doğrulayın. Daha düşük sürüme dönmek için
eski tag’i yeniden yayınlamak yerine düzeltmeyi **daha yüksek sürümle** yayımlayın.

Yerel sürüm yükseltme ve Windows aday paketleme:

```sh
python tools/release_version.py --version 6.0.1
# Değişiklikleri inceleyip commit edin.
```

Ardından temiz kaynak ağacında, x64 Native Tools PowerShell ortamında:

```powershell
./tools/make_release.ps1 -Version 6.0.1
```

Yerel araç taze EXE, dil dosyaları, revizyon/sürüm işaretleri ve ZIP üretir;
yayınlamaz veya otomatik imzalamaz. İmzalama yardımcısı `tools/sign_release.ps1`.

## Dosya doğrulama

Release’teki tüm dosyaları aynı dizine indirip Linux/macOS uygun SHA-256 aracıyla:

```sh
sha256sum -c SHA256SUMS.txt
```

Windows’ta seçtiğiniz dosyanın sonucunu `SHA256SUMS.txt` girdisiyle karşılaştırın:

```powershell
Get-FileHash ./NetLurker-v6.0.1-win64.zip -Algorithm SHA256
Get-AuthenticodeSignature ./NetLurker-v6.0.1-setup.exe
```

Özetler bozulmayı/sürüm karışıklığını yakalar; yayıncı kimliğini tek başına ispatlamaz.
Build ve paket testleri de cihaz, gerçek sağlayıcı veya güvenlik denetiminin yerine geçmez.
