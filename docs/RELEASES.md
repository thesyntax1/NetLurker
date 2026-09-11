# Sürümler, Bütünlük ve İmzalama

## Sürüm döngüsü

1. Kaynakta değişiklikler `main` dalına girer.
2. `vX.Y.Z` etiketi itilince GitHub Actions otomatik olarak:
   - MSVC ile `build.bat` derlemesi yapar,
   - `lang\` klasörünü pakete ekler,
   - (tanımlıysa) `WINDOWS_CERT_BASE64` sırrıyla imzalar,
   - `NetLurker-vX.Y.Z-win64.zip` + `SHA256SUMS` üretir,
   - GitHub Release oluşturur.
3. Sürüm notları otomatik üretilir; gerekirse elle düzenlenir.

```bash
git tag v6.0.0
git push origin v6.0.0
```

> **Kurulum notu:** Workflow dosyası `tools/release.workflow.yml` içinde saklanır.
> Etkinleştirmek için depo sahibi bunu bir kez
> `.github/workflows/release.yml` konumuna kopyalamalıdır (GitHub web arayüzünden
> "Add file → Create new file" ile aynı içerik yapıştırılabilir). Böylece workflow
> geçmişi ve izinleri depo sahibinin kendi hesabı altında oluşur.

## Yerel paketleme (Actions olmadan)

"x64 Native Tools Command Prompt" içinde:

```powershell
powershell -ExecutionPolicy Bypass -File tools\make_release.ps1 -Version 6.0.0
```

`build.bat` derlemesi + `lang` kopyalama + zip + `SHA256SUMS` üretir. Sürüm
numarası `res/netlurker.rc` içindeki `VERSIONINFO` kaynağından gelir.

## Bütünlük doğrulama (kullanıcı tarafı)

```powershell
Get-FileHash .\NetLurker.exe -Algorithm SHA256   # veya:
certutil -hashfile .\NetLurker.exe SHA256
```

Çıktıyı release sayfasındaki `SHA256SUMS` ile karşılaştırın.

## Kod imzalama

NetLurker açık kaynak bir projedir; resmi yapılar **EV/OV kod imzalama
sertifikası** ile imzalanmalıdır (SmartScreen itibarı ve bütünlük güvencesi
için). Sertifika edinme bir kimlik doğrulama süreci gerektirdiğinden
(github.com üzerinden tamamlanamaz), imzalama tamamen **hazır araçlarla**
bırakılmıştır:

```powershell
# PFX ile imzala + zaman damgası + doğrula
powershell -ExecutionPolicy Bypass -File tools\sign_release.ps1 `
    -File build\NetLurker.exe -Cert C:\secrets\codesign.pfx -Password "..."

# veya sertifika mağazasından (parmak iziyle)
powershell -ExecutionPolicy Bypass -File tools\sign_release.ps1 `
    -File build\NetLurker.exe -Thumbprint 00112233445566778899AABBCCDDEEFF00112233

# yalnızca doğrulama
powershell -ExecutionPolicy Bypass -File tools\sign_release.ps1 `
    -File build\NetLurker.exe -Verify
```

GitHub Actions'ta kullanmak için depo sırları:

| Sır | Değer |
|---|---|
| `WINDOWS_CERT_BASE64` | PFX dosyasının Base64 hali |
| `WINDOWS_CERT_PASSWORD` | PFX parolası |

## Yükleyici (isteğe bağlı)

`installer\NetLurker.iss` Inno Setup betiği; `make_release.ps1` çıktısını alıp
"Başlat menüsü kısayolu + `lang` klasörü + kaldırıcı" içeren tek kurulum dosyası
üretir. Taşınabilir zip varsayılan dağıtımdır; yükleyici yalnızca isteyenler
içindir.

## Dağıtım şeması

```
NetLurker-v6.0.0-win64.zip
├── NetLurker.exe        (x64, C++17, statik CRT — kurulum gerektirmez)
└── lang\
    ├── en.ini  (varsayılan İngilizce sözlük)
    ├── tr.ini  ├── es.ini  ├── de.ini  ├── fr.ini
    ├── ja.ini  ├── zh.ini  └── pt.ini
```
