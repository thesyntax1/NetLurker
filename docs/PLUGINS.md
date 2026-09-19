# NetLurker Eklenti / Sağlayıcı Sistemi

NetLurker, yerleşik 5 istihbarat sağlayıcısına ek olarak **harici JSON sağlayıcı
eklentileri** çalıştırabilir:

| Yerleşik sağlayıcı | Veri |
|---|---|
| AbuseIPDB | Kötüye kullanım puanı + raporlar (sorgu için anahtar gerekir) |
| DNS kara listeleri | Spamhaus SBL/XBL, Blocklist.de, Barracuda, UCEPROTECT |
| CIRCL pasif DNS | IP'nin geçmişte çözdüğü alan adları |
| RDAP / WHOIS | Ağ sahibi, organizasyon, abuse iletişimi, tahsis tarihi |
| VirusTotal | Topluluk tespitleri (isteğe bağlı anahtar) |
| **Eklentiler** | Sizin yazdığınız herhangi bir dış kaynak |

## Eklenti nasıl yazılır

`plugins` klasörüne bir JSON tanım dosyası ve çalıştırılabilir bir program
koymanız yeterli. NetLurker şu iki klasörü arar (ikisi de yüklenir):

1. `NetLurker.exe` yanındaki `plugins\` (taşınabilir)
2. `%APPDATA%\NetLurker\plugins\` (kullanıcıya özel)

### Tanım dosyası: `plugins\benim-kaynak.json`

```json
{
  "name": "Kurumsal tehdit beslemesi",
  "exe": "C:\\tools\\probe.exe",
  "args": "{ip}",
  "timeoutMs": 8000
}
```

| Alan | Açıklama |
|---|---|
| `name` | Tanım adı; aynı adla yüklenen tanım öncekinin yerini alır |
| `exe` | Çalıştırılabilir dosya; tam yol kullanılması önerilir |
| `args` | Komut satırı; `{ip}` sorgulanan IP ile değiştirilir |
| `timeoutMs` | En fazla bekleme süresi (500–60000 ms, varsayılan 8000) |

### Çalışma sözleşmesi

1. NetLurker eklentiyi her genel hedef IP için ayrı bir süreçte başlatır
   (eklenti başına kendi kopyası, `CREATE_NO_WINDOW`).
2. **stdin'e** tek satır halinde IP yazılır (ör. `8.8.8.8\n`).
3. Eklenti **stdout'a** JSON döndürür:

```json
{"risk": 72, "verdict": "malicious", "note": "Kurumsal beslememizde 3 isaret var"}
```

| Alan | Açıklama |
|---|---|
| `risk` | 0–100 sayı; zorunlu. Ayrı bir eklenti sonucu olarak saklanır |
| `verdict` | İsteğe bağlı: `clean` / `suspicious` / `malicious` |
| `note` | Sonuca eklenen isteğe bağlı açıklama |

4. Çıkış kodu **0** olmalı; aksi halde sonuç yok sayılır.

### Örnek: PowerShell ile basit eklenti

Bu örnek giriş/çıkış biçimini gösterir. Adresler dokümantasyon için ayrılmıştır;
bir adresin listede olmaması güvenli olduğunu göstermez.

`plugins\feed.ps1`:

```powershell
$ip = [Console]::In.ReadLine()
# kendi listenizi burada sorgulayin (dosya, REST API, DNSBL ...)
$bad = @('203.0.113.7','198.51.100.23')
if ($bad -contains $ip) {
  '{"risk": 85, "verdict": "malicious", "note": "yerel kara liste"}'
} else {
  '{"risk": 0, "verdict": "", "note": "Listede kayit yok; guvenlik degerlendirmesi yapilmadi"}'
}
```

`plugins\feed.json`:

```json
{
  "name": "Yerel kara liste",
  "exe": "powershell.exe",
  "args": "-NoProfile -File C:\\tools\\feed.ps1",
  "timeoutMs": 6000
}
```

> Eklentiler NetLurker ile aynı kullanıcı yetkileriyle çalışır; bir sandbox içinde
> değildir. stdin üzerinden IP verilmesi, eklentinin dosya veya ağ erişimini sınırlamaz.
> Yalnızca güvendiğiniz programları kullanın; sistemin script politikasını devre dışı bırakmayın.

## Sonucun kullanılması

- Bir sorguda en fazla dört eklenti çalıştırılır. Geçerli sonuçlardan en yüksek puan seçilir.
- Puan ve açıklama `pluginRisk` / `pluginNote` alanlarında ayrı tutulur; JSON dışa aktarımında
  `plugin_score` alanı bulunur. Sonuç AbuseIPDB puanının yerine konulmaz ve onun risk
  kurallarına eklenmez.
- Eklenti puanı tek başına genel risk puanını veya renk bandını yükseltmez.
- Sonuçlar bellek önbelleğinde tutulur; birleşik tehdit disk önbelleği kullanılmaz.
- Zaman aşımı, sıfırdan farklı çıkış kodu veya geçersiz sonuç, temiz kayıt anlamına gelmez.
