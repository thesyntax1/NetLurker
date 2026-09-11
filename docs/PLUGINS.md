# NetLurker Eklenti / Sağlayıcı Sistemi

NetLurker, yerleşik 5 istihbarat sağlayıcısına ek olarak **harici JSON sağlayıcı
eklentileri** çalıştırabilir:

| Yerleşik sağlayıcı | Veri |
|---|---|
| AbuseIPDB | Kötüye kullanım puanı + raporlar (isteğe bağlı anahtar) |
| DNS kara listeleri | Spamhaus SBL/XBL, Blocklist.de, Sorbs, Barracuda, UCEPROTECT |
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
| `name` | Görünen ad (risk notuna eklenir) |
| `exe` | Çalıştırılabilir dosyanın tam yolu |
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
| `risk` | 0–100 sayı; zorunlu. NetLurker'ın yerel tehdit puanıyla birleştirilir (yüksek olan kazanır) |
| `verdict` | İsteğe bağlı: `clean` / `suspicious` / `malicious` |
| `note` | İsteğe bağlı kısa açıklama (risk notuna eklenir) |

4. Çıkış kodu **0** olmalı; aksi halde sonuç yok sayılır.

### Örnek: PowerShell ile basit eklenti

`plugins\feed.ps1`:

```powershell
$ip = [Console]::In.ReadLine()
# kendi listenizi burada sorgulayin (dosya, REST API, DNSBL ...)
$bad = @('203.0.113.7','198.51.100.23')
if ($bad -contains $ip) {
  '{"risk": 85, "verdict": "malicious", "note": "yerel kara liste"}'
} else {
  '{"risk": 5, "verdict": "clean", "note": ""}'
}
```

`plugins\feed.json`:

```json
{
  "name": "Yerel kara liste",
  "exe": "powershell.exe",
  "args": "-NoProfile -ExecutionPolicy Bypass -File C:\\tools\\feed.ps1",
  "timeoutMs": 6000
}
```

> Güvenlik notu: Eklentiler NetLurker ile aynı haklarda çalışır. Yalnızca
> güvendiğiniz eklentileri kurun. NetLurker eklentiye yalnızca IP'yi iletir;
> başka hiçbir veri paylaşmaz.

## Sonuç nasıl kullanılır

- Eklenti puanı ≥ yerel puan ise **Tehdit** sütununa yansır.
- Puan ≥ 40 ise satırın **risk notuna** `Eklenti: <verdict> — <note>` eklenir.
- Eklenti puanı diğer sinyallerle birlikte kırmızı/turuncu risk bandını etkiler.
- Sorgu sonuçları diğer istihbarat verileriyle birlikte 7 gün önbelleklenir.
