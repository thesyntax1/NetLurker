# Yol haritası

Bu liste öncelikleri gösterir; sürüm tarihi veya özellik taahhüdü değildir.
Sürüm biçimi ve paketleme kuralları [Yayın rehberinde](RELEASES.md) bulunur.

## Mevcut kapsam

- Windows soket tablolarından bağlantı ve süreç bilgileri.
- Sağlayıcı sorguları, kural tabanlı risk açıklamaları ve isteğe bağlı AI analizi.
- Arama, filtreler, rapor dışa aktarma ve sekiz arayüz dili.
- Windows demo modu, ağ grafiği ve bağlantı sayısı geçmişine dayalı anomali işaretleri.
- JSON tanımlarıyla çalışan harici Windows eklentileri.
- Android'de cihaz ağı, paket bilgileri ve elle girilen hedeflerin incelenmesi.
- Windows ZIP/yükleyici paketleme, sürüm kontrolü ve SHA-256 dosyaları.

Platform kısıtları ve veri kaynakları [DATA-ACCURACY.md](DATA-ACCURACY.md) içinde
ayrıntılıdır. Bir özelliğin kodda bulunması, bütün cihazlarda doğrulandığı anlamına gelmez.

## Yayın öncesi

- [ ] Windows'ta normal/yönetici çalıştırma, farklı DPI değerleri ve yükleyici yükseltmesi.
- [ ] Fiziksel Android cihazında izin reddi, büyük yazı ve okunamayan sayaçlar.
- [ ] Sağlayıcı kesintisi, zaman aşımı, eksik anahtar ve başarısız sorgu senaryoları.
- [ ] Test edilen sürümden, özel bilgileri temizlenmiş ekran görüntüleri.
- [ ] Kısa kullanım videosunun kaydı. `docs/video/` içindeki dosyalar yalnızca kayıt planıdır.

Ayrıntılı kabul ölçütleri: [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md).
Android üretim yayını kapalıdır; imza kurulumu bu proje için şu anda bir yayın hedefi değildir.
Windows imzası da yapılandırılmadıkça paketler imzasız olarak belirtilir.

## Değerlendirilecek işler

Önce tekrarlanabilir hatalar, yanlış pozitifler ve ilk kullanım sorunları ele alınacak.
Bunlardan sonra değerlendirilebilecek işler:

- Windows'ta kısa ömürlü bağlantıları yakalamak için ETW olayları.
- Kullanılabilen EStats verisinden daha ayrıntılı süreç trafik geçmişi.
- Kullanıcı tanımlı bildirim eşikleri ve filtre kuralları.
- Uzun oturumlar için dosyaya JSONL olay kaydı.

Sürücü tabanlı izleme, bellek taraması ve merkezi yönetim mevcut kapsamın dışındadır.
Yeni bir özellik önerirken kullanım örneğini ve varsa veri kaynağını
[issue olarak](https://github.com/thesyntax1/NetLurker/issues/new/choose) paylaşabilirsiniz.
