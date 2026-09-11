# Güvenlik politikası

EveryPisi güvenlik açısından temkinli davranır; ancak aktif geliştirme
aşamasında olduğu için henüz her paket biçimi ve sistem ortamı için garanti
vermez.

## Güvenlik bildirimi

Güvenlik açığını public issue olarak yayımlamadan önce depo sahibiyle
iletişime geçin. GitHub deposundaki özel güvenlik bildirimi özelliğini veya
YunusTAS13 hesabına ait doğrulanmış iletişim kanalını kullanın.

Bildirime mümkünse şunları ekleyin:

- Etkilenen sürüm veya commit
- Yeniden üretme adımları
- Etkilenen paket biçimi
- Beklenen ve gerçekleşen davranış
- Zararsız bir test paketi veya minimal örnek

Gerçek kullanıcı paketlerini, gizli anahtarları veya kişisel verileri
bildirime eklemeyin.

## Güvenli kullanım

Dönüştürülen paketi kurmadan önce JSON uyumluluk raporunu inceleyin.
İmza, bağımlılık, ABI veya metadata kaybı uyarılarını açık onay seçenekleriyle
bastırmak yalnızca hedef sistem incelendikten sonra yapılmalıdır.

