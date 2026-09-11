# EveryPisi

EveryPisi, Debian `.deb`, RPM `.rpm` ve Arch paketlerini Pisi Linux için analiz eden, güvenli biçimde doğrulayan ve mümkün olduğunda gerçek Pisi `.pisi` paketine dönüştüren bir paket uyumluluk aracıdır.

> **Durum: Aktif geliştirme aşamasında**
>
> EveryPisi şu anda üretim sistemlerinde her yabancı paketin çalışacağını garanti etmez. Güvenli biçimde doğrulanamayan veya hedef Pisi ortamıyla uyumsuz paketleri açık gerekçeyle reddeder.

## Amaç

Farklı Linux dağıtımlarının paket biçimleri yalnızca farklı arşiv uzantılarından ibaret değildir. Bağımlılık sözdizimi, dosya sahipliği, kurulum betikleri, imza modeli, ABI ve dağıtım politikaları da farklıdır.

EveryPisi bu farkları görünür hâle getirir:

- Paketi kurmadan ve yabancı kurulum kodunu çalıştırmadan inceler.
- Arşiv yapısını, dosya yollarını ve dosya türlerini güvenlik sınırları içinde denetler.
- Doğrudan ve transitif çalışma zamanı bağımlılıklarını Pisi deposuna göre çözer.
- Uyumlu içerikleri Pisi 1.2 paket yapısına dönüştürür.
- Kaynak paket ile oluşturulan çıktı için denetlenebilir hash ve JSON raporu üretir.
- İkili yeniden paketleme ile kaynak koddan native Pisi derlemesini birbirinden ayırır.

## Özellikler

### Paket biçimleri

- Debian `.deb`: `ar` dış kabı, `control.tar.*`, `data.tar.*`, bağımlılıklar, sürüm kısıtları, `Breaks`, `Replaces`, `md5sums` ve maintainer betikleri.
- RPM `.rpm`: RPM v4 lead/header yapısı, standart ve stripped CPIO, digest alanları, OpenPGP imzaları, scriptlet'ler, dosya digest'leri ve RPM sürüm/release ilişkileri.
- Arch: `.PKGINFO`, `.INSTALL`, `.MTREE`, sıkıştırılmış payload, detached imza ve güvenli hardlink/symlink denetimleri.

### Güvenlik

- Mutlak yol, `..` geçişi ve arşiv dışına yazma girişimleri engellenir.
- Duplicate üyeler, çakışan dosya türleri ve güvenli olmayan forward hardlink'ler reddedilir.
- Device, FIFO, SUID/SGID, xattr, ACL ve file capability gibi riskli veya taşınamayan metadata tespit edilir.
- Compression bomb riskine karşı giriş boyutu, açılmış veri boyutu, üye sayısı ve yol uzunluğu sınırlandırılır.
- Debian, RPM ve Arch bütünlük bilgileri mevcut olduğunda doğrulanır.
- İmza keyring olmadan hiçbir imza güvenilir kabul edilmez.
- Maintainer betikleri, RPM scriptlet'leri, Arch `.INSTALL` hook'ları ve trigger'lar çalıştırılmaz.

### Uyumluluk

- Hedef mimari ve ELF machine türü karşılaştırılır.
- ELF bitness ve dynamic loader/interpreter kontrol edilir.
- `DT_NEEDED`, SONAME, RPATH/RUNPATH ve sürümlü sembol gereksinimleri raporlanır.
- Pisi stable2 repository index'i doğrulanmışsa doğrudan ve transitif bağımlılık grafiği taranır.
- Pisi'nin ifade edemediği RPM rich/boolean bağımlılıkları veya sanal `Provides` alanları sahte paket adına dönüştürülmez.
- Sürüm ve release kısıtları mümkün olduğunda Pisi metadata'sına aktarılır.
- Güvenli ve kayıpsız olmayan dönüşümler varsayılan olarak durdurulur; riskli seçenekler açık onay gerektirir.

## Kurulum

Python 3.10 veya daha yeni bir sürüm gerekir. Çekirdek uygulamanın zorunlu üçüncü taraf Python bağımlılığı yoktur.

Kaynak kodundan:

```bash
git clone https://github.com/YunusTAS13/EveryPisi.git
cd EveryPisi
python3 -m pip install .
```

İsteğe bağlı sistem araçları:

- RPM imzası ve detached OpenPGP doğrulaması için `gpgv`
- RPM'nin desteklediği ancak Python standart kütüphanesinde bulunmayan sıkıştırmalar için ilgili dış açıcılar
- Daha ayrıntılı ELF incelemesi için `readelf`

## Komutlar

```bash
# Paketi kurmadan analiz et
everypisi inspect PAKET

# JSON uyumluluk raporu üret
everypisi inspect PAKET --json

# Mevcut Pisi paketini doğrula
everypisi validate PAKET.pisi --strict-install-tar-hash

# Uygun paketi Pisi paketine dönüştür
everypisi convert PAKET --output-dir ./out

# Native Pisi reçetesinden yeniden derle
everypisi rebuild RECIPE_DIR --output-dir ./out
```

Ayrıntılı seçenekler:

```text
everypisi inspect PACKAGE [--json] [--rpm-keyring KEYRING]
                  [--detached-signature SIG --keyring KEYRING]
                  [--debsig-policies-dir DIR --debsig-keyrings-dir DIR
                   [--debsig-root DIR]]

everypisi validate PACKAGE [--strict-install-tar-hash]

everypisi convert PACKAGE --output-dir OUT
                  [--repo-index INDEX [--repo-index-sha1 HEX] | --offline]
                  [--dependency-map MAP.json]
                  [--rpm-keyring KEYRING]
                  [--detached-signature SIG --keyring KEYRING]
                  [--debsig-policies-dir DIR --debsig-keyrings-dir DIR
                   [--debsig-root DIR]]
                  [--allow-unresolved]
                  [--allow-foreign-scripts]
                  [--allow-privileged-files]
                  [--allow-unsupported-metadata]
                  [--allow-lossy-relations]
                  [--allow-unverified-signature]
                  [--allow-unverified-repository]
```

## Dönüşüm politikası

Varsayılan hedef `PisiLinux 2.0 / p2 / x86_64` değerleridir. Desteklenen ELF hedefleri:

- `x86_64`
- `aarch64`
- `i686`

EveryPisi, bir paketin yalnızca arşiv olarak açılabilmesini yeterli kabul etmez. Şu durumlarda dönüşüm varsayılan olarak reddedilebilir:

- Çalışma zamanı veya transitif bağımlılık çözülemiyorsa
- Hedef mimari ya da ELF ABI uyumsuzsa
- Script, trigger veya taşınamayan metadata varsa
- RPM rich/boolean relation kaybı oluşacaksa
- Güvenlik imzası mevcut olup doğrulanamıyorsa
- Sürüm/release bilgisi Pisi biçiminde güvenilir biçimde ifade edilemiyorsa

`--allow-unresolved`, `--allow-unsupported-metadata`, `--allow-lossy-relations` ve benzeri seçenekler güvenlik kapılarını bilinçli biçimde gevşetir. Bu seçenekler yalnızca paket içeriği ve hedef sistem incelendikten sonra kullanılmalıdır. Her onay JSON raporuna kaydedilir.

## Pisi çıktısı

Üretilen paket gerçek Pisi 1.2 yapısındadır:

- `metadata.xml`
- `files.xml`
- `install.tar.xz`

Dosya yolu, türü, boyutu, UID/GID, izinleri ve SHA-1 manifesti çıktıda korunur. ZIP, XML ve TAR içeriği dönüşüm sonunda tekrar doğrulanır. `SOURCE_DATE_EPOCH` ayarlanırsa mümkün olduğunca tekrarlanabilir çıktı üretilir.

## Native rebuild

Binary yeniden paketleme, yabancı dağıtım betiklerinin davranışını Pisi'ye çevirdiği anlamına gelmez. Servis kaydı, COMAR entegrasyonu, trigger ve dağıtıma özgü kurulum işlemleri için `pspec.xml` ve `actions.py` içeren native Pisi reçetesi kullanılmalıdır.

`rebuild` backend'i Pisi'yi sandbox, check ve safety seçeneklerini kapatmadan çalıştırır.

## Sınırlar

Bu proje aktif geliştirme aşamasındadır. Henüz şu sonuçlar garanti edilmez:

- Her Debian, RPM veya Arch paketinin tek komutla çalışması
- Farklı glibc, libstdc++, kernel ve ABI ortamları arasında tam eşdeğerlik
- xattr, POSIX ACL, file capability ve trigger davranışlarının eksiksiz aktarımı
- Debian archive, RPM ve Arch anahtar zincirlerinin her kurulum ortamında otomatik yönetimi
- Pisi Linux'un tüm sürüm ve mimarileri için tam sistem kurulum matrisi

Uyumluluk raporunu ve gerekçeli ret mesajlarını incelemeden dönüştürülmüş paketi üretim sistemine kurmayın.

## Geliştirme

Testleri çalıştırmak için:

```bash
python3 -m compileall -q src tests
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Mevcut doğrulama kapsamında 65 test geçmektedir. Gerçek Debian, RPM ve Arch paketleri Pisi paketine dönüştürülmüş; çıktılar strict validator ve Pisi'nin kendi paket kurulum motoruyla geçici hedef köklerde sınanmıştır.

Araştırma ve tasarım kararları [RESEARCH.md](RESEARCH.md) dosyasında açıklanmıştır.

## Araştırma kaynakları

- [Pisi Linux paket yapımı](https://developer.pisilinux.org/page/4/paket-yapimi)
- [Pisi kaynak kodu](https://github.com/pisilinux/pisi)
- [Pisi stable2 repository index](https://stable2.pisilinux.org/)
- [Debian .deb formatı](https://manpages.debian.org/testing/dpkg-dev/deb.5.en.html)
- [Debian debsig-verify](https://manpages.debian.org/testing/debsig-verify/debsig-verify.1.en.html)
- [RPM v4 formatı](https://rpm.org/docs/4.20.x/manual/format_v4.html)
- [RPM v6 formatı](https://rpm.org/docs/latest/manual/format_v6.html)
- [RPM boolean/rich dependencies](https://rpm.org/docs/latest/manual/boolean_dependencies)
- [Arch paket formatı](https://wiki.archlinux.org/title/User%3AApg)

## Lisans

Bu proje [GNU Affero Genel Kamu Lisansı sürüm 3](LICENSE) ile lisanslanmıştır.

