# EveryPisi araştırma ve tasarım notları

Bu belge, EveryPisi'nin “arşivi açıp yeniden sıkıştıran” bir araç olmaması için
dayandığı format ve güvenlik kararlarını kaydeder.

## Pisi Linux hedefi

Pisi 1.2 binary paketinin dış kabı ZIP'tir ve şu üyeleri içerir:

- `metadata.xml`
- `files.xml`
- `install.tar.xz`

`metadata.xml` içindeki zorunlu hedef bilgilerinden `Distribution=PisiLinux`,
`DistributionRelease`, `Architecture`, `InstalledSize` ve `PackageFormat=1.2`
üretilir. `files.xml` dosya yolu, türü, boyutu, UID/GID, modu ve SHA-1 bilgisini
taşır. `install.tar.xz` içindeki dosya sahipliği ve izinleri de manifest ile
aynı tutulur.

Güncel stable2 paketlerinde dağıtım kimliği `PisiLinux`, release değeri `2.0`,
kimlik `p2` ve x86_64 mimarisi kullanıldığı için EveryPisi’nin varsayılan hedefi
bu değerlerdir; farklı hedefler açık CLI seçeneğiyle belirtilmelidir.

Pisi'nin gerçek kaynak kodu ve resmi depodan alınan bir `zlib` paketi bu
şemanın doğrulanmasında kullanıldı. Resmi depodaki bazı eski paketlerde
`InstallTarHash` değeri arşivin gerçek hash'iyle uyuşmayabildiği görüldü; bu
nedenle validator varsayılan olarak resmi paketleri kabul eder, EveryPisi'nin
ürettiği paketlerde ise hash kontrolü katı uygulanır.

## Kaynak formatları

### Debian

`ar` dış kabı, doğru sıradaki `debian-binary=2.0`, `control.tar.*` ve
`data.tar.*` üyeleri ayrıştırılır; Debian’ın izin verdiği `_` ile başlayan
ara üyeler dışında belirsiz sıra reddedilir. `Depends`, `Pre-Depends`, öneriler,
alternatifler, Debian sürüm kısıtları, `Breaks`, `Replaces` ve maintainer
script'leri analiz edilir. Script'ler hiçbir koşulda çalıştırılmaz veya Pisi
payload'ına kopyalanmaz.

### RPM

RPM v4 lead/header yapısı, header veri tipleri, gzip/bzip2/xz/lzma/zstd payload
ve `newc`/CRC CPIO okunur. RPM'nin belgelenmiş `07070X` stripped-CPIO
varyantında dosya adları, boyutlar, modlar, sahipler ve hardlink ilişkileri
header dizilerinden alınır; payload kaydı yalnızca indeks ve içerik taşır.
RPM iç kabiliyetleri (`rpmlib`, `rtld`) işletim sistemi bağımlılığı gibi yanlış
yorumlanmaz. Header/payload digest alanları, mevcut olduklarında, dönüşümden
önce doğrulanır; `FileDigests` ve `FileDigestAlgorithm` mevcutsa çıkarılan
dosyalar da tek tek karşılaştırılır. RPM v6’nın ek SHA-256/SHA3-256 ve SHA-512
alanları mevcut olduğunda ayrıca kontrol edilir. ELF `NEEDED`, SONAME,
interpreter, RPATH/RUNPATH ve sürümlü sembol gereksinimleri ayrıca incelenir;
`DT_NEEDED` bağımlılıkları paket metadata’sında bulunmasa bile runtime listesine
eklenir.
RPM v4'te signature-header tag numaraları main-header tag'leriyle çakışabildiği
 için v4'ün `PGP/GPG/MD5` (1002/1005/1004) alanları ile v6/uyumluluk
 `259/262/261` alanları ayrı ele alınır; v6 OpenPGP imzaları 278 tag'ındaki
 base64 dizi üzerinden header bölgesinde doğrulanır. CRC'li CPIO (`070702`) için
 içerik toplamı da kontrol edilir.

### Arch

`.PKGINFO` ve `.INSTALL` metadata olarak okunur; payload içindeki traversal,
duplicate üyeler, forward hardlink, özel dosya ve symlink davranışları güvenli
çıkarma kurallarıyla denetlenir. `.pkg.tar.zst` dahil sıkıştırma biçimleri
desteklenir ve `.MTREE` bütünlük manifesti varsa doğrulanır.

## Güvenlik politikası

- Yabancı kurulum/kaldırma script'leri analiz edilir, çalıştırılmaz ve varsayılan
  olarak dönüşüm reddedilir.
- Mutlak yollar, `..` traversal, bozuk arşiv boyutları ve özel cihaz/FIFO
  girdileri reddedilir veya payload dışı bırakılır; payload’dan düşen özel
  girdiler ayrıca metadata kaybı olarak işaretlenir ve varsayılan dönüşüm
  durdurulur.
- Hedef mimari ve ELF makinesi, bitness'i veya dinamik loader/interpreter'ı
  uyuşmuyorsa dönüşüm reddedilir. Şu an ELF hedef profilleri `x86_64`,
  `aarch64` ve `i686` için tanımlıdır.
- Pisi repository index'i cache'e alınmadan önce `.sha1sum` ile doğrulanır;
  özel indeksler de aynı doğrulamayı `--repo-index-sha1` ile kullanabilir.
  CLI, özel indeks checksum ile doğrulanmadan dependency truth olarak
  kullanılmasını varsayılan olarak reddeder; yalnızca ayrı
  `--allow-unverified-repository` onayı bu kapıyı açar.
  Uzak indeksler HTTP üzerinden kabul edilmez; checksum, güvenli taşıma
  yerine geçmediği için yalnızca HTTPS kullanılır.
- İndeksin üst seviye dağıtım kimliği, release değeri ve bildirilen mimarileri
  okunur; CLI, istenen `PisiLinux`/`2.0`/hedef mimariyle uyuşmayan doğrulanmış
  veya yerel indeks üzerinde bağımlılık çözümlemesini başlatmaz.
- Her çıktı ZIP/XML/TAR içeriği ve `InstallTarHash` ile dönüşüm sonunda yeniden
  doğrulanır.
- Analiz ve dönüşüm raporları kaynak/çıktı boyutlarını ve SHA-256/SHA-512
  özetlerini kaydeder; bu özetler arşivin rapor sonrasında değiştirilip
  değiştirilmediğini denetlemeye yarar.
- Dış ZIP üyeleri sabit zaman/izin bilgileriyle yazılır; `SOURCE_DATE_EPOCH`
  verildiğinde metadata tarihi de sabitlenerek tekrar üretilebilir çıktı alınır.
- Aynı doğrulama bağımsız olarak `everypisi validate PACKAGE` komutuyla da
  çalıştırılabilir.
- İmzalı kaynak paketin imzası keyring olmadan “doğrulandı” kabul edilmez;
  parser, imza verisini yürütmeden yalnızca paket içeriğini analiz eder. RPM
  içinde imza bulunduğu halde keyring doğrulaması yapılamazsa dönüşüm
  varsayılan olarak durur. Kullanıcı `--rpm-keyring` verirse gömülü header
  veya header+payload OpenPGP imzası izole `gpgv` çağrısıyla doğrulanır;
  doğrulama başarısızsa yalnızca `--allow-unverified-signature` açık
  onayıyla devam edilir. Bu doğrulama yolu geçici bir test anahtarıyla
  otomatik olarak da sınanır.
  Üretim kullanımı için dağıtım anahtar zincirinin güncel anahtarlarla
  yönetilmesi ayrıca gereklidir.
- RPM’nin header/payload digest alanları mevcutsa doğrulanır; OpenPGP imzasının
  varlığı raporlanır fakat keyring doğrulaması yapılmadan güvenilir kabul edilmez.
- Arch detached `.sig` ve aynı modeli kullanan kaynaklar, kullanıcı tarafından
  verilen keyring ile `gpgv` üzerinden bütün kaynak arşivine karşı doğrulanır;
  keyring olmadan detached imza doğrulanmış sayılmaz. Debian paketlerindeki
  imza modeli ise çoğunlukla `debsig-verify` policy/keyring düzeniyle ele
  alınmalıdır; EveryPisi `_gpg*`/`_sig*` üyelerini tespit eder, varsayılan
  olarak doğrulanmamış imza sayar ve bunu otomatik olarak Debian archive trust
  zinciri varsayımıyla geçmez. Kullanıcı açıkça policy ve keyring dizinleri
  verirse `debsig-verify` 30 saniye timeout ile çalıştırılır.
- Pisi 1.2 relation şeması yalnızca kapsayıcı sürüm sınırları taşıdığı için
  yabancı `<`/`>` kısıtları varsayılan olarak reddedilir; yaklaşık dönüşüm ancak
  `--allow-lossy-relations` ile açıkça kabul edilir ve rapora yazılır.
- Pisi sürüm ayrıştırıcısı `-`/RPM release suffix gibi yabancı biçimleri kabul
  etmediği için RPM version ile release ayrıştırılır; sayı dışı release veya
  geçersiz version güvenli Pisi biçimine normalize edilir, metadata kaybı
  işaretlenir ve varsayılan dönüşüm durdurulur.
- Debian `md5sums` manifesti mevcutsa her listelenen regular file doğrulanır;
  Debian dokümantasyonundaki gibi bu bütünlük kontrolü tek başına authenticity
  veya güvenlik imzası sayılmaz.
- Arch `.MTREE` mevcutsa gzip içeriği parse edilerek payload’daki tüm dosyaların
  türü, boyutu, SHA-256 hash’i, symlink hedefi ve UID/GID/mod bilgisi kontrol edilir.
- POSIX ACL, xattr ve file capability metadata’sı plain filesystem staging ile
  kaybolabileceği için tespit edilir ve varsayılan olarak dönüşüm reddedilir.
- Debian virtual `Provides`, RPM capability ve Arch `provides` ilişkileri Pisi
  1.2’de genel bir Provides alanı bulunmadığı için varsayılan olarak kayıp
  metadata sayılır; yalnızca açık onayla dönüştürülür ve raporlanır.
- RPM 4.13+ boolean/rich dependency sözdizimi (`and`, `or`, `if`, `with` ve
  benzerleri) resmi RPM belgelerinde ayrı bir ifade ağacı olarak tanımlanır.
  Pisi 1.2 bunu ifade edemediği için EveryPisi bu ilişkileri sahte paket adına
  indirgemez; relation’ı çıkarır, kaybı raporlar ve varsayılan dönüşümü durdurur.
- Debian multi-arch gibi mimari nitelemeli runtime bağımlılıkları Pisi 1.2’ye
  mimari bilgisi kaybedilmeden taşınamadığı için varsayılan olarak reddedilir;
  explicit metadata kaybı onayı olmadan genel bağımlılığa indirgenmez.
- Debian `triggers` ve RPM file/transaction trigger tag’leri de Pisi’ye
  otomatik olarak çevrilmez; bu tür paketler native rebuild veya açık risk
  onayı gerektirir.
- Pisi relation şemasındaki `release`, `releaseFrom` ve `releaseTo` alanları
  native kaynak koddan doğrulandı; EveryPisi bunları repository indeksinin en
  güncel `History/Update` kaydıyla kontrol eder ve çıktı metadata’sına taşır.
  Sayısal olmayan release değerleri güvenilir uyumluluk kanıtı sayılmaz.
- Girdi boyutu 1 GiB, açılmış veri boyutu 2 GiB, arşiv üye sayısı bir milyon ve
  üye yolu 4096 byte ile sınırlandırıldı. Python
  standard-library decompressor’ları ve mevcutsa dış zstd/lz4/lzip/lzop
  süreçleri çıktı akışı okunurken bu sınıra tabi tutulur; sınır aşımı kaynak
  paket dönüştürülmeden durdurulur.

## Dönüşüm ve yeniden derleme ayrımı

Binary repackaging, yabancı dosyaları Pisi arşivine taşır; Debian maintainer
script'lerinin, RPM scriptlet'lerinin, Arch `.INSTALL` hook'larının ve COMAR
entegrasyonlarının davranışını otomatik olarak Pisi'ye çevirdiğini iddia etmez.
Bu davranışlar için Pisi `pspec.xml` + `actions.py` ile native rebuild backend'i
kullanılır. EveryPisi bu backend'i güvenlik bayraklarını gevşetmeden çağırır.

## Kalan üretim seviyesi çalışmalar

1. Pisi Linux 2.x (resmî paket metadata’sındaki `DistributionRelease=2.0`)
   üzerinde farklı güncel sistem release’leriyle gerçek `pisi it`/transaction
   test matrisi.
2. RPM/Arch imza zinciri ve Debian Release/InRelease doğrulaması.
3. ELF symbol-version, ABI, glibc/libstdc++ ve kernel özellikleri için daha
   kapsamlı hedef ortam matrisi.
4. xattr, POSIX ACL, file capabilities ve trigger semantiğinin Pisi
   karşılıkları.
5. Pisi transaction'ının resmî Pisi Linux 2.x imajları ve daha geniş paket
   matrisiyle sınanması; geçici kökte bağımlılık, `Replaces`, hardlink ve
   symlink davranışları zaten gerçek Pisi işlem motoruyla doğrulandı.

Mevcut doğrulama turunda Pisi kaynak kodu ve `piksemel` ile izole bir Python
ortamı kuruldu; gerçek Debian, RPM ve Arch girdilerinden üretilen üç `.pisi`
çıktısı Pisi’nin `pisi.package.Package` okuyucusuyla başarıyla açıldı. Debian
ve RPM örnekleri stable2 bağımlılık grafiğiyle strict modda üretildi; Arch
örneği ise ELF incelemesinde `libc.so.6 >= 2.43` istediği, mevcut stable2
indeksinde ise glibc 2.42 bulunduğu için varsayılan modda doğru biçimde
reddedildi ve yalnızca `--allow-unresolved` ile raporlu olarak üretildi. Bu,
paket şeması uyumluluğunu ve Pisi’nin kendi `install.tar.xz` okuyucusuyla
çıkarma yapılabildiğini doğrular; tam sistem kurulum imajı matrisi ise ayrıca
gereklidir.

Ayrıcalıklı, geçici bir hedef kökte Pisi transaction smoke testi de yapıldı:
bağımlılıksız bir EveryPisi paketi gerçek `pisi it` ile kuruldu ve `pisi check`
ile bütünlük kontrolü `OK` döndü. İkinci testte iki EveryPisi paketi aynı
transaction’da runtime bağımlılığıyla kuruldu; üçüncü testte önce eski paket,
sonra `Replaces` ilişkili yeni paket kuruldu ve eski paket Pisi tarafından
otomatik kaldırıldı. Testler kaynak ağacının eski varsayılanı yerine geçici
PisiLinux 2.0 dağıtım ayarlarıyla ve `--ignore-check` kullanılmadan çalıştırıldı;
yalnızca COMAR entegrasyonu kapatıldı. Bu testler sadece geçici hedef kökte
çalıştırıldı; resmî Pisi Linux kurulum imajındaki tam sistem matrisi ayrıca
gereklidir.

Aynı kökte regular file, hardlink ve symlink içeren bir paket de kuruldu;
Pisi’nin kurduğu hardlink aynı inode’u korudu, symlink hedefi korundu ve
`pisi check` sonucu `OK` oldu. Resmî stable2 indeksinin gerçek bağımlılık grafiği
de kullanılarak Debian ve RPM örneklerinde doğrudan ve transitif çözümleme
başarılı oldu; raporlar eksik transitif düğüm listesini ayrıca taşır.

Bu maddeler tamamlanmadan “her yabancı paket kusursuz biçimde kurulabilir”
sonucu verilmez; araç, güvenli biçimde doğrulanamayan paketi açık gerekçeyle
reddeder.

## Kaynaklar

- [Pisi Linux paket yapımı](https://developer.pisilinux.org/page/4/paket-yapimi)
- [Pisi kaynak kodu](https://github.com/pisilinux/pisi)
- [Pisi stable repository index](https://stable2.pisilinux.org/)
- [Debian `.deb` formatı](https://manpages.debian.org/testing/dpkg-dev/deb.5.en.html)
- [Debian debsig-verify](https://manpages.debian.org/testing/debsig-verify/debsig-verify.1.en.html)
- [Debian paket imzalama](https://www.debian.org/doc/manuals/securing-debian-manual/deb-pack-sign.en.html)
- [RPM v4 formatı](https://rpm.org/docs/4.20.x/manual/format_v4.html)
- [RPM v6 formatı (taslak)](https://rpm.org/docs/latest/manual/format_v6.html)
- [RPM tag tablosu](https://rpm.org/docs/latest/manual/tags)
- [RPM boolean/rich dependencies](https://rpm.org/docs/latest/manual/boolean_dependencies)
- [RPM dependency API (`rpmds`)](https://rpm.org/docs/latest/api/rpmds_8h.html)
- [Arch package format açıklaması](https://wiki.archlinux.org/title/User%3AApg)
