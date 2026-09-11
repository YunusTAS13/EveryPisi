# Katkı rehberi

EveryPisi aktif geliştirme aşamasındadır. Katkılar; güvenlik, doğrulanabilirlik,
Pisi uyumluluğu ve test edilebilirlik öncelikleriyle değerlendirilir.

## Geliştirme ortamı

Python 3.10 veya daha yeni bir sürüm kullanın:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

## Test

Değişiklik göndermeden önce:

```bash
python3 -m compileall -q src tests
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Yeni bir parser, güvenlik kuralı veya dönüşüm davranışı ekleniyorsa ilgili
başarılı ve başarısız durumlar için test de eklenmelidir. Yabancı paketlerin
kurulum betikleri test sırasında çalıştırılmamalıdır.

## Pull request

Pull request açıklaması Türkçe olmalı ve şunları içermelidir:

- Değişikliğin amacı
- Güvenlik etkisi
- Eklenen veya güncellenen testler
- Bilinen sınırlamalar
- Gerekirse örnek JSON raporu veya örnek paket davranışı

Her değişiklik AGPL-3.0 koşulları altında yayımlanır.

