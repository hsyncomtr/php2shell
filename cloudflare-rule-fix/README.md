# Cloudflare özel kuralı (php2shell) - RESMİ OLMAYAN, GEÇİCİ

Panel: **Security -> WAF -> Custom rules**. Eylem: **Block** (Engelle).

> Cloudflare, Free dahil tüm planlarda php2shell için **yönetilen WAF kuralları**
> yayımladı. Bu koruma bölgenizde zaten etkin olabilir. Aşağıdaki kurallar ek,
> açık kontrol içindir.

## Önerilen: multipart'ı engelle, kapsamlı, yükleme yolları hariç

```
(any(lower(http.request.headers["content-type"][*]) contains "multipart/form-data"))
and (http.request.method in {"POST" "PUT" "PATCH"})
and not (http.request.uri.path in {"/upload" "/api/upload" "/wp-admin/async-upload.php"})
```

`contains "multipart/form-data"` ayrıca virgüllü varyantı da yakalar
(`multipart/form-data,boundary=x`) — PHP bunu hâlâ multipart olarak ele alır.
PUT/PATCH dahildir çünkü PHP 8.4'ün `request_parse_body()` fonksiyonu bu
metotlarda da multipart ayrıştırır. Yükleme-yolu izin listesini uygulamanıza
göre uyarlayın. Bu, diğer tüm yollardaki meşru yüklemeleri yine engeller.

## Cerrahi (Kurumsal plan, istek-gövdesi incelemesi): yalnızca PoC alanını engelle

```
any(http.request.body.form.names[*] == "PHP_SESSION_UPLOAD_PROGRESS")
```

Yalnızca `PHP_SESSION_UPLOAD_PROGRESS` form alanını taşıyan istekleri engeller;
normal yüklemeler çalışmaya devam eder. Özel kurallara istek gövdesinin
sunulduğu bir plan gerekir. php.ini içinde `session.upload_progress.name`
değerini değiştirdiyseniz o adı kullanın.

## PHPSESSID üzerine engelleme YAPMAYIN

Yaygın olarak paylaşılan bir parçacık, cookie'sinde veya sorgu dizisinde
`phpsessid` geçen HER istediği engelliyor. Onu kullanmayın:

- **Normal ziyaretçileri bozar.** `PHPSESSID` PHP'nin varsayılan oturum
  cookie'sidir; oturumu olan herkes (giriş, sepet, panel) çoğu istekte gönderir.
  Engellemek siteyi onlar için düşürür.
- **Exploit ile eşleşmez.** PoC `PHP_SESSION_UPLOAD_PROGRESS` form alanını
  kullanır, `PHPSESSID` cookie'sini değil; yükleme-ilerlemesi, cookie hiç
  olmadan multipart alanından oturum başlatabilir.
- **Atlatılabilir.** `session_name()` ile özel oturum adı belirleyen
  uygulamalar `PHPSESSID` sabitiyle hiç eşleşmez.

Her zamanki gibi: WAF, multipart'ı PHP'den farklı ayrıştırır; bunlar geçici
çözümlerdir ve gerçek çözüm PHP'yi güncellemektir.
