Eğitim amaçlı: Bot vs İnsan davranışı simülatörü

UYARI
- Bu örnek "cloaking" (arka planda botlara farklı içerik gösterme) tekniğinin nasıl çalıştığını göstermek için SADECE yerel ortamda kullanılmalıdır.
- Canlı web sitelerinde arama motorlarını veya servis sağlayıcıları yanıltmak politikaları ihlal eder ve hesap kapatılmasına veya arama motoru cezasına yol açabilir. Gerçek dünyada uygulamayın.

Amaç
- Okul projesi için: bot (ör. Googlebot) ile normal kullanıcı arasında sunucu tarafında nasıl farklı davranış gösterilebileceğini "gözlemlemek".
- Güvenli bir lab ortamında test etme ve sonuçları raporlamak.

Nasıl çalıştırılır (yerel)
1) Node.js yüklü olduğundan emin olun (>= 14)
2) Terminalde bu klasöre gelin:
   cd /workspaces/nakliye/simulator
3) Sunucuyu başlatın:
   node app.js
4) Tarayıcıda veya curl ile test edin:
   # Normal kullanıcı görünümü
   curl -i http://localhost:8080/

   # Googlebot gibi davranan istek
   curl -i -A "Googlebot/2.1 (+http://www.google.com/bot.html)" http://localhost:8080/

   # Redirect davranışı (örnek query ile)
   curl -i "http://localhost:8080/redirect?gclid=test"
   curl -i -A "Googlebot/2.1" "http://localhost:8080/redirect?gclid=test"

Ne incelenmeli (ödev için öneriler)
- Hangi header'ların (User-Agent, Referer, IP) farklı davranış tetiklediğini not edin.
- Bot simülasyonu ile gerçek kullanıcı davranışını karşılaştırın.
- Etik ve politika kısmında neden canlı sitelerde kullanılmaması gerektiğini açıklayın.

Uyarı: Bu kodu asla üretim/gerçek siteye deploy etmeyin. Sadece yerel test ve raporlama amaçlıdır.
