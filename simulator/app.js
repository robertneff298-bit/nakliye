// Basit yerel simülatör — eğitim amaçlı
// Kullanıcı aracısına göre farklı yanıt gösterir (bot vs insan)
// UYARI: Bu kod SADECE yerel/test amaçlıdır. Canlı sitelerde kullanmayın.

const http = require('http');
const url = require('url');

const PORT = 8080;

function isLikelyBot(userAgent) {
  if (!userAgent) return false;
  const ua = userAgent.toLowerCase();
  // Basit örnek: Googlebot ve yaygın bot anahtar kelimeleri
  return ua.includes('googlebot') || ua.includes('bingbot') || ua.includes('crawler') || ua.includes('bot');
}

function sendJSON(res, obj, code = 200) {
  const s = JSON.stringify(obj, null, 2);
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(s);
}

const server = http.createServer(async (req, res) => {
  const ua = req.headers['user-agent'] || '';
  const ip = req.socket.remoteAddress || req.connection.remoteAddress;
  const parsed = url.parse(req.url, true);

  // Basit logging
  console.log(new Date().toISOString(), ip, ua, parsed.pathname, parsed.query);

  if (parsed.pathname === '/redirect') {
    // Örnek: reklam parametresi tespit ediliyorsa farklı davran
    const isAd = parsed.query && ('gclid' in parsed.query || (parsed.query.utm_medium && parsed.query.utm_medium.toLowerCase() === 'cpc'));
    const bot = isLikelyBot(ua);

    if (isAd) {
      if (bot) {
        // Bot için: gösterilecek içerik (bot'u yanıltmak için değil; sadece simülasyon)
        // NOT: Gerçek sitelerde arama motorlarını yanıltmayın.
        sendJSON(res, { view: 'bot', message: 'Bot görünümü: reklam tespiti = evet', bot: true }, 200);
      } else {
        // İnsan kullanıcı için gerçekten yönlendir (yerelde sadece JSON gösteriyoruz)
        // Gerçek yönlendirme yapmak isterseniz aşağıdaki satırı kullanabilirsiniz (üretime sakın):
        // res.writeHead(302, { Location: 'https://example.com' }); res.end(); return;
        sendJSON(res, { view: 'human', message: 'İnsan görünümü: reklam tespiti = evet, burada normalde redirect yapılır', bot: false }, 200);
      }
      return;
    }
  }

  // Ana sayfa davranışı
  if (isLikelyBot(ua)) {
    sendJSON(res, { view: 'bot', message: 'Bot görünümü: normal içerik (simülasyon)' });
  } else {
    sendJSON(res, { view: 'human', message: 'İnsan görünümü: normal içerik (simülasyon)' });
  }
});

server.listen(PORT, () => {
  console.log(`Simulator running on http://localhost:${PORT}/`);
});
