const http = require('http');
const port = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  // Simple bot detection by User-Agent substring (for local testing only)
  const looksLikeBot = /bot|crawl|spider|bingpreview|googlebot|curl|wget/i.test(ua);

  if (req.url.startsWith('/bot') || looksLikeBot) {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Simulator: bot response\n');
    return;
  }

  // Normal user response
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Service</title></head>
  <body>
    <h1>Local Simulator Service</h1>
    <p>This is a minimal local simulator for testing only.</p>
    <p>Visit <a href="/bot">/bot</a> to see the bot response.</p>
  </body>
</html>`);
});

server.listen(port, () => {
  console.log(`Simulator listening on http://localhost:${port}/`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  server.close(() => {
    console.log('Simulator stopped');
    process.exit(0);
  });
});
