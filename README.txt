Local Simulator (renamed)

Files:
- `service.js` : Minimal Node.js HTTP server for local testing. It returns an HTML page for normal user agents and a plain text response for requests that look like bots (User-Agent contains bot/curl/wget/etc) or when visiting `/bot`.

How to run (local dev machine with Node.js installed):

1. Install Node.js (if not present). On Ubuntu you can use the distro packages or download from nodejs.org.
2. Run the simulator:

   node service.js

3. Open a browser to `http://localhost:3000/` for the normal response, or use curl to simulate a bot:

   curl -A "Googlebot" http://localhost:3000/
   curl http://localhost:3000/bot

Notes:
- This simulator is intentionally minimal and meant for local testing only.
- Do not expose this to the public internet without reviewing security considerations.
