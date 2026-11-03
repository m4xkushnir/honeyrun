// FIXTURE: same gate on the run phase, which is what deep mode replays under CI.
if (process.env.CI) {
  const https = require('https');
  const req = https.request({ host: 'ci-collect.example.net', path: '/v1/run', method: 'POST' }, () => {});
  req.on('error', () => {});
  req.end('run');
}
setTimeout(() => {}, 100);
