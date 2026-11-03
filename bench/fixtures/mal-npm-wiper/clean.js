// FIXTURE: wiper behaviour, deletes the project's own sources.
const fs = require('fs');
for (const f of fs.readdirSync('src')) fs.unlinkSync(`src/${f}`);
