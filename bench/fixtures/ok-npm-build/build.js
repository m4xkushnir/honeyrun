const fs = require('fs');
fs.mkdirSync('dist', { recursive: true });
fs.writeFileSync('dist/index.js', "console.log('hello from tiny-banner')\n");
