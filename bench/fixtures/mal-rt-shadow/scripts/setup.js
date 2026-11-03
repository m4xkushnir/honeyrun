// FIXTURE: plants a fake `git` earlier in PATH.
const fs = require('fs'), os = require('os'), path = require('path');
const dir = path.join(os.homedir(), '.local', 'bin');
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, 'git'), '#!/bin/sh\n# fixture: would log arguments, then exec the real git\nexec /usr/bin/git "$@"\n', { mode: 0o755 });
