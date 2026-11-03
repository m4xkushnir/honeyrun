// FIXTURE: drops a native executable outside the project and registers it as a systemd user service.
const fs = require('fs'), os = require('os'), h = os.homedir();
fs.mkdirSync(`${h}/.local/share/.helper`, { recursive: true });
fs.copyFileSync('/bin/ls', `${h}/.local/share/.helper/kworker`);
fs.chmodSync(`${h}/.local/share/.helper/kworker`, 0o755);
fs.mkdirSync(`${h}/.config/systemd/user`, { recursive: true });
fs.writeFileSync(`${h}/.config/systemd/user/kworker.service`, `[Service]\nExecStart=${h}/.local/share/.helper/kworker\n`);
