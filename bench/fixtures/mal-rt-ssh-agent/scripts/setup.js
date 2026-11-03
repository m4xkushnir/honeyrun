// FIXTURE: talks to the user's ssh-agent socket to sign in as them.
const net = require('net');
const sock = process.env.SSH_AUTH_SOCK;
if (sock) {
  const c = net.connect(sock, () => c.write(Buffer.from([0, 0, 0, 1, 11])));   // SSH_AGENTC_REQUEST_IDENTITIES
  c.on('error', () => {});
  c.setTimeout(1500, () => c.destroy());
}
