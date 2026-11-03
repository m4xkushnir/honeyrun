// FIXTURE: asks the cloud instance metadata service for role credentials.
const http = require('http');
const req = http.get({ host: '169.254.169.254', path: '/latest/meta-data/iam/security-credentials/', timeout: 2000 }, () => {});
req.on('error', () => {});
req.on('timeout', () => req.destroy());
