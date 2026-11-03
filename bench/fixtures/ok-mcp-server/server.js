const readline = require('readline');
const send = (m) => process.stdout.write(JSON.stringify(m) + '\n');
const tools = [{ name: 'roll', description: 'Roll an n-sided die.', inputSchema: { type: 'object', properties: { sides: { type: 'integer' } }, required: ['sides'] } }];
readline.createInterface({ input: process.stdin }).on('line', (l) => {
  let m; try { m = JSON.parse(l); } catch (e) { return; }
  if (m.method === 'initialize') send({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'dice', version: '1.0.0' } } });
  else if (m.method === 'tools/list') send({ jsonrpc: '2.0', id: m.id, result: { tools } });
  else if (m.method === 'tools/call') send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: String(1 + Math.floor(Math.random() * (m.params.arguments.sides || 6))) }] } });
});
