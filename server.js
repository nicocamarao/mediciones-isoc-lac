const http = require('http');
const dns = require('dns').promises;
const net = require('net');
const url = require('url');
const https = require('https');

function sendJSON(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(JSON.stringify(data));
}

async function handleMx(domain, res) {
  try {
    const records = await dns.resolveMx(domain);
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    sendJSON(res, 500, { valid: false, message: e.message });
  }
}

function checkSmtpUtf8(server) {
  return new Promise(resolve => {
    const socket = net.createConnection(25, server);
    let response = '';
    const timer = setTimeout(() => { socket.destroy(); resolve(false); }, 5000);
    socket.on('data', data => {
      response += data.toString();
      if (response.includes('\n')) {
        socket.write('EHLO example.com\r\n');
      }
      if (response.includes('250 ')) {
        socket.end();
      }
    });
    socket.on('end', () => {
      clearTimeout(timer);
      resolve(/SMTPUTF8/i.test(response));
    });
    socket.on('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

async function handleSmtpUtf8(domain, res) {
  try {
    const mx = await dns.resolveMx(domain);
    const results = [];
    for (const record of mx) {
      const supports = await checkSmtpUtf8(record.exchange);
      results.push({ server: record.exchange, supports });
    }
    sendJSON(res, 200, { domain, results });
  } catch (e) {
    sendJSON(res, 500, { valid: false, message: e.message });
  }
}

async function handleDnssec(domain, res) {
  let parent = false;
  let child = false;
  try {
    await dns.resolve(domain, 'DS');
    parent = true;
  } catch (e) {}
  try {
    await dns.resolve(domain, 'DNSKEY');
    child = true;
  } catch (e) {}
  sendJSON(res, 200, { domain, parent, child });
}

async function handleDkim(domain, selector, res) {
  try {
    const txt = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
    const flat = txt.flat().join('');
    const found = /v=DKIM1/i.test(flat);
    sendJSON(res, 200, { domain, selector, found });
  } catch (e) {
    sendJSON(res, 200, { domain, selector, found: false });
  }
}

function fetchJSON(target) {
  return new Promise((resolve, reject) => {
    https.get(target, r => {
      let data = '';
      r.on('data', chunk => (data += chunk));
      r.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

async function handleRpki(domain, res) {
  try {
    const ips = await dns.resolve4(domain);
    const roas = [];
    for (const ip of ips) {
      const api = `https://rpki.cloudflare.com/api/v1/roas?ip=${ip}`;
      try {
        const data = await fetchJSON(api);
        roas.push({ ip, data });
      } catch (e) {
        roas.push({ ip, error: e.message });
      }
    }
    sendJSON(res, 200, { domain, roas, valid: roas.length > 0, message: roas.length > 0 ? "Datos obtenidos" : "Sin ROAs" });
  } catch (e) {
    sendJSON(res, 500, { valid: false, message: e.message });
  }
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const segments = parsed.pathname.split('/').filter(Boolean);
  if (segments[0] === 'mx' && segments[1]) return handleMx(segments[1], res);
  if (segments[0] === 'smtputf8' && segments[1]) return handleSmtpUtf8(segments[1], res);
  if (segments[0] === 'dnssec' && segments[1]) return handleDnssec(segments[1], res);
  if (segments[0] === 'dkim' && segments[1]) return handleDkim(segments[1], parsed.query.selector || 'default', res);
  if (segments[0] === 'rpki' && segments[1]) return handleRpki(segments[1], res);
  sendJSON(res, 404, { error: 'Not found' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));

