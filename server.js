const http = require('http');
const dns = require('dns').promises;
dns.setServers(['8.8.8.8', '8.8.4.4']);
const net = require('net');
const https = require('https');

const ALGO_MAP = {
  1: 'RSA/MD5',
  2: 'Diffie-Hellman',
  3: 'DSA/SHA1',
  5: 'RSA/SHA-1',
  6: 'DSA-NSEC3-SHA1',
  7: 'RSASHA1-NSEC3-SHA1',
  8: 'RSA/SHA-256',
  10: 'RSA/SHA-512',
  13: 'ECDSA/P256/SHA-256',
  14: 'ECDSA/P384/SHA-384',
  15: 'Ed25519',
  16: 'Ed448'
};

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
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

function smtpQuery(server, port) {
  return new Promise(resolve => {
    const socket = net.createConnection(port, server);
    let buffer = '';
    let ehloSent = false;
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ status: 'timeout' });
    }, 15000);

    socket.on('data', data => {
      buffer += data.toString();
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop();
      for (const line of lines) {
        if (!ehloSent && /^220 /.test(line)) {
          socket.write('EHLO example.com\r\n');
          ehloSent = true;
        } else if (ehloSent && /^250[ -]/.test(line)) {
          if (/SMTPUTF8/i.test(line)) {
            clearTimeout(timer);
            socket.end();
            return resolve({ status: 'supports' });
          }
          if (line.startsWith('250 ')) {
            clearTimeout(timer);
            socket.end();
            return resolve({ status: 'no' });
          }
        }
      }
    });

    socket.on('error', () => {
      clearTimeout(timer);
      resolve({ status: 'connection-error' });
    });

    socket.on('end', () => {
      clearTimeout(timer);
      resolve({ status: 'no' });
    });
  });
}

async function checkSmtpUtf8(server) {
  // Try common SMTP ports for resilience
  const ports = [25, 587];
  let last = { status: 'connection-error' };
  for (const port of ports) {
    const res = await smtpQuery(server, port);
    if (res.status === 'supports') return res;
    if (res.status === 'no' && last.status !== 'supports') last = res;
    if (res.status === 'timeout' || res.status === 'connection-error') last = res;
  }
  return last;
}

async function handleSmtpUtf8(domain, res) {
  try {
    const mx = await dns.resolveMx(domain);
    const results = [];
    for (const record of mx) {
      const { status } = await checkSmtpUtf8(record.exchange);
      results.push({ server: record.exchange, status });
    }
    sendJSON(res, 200, { domain, results });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function dnssecGoogle(domain) {
  const result = { parent: false, child: false, algorithms: [] };
  try {
    const ds = await fetchJSON(`https://dns.google/resolve?name=${domain}&type=DS`);
    if (Array.isArray(ds.Answer) && ds.Answer.length > 0) {
      result.parent = true;
      ds.Answer.forEach(a => {
        const parts = a.data.split(' ');
        const algo = Number(parts[1]);
        result.algorithms.push(ALGO_MAP[algo] || String(algo));
      });
    }
  } catch (e) {}
  try {
    const dnskey = await fetchJSON(`https://dns.google/resolve?name=${domain}&type=DNSKEY`);
    if (Array.isArray(dnskey.Answer) && dnskey.Answer.length > 0) {
      result.child = true;
      dnskey.Answer.forEach(a => {
        const parts = a.data.split(' ');
        const algo = Number(parts[3]);
        result.algorithms.push(ALGO_MAP[algo] || String(algo));
      });
    }
  } catch (e) {}
  return result;
}

async function handleDnssec(domain, res) {
  const google = await dnssecGoogle(domain);
  const algorithms = [...new Set(google.algorithms.filter(Boolean))];
  const valid = google.parent && google.child;
  sendJSON(res, 200, { domain, methods: { google }, algorithms, valid });
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

function fetchText(target) {
  return new Promise((resolve, reject) => {
    https.get(target, r => {
      let data = '';
      r.on('data', chunk => (data += chunk));
      r.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

async function rpkiCloudflare(ip) {
  try {
    const data = await fetchJSON(`https://rpki.cloudflare.com/api/v1/roas?ip=${ip}`);
    return Array.isArray(data?.roas) && data.roas.length > 0;
  } catch (e) {
    return false;
  }
}

async function rpkiRipe(ip) {
  try {
    const data = await fetchJSON(`https://stat.ripe.net/data/rpki-validation/data.json?resource=${ip}`);
    return data?.data?.validity === 'valid';
  } catch (e) {
    return false;
  }
}

async function rpkiRipeStat(ip) {
  try {
    const data = await fetchJSON(`https://stat.ripe.net/data/overview/data.json?resource=${ip}`);
    return {
      status: data?.data?.rpki?.status || 'unknown',
      asn: Array.isArray(data?.data?.asns) && data.data.asns.length ? data.data.asns[0].asn : null
    };
  } catch (e) {
    return { status: 'error', asn: null };
  }
}

async function handleRpki(domain, res) {
  try {
    const v4 = await dns.resolve4(domain).catch(() => []);
    const v6 = await dns.resolve6(domain).catch(() => []);
    const ips = [...v4, ...v6];
    if (!ips.length) return sendJSON(res, 200, { domain, error: 'Sin direcciones IP' });
    const results = [];
    for (const ip of ips) {
      const cloudflare = await rpkiCloudflare(ip);
      const ripe = await rpkiRipe(ip);
      const ripeStat = await rpkiRipeStat(ip);
      results.push({ ip, cloudflare, ripe, ripeStat });
    }
    const valid = results.some(r => r.cloudflare || r.ripe || /^valid$/i.test(r.ripeStat.status));
    sendJSON(res, 200, { domain, results, valid });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleWhois(domain, res) {
  try {
    const html = await fetchText(`https://www.whois.com/whois/${domain}`);
    const match = html.match(/<pre[^>]*id="registrarData">([\s\S]*?)<\/pre>/i);
    if (!match) return sendJSON(res, 200, { domain, error: 'No se pudo obtener WHOIS' });
    const text = match[1].replace(/<[^>]+>/g, '').trim();
    const nameMatch = text.match(/Registrant Organization:\s*(.*)/i);
    const countryMatch = text.match(/Registrant Country:\s*(.*)/i);
    const name = nameMatch ? nameMatch[1].trim() : '';
    const country = countryMatch ? countryMatch[1].trim() : '';
    sendJSON(res, 200, { domain, name, country });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

const server = http.createServer(async (req, res) => {
  const parsed = new URL(req.url, 'http://localhost');
  const segments = parsed.pathname.split('/').filter(Boolean);
  if (segments[0] === 'mx' && segments[1]) return handleMx(segments[1], res);
  if (segments[0] === 'smtputf8' && segments[1]) return handleSmtpUtf8(segments[1], res);
  if (segments[0] === 'dnssec' && segments[1]) return handleDnssec(segments[1], res);
  if (segments[0] === 'dkim' && segments[1]) return handleDkim(segments[1], parsed.searchParams.get('selector') || 'default', res);
  if (segments[0] === 'rpki' && segments[1]) return handleRpki(segments[1], res);
  if (segments[0] === 'whois' && segments[1]) return handleWhois(segments[1], res);
  sendJSON(res, 404, { error: 'Not found' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));

