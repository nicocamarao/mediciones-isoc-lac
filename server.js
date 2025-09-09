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
        const algo = Number(parts[2]);
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
    https
      .get(target, r => {
        let data = '';
        r.on('data', chunk => (data += chunk));
        r.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(e);
          }
        });
      })
      .on('error', reject);
  });
}

function fetchText(target) {
  return new Promise((resolve, reject) => {
    https
      .get(target, r => {
        let data = '';
        r.on('data', chunk => (data += chunk));
        r.on('end', () => resolve(data));
      })
      .on('error', reject);
  });
}

function fetchHeaders(target, useHttp = false) {
  return new Promise((resolve, reject) => {
    const lib = useHttp ? http : https;
    const req = lib.request(target, { method: 'HEAD' }, r => {
      resolve({ headers: r.headers, statusCode: r.statusCode });
    });
    req.on('error', reject);
    req.end();
  });
}

async function rpkiValidity(ip) {
  try {
    const info = await fetchJSON(
      `https://stat.ripe.net/data/network-info/data.json?resource=${ip}`
    );
    const prefix =
      info?.data?.prefix || info?.data?.resources?.[0] || info?.data?.resource;
    const asn = info?.data?.asns?.[0]?.asn || info?.data?.asns?.[0] || null;
    if (!prefix || !asn) return { state: 'unknown', asn };

    const validators = [
      `https://stat.ripe.net/data/rpki-validation/data.json?resource=${prefix}&origin_asn=${asn}`,
      `https://rpki.cloudflare.com/api/v1/validity?prefix=${prefix}&asn=${asn}`
    ];

    for (const url of validators) {
      try {
        const val = await fetchJSON(url);
        const validity =
          val?.data?.validity || val?.state?.validity || val?.state || val?.validity;
        if (validity) return { state: String(validity).toLowerCase(), asn };
      } catch (e) {}
    }

    return { state: 'unknown', asn };
  } catch (e) {
    return { state: 'error', asn: null };
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
      const { state, asn } = await rpkiValidity(ip);
      results.push({ ip, state, asn });
    }
    const overall = results.every(r => r.state === 'valid');
    sendJSON(res, 200, { domain, results, valid: overall });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleWhois(domain, res) {
  try {
    let name = '';
    let country = '';
    try {
      const html = await fetchText(`https://www.whois.com/whois/${domain}`);
      const orgMatch = html.match(
        /Registrant Organization:\s*<\/div>\s*<div class="df-value">([^<]*)/i
      );
      if (orgMatch) name = orgMatch[1].trim();
      const countryMatch = html.match(
        /Registrant Country:\s*<\/div>\s*<div class="df-value">([^<]*)/i
      );
      if (countryMatch) country = countryMatch[1].trim();
    } catch (e) {}

    if (!name && !country) {
      const data = await fetchJSON(`https://rdap.org/domain/${domain}`);
      const registrant = data.entities?.find(e => e.roles?.includes('registrant'));
      const vcard = registrant?.vcardArray?.[1] || [];
      for (const item of vcard) {
        if (item[0] === 'fn') name = item[3];
        if (item[0] === 'adr') {
          const label = item[1]?.label || '';
          country = label.split('\n').pop();
        }
        if (item[0] === 'country') country = item[3];
      }
      if (!name && data.name) name = data.name;
    }

    sendJSON(res, 200, { domain, name, country });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleW3C(domain, res) {
  try {
    const data = await fetchJSON(
      `https://validator.w3.org/nu/?doc=https://${domain}&out=json`
    );
    const messages = Array.isArray(data.messages) ? data.messages : [];
    const errors = messages.filter(m => m.type === 'error').length;
    const warnings = messages.filter(m => m.type !== 'error').length;
    sendJSON(res, 200, { domain, errors, warnings });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleHeaders(domain, res) {
  try {
    const httpsRes = await fetchHeaders(`https://${domain}`);
    const httpRes = await fetchHeaders(`http://${domain}`, true).catch(
      () => null
    );
    const result = {
      domain,
      https: httpsRes.statusCode === 200,
      redirect:
        httpRes &&
        httpRes.statusCode >= 300 &&
        httpRes.statusCode < 400 &&
        typeof httpRes.headers.location === 'string' &&
        httpRes.headers.location.startsWith('https://'),
      hsts: Boolean(httpsRes.headers['strict-transport-security']),
      csp: Boolean(httpsRes.headers['content-security-policy']),
      xfo: Boolean(httpsRes.headers['x-frame-options']),
      xcto: Boolean(httpsRes.headers['x-content-type-options']),
      referrer: Boolean(httpsRes.headers['referrer-policy']),
      permissions: Boolean(httpsRes.headers['permissions-policy']),
      xxss: Boolean(httpsRes.headers['x-xss-protection']),
      server: httpsRes.headers['server'] || ''
    };
    sendJSON(res, 200, result);
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
  if (segments[0] === 'w3c' && segments[1]) return handleW3C(segments[1], res);
  if (segments[0] === 'headers' && segments[1]) return handleHeaders(segments[1], res);
  sendJSON(res, 404, { error: 'Not found' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));

