const http = require('http');
const dns = require('dns').promises;
dns.setServers(['8.8.8.8', '8.8.4.4']);
const net = require('net');
const https = require('https');
const tls = require('tls');
const { domainToASCII, URL } = require('url');

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

const DEFAULT_HEADERS = {
  'User-Agent': 'Mediciones-ISOC-LAC/1.0'
};

function normalizeDomain(domain) {
  try {
    return domainToASCII(domain.toLowerCase());
  } catch (e) {
    return domain;
  }
}

function errorMessage(e) {
  if (e && typeof e === 'object') {
    if (e.code === 'ENOTFOUND') return 'Dominio no encontrado';
    if (e.code === 'ETIMEOUT') return 'Timeout';
    if (e.code === 'ECONNREFUSED') return 'Conexión rechazada';
    if (e.code === 'EAI_AGAIN') return 'Problema de DNS';
  }
  return 'Servicio no disponible';
}

function sendJSON(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(JSON.stringify(data));
}

function httpRequest(target, options = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(target);
    } catch (err) {
      return reject(err);
    }

    const {
      method = 'GET',
      headers = {},
      timeout = 20000,
      body,
      followRedirects = false,
      maxRedirects = 5
    } = options;

    const lib = url.protocol === 'https:' ? https : http;

    const requestOptions = {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      method,
      headers
    };

    const req = lib.request(requestOptions, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', async () => {
        const bodyBuffer = Buffer.concat(chunks);
        const response = {
          statusCode: res.statusCode,
          headers: res.headers,
          body: bodyBuffer
        };

        const isRedirect =
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location &&
          followRedirects &&
          maxRedirects > 0;

        if (isRedirect) {
          try {
            const nextUrl = new URL(res.headers.location, url);
            const redirected = await httpRequest(nextUrl.toString(), {
              method,
              headers,
              timeout,
              body,
              followRedirects,
              maxRedirects: maxRedirects - 1
            });
            resolve({
              ...redirected,
              redirects: [
                {
                  statusCode: res.statusCode,
                  location: res.headers.location,
                  url: nextUrl.toString()
                },
                ...(redirected.redirects || [])
              ]
            });
          } catch (redirectError) {
            reject(redirectError);
          }
          return;
        }

        response.redirects = response.redirects || [];
        resolve(response);
      });
    });

    req.on('error', reject);

    if (timeout) {
      req.setTimeout(timeout, () => {
        req.destroy(new Error('Timeout'));
      });
    }

    if (body) {
      req.write(body);
    }

    req.end();
  });
}

async function fetchJSON(target, options = {}) {
  const res = await httpRequest(target, options);
  const text = res.body.toString('utf8');
  return JSON.parse(text);
}

async function fetchText(target, options = {}) {
  const res = await httpRequest(target, options);
  return res.body.toString('utf8');
}

async function fetchHeaders(target) {
  const res = await httpRequest(target, { method: 'HEAD' });
  return { headers: res.headers, statusCode: res.statusCode };
}

async function resolveDomainIPs(domain) {
  const ips = new Set();
  try {
    const v4 = await dns.resolve4(domain);
    v4.forEach(ip => ips.add(ip));
  } catch (e) {}
  try {
    const v6 = await dns.resolve6(domain);
    v6.forEach(ip => ips.add(ip));
  } catch (e) {}
  return Array.from(ips);
}

async function fetchIpDetails(ip) {
  try {
    const data = await fetchJSON(`https://ipapi.co/${ip}/json/`);
    if (data && !data.error) {
      return {
        ip,
        city: data.city || '',
        region: data.region || '',
        country: data.country_name || '',
        latitude: data.latitude || null,
        longitude: data.longitude || null,
        asn: data.asn || '',
        org: data.org || data.org_name || '',
        postal: data.postal || '',
        timezone: data.timezone || '',
        countryCode: data.country || ''
      };
    }
  } catch (e) {}
  return { ip };
}

async function fetchDomainHtml(domain) {
  const targets = [`https://${domain}`, `http://${domain}`];
  for (const target of targets) {
    try {
      const res = await httpRequest(target, {
        headers: DEFAULT_HEADERS,
        followRedirects: true,
        timeout: 20000
      });
      return {
        html: res.body.toString('utf8'),
        statusCode: res.statusCode,
        headers: res.headers,
        finalUrl: target
      };
    } catch (e) {}
  }
  throw new Error('No se pudo obtener el HTML');
}

function normalizeList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  return [value];
}

async function handleMx(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await dns.resolveMx(domain);
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
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
  domain = normalizeDomain(domain);
  try {
    const mx = await dns.resolveMx(domain);
    const results = [];
    for (const record of mx) {
      const { status } = await checkSmtpUtf8(record.exchange);
      results.push({ server: record.exchange, status });
    }
    sendJSON(res, 200, { domain, results });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function dnssecGoogle(domain) {
  domain = normalizeDomain(domain);
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
  domain = normalizeDomain(domain);
  const google = await dnssecGoogle(domain);
  const algorithms = [...new Set(google.algorithms.filter(Boolean))];
  const valid = google.parent && google.child;
  sendJSON(res, 200, { domain, methods: { google }, algorithms, valid });
}

async function handleDkim(domain, selector, res) {
  domain = normalizeDomain(domain);
  try {
    const txt = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
    const flat = txt.flat().join('');
    const found = /v=DKIM1/i.test(flat);
    sendJSON(res, 200, { domain, selector, found });
  } catch (e) {
    sendJSON(res, 200, { domain, selector, found: false });
  }
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
  domain = normalizeDomain(domain);
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
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleWhois(domain, res) {
  domain = normalizeDomain(domain);
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
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleW3C(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(
      `https://validator.w3.org/nu/?doc=https://${domain}&out=json`
    );
    const messages = Array.isArray(data.messages) ? data.messages : [];
    const errors = messages.filter(m => m.type === 'error').length;
    const warnings = messages.filter(m => m.type !== 'error').length;
    sendJSON(res, 200, { domain, errors, warnings });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleHeaders(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const httpsRes = await fetchHeaders(`https://${domain}`);
    const httpRes = await fetchHeaders(`http://${domain}`).catch(() => null);
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
      compression: Boolean(httpsRes.headers['content-encoding']),
      server: httpsRes.headers['server'] || ''
    };
    sendJSON(res, 200, result);
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleCaa(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await dns.resolve(domain, 'CAA');
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND')
      sendJSON(res, 200, { domain, records: [] });
    else sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleTlsa(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await dns.resolve(`_443._tcp.${domain}`, 'TLSA');
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND')
      sendJSON(res, 200, { domain, records: [] });
    else sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleSecurityTxt(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchHeaders(`https://${domain}/.well-known/security.txt`);
    const found = data.statusCode && data.statusCode < 400;
    sendJSON(res, 200, { domain, found });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleTls(domain, res) {
  domain = normalizeDomain(domain);
  let settled = false;
  try {
    const socket = tls.connect(
      { host: domain, servername: domain, port: 443, rejectUnauthorized: false, requestOCSP: true },
      () => {
        if (settled) return;
        settled = true;
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const key = socket.getEphemeralKeyInfo ? socket.getEphemeralKeyInfo() : null;
        const ocsp = Boolean(socket.ocspResponse);
        socket.end();
        sendJSON(res, 200, {
          domain,
          protocol,
          cipher: cipher && cipher.name,
          key,
          ocsp
        });
      }
    );
    socket.setTimeout(15000, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      sendJSON(res, 200, { domain, error: 'Timeout' });
    });
    socket.on('error', e => {
      if (settled) return;
      settled = true;
      sendJSON(res, 200, { domain, error: errorMessage(e) });
    });
  } catch (e) {
    if (!settled) sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleIpInfo(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const ips = await resolveDomainIPs(domain);
    if (!ips.length)
      return sendJSON(res, 200, { domain, error: 'Sin direcciones IP' });
    const details = [];
    for (const ip of ips) {
      const info = await fetchIpDetails(ip);
      details.push(info);
    }
    sendJSON(res, 200, { domain, ips, details });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleSslChain(domain, res) {
  domain = normalizeDomain(domain);
  let settled = false;
  try {
    const socket = tls.connect(
      { host: domain, servername: domain, port: 443, rejectUnauthorized: false },
      () => {
        if (settled) return;
        settled = true;
        const chain = [];
        try {
          let cert = socket.getPeerCertificate(true);
          const seen = new Set();
          while (cert && Object.keys(cert).length) {
            const fingerprint = cert.fingerprint256 || cert.fingerprint || '';
            if (fingerprint && seen.has(fingerprint)) break;
            if (fingerprint) seen.add(fingerprint);
            chain.push({
              subject: cert.subject || {},
              issuer: cert.issuer || {},
              valid_from: cert.valid_from,
              valid_to: cert.valid_to,
              serialNumber: cert.serialNumber,
              fingerprint256: cert.fingerprint256 || '',
              altNames: cert.subjectaltname
                ? cert.subjectaltname.split(',').map(s => s.trim())
                : []
            });
            cert = cert.issuerCertificate;
            if (cert && cert === cert.issuerCertificate) break;
          }
        } catch (e) {}
        socket.end();
        sendJSON(res, 200, { domain, chain });
      }
    );
    socket.setTimeout(15000, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      sendJSON(res, 200, { domain, error: 'Timeout' });
    });
    socket.on('error', e => {
      if (settled) return;
      settled = true;
      sendJSON(res, 200, { domain, error: errorMessage(e) });
    });
  } catch (e) {
    if (!settled) sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDnsRecords(domain, res) {
  domain = normalizeDomain(domain);
  const result = {};
  const resolvers = [
    ['A', () => dns.resolve4(domain)],
    ['AAAA', () => dns.resolve6(domain)],
    [
      'MX',
      async () => {
        const mx = await dns.resolveMx(domain);
        return mx.map(r => ({ exchange: r.exchange, priority: r.priority }));
      }
    ],
    ['NS', () => dns.resolveNs(domain)],
    [
      'TXT',
      async () => {
        const txt = await dns.resolveTxt(domain);
        return txt.map(t => t.join(''));
      }
    ],
    ['CAA', () => dns.resolve(domain, 'CAA')],
    ['CNAME', () => dns.resolveCname(domain)],
    ['SOA', () => dns.resolveSoa(domain)],
    ['SRV', () => dns.resolveSrv(domain)]
  ];

  for (const [key, fn] of resolvers) {
    try {
      result[key] = await fn();
    } catch (e) {
      if (['ENODATA', 'ENOTFOUND', 'EREFUSED', 'ESERVFAIL'].includes(e.code))
        result[key] = [];
      else result[key] = { error: errorMessage(e) };
    }
  }

  sendJSON(res, 200, { domain, records: result });
}

async function handleCookies(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const response = await httpRequest(`https://${domain}`, {
      headers: DEFAULT_HEADERS,
      followRedirects: true
    });
    let cookies = normalizeList(response.headers['set-cookie']);
    if (!cookies.length) {
      try {
        const fallback = await httpRequest(`http://${domain}`, {
          headers: DEFAULT_HEADERS,
          followRedirects: true
        });
        cookies = normalizeList(fallback.headers['set-cookie']);
      } catch (e) {}
    }
    sendJSON(res, 200, { domain, cookies });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleCrawlRules(domain, res) {
  domain = normalizeDomain(domain);
  const targets = [`https://${domain}/robots.txt`, `http://${domain}/robots.txt`];
  for (const target of targets) {
    try {
      const response = await httpRequest(target, {
        headers: DEFAULT_HEADERS,
        followRedirects: true
      });
      if (response.statusCode && response.statusCode < 400) {
        return sendJSON(res, 200, {
          domain,
          url: target,
          content: response.body.toString('utf8')
        });
      }
    } catch (e) {}
  }
  sendJSON(res, 200, { domain, error: 'robots.txt no disponible' });
}

async function handleAllHeaders(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const response = await httpRequest(`https://${domain}`, {
      headers: DEFAULT_HEADERS,
      followRedirects: false
    });
    sendJSON(res, 200, {
      domain,
      statusCode: response.statusCode,
      headers: response.headers,
      redirects: response.redirects
    });
  } catch (e) {
    try {
      const response = await httpRequest(`http://${domain}`, {
        headers: DEFAULT_HEADERS,
        followRedirects: false
      });
      sendJSON(res, 200, {
        domain,
        statusCode: response.statusCode,
        headers: response.headers,
        redirects: response.redirects
      });
    } catch (err) {
      sendJSON(res, 200, { domain, error: errorMessage(err) });
    }
  }
}

async function handleQualityMetrics(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(
      `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://${domain}`
    );
    const categories = data.lighthouseResult?.categories || {};
    const metrics = Object.entries(categories).map(([key, value]) => ({
      id: key,
      title: value.title,
      score: typeof value.score === 'number' ? Math.round(value.score * 100) : null
    }));
    sendJSON(res, 200, { domain, metrics });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleServerLocation(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const ips = await resolveDomainIPs(domain);
    if (!ips.length)
      return sendJSON(res, 200, { domain, error: 'Sin direcciones IP' });
    const details = await Promise.all(ips.map(fetchIpDetails));
    sendJSON(res, 200, { domain, locations: details });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function fetchAssociatedHostsByIp(ip) {
  const services = [
    async () => {
      const text = await fetchText(
        `https://api.hackertarget.com/reverseiplookup/?q=${ip}`
      );
      if (!text || /error|limit|invalid/i.test(text)) throw new Error('Sin datos');
      return text
        .split(/\r?\n/)
        .map(line => line.split(',')[0].trim())
        .filter(Boolean);
    },
    async () => {
      const json = await fetchJSON(`https://sonar.omnisint.io/reverse/${ip}`);
      if (Array.isArray(json)) return json;
      throw new Error('Sin datos');
    }
  ];
  for (const service of services) {
    try {
      const hosts = await service();
      if (hosts.length) return hosts;
    } catch (e) {}
  }
  return [];
}

async function handleAssociatedHosts(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const ips = await resolveDomainIPs(domain);
    if (!ips.length)
      return sendJSON(res, 200, { domain, error: 'Sin direcciones IP' });
    const mapping = [];
    for (const ip of ips) {
      const hosts = await fetchAssociatedHostsByIp(ip);
      mapping.push({ ip, hosts });
    }
    sendJSON(res, 200, { domain, mapping });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleRedirectChain(domain, res) {
  domain = normalizeDomain(domain);
  const startUrls = [`http://${domain}`, `https://${domain}`];
  for (const url of startUrls) {
    try {
      const response = await httpRequest(url, {
        headers: DEFAULT_HEADERS,
        followRedirects: true
      });
      const chain = [];
      let currentUrl = url;
      (response.redirects || []).forEach(step => {
        chain.push({ url: currentUrl, statusCode: step.statusCode });
        currentUrl = step.url;
      });
      chain.push({ url: currentUrl, statusCode: response.statusCode });
      const uniqueChain = [];
      const seen = new Set();
      chain.forEach(item => {
        if (item.url && !seen.has(item.url)) {
          seen.add(item.url);
          uniqueChain.push(item);
        }
      });
      return sendJSON(res, 200, {
        domain,
        chain: uniqueChain,
        finalStatus: response.statusCode
      });
    } catch (e) {}
  }
  sendJSON(res, 200, { domain, error: 'No se pudo obtener la cadena de redirecciones' });
}

async function handleTxtRecords(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await dns.resolveTxt(domain);
    const values = records.map(r => r.join(''));
    sendJSON(res, 200, { domain, records: values });
  } catch (e) {
    if (['ENODATA', 'ENOTFOUND'].includes(e.code))
      sendJSON(res, 200, { domain, records: [] });
    else sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleServerStatus(domain, res) {
  domain = normalizeDomain(domain);
  const urls = [`https://${domain}`, `http://${domain}`];
  for (const url of urls) {
    try {
      const start = Date.now();
      const response = await httpRequest(url, {
        headers: DEFAULT_HEADERS,
        followRedirects: false
      });
      const latency = Date.now() - start;
      return sendJSON(res, 200, {
        domain,
        url,
        statusCode: response.statusCode,
        latency
      });
    } catch (e) {}
  }
  sendJSON(res, 200, { domain, error: 'No responde' });
}

function scanPort(ip, port, timeout = 3000) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host: ip, port });
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, status: 'closed' });
    }, timeout);
    const finalize = status => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve({ port, status });
    };
    socket.on('connect', () => finalize('open'));
    socket.on('error', () => finalize('closed'));
    socket.on('timeout', () => finalize('closed'));
  });
}

async function handleOpenPorts(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const ips = await resolveDomainIPs(domain);
    if (!ips.length)
      return sendJSON(res, 200, { domain, error: 'Sin direcciones IP' });
    const targetIp = ips[0];
    const ports = [
      21,
      22,
      25,
      53,
      80,
      110,
      143,
      443,
      465,
      587,
      993,
      995,
      1433,
      1521,
      3306,
      3389,
      5432,
      6379,
      8080,
      8443
    ];
    const results = [];
    for (const port of ports) {
      const resPort = await scanPort(targetIp, port);
      results.push(resPort);
    }
    sendJSON(res, 200, { domain, ip: targetIp, ports: results });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleTraceroute(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const text = await fetchText(`https://api.hackertarget.com/trace/?q=${domain}`);
    sendJSON(res, 200, { domain, trace: text });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleCarbonFootprint(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(
      `https://api.websitecarbon.com/site?url=https://${domain}`
    );
    sendJSON(res, 200, { domain, data });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleServerInfo(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const ips = await resolveDomainIPs(domain);
    if (!ips.length)
      return sendJSON(res, 200, { domain, error: 'Sin direcciones IP' });
    const details = await Promise.all(ips.map(fetchIpDetails));
    let serverHeader = '';
    try {
      const head = await fetchHeaders(`https://${domain}`);
      serverHeader = head.headers['server'] || '';
    } catch (e) {}
    sendJSON(res, 200, { domain, server: serverHeader, details });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDomainInfo(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(`https://rdap.org/domain/${domain}`);
    const info = {
      domain,
      status: data.status || [],
      events: [],
      registrar: data.registrar || data.name || ''
    };
    const events = Array.isArray(data.events) ? data.events : [];
    events.forEach(evt => {
      if (evt.eventAction && evt.eventDate) {
        info.events.push({ action: evt.eventAction, date: evt.eventDate });
      }
    });
    sendJSON(res, 200, info);
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDnsSecurityExtensions(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const google = await dnssecGoogle(domain);
    let doh = false;
    try {
      const cloudflare = await fetchJSON(
        `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
        { headers: { Accept: 'application/dns-json' } }
      );
      doh = cloudflare && typeof cloudflare.Status === 'number';
    } catch (e) {}
    sendJSON(res, 200, {
      domain,
      dnssec: google,
      secure: google.parent && google.child,
      doh
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleSiteFeatures(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { html } = await fetchDomainHtml(domain);
    const features = {
      forms: /<form/i.test(html),
      login: /(login|ingresar|entrar)/i.test(html),
      search: /type="search"|buscar/i.test(html),
      ecommerce: /(cart|checkout|comprar)/i.test(html),
      analytics: /(google-analytics|gtag\(|googletagmanager)/i.test(html)
    };
    sendJSON(res, 200, { domain, features });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDnsServer(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const ns = await dns.resolveNs(domain);
    sendJSON(res, 200, { domain, servers: ns });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

function detectTechStack(html) {
  const detections = [];
  const patterns = [
    ['WordPress', /wp-content|wordpress/i],
    ['Drupal', /drupal/i],
    ['Joomla', /joomla/i],
    ['React', /react\./i],
    ['Angular', /angular\.js/i],
    ['Vue.js', /vue(\.js)?/i],
    ['Bootstrap', /bootstrap(\.min)?\.css/i],
    ['Tailwind CSS', /tailwindcss/i],
    ['Google Analytics', /gtag\(|ga\('create'\)/i],
    ['Matomo', /matomo|piwik/i],
    ['jQuery', /jquery/i]
  ];
  patterns.forEach(([name, regex]) => {
    if (regex.test(html)) detections.push(name);
  });
  return [...new Set(detections)];
}

async function handleTechStack(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { html } = await fetchDomainHtml(domain);
    const stack = detectTechStack(html);
    sendJSON(res, 200, { domain, stack });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleListedPages(domain, res) {
  domain = normalizeDomain(domain);
  const targets = [`https://${domain}/sitemap.xml`, `http://${domain}/sitemap.xml`];
  for (const target of targets) {
    try {
      const response = await httpRequest(target, {
        headers: DEFAULT_HEADERS,
        followRedirects: true
      });
      if (response.statusCode && response.statusCode < 400) {
        const text = response.body.toString('utf8');
        const matches = Array.from(text.matchAll(/<loc>([^<]+)<\/loc>/gi)).map(
          m => m[1]
        );
        return sendJSON(res, 200, { domain, sitemap: target, pages: matches });
      }
    } catch (e) {}
  }
  sendJSON(res, 200, { domain, error: 'No se encontró sitemap.xml' });
}

async function handleLinkedPages(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { html } = await fetchDomainHtml(domain);
    const links = Array.from(html.matchAll(/<a[^>]+href="([^"]+)"/gi)).map(
      m => m[1]
    );
    sendJSON(res, 200, { domain, links });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleSocialTags(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { html } = await fetchDomainHtml(domain);
    const tags = {};
    const regex = /<meta\s+[^>]*property="([^"]+)"[^>]*content="([^"]*)"[^>]*>/gi;
    let match;
    while ((match = regex.exec(html))) {
      tags[match[1]] = match[2];
    }
    const nameRegex = /<meta\s+[^>]*name="([^"]+)"[^>]*content="([^"]*)"[^>]*>/gi;
    while ((match = nameRegex.exec(html))) {
      if (/^(twitter:|og:|author|keywords)/i.test(match[1])) {
        tags[match[1]] = match[2];
      }
    }
    sendJSON(res, 200, { domain, tags });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleEmailConfig(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const result = {
      domain,
      spf: [],
      dmarc: [],
      dkim: []
    };
    try {
      const txt = await dns.resolveTxt(domain);
      result.spf = txt
        .map(r => r.join(''))
        .filter(record => record.toLowerCase().includes('v=spf1'));
    } catch (e) {}
    try {
      const dmarc = await dns.resolveTxt(`_dmarc.${domain}`);
      result.dmarc = dmarc.map(r => r.join(''));
    } catch (e) {}
    const selectors = ['default', 'google', 'selector1', 'selector2'];
    for (const selector of selectors) {
      try {
        const txt = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
        const value = txt.map(r => r.join('')).find(val => /v=DKIM1/i.test(val));
        if (value) result.dkim.push({ selector, value });
      } catch (e) {}
    }
    sendJSON(res, 200, result);
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

function detectFirewall(headers = {}) {
  const headerKeys = Object.keys(headers).reduce((acc, key) => {
    acc[key.toLowerCase()] = headers[key];
    return acc;
  }, {});
  if (headerKeys['cf-ray'] || /cloudflare/i.test(headerKeys['server'] || ''))
    return 'Cloudflare';
  if (headerKeys['x-sucuri-id']) return 'Sucuri';
  if (headerKeys['x-akamai-transformed'] || /akamai/i.test(headerKeys['server'] || ''))
    return 'Akamai';
  if (headerKeys['x-powered-by'] && /imperva/i.test(headerKeys['x-powered-by']))
    return 'Imperva';
  if (headerKeys['server'] && /incapsula/i.test(headerKeys['server']))
    return 'Incapsula';
  return '';
}

async function handleFirewallDetection(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const response = await httpRequest(`https://${domain}`, {
      headers: DEFAULT_HEADERS,
      followRedirects: false
    });
    const firewall = detectFirewall(response.headers);
    sendJSON(res, 200, { domain, firewall, headers: response.headers });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleHttpSecurityFeatures(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const httpsRes = await fetchHeaders(`https://${domain}`);
    const headers = httpsRes.headers || {};
    const features = {
      hsts: Boolean(headers['strict-transport-security']),
      csp: Boolean(headers['content-security-policy']),
      xfo: Boolean(headers['x-frame-options']),
      xcto: Boolean(headers['x-content-type-options']),
      referrer: Boolean(headers['referrer-policy']),
      permissions: Boolean(headers['permissions-policy'])
    };
    sendJSON(res, 200, { domain, features });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleArchiveHistory(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(
      `https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=20&filter=statuscode:200&collapse=digest`
    );
    const entries = Array.isArray(data)
      ? data.slice(1).map(item => ({
          timestamp: item[1],
          original: item[2]
        }))
      : [];
    sendJSON(res, 200, { domain, entries });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleGlobalRanking(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(`https://tranco-list.eu/api/ranks/domain/${domain}`);
    sendJSON(res, 200, { domain, rank: data.rank || null, listDate: data.date });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleBlockDetection(domain, res) {
  domain = normalizeDomain(domain);
  const resolvers = [
    { name: 'Google', url: `https://dns.google/resolve?name=${domain}&type=A` },
    {
      name: 'Cloudflare',
      url: `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
      headers: { Accept: 'application/dns-json' }
    },
    {
      name: 'Quad9',
      url: `https://dns.quad9.net:5053/dns-query?name=${domain}&type=A`,
      headers: { Accept: 'application/dns-json' }
    },
    {
      name: 'AdGuard',
      url: `https://dns.adguard.com/dns-query?name=${domain}&type=A`,
      headers: { Accept: 'application/dns-json' }
    }
  ];
  const results = [];
  for (const resolver of resolvers) {
    try {
      const data = await fetchJSON(resolver.url, {
        headers: { ...(resolver.headers || {}), ...DEFAULT_HEADERS }
      });
      results.push({
        resolver: resolver.name,
        status: data.Status,
        blocked: data.Status !== 0
      });
    } catch (e) {
      results.push({ resolver: resolver.name, error: errorMessage(e) });
    }
  }
  sendJSON(res, 200, { domain, results });
}

async function handleMalwareDetection(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const response = await httpRequest('https://urlhaus-api.abuse.ch/v1/hostinfo/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...DEFAULT_HEADERS
      },
      body: `host=${encodeURIComponent(domain)}`
    });
    const data = JSON.parse(response.body.toString('utf8'));
    sendJSON(res, 200, { domain, data });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function testCipher(domain, cipher) {
  return new Promise(resolve => {
    let settled = false;
    try {
      const socket = tls.connect(
        {
          host: domain,
          servername: domain,
          port: 443,
          rejectUnauthorized: false,
          ciphers: cipher,
          secureContext: tls.createSecureContext({ ciphers: cipher })
        },
        () => {
          settled = true;
          socket.end();
          resolve(true);
        }
      );
      socket.setTimeout(7000, () => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(false);
      });
      socket.on('error', () => {
        if (settled) return;
        settled = true;
        resolve(false);
      });
    } catch (e) {
      resolve(false);
    }
  });
}

async function handleTlsCipherSuites(domain, res) {
  domain = normalizeDomain(domain);
  const ciphers = [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-CHACHA20-POLY1305'
  ];
  const supported = [];
  for (const cipher of ciphers) {
    const ok = await testCipher(domain, cipher);
    if (ok) supported.push(cipher);
  }
  sendJSON(res, 200, { domain, ciphers: supported });
}

async function handleTlsSecurityConfig(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const info = await httpRequest(`https://${domain}`, {
      method: 'HEAD',
      headers: DEFAULT_HEADERS
    });
    const tlsInfo = await new Promise((resolve, reject) => {
      const socket = tls.connect(
        { host: domain, servername: domain, port: 443, rejectUnauthorized: false },
        () => {
          const protocol = socket.getProtocol();
          const cipher = socket.getCipher();
          const ocsp = Boolean(socket.ocspResponse);
          socket.end();
          resolve({ protocol, cipher, ocsp });
        }
      );
      socket.setTimeout(15000, () => {
        socket.destroy();
        reject(new Error('Timeout'));
      });
      socket.on('error', reject);
    });
    const modern = ['TLSv1.2', 'TLSv1.3'];
    const status = modern.includes(tlsInfo.protocol) ? 'ok' : 'fail';
    sendJSON(res, 200, {
      domain,
      status,
      info: tlsInfo,
      headers: info.headers
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function simulateTlsVersion(domain, minVersion, maxVersion) {
  return new Promise(resolve => {
    let settled = false;
    try {
      const socket = tls.connect(
        {
          host: domain,
          servername: domain,
          port: 443,
          rejectUnauthorized: false,
          minVersion,
          maxVersion
        },
        () => {
          settled = true;
          const protocol = socket.getProtocol();
          socket.end();
          resolve({ supported: true, protocol });
        }
      );
      socket.setTimeout(10000, () => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve({ supported: false });
      });
      socket.on('error', () => {
        if (settled) return;
        settled = true;
        resolve({ supported: false });
      });
    } catch (e) {
      resolve({ supported: false });
    }
  });
}

async function handleTlsHandshake(domain, res) {
  domain = normalizeDomain(domain);
  const versions = [
    { label: 'TLS 1.0', min: 'TLSv1', max: 'TLSv1' },
    { label: 'TLS 1.1', min: 'TLSv1.1', max: 'TLSv1.1' },
    { label: 'TLS 1.2', min: 'TLSv1.2', max: 'TLSv1.2' },
    { label: 'TLS 1.3', min: 'TLSv1.3', max: 'TLSv1.3' }
  ];
  const results = [];
  for (const version of versions) {
    const outcome = await simulateTlsVersion(domain, version.min, version.max);
    results.push({ label: version.label, ...outcome });
  }
  sendJSON(res, 200, { domain, results });
}

async function handleScreenshot(domain, res) {
  domain = normalizeDomain(domain);
  const url = `https://image.thum.io/get/width/1200/crop/800/https://${domain}`;
  sendJSON(res, 200, { domain, url });
}

const server = http.createServer(async (req, res) => {
  const parsed = new URL(req.url, 'http://localhost');
  const segments = parsed.pathname.split('/').filter(Boolean);
  if (segments[0] === 'mx' && segments[1]) return handleMx(segments[1], res);
  if (segments[0] === 'smtputf8' && segments[1]) return handleSmtpUtf8(segments[1], res);
  if (segments[0] === 'dnssec' && segments[1]) return handleDnssec(segments[1], res);
  if (segments[0] === 'dkim' && segments[1])
    return handleDkim(segments[1], parsed.searchParams.get('selector') || 'default', res);
  if (segments[0] === 'rpki' && segments[1]) return handleRpki(segments[1], res);
  if (segments[0] === 'whois' && segments[1]) return handleWhois(segments[1], res);
  if (segments[0] === 'w3c' && segments[1]) return handleW3C(segments[1], res);
  if (segments[0] === 'headers' && segments[1]) return handleHeaders(segments[1], res);
  if (segments[0] === 'caa' && segments[1]) return handleCaa(segments[1], res);
  if (segments[0] === 'tlsa' && segments[1]) return handleTlsa(segments[1], res);
  if (segments[0] === 'securitytxt' && segments[1])
    return handleSecurityTxt(segments[1], res);
  if (segments[0] === 'tlsinfo' && segments[1]) return handleTls(segments[1], res);
  if (segments[0] === 'ipinfo' && segments[1]) return handleIpInfo(segments[1], res);
  if (segments[0] === 'sslchain' && segments[1])
    return handleSslChain(segments[1], res);
  if (segments[0] === 'dnsrecords' && segments[1])
    return handleDnsRecords(segments[1], res);
  if (segments[0] === 'cookies' && segments[1]) return handleCookies(segments[1], res);
  if (segments[0] === 'crawl' && segments[1]) return handleCrawlRules(segments[1], res);
  if (segments[0] === 'allheaders' && segments[1])
    return handleAllHeaders(segments[1], res);
  if (segments[0] === 'quality' && segments[1])
    return handleQualityMetrics(segments[1], res);
  if (segments[0] === 'serverlocation' && segments[1])
    return handleServerLocation(segments[1], res);
  if (segments[0] === 'associated' && segments[1])
    return handleAssociatedHosts(segments[1], res);
  if (segments[0] === 'redirects' && segments[1])
    return handleRedirectChain(segments[1], res);
  if (segments[0] === 'txt' && segments[1]) return handleTxtRecords(segments[1], res);
  if (segments[0] === 'serverstatus' && segments[1])
    return handleServerStatus(segments[1], res);
  if (segments[0] === 'openports' && segments[1])
    return handleOpenPorts(segments[1], res);
  if (segments[0] === 'traceroute' && segments[1])
    return handleTraceroute(segments[1], res);
  if (segments[0] === 'carbon' && segments[1])
    return handleCarbonFootprint(segments[1], res);
  if (segments[0] === 'serverinfo' && segments[1])
    return handleServerInfo(segments[1], res);
  if (segments[0] === 'domaininfo' && segments[1])
    return handleDomainInfo(segments[1], res);
  if (segments[0] === 'dnssecurity' && segments[1])
    return handleDnsSecurityExtensions(segments[1], res);
  if (segments[0] === 'sitefeatures' && segments[1])
    return handleSiteFeatures(segments[1], res);
  if (segments[0] === 'dnsserver' && segments[1])
    return handleDnsServer(segments[1], res);
  if (segments[0] === 'techstack' && segments[1])
    return handleTechStack(segments[1], res);
  if (segments[0] === 'listedpages' && segments[1])
    return handleListedPages(segments[1], res);
  if (segments[0] === 'linkedpages' && segments[1])
    return handleLinkedPages(segments[1], res);
  if (segments[0] === 'socialtags' && segments[1])
    return handleSocialTags(segments[1], res);
  if (segments[0] === 'emailconfig' && segments[1])
    return handleEmailConfig(segments[1], res);
  if (segments[0] === 'firewall' && segments[1])
    return handleFirewallDetection(segments[1], res);
  if (segments[0] === 'httpsecurity' && segments[1])
    return handleHttpSecurityFeatures(segments[1], res);
  if (segments[0] === 'archive' && segments[1])
    return handleArchiveHistory(segments[1], res);
  if (segments[0] === 'globalrank' && segments[1])
    return handleGlobalRanking(segments[1], res);
  if (segments[0] === 'block' && segments[1])
    return handleBlockDetection(segments[1], res);
  if (segments[0] === 'malware' && segments[1])
    return handleMalwareDetection(segments[1], res);
  if (segments[0] === 'tlsciphers' && segments[1])
    return handleTlsCipherSuites(segments[1], res);
  if (segments[0] === 'tlsconfig' && segments[1])
    return handleTlsSecurityConfig(segments[1], res);
  if (segments[0] === 'tlshandshake' && segments[1])
    return handleTlsHandshake(segments[1], res);
  if (segments[0] === 'screenshot' && segments[1])
    return handleScreenshot(segments[1], res);
  sendJSON(res, 404, { error: 'Not found' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));

