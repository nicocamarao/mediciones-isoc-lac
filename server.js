const http = require('http');
const dns = require('dns').promises;
const fs = require('fs/promises');
const DEFAULT_SERVERS = ['8.8.8.8', '8.8.4.4'];
if (process.env.DNS_SERVERS) {
  const servers = process.env.DNS_SERVERS.split(',')
    .map(item => item.trim())
    .filter(Boolean);
  if (servers.length) dns.setServers(servers);
} else {
  dns.setServers(DEFAULT_SERVERS);
}
const path = require('path');
const net = require('net');
const https = require('https');
const tls = require('tls');
const { execFile } = require('child_process');
const { domainToASCII } = require('url');
const { URL } = require('url');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

const htmlCache = new Map();
const headerCache = new Map();
const dnsCache = new Map();
const dnssecCache = new Map();
const routeCache = new Map();
const ipMetaCache = new Map();
const cctldCache = new Map();
const pulseCache = new Map();
const dnsvizMetaCache = new Map();
const dnsvizSvgCache = new Map();
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 10000);
const SELFTEST_TIMEOUT_MS = Number(process.env.SELFTEST_TIMEOUT_MS || 12000);
const INDEX_PATH = path.join(__dirname, 'index.html');
const PARTIALS_DIR = path.join(__dirname, 'partials');
const LACNIC_CCTLDS = [
  'ar','bo','br','cl','co','ec','fk','gf','gy','pe','py','sr','uy','ve',
  'bz','cr','gt','hn','ni','pa','sv',
  'mx',
  'ai','ag','aw','bb','bl','bm','bq','bs','cu','cw','dm','do','gd','gp','ht','jm','kn','ky','lc','mf','mq','ms','pr','sx','tc','tt','vc','vg','vi'
].sort((a, b) => a.localeCompare(b));
const cctldRefreshPromises = new Map();

const WIFI_6GHZ_STATUS_BY_CCTLD = {
  ar: [{ territory: 'Argentina', status: 'FULL_5925_7125' }],
  aw: [{ territory: 'Aruba', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  bz: [{ territory: 'Belize', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  bo: [{ territory: 'Bolivia', status: 'LOW_5925_6425' }],
  bq: [
    { territory: 'Bonaire', status: 'NO_PUBLIC_ADOPTION_FOUND' },
    { territory: 'Saba', status: 'NO_PUBLIC_ADOPTION_FOUND' },
    { territory: 'Sint Eustatius', status: 'NO_PUBLIC_ADOPTION_FOUND' }
  ],
  br: [{ territory: 'Brazil', status: 'FULL_5925_7125' }],
  cl: [{ territory: 'Chile', status: 'LOW_5925_6425' }],
  co: [{ territory: 'Colombia', status: 'FULL_5925_7125' }],
  cr: [{ territory: 'Costa Rica', status: 'FULL_5925_7125' }],
  cu: [{ territory: 'Cuba', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  cw: [{ territory: 'Curacao', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  ec: [{ territory: 'Ecuador', status: 'LOW_5925_6425' }],
  sv: [{ territory: 'El Salvador', status: 'FULL_5925_7125' }],
  gf: [{ territory: 'French Guiana', status: 'LOW_5925_6425', note: 'Territory of France; no separate local 6 GHz evidence found' }],
  gt: [{ territory: 'Guatemala', status: 'FULL_5925_7125' }],
  gy: [{ territory: 'Guyana', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  ht: [{ territory: 'Haiti', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  hn: [{ territory: 'Honduras', status: 'LOW_5925_6425' }],
  mx: [{ territory: 'Mexico', status: 'LOW_5925_6425' }],
  ni: [{ territory: 'Nicaragua', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  pa: [{ territory: 'Panama', status: 'CONSULTATION', note: 'Public consultation proposed indoor unlicensed 5925-7125 MHz' }],
  py: [{ territory: 'Paraguay', status: 'LOW_5925_6425', note: 'Confirmed by CONATEL Resolution 1035/2025' }],
  pe: [{ territory: 'Peru', status: 'FULL_5925_7125' }],
  do: [{ territory: 'Dominican Republic', status: 'FULL_5925_7125' }],
  sx: [{ territory: 'Sint Maarten', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  fk: [{ territory: 'Falkland Islands (Malvinas)', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  gs: [{ territory: 'South Georgia and the South Sandwich Islands', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  sr: [{ territory: 'Suriname', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  tt: [{ territory: 'Trinidad and Tobago', status: 'LOW_5925_6425' }],
  uy: [{ territory: 'Uruguay', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  ve: [{ territory: 'Venezuela', status: 'NO_PUBLIC_ADOPTION_FOUND' }]
};

function formatWifiStatusLabel(status) {
  const labels = {
    FULL_5925_7125: 'Libre 5925-7125',
    LOW_5925_6425: 'Parcial 5925-6425',
    NO_PUBLIC_ADOPTION_FOUND: 'Sin adopción pública',
    CONSULTATION: 'Consulta pública'
  };
  return labels[status] || status || 'Próximamente';
}

function cleanDomain(domain) {
  return String(domain || '')
    .trim()
    .replace(/\.+$/, '');
}

async function resolveAddresses(domain) {
  domain = cleanDomain(domain);
  const cached = cacheGet(dnsCache, `addr:${domain}`, 10 * 60 * 1000);
  if (cached) return cached;
  const v4 = await dns.resolve4(domain).catch(() => []);
  const v6 = await dns.resolve6(domain).catch(() => []);
  const value = { v4, v6 };
  cacheSet(dnsCache, `addr:${domain}`, value);
  return value;
}

async function resolveFirstIp(domain) {
  const { v4, v6 } = await resolveAddresses(domain);
  if (v4.length) return { ip: v4[0], family: 4 };
  if (v6.length) return { ip: v6[0], family: 6 };
  return { ip: null, family: null };
}

function ipToCymruQuery(ipIn) {
  const ip = net.isIP(ipIn);
  if (!ip) throw new Error(`Error parsing IP address ${ipIn}.`);
  if (ip === 4) {
    const split = String(ipIn).split('.').slice(0, 3).reverse();
    return `${split.join('.')}.origin.asn.cymru.com.`;
  }
  const [left, right = ''] = String(ipIn).toLowerCase().split('::');
  const leftParts = left ? left.split(':').filter(Boolean) : [];
  const rightParts = right ? right.split(':').filter(Boolean) : [];
  const fill = Math.max(0, 8 - leftParts.length - rightParts.length);
  const expanded = [...leftParts, ...Array(fill).fill('0'), ...rightParts]
    .map(part => part.padStart(4, '0'))
    .join('');
  const hex = expanded.padEnd(32, '0').slice(0, 12);
  return `${hex.split('').reverse().join('.')}.origin6.asn.cymru.com.`;
}

async function resolveOriginRoutesViaCymru(ipIn) {
  const cached = cacheGet(routeCache, `cymru:${ipIn}`, 10 * 60 * 1000);
  if (cached) return cached;
  const query = ipToCymruQuery(ipIn);
  const txt = await dns.resolveTxt(query);
  const rows = txt
    .flat()
    .map(String)
    .filter(Boolean);
  const routes = [];
  for (const row of rows) {
    const [left, right] = row.split('|').map(part => part && part.trim());
    if (!left || !right) continue;
    const prefix = right;
    const asns = left.split(' ').map(item => item.trim()).filter(Boolean);
    for (const asn of asns) {
      routes.push({ asn: Number(asn), prefix });
    }
  }
  cacheSet(routeCache, `cymru:${ipIn}`, routes);
  return routes;
}

async function lookupIpMeta(ip) {
  if (!ip) throw new Error('Sin dirección IP');
  const cached = cacheGet(ipMetaCache, `ipmeta:${ip}`, 15 * 60 * 1000);
  if (cached) return cached;
  const data = await fetchJSON(`https://ipwho.is/${encodeURIComponent(ip)}`);
  if (!data || data.success === false) {
    const message =
      typeof data?.message === 'string' && data.message.trim()
        ? data.message.trim()
        : 'Servicio no disponible';
    throw new Error(message);
  }
  const connection = data.connection || {};
  const value = {
    ip,
    city: data.city || '',
    region: data.region || data.region_name || data.region_code || '',
    country: data.country || data.country_name || '',
    latitude: data.latitude ?? null,
    longitude: data.longitude ?? null,
    timezone:
      (data.timezone && data.timezone.id) ||
      data.timezone ||
      data.timezone_gmt ||
      '',
    asn: connection.asn || data.asn || null,
    org: connection.org || data.org || data.connection?.organization || '',
    isp: connection.isp || data.isp || '',
    network:
      connection.route ||
      connection.network ||
      connection.domain ||
      data.network ||
      ''
  };
  cacheSet(ipMetaCache, `ipmeta:${ip}`, value);
  return value;
}

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

const DIGEST_MAP = {
  1: 'SHA-1',
  2: 'SHA-256',
  4: 'SHA-384'
};

function normalizeDomain(domain) {
  try {
    return domainToASCII(cleanDomain(domain).toLowerCase());
  } catch (e) {
    return cleanDomain(domain);
  }
}

function sendHTML(res, status, html) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(html);
}

function sendSVG(res, status, svg) {
  res.writeHead(status, {
    'Content-Type': 'image/svg+xml; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store'
  });
  res.end(svg);
}

function placeholderSvg(title, subtitle = '') {
  const safeTitle = String(title || '').replace(/[<&>]/g, s => ({
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;'
  })[s]);
  const safeSubtitle = String(subtitle || '').replace(/[<&>]/g, s => ({
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;'
  })[s]);
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 700" role="img" aria-label="${safeTitle}">
  <defs>
    <linearGradient id="g" x1="0" x2="1" y1="0" y2="1">
      <stop offset="0%" stop-color="#f6f8fb"/>
      <stop offset="100%" stop-color="#e8eef5"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="700" rx="28" fill="url(#g)"/>
  <rect x="60" y="60" width="1080" height="580" rx="24" fill="#ffffff" stroke="#d0d7e2"/>
  <text x="110" y="190" font-family="Inter, Arial, sans-serif" font-size="40" font-weight="700" fill="#16324f">${safeTitle}</text>
  <text x="110" y="250" font-family="Inter, Arial, sans-serif" font-size="24" fill="#4d6177">${safeSubtitle || 'DNSViz no respondió con un gráfico listo para mostrar.'}</text>
  <rect x="110" y="320" width="980" height="220" rx="20" fill="#f7fafc" stroke="#d7e0ea" stroke-dasharray="10 10"/>
  <text x="600" y="430" text-anchor="middle" font-family="Inter, Arial, sans-serif" font-size="28" font-weight="600" fill="#274261">DNSSEC / DNSViz</text>
  <text x="600" y="470" text-anchor="middle" font-family="Inter, Arial, sans-serif" font-size="18" fill="#5a7088">Se mostrará el gráfico real cuando el análisis esté disponible.</text>
</svg>`;
}

function errorMessage(e) {
  if (e && typeof e === 'object') {
    if (e.code === 'ENOTFOUND') return 'Dominio no encontrado';
    if (e.code === 'ETIMEOUT' || e.message === 'Timeout' || /timeout/i.test(e.message || '')) return 'Timeout';
    if (e.code === 'ECONNREFUSED') return 'Conexión rechazada';
    if (e.code === 'EAI_AGAIN') return 'Problema de DNS';
  }
  return 'Servicio no disponible';
}

function sendJSON(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify(data));
}

async function handleMx(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await resolveMxRecords(domain, 'local');
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

function normalizeMxRecord(record) {
  if (record && typeof record === 'object') {
    const exchange = normalizeDomain(record.exchange || record.host || record.name || '');
    return {
      exchange,
      priority: Number.isFinite(record.priority) ? record.priority : (Number.isFinite(Number(record.priority)) ? Number(record.priority) : null)
    };
  }
  const value = String(record || '').trim();
  if (!value) return { exchange: '', priority: null };
  const parts = value.split(/\s+/).filter(Boolean);
  if (parts.length >= 2 && /^\d+$/.test(parts[0])) {
    return {
      priority: Number(parts[0]),
      exchange: normalizeDomain(parts.slice(1).join(' '))
    };
  }
  return { exchange: normalizeDomain(value), priority: null };
}

function smtpQuery(server, port) {
  return new Promise(resolve => {
    const socket = net.createConnection(port, server);
    let buffer = '';
    let ehloSent = false;
    let capabilities = [];
    let banner = null;
    let transcript = [];
    let finished = false;
    const timer = setTimeout(() => {
      socket.destroy();
      if (finished) return;
      finished = true;
      resolve({ status: 'timeout', capabilities, banner, transcript, port });
    }, REQUEST_TIMEOUT_MS);

    const finish = payload => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try {
        socket.end();
      } catch (e) {}
      resolve({ capabilities, banner, transcript, port, ...payload });
    };

    socket.on('data', data => {
      buffer += data.toString();
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop();
      for (const line of lines) {
        transcript.push(line);
        if (!banner && /^220[ -]/.test(line)) {
          banner = line.replace(/^220[ -]/, '').trim();
        }
        if (!ehloSent && /^220/.test(line)) {
          socket.write('EHLO mediciones.isoc-lac\r\n');
          ehloSent = true;
          continue;
        }
        if (ehloSent && /^250[ -]/.test(line)) {
          capabilities.push(line.replace(/^250[ -]/, '').trim());
          if (line.startsWith('250 ')) {
            const supportsUtf8 = capabilities.some(cap => /^SMTPUTF8\b/i.test(cap) || /^UTF8\b/i.test(cap) || /^UTF-8\b/i.test(cap));
            return finish({ status: supportsUtf8 ? 'supports' : 'no' });
          }
        }
      }
    });

    socket.on('error', () => {
      finish({ status: 'connection-error' });
    });

    socket.on('end', () => {
      const supportsUtf8 = capabilities.some(cap => /^SMTPUTF8\b/i.test(cap) || /^UTF8\b/i.test(cap) || /^UTF-8\b/i.test(cap));
      finish({ status: supportsUtf8 ? 'supports' : 'no' });
    });
  });
}

async function checkSmtpUtf8(server) {
  // Prefer port 25, but keep 587 as a fallback when MX exposure is unusual.
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
    const mx = await resolveMxRecords(domain, 'local');
    const results = [];
    for (const record of mx) {
      const { exchange, priority } = normalizeMxRecord(record);
      if (!exchange) continue;
      const result = await checkSmtpUtf8(exchange);
      results.push({
        server: exchange,
        priority,
        status: result.status,
        port: result.port || 25,
        banner: result.banner || null,
        capabilities: result.capabilities || [],
        transcript: Array.isArray(result.transcript) ? result.transcript.slice(0, 8) : []
      });
    }
    sendJSON(res, 200, { domain, results });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleStarttls(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const mx = await resolveMxRecords(domain, 'local');
    const results = [];
    for (const record of mx) {
      const { exchange, priority } = normalizeMxRecord(record);
      if (!exchange) continue;
      const result = await checkSmtpUtf8(exchange);
      const starttls = (result.capabilities || []).some(cap => /^STARTTLS\b/i.test(cap));
      results.push({
        server: exchange,
        priority,
        status: starttls ? 'supports' : 'no',
        capabilities: result.capabilities || []
      });
    }
    sendJSON(res, 200, { domain, results });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function dnssecGoogle(domain, mode = 'remote') {
  domain = normalizeDomain(domain);
  const cacheKey = `dnssec:${mode}:${domain}`;
  const cached = cacheGet(dnssecCache, cacheKey, 10 * 60 * 1000);
  if (cached) return cached;
  const result = {
    parent: false,
    child: false,
    algorithms: [],
    digests: [],
    dsRecords: [],
    dnskeyRecords: [],
    nsec3: {
      present: false,
      configured: false,
      hashAlgorithm: null,
      hashAlgorithmName: null,
      iterations: null,
      salt: null,
      hasSha1: false,
      records: [],
      notes: []
    }
  };

  if (mode === 'local' || mode === 'servers') {
    try {
      const ds = await resolveDsRecords(domain, mode);
      if (Array.isArray(ds) && ds.length > 0) {
        result.parent = true;
        result.dsRecords = ds.map(parseDnssecDsRecord).filter(Boolean);
        result.dsRecords.forEach(record => {
          if (record.algorithmName) result.algorithms.push(record.algorithmName);
          if (record.digestName) result.digests.push(record.digestName);
          if (record.digestType === 1) result.nsec3.hasSha1 = true;
        });
      }
    } catch (e) {}
    try {
      const dnskey = await resolveDnskeyRecords(domain, mode);
      if (Array.isArray(dnskey) && dnskey.length > 0) {
        result.child = true;
        result.dnskeyRecords = dnskey.map(parseDnssecDnskeyRecord).filter(Boolean);
        result.dnskeyRecords.forEach(record => {
          if (record.algorithmName) result.algorithms.push(record.algorithmName);
        });
      }
    } catch (e) {}
    try {
      const nsec3param = await resolveDnsValue(domain, 'NSEC3PARAM', mode).catch(() => []);
      const nsec3 = await resolveDnsValue(domain, 'NSEC3', mode).catch(() => []);
      const paramRecord = Array.isArray(nsec3param) && nsec3param.length ? parseNsec3ParamRecord(nsec3param[0]) : null;
      result.nsec3.present = Boolean((Array.isArray(nsec3param) && nsec3param.length) || (Array.isArray(nsec3) && nsec3.length));
      result.nsec3.records = Array.isArray(nsec3param) ? nsec3param.slice() : [];
      if (paramRecord) {
        result.nsec3.hashAlgorithm = paramRecord.hashAlgorithm;
        result.nsec3.hashAlgorithmName = paramRecord.hashAlgorithmName;
        result.nsec3.iterations = paramRecord.iterations;
        result.nsec3.salt = paramRecord.salt;
        result.nsec3.hasSha1 = paramRecord.hasSha1;
      }
      if (!result.nsec3.present && result.parent && result.child) {
        result.nsec3.notes.push('La zona parece usar DNSSEC clásico sin NSEC3.');
      } else if (result.nsec3.present && !(Array.isArray(nsec3) && nsec3.length)) {
        result.nsec3.notes.push('NSEC3PARAM aparece, pero no se detectaron registros NSEC3.');
      } else if (result.nsec3.present && Array.isArray(nsec3) && nsec3.length) {
        result.nsec3.configured = true;
        if (paramRecord && paramRecord.hasSha1) {
          result.nsec3.notes.push('NSEC3 usa SHA-1.');
        }
      }
    } catch (e) {}
    cacheSet(dnssecCache, cacheKey, result);
    return result;
  }

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
  cacheSet(dnssecCache, cacheKey, result);
  return result;
}

async function dnssecChain(domain, mode = 'remote') {
  domain = normalizeDomain(domain);
  const labels = domain.split('.').filter(Boolean);
  const chain = [];
  for (let i = 0; i < labels.length; i += 1) {
    const name = labels.slice(i).join('.');
    const google = await dnssecGoogle(name, mode);
    chain.push({
      name,
      level: i === 0 ? 'target' : (i === labels.length - 1 ? 'tld' : 'ancestor'),
      parent: google.parent,
      child: google.child,
      algorithms: [...new Set(google.algorithms.filter(Boolean))],
      valid: google.parent && google.child
    });
  }
  chain.push({
    name: 'raíz',
    level: 'root',
    parent: true,
    child: true,
    algorithms: [],
    valid: true,
    note: 'ancla de confianza'
  });
  return chain;
}

async function handleDnssec(domain, res) {
  domain = normalizeDomain(domain);
  const [google, dnsviz] = await Promise.all([
    dnssecGoogle(domain, 'local'),
    resolveDnsvizMeta(domain).catch(() => null)
  ]);
  const assessment = buildDnssecAssessment(google);
  const algorithms = [...new Set(google.algorithms.filter(Boolean))];
  const digests = [...new Set((google.digests || []).filter(Boolean))];
  const notices = dnsviz?.notices?.notices || dnsviz?.notices || {};
  const warnings = Array.isArray(notices.warnings) ? notices.warnings : [];
  const errors = Array.isArray(notices.errors) ? notices.errors : [];
  assessment.status = assessment.valid ? (warnings.length || errors.length ? 'warning' : 'ok') : 'fail';
  if (dnsviz) {
    assessment.sections.push({
      id: 'dnsviz',
      label: 'DNSViz',
      status: errors.length ? 'fail' : (warnings.length ? 'warning' : (dnsviz.available ? 'ok' : 'info')),
      note: dnsviz.available
        ? 'Recomendaciones y avisos tomados desde DNSViz.'
        : 'DNSViz no respondió por completo en este entorno.',
      items: [
        ...warnings.map(text => ({ text, status: 'warning' })),
        ...errors.map(text => ({ text, status: 'fail' }))
      ]
    });
    if (Array.isArray(dnsviz.observations) && dnsviz.observations.length) {
      assessment.summaryLines.push(...dnsviz.observations.slice(0, 8));
    }
  }
  sendJSON(res, 200, { domain, methods: { google }, algorithms, digests, valid: assessment.valid, assessment, dnsviz });
}

async function handleDkim(domain, selector, res) {
  domain = normalizeDomain(domain);
  try {
    if (!selector || selector === 'support') {
      const supported = await detectDkimSupport(domain);
      sendJSON(res, 200, {
        domain,
        supported: Boolean(supported?.supported),
        selector: null,
        matches: Array.isArray(supported?.matches) ? supported.matches : [],
        checkedSelectors: Array.isArray(supported?.checkedSelectors) ? supported.checkedSelectors : []
      });
      return;
    }
    const txt = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
    const records = extractTxtRecords(txt);
    const found = records.some(row => /v=DKIM1/i.test(row));
    sendJSON(res, 200, { domain, selector, supported: found || records.length > 0, found, records });
  } catch (e) {
    if (e.code === 'ENODATA' && (!selector || selector === 'support')) {
      sendJSON(res, 200, { domain, supported: true, selector: null });
      return;
    }
    sendJSON(res, 200, { domain, selector, supported: false, found: false });
  }
}

async function handleSpf(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const txt = await resolveTxtRecords(domain, 'local').catch(() => []);
    const records = extractTxtRecords(txt).filter(row => /^v=spf1\b/i.test(row));
    const parsed = records.map(parseSpfPolicy);
    const strict = parsed.some(item => item.strict);
    const valid = parsed.some(item => item.valid);
    sendJSON(res, 200, {
      domain,
      records,
      parsed,
      valid,
      strict,
      policyStatus: !records.length ? 'missing' : strict ? 'strict' : valid ? 'weak' : 'invalid'
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDmarc(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const txt = await resolveTxtRecords(`_dmarc.${domain}`, 'local').catch(() => []);
    const records = extractTxtRecords(txt).filter(row => /^v=dmarc1\b/i.test(row));
    const parsed = records.map(parseDmarcPolicy);
    const strict = parsed.some(item => item.strict);
    const valid = parsed.some(item => item.valid);
    sendJSON(res, 200, {
      domain,
      records,
      parsed,
      valid,
      strict,
      policyStatus: !records.length ? 'missing' : strict ? 'strict' : valid ? 'weak' : 'invalid'
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleIpv4(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await resolveDnsValue(domain, 'A', 'local').catch(() => []);
    sendJSON(res, 200, { domain, records, present: records.length > 0 });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleIpv6(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await resolveDnsValue(domain, 'AAAA', 'local').catch(() => []);
    sendJSON(res, 200, { domain, records, present: records.length > 0 });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleMailDnssec(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const mx = await resolveMxRecords(domain, 'local').catch(() => []);
    const domainDnssec = await dnssecGoogle(domain, 'local');
    const results = [];
    for (const record of mx) {
      const { exchange } = normalizeMxRecord(record);
      if (!exchange) continue;
      const exchangeDnssec = await dnssecGoogle(exchange, 'local');
      results.push({
        exchange,
        secure: exchangeDnssec.parent && exchangeDnssec.child,
        algorithms: [...new Set(exchangeDnssec.algorithms.filter(Boolean))]
      });
    }
    sendJSON(res, 200, {
      domain,
      domainDnssec: {
        secure: domainDnssec.parent && domainDnssec.child,
        algorithms: [...new Set(domainDnssec.algorithms.filter(Boolean))]
      },
      mx: results
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleMailIpv6(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const mx = await resolveMxRecords(domain, 'local').catch(() => []);
    const results = [];
    for (const record of mx) {
      const { exchange, priority } = normalizeMxRecord(record);
      if (!exchange) continue;
      const ipv6 = await resolveDnsValue(exchange, 'AAAA', 'local').catch(() => []);
      results.push({
        exchange,
        priority,
        ipv6,
        present: ipv6.length > 0
      });
    }
    sendJSON(res, 200, {
      domain,
      mx: results,
      present: results.length > 0 && results.every(item => item.present)
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function withConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let index = 0;
  const runners = Array.from({ length: Math.max(1, limit) }, async () => {
    while (index < items.length) {
      const current = index;
      index += 1;
      results[current] = await worker(items[current], current);
    }
  });
  await Promise.all(runners);
  return results;
}

async function summarizeCctld(tld, mode = 'local') {
  const domain = normalizeDomain(tld);
  const cached = cacheGet(cctldCache, `${mode}:${domain}`, 15 * 60 * 1000);
  if (cached) return cached;

  const [ns, dnssec] = await Promise.all([
    resolveNsRecords(domain, mode).catch(() => []),
    dnssecGoogle(domain, mode).catch(() => ({ parent: false, child: false, algorithms: [] }))
  ]);
  const dnssecAssessment = buildDnssecAssessment(dnssec);

  const nsDetails = await withConcurrency(ns.slice(0, 6), 3, async host => {
    const [ipv4, ipv6] = await Promise.all([
      resolveDnsValue(host, 'A', mode).catch(() => []),
      resolveDnsValue(host, 'AAAA', mode).catch(() => [])
    ]);
    return {
      host,
      ipv4,
      ipv6,
      ipv4Count: ipv4.length,
      ipv6Count: ipv6.length,
      reachableV4: ipv4.length > 0,
      reachableV6: ipv6.length > 0
    };
  });

  const ipv4NsCount = nsDetails.filter(item => item.reachableV4).length;
  const ipv6NsCount = nsDetails.filter(item => item.reachableV6).length;
  const validDnssec = Boolean(dnssec.parent && dnssec.child);
  const dnssecAssessmentStatus = dnssecAssessment.status || (validDnssec ? 'ok' : 'fail');
  const wifi = await summarizeWifiCountry(domain).catch(() => ({
    status: 'pending',
    label: 'Próximamente',
    notes: ['No se pudo resolver el bloque Wi‑Fi.']
  }));
  const pulse = await summarizePulseCountry(domain).catch(() => ({
    available: false,
    notes: ['No se pudo recuperar Pulse.']
  }));
  const value = {
    tld: domain,
    nsCount: ns.length,
    ipv4NsCount,
    ipv6NsCount,
    dnssec: {
      parent: Boolean(dnssec.parent),
      child: Boolean(dnssec.child),
      valid: validDnssec,
      algorithms: [...new Set((dnssec.algorithms || []).filter(Boolean))],
      digests: [...new Set((dnssec.digests || []).filter(Boolean))],
      dsRecords: Array.isArray(dnssec.dsRecords) ? dnssec.dsRecords : [],
      dnskeyRecords: Array.isArray(dnssec.dnskeyRecords) ? dnssec.dnskeyRecords : [],
      nsec3: {
        present: Boolean(dnssec.nsec3?.present),
        configured: Boolean(dnssec.nsec3?.configured),
        hashAlgorithm: dnssec.nsec3?.hashAlgorithm ?? null,
        hashAlgorithmName: dnssec.nsec3?.hashAlgorithmName ?? null,
        iterations: dnssec.nsec3?.iterations ?? null,
        salt: dnssec.nsec3?.salt ?? null,
        hasSha1: Boolean(dnssec.nsec3?.hasSha1),
        records: Array.isArray(dnssec.nsec3?.records) ? dnssec.nsec3.records : [],
        notes: Array.isArray(dnssec.nsec3?.notes) ? dnssec.nsec3.notes : []
      },
      assessment: dnssecAssessment
    },
    nsDetails,
    wifi,
    pulse,
    status: dnssecAssessmentStatus === 'warning' ? 'warning' : (validDnssec ? 'ok' : 'fail'),
    dnssecValid: validDnssec,
    refreshedAt: new Date().toISOString()
  };
  value.dnsviz = {
    available: false,
    pageUrl: `https://dnsviz.net/d/${domain}/dnssec/`,
    svgUrl: `https://dnsviz.net/d/${domain}/dnssec/auth_graph.svg?download=1`,
    observations: []
  };
  resolveDnsvizMeta(domain)
    .then(async dnsviz => {
      const dnsvizValue = {
        available: dnsviz.available,
        updated: dnsviz.updated,
        pageUrl: dnsviz.pageUrl,
        svgUrl: dnsviz.svgUrl,
        observations: dnsviz.observations || [],
        warningCount: dnsviz.warningCount || 0,
        errorCount: dnsviz.errorCount || 0,
        warnings: Array.isArray(dnsviz.warnings) ? dnsviz.warnings : [],
        errors: Array.isArray(dnsviz.errors) ? dnsviz.errors : [],
        notices: dnsviz.notices || null
      };
      const notices = dnsviz?.notices?.notices || dnsviz?.notices || {};
      const warnings = Array.isArray(notices.warnings) ? notices.warnings : [];
      const errors = Array.isArray(notices.errors) ? notices.errors : [];
      const current = cacheGet(cctldCache, `${mode}:${domain}`, 15 * 60 * 1000);
      if (current) {
        current.dnsviz = dnsvizValue;
        const hasDnsvizIssues = Boolean((warnings.length || errors.length));
        current.status = current.dnssecValid ? (hasDnsvizIssues ? 'warning' : 'ok') : 'fail';
        cacheSet(cctldCache, `${mode}:${domain}`, current);
      }
      if (dnsviz.svgUrl) {
        await fetchCachedDnsvizSvg(dnsviz.svgUrl, domain).catch(() => {});
      }
    })
    .catch(() => {});
  cacheSet(cctldCache, `${mode}:${domain}`, value);
  return value;
}

async function refreshCctldReport(mode = 'local') {
  if (cctldRefreshPromises.has(mode)) return cctldRefreshPromises.get(mode);
  const promise = (async () => {
    const items = await withConcurrency(LACNIC_CCTLDS, 4, async tld => summarizeCctld(tld, mode));
    cctldReportState.items = items;
    cctldReportState.generatedAt = new Date().toISOString();
    cctldReportState.mode = mode;
    return cctldReportState;
  })().finally(() => {
    cctldRefreshPromises.delete(mode);
  });
  cctldRefreshPromises.set(mode, promise);
  return promise;
}

const cctldReportState = {
  generatedAt: null,
  items: [],
  mode: 'local'
};

async function handleCctldReport(res, mode = 'local') {
  if (!cctldReportState.items.length || cctldReportState.mode !== mode) {
    await refreshCctldReport(mode).catch(() => {});
  }
  sendJSON(res, 200, { ...cctldReportState, generating: cctldRefreshPromises.has(mode) });
}

function pickLib(target) {
  const url = typeof target === 'string' ? new URL(target) : target;
  return url.protocol === 'http:' ? http : https;
}

function fetchJSON(target, options = {}) {
  return new Promise((resolve, reject) => {
    const url = typeof target === 'string' ? new URL(target) : target;
    const lib = pickLib(url);
    const req = lib.request(
      url,
      { method: options.method || 'GET', headers: options.headers || {} },
      r => {
        let data = '';
        r.on('data', chunk => (data += chunk));
        r.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on('error', reject);
    req.setTimeout(options.timeout || REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error('Timeout'));
    });
    if (options.body) req.write(options.body);
    req.end();
  });
}

function fetchText(target, options = {}) {
  return new Promise((resolve, reject) => {
    const url = typeof target === 'string' ? new URL(target) : target;
    const lib = pickLib(url);
    const req = lib.request(
      url,
      { method: options.method || 'GET', headers: options.headers || {} },
      r => {
        let data = '';
        r.on('data', chunk => (data += chunk));
        r.on('end', () => resolve(data));
      }
    );
    req.on('error', reject);
    req.setTimeout(options.timeout || REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error('Timeout'));
    });
    if (options.body) req.write(options.body);
    req.end();
  });
}

function parseWifiSpectrumCertificate(text, sourceUrl) {
  const lines = String(text || '')
    .replace(/\r/g, '')
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean);
  const certId = (text.match(/Certification ID:\s*(WFA\d+)/i) || [null, null])[1] || null;
  const productName = (text.match(/Product Name\s+(.+)/i) || [null, null])[1] || null;
  const modelVariant = (text.match(/Product Model Variant\s+(.+)/i) || [null, null])[1] || null;
  const bands = [];
  for (const line of lines) {
    const match = line.match(/^(2\.4|5|6)\s*GHz\s*\|\s*(\d+)\s*\|\s*(\d+)$/i);
    if (match) {
      bands.push({
        band: `${match[1]} GHz`,
        tx: Number(match[2]),
        rx: Number(match[3])
      });
    }
  }
  const capabilityPatterns = [
    /Spectrum & Regulatory/i,
    /Channel Width in \d(\.4)? GHz/i,
    /WMM®?-Power Save/i,
    /Legacy Power Save/i,
    /Unschedule auto PS/i,
    /Protected Management Frames/i,
    /802\.11[a-z]?/i,
    /WPA[23]/i,
    /Wi-Fi CERTIFIED/i,
    /Wi-Fi Agile Multiband/i,
    /Wi-Fi Enhanced Open/i,
    /EAP (TLS|TTLS|PEAP|methods)/i,
    /MCS Index/i
  ];
  const capabilities = [];
  for (const line of lines) {
    if (capabilityPatterns.some(pattern => pattern.test(line)) && !capabilities.includes(line)) {
      capabilities.push(line);
    }
  }
  const classification = lines.filter(line =>
    /Wi-Fi CERTIFIED|Connectivity|Optimization|Security|Spectrum & Regulatory/i.test(line)
  );
  return {
    sourceUrl,
    certId,
    productName,
    modelVariant,
    bands,
    capabilities: capabilities.slice(0, 25),
    classifications: Array.from(new Set(classification)).slice(0, 25),
    lines: lines.slice(0, 40)
  };
}

async function fetchHeaders(target, useHttp = false) {
  try {
    const head = await fetchPage(target, { method: 'HEAD', useHttp });
    if (head.statusCode === 405 || head.statusCode === 501) {
      throw new Error('HEAD not allowed');
    }
    return { headers: head.headers, statusCode: head.statusCode };
  } catch (e) {
    const get = await fetchPage(target, { method: 'GET', useHttp });
    return { headers: get.headers, statusCode: get.statusCode };
  }
}

function fetchPage(target, options = {}) {
  return new Promise((resolve, reject) => {
    try {
      const url = typeof target === 'string' ? new URL(target) : target;
      const lib = options.useHttp || url.protocol === 'http:' ? http : https;
      const req = lib.request(
        url,
        {
          method: options.method || 'GET',
          headers: options.headers || {},
          timeout: options.timeout || REQUEST_TIMEOUT_MS
        },
        res => {
          const chunks = [];
          res.on('data', chunk => chunks.push(chunk));
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode,
              headers: res.headers,
              body: Buffer.concat(chunks).toString(options.encoding || 'utf8')
            });
          });
        }
      );
      req.on('error', reject);
      req.setTimeout(options.timeout || REQUEST_TIMEOUT_MS, () => {
        req.destroy(new Error('Timeout'));
      });
      if (options.body) req.write(options.body);
      req.end();
    } catch (e) {
      reject(e);
    }
  });
}

function cacheGet(cache, key, ttl = 60000) {
  const item = cache.get(key);
  if (!item) return null;
  if (Date.now() - item.timestamp > ttl) {
    cache.delete(key);
    return null;
  }
  return item.value;
}

function cacheSet(cache, key, value) {
  cache.set(key, { timestamp: Date.now(), value });
}

function digServers(mode) {
  if (mode === 'servers') {
    return DEFAULT_SERVERS.map(server => `@${server}`);
  }
  return [];
}

function parseDigShortLines(output) {
  return String(output || '')
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean);
}

function escapeRegExp(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function decodeHtmlEntities(value) {
  return String(value || '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function parsePingOutput(output) {
  const lines = String(output || '')
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean);
  const summaryLine = lines.find(line => /packet loss|packets transmitted/i.test(line)) || '';
  const rttLine = lines.find(line => /min\/avg\/max/i.test(line)) || '';
  const transmitted = Number((summaryLine.match(/(\d+)\s+packets transmitted/i) || [])[1] || 0);
  const received = Number((summaryLine.match(/(\d+)\s+(?:packets )?received/i) || [])[1] || 0);
  const loss = Number((summaryLine.match(/(\d+(?:\.\d+)?)%\s*packet loss/i) || [])[1] || 0);
  const rttParts = (rttLine.match(/=\s*([^ ]+)/) || [])[1] || '';
  const [min, avg, max, stddev] = rttParts.split('/').map(Number);
  return {
    lines,
    summary: {
      transmitted,
      received,
      loss,
      min: Number.isFinite(min) ? min : null,
      avg: Number.isFinite(avg) ? avg : null,
      max: Number.isFinite(max) ? max : null,
      stddev: Number.isFinite(stddev) ? stddev : null
    }
  };
}

function parseTracerouteOutput(output) {
  const lines = String(output || '')
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean);
  const hops = [];
  for (const line of lines) {
    const match = line.match(/^(\d+)\s+(.*)$/);
    if (!match) continue;
    const hop = Number(match[1]);
    const rest = match[2];
    const unresolved = /^\*+/.test(rest);
    const hostMatch = rest.match(/(?:^|\s)([a-z0-9.-]+\.[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|\[[^\]]+\])/i);
    const rtts = [...rest.matchAll(/(\d+(?:\.\d+)?)\s*ms/gi)].map(m => Number(m[1])).filter(Number.isFinite);
    hops.push({
      hop,
      line: rest,
      unresolved,
      host: hostMatch ? hostMatch[1].replace(/^\[|\]$/g, '') : null,
      rtts
    });
  }
  return { lines, hops };
}

async function runLocalPing(host, family = 4) {
  const candidates = family === 6
    ? [['/sbin/ping6', ['-c', '3', '-n', host]], ['ping', ['-6', '-c', '3', '-n', host]]]
    : [['/sbin/ping', ['-c', '3', '-n', host]], ['ping', ['-c', '3', '-n', host]]];
  try {
    let lastError = null;
    for (const [cmd, args] of candidates) {
      try {
        const { stdout } = await execFileAsync(cmd, args, { timeout: REQUEST_TIMEOUT_MS });
        return parsePingOutput(stdout);
      } catch (error) {
        lastError = error;
      }
    }
    if (family === 6) {
      throw new Error('Sin conectividad IPv6 local en este entorno');
    }
    throw lastError || new Error('Servicio no disponible');
  } catch (error) {
    throw error;
  }
}

async function runLocalTraceroute(host) {
  const candidates = [
    ['/usr/sbin/traceroute', ['-n', '-m', '5', '-q', '1', '-w', '1', host]],
    ['traceroute', ['-n', '-m', '5', '-q', '1', '-w', '1', host]],
  ];
  try {
    let lastError = null;
    for (const [cmd, args] of candidates) {
      try {
        const { stdout } = await execFileAsync(cmd, args, { timeout: REQUEST_TIMEOUT_MS });
        return parseTracerouteOutput(stdout);
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError || new Error('Servicio no disponible');
  } catch (error) {
    throw error;
  }
}

async function digQuery(name, type, mode = 'local', extraArgs = []) {
  const args = [
    '+time=2',
    '+tries=1',
    '+short',
    ...digServers(mode),
    ...extraArgs,
    name,
    type
  ];
  const { stdout } = await execFileAsync('dig', args, { timeout: REQUEST_TIMEOUT_MS });
  return parseDigShortLines(stdout);
}

async function resolveDnsValue(domain, type, mode = 'remote') {
  const clean = normalizeDomain(domain);
  const cacheKey = `${mode}:${type}:${clean}`;
  const cache = dnsCache;
  const cached = cacheGet(cache, cacheKey, 10 * 60 * 1000);
  if (cached) return cached;
  let value;
  if (mode === 'local' || mode === 'servers') {
    try {
      value = await digQuery(clean, type, mode);
    } catch (e) {
      if (mode === 'local') {
        value = await resolveDnsValue(clean, type, 'remote').catch(() => []);
      } else {
        value = [];
      }
    }
  } else {
    const resolver = {
      A: () => dns.resolve4(clean),
      AAAA: () => dns.resolve6(clean),
      NS: () => dns.resolveNs(clean),
      TXT: () => dns.resolveTxt(clean),
      MX: () => dns.resolveMx(clean),
      CNAME: () => dns.resolveCname(clean),
      CAA: () => dns.resolve(clean, 'CAA'),
      DS: () => dns.resolve(clean, 'DS'),
      DNSKEY: () => dns.resolve(clean, 'DNSKEY'),
      TLSA: () => dns.resolve(`_443._tcp.${clean}`, 'TLSA')
    }[type];
    value = resolver ? await resolver().catch(() => []) : [];
  }
  cacheSet(cache, cacheKey, value);
  return value;
}

async function resolveAddressRecords(domain, mode = 'remote') {
  const v4 = await resolveDnsValue(domain, 'A', mode);
  const v6 = await resolveDnsValue(domain, 'AAAA', mode);
  return { v4, v6 };
}

async function resolveNsRecords(domain, mode = 'remote') {
  return resolveDnsValue(domain, 'NS', mode);
}

async function resolveMxRecords(domain, mode = 'remote') {
  return resolveDnsValue(domain, 'MX', mode);
}

async function resolveTxtRecords(domain, mode = 'remote') {
  return resolveDnsValue(domain, 'TXT', mode);
}

async function resolveCaaRecords(domain, mode = 'remote') {
  return resolveDnsValue(domain, 'CAA', mode);
}

async function resolveDsRecords(domain, mode = 'remote') {
  return resolveDnsValue(domain, 'DS', mode);
}

async function resolveDnskeyRecords(domain, mode = 'remote') {
  return resolveDnsValue(domain, 'DNSKEY', mode);
}

async function resolveTlsaRecords(domain, mode = 'remote') {
  return resolveDnsValue(domain, 'TLSA', mode);
}

function flattenTxt(records) {
  return Array.isArray(records)
    ? records.flat().map(item => (Array.isArray(item) ? item.join('') : String(item))).join('')
    : '';
}

function extractTxtRecords(records) {
  return (Array.isArray(records) ? records : [])
    .map(row => (Array.isArray(row) ? row.join('') : String(row)))
    .map(row => row.replace(/^"|"$/g, ''))
    .filter(Boolean);
}

function parseSpfPolicy(record) {
  const value = String(record || '').trim();
  if (!/^v=spf1\b/i.test(value)) {
    return { valid: false, strict: false, policy: 'missing' };
  }
  const strictMatch = value.match(/([+?~-])all\b/i);
  const token = strictMatch ? strictMatch[1] : null;
  if (token === '-') {
    return { valid: true, strict: true, policy: 'reject' };
  }
  if (token === '~') {
    return { valid: true, strict: false, policy: 'softfail' };
  }
  if (token === '+' || token === '?') {
    return { valid: true, strict: false, policy: 'weak' };
  }
  return { valid: true, strict: false, policy: 'missing-all' };
}

function parseDmarcPolicy(record) {
  const value = String(record || '').trim();
  if (!/^v=dmarc1\b/i.test(value)) {
    return { valid: false, strict: false, policy: 'missing' };
  }
  const p = (value.match(/(?:^|;)\s*p=([^;]+)/i) || [])[1];
  const sp = (value.match(/(?:^|;)\s*sp=([^;]+)/i) || [])[1];
  const effective = String(sp || p || '').trim().toLowerCase();
  if (effective === 'reject' || effective === 'quarantine') {
    return { valid: true, strict: true, policy: effective || 'strict' };
  }
  if (effective === 'none') {
    return { valid: true, strict: false, policy: 'none' };
  }
  return { valid: true, strict: false, policy: effective || 'missing' };
}

function parseDnssecAlgorithmFromDs(record) {
  const parts = String(record || '').trim().split(/\s+/);
  const algo = Number(parts[1]);
  return ALGO_MAP[algo] || (Number.isFinite(algo) ? String(algo) : null);
}

function parseDnssecAlgorithmFromDnskey(record) {
  const parts = String(record || '').trim().split(/\s+/);
  const algo = Number(parts[2]);
  return ALGO_MAP[algo] || (Number.isFinite(algo) ? String(algo) : null);
}

function parseDnssecDsRecord(record) {
  const parts = String(record || '').trim().split(/\s+/).filter(Boolean);
  if (parts.length < 4) return null;
  const keyTag = Number(parts[0]);
  const algorithm = Number(parts[1]);
  const digestType = Number(parts[2]);
  return {
    raw: String(record || '').trim(),
    keyTag: Number.isFinite(keyTag) ? keyTag : null,
    algorithm,
    algorithmName: ALGO_MAP[algorithm] || (Number.isFinite(algorithm) ? String(algorithm) : null),
    digestType,
    digestName: DIGEST_MAP[digestType] || (Number.isFinite(digestType) ? String(digestType) : null)
  };
}

function parseDnssecDnskeyRecord(record) {
  const parts = String(record || '').trim().split(/\s+/).filter(Boolean);
  if (parts.length < 4) return null;
  const flags = Number(parts[0]);
  const protocol = Number(parts[1]);
  const algorithm = Number(parts[2]);
  return {
    raw: String(record || '').trim(),
    flags: Number.isFinite(flags) ? flags : null,
    protocol: Number.isFinite(protocol) ? protocol : null,
    algorithm,
    algorithmName: ALGO_MAP[algorithm] || (Number.isFinite(algorithm) ? String(algorithm) : null)
  };
}

function parseNsec3ParamRecord(record) {
  const parts = String(record || '').trim().split(/\s+/).filter(Boolean);
  if (parts.length < 4) return null;
  const hashAlgorithm = Number(parts[0]);
  const flags = Number(parts[1]);
  const iterations = Number(parts[2]);
  const salt = parts[3] || '';
  return {
    raw: String(record || '').trim(),
    hashAlgorithm,
    hashAlgorithmName: hashAlgorithm === 1 ? 'SHA-1' : (Number.isFinite(hashAlgorithm) ? String(hashAlgorithm) : null),
    flags: Number.isFinite(flags) ? flags : null,
    iterations: Number.isFinite(iterations) ? iterations : null,
    salt: salt === '-' ? '' : salt,
    hasSha1: hashAlgorithm === 1
  };
}

function quantumResistanceTagForAlgorithm(name) {
  const value = String(name || '').trim();
  const upper = value.toUpperCase();
  if (!value) {
    return {
      label: 'PQC: por verificar',
      tone: 'info',
      note: 'No se pudo identificar el algoritmo.'
    };
  }
  if (/SHA-1|DSA|RSA\/SHA-1|NSEC3/i.test(upper)) {
    return {
      label: 'PQC: no',
      tone: 'warning',
      note: 'Algoritmo clásico con componentes legados; conviene migrar.'
    };
  }
  return {
    label: 'PQC: no',
    tone: 'info',
    note: 'Algoritmo clásico, no post-cuántico.'
  };
}

function formatDnssecRecordSummary(record, kind = 'record') {
  if (!record || typeof record !== 'object') return null;
  const pieces = [];
  if (kind === 'ds') {
    if (record.keyTag !== null && record.keyTag !== undefined) pieces.push(`keytag ${record.keyTag}`);
    if (record.algorithmName) pieces.push(record.algorithmName);
    else if (record.algorithm !== null && record.algorithm !== undefined) pieces.push(`alg ${record.algorithm}`);
    if (record.digestName) pieces.push(`digest ${record.digestName}`);
    else if (record.digestType !== null && record.digestType !== undefined) pieces.push(`digest ${record.digestType}`);
  } else if (kind === 'dnskey') {
    if (record.flags !== null && record.flags !== undefined) pieces.push(`flags ${record.flags}`);
    if (record.algorithmName) pieces.push(record.algorithmName);
    else if (record.algorithm !== null && record.algorithm !== undefined) pieces.push(`alg ${record.algorithm}`);
  } else {
    if (record.raw) pieces.push(record.raw);
  }
  return pieces.filter(Boolean).join(' · ') || (record.raw || null);
}

function buildDnssecAssessment(google = {}) {
  const parent = Boolean(google.parent);
  const child = Boolean(google.child);
  const dsRecords = Array.isArray(google.dsRecords) ? google.dsRecords : [];
  const dnskeyRecords = Array.isArray(google.dnskeyRecords) ? google.dnskeyRecords : [];
  const nsec3 = google.nsec3 || {};
  const valid = parent && child;
  const chainStatus = valid ? 'ok' : (parent || child ? 'warning' : 'fail');
  const dsLegacy = dsRecords.some(record => {
    const algo = String(record?.algorithmName || '').toUpperCase();
    return /SHA-1|DSA|RSA\/SHA-1/.test(algo) || record?.digestName === 'SHA-1';
  });
  const dnskeyLegacy = dnskeyRecords.some(record => {
    const algo = String(record?.algorithmName || '').toUpperCase();
    return /SHA-1|DSA|RSA\/SHA-1/.test(algo);
  });
  const nsec3Legacy = Boolean(nsec3.present && (nsec3.hasSha1 || /SHA-1/i.test(String(nsec3.hashAlgorithmName || ''))));
  const nsec3Configured = Boolean(nsec3.present && nsec3.configured);
  const sections = [
    {
      id: 'chain',
      label: 'Cadena DNSSEC',
      status: chainStatus,
      note: valid
        ? 'DS y DNSKEY están visibles en la cadena.'
        : (parent || child ? 'Falta al menos una pieza de la validación.' : 'No se detectó cadena DNSSEC.')
    },
    {
      id: 'parent',
      label: 'Padre (DS)',
      status: parent ? 'ok' : 'fail',
      note: parent ? 'El padre publica DS.' : 'No se detectó DS en el padre.'
    },
    {
      id: 'child',
      label: 'Hijo (DNSKEY)',
      status: child ? 'ok' : 'fail',
      note: child ? 'El hijo publica DNSKEY.' : 'No se detectó DNSKEY en el hijo.'
    },
    {
      id: 'ds-algorithms',
      label: 'Algoritmos DS',
      status: dsRecords.length ? (dsLegacy ? 'warning' : 'ok') : 'info',
      note: dsRecords.length
        ? 'Se listan los DS del padre con comentario de resiliencia cuántica.'
        : 'Sin registros DS para listar.',
      items: dsRecords.map(record => ({
        text: formatDnssecRecordSummary(record, 'ds'),
        status: record.digestName === 'SHA-1' ? 'warning' : 'ok',
        tag: quantumResistanceTagForAlgorithm(record.algorithmName || record.algorithm)
      }))
    },
    {
      id: 'dnskey-algorithms',
      label: 'Algoritmos DNSKEY',
      status: dnskeyRecords.length ? (dnskeyLegacy ? 'warning' : 'ok') : 'info',
      note: dnskeyRecords.length
        ? 'Se listan las claves DNSKEY del hijo.'
        : 'Sin registros DNSKEY para listar.',
      items: dnskeyRecords.map(record => ({
        text: formatDnssecRecordSummary(record, 'dnskey'),
        status: /SHA-1|DSA|RSA\/SHA-1/i.test(String(record?.algorithmName || '').toUpperCase()) ? 'warning' : 'ok',
        tag: quantumResistanceTagForAlgorithm(record.algorithmName || record.algorithm)
      }))
    },
    {
      id: 'nsec3',
      label: 'NSEC3',
      status: nsec3.present ? (nsec3Configured && !nsec3Legacy ? 'ok' : 'warning') : 'info',
      note: nsec3.present
        ? (nsec3Configured && !nsec3Legacy
          ? 'NSEC3 configurado y sin señales legadas.'
          : (nsec3Configured
            ? 'Se detectó NSEC3, pero conviene revisar el hash y las iteraciones.'
            : 'NSEC3PARAM aparece, pero no se detectó NSEC3 completo.'))
        : 'No se detectó NSEC3.',
      items: nsec3.present
        ? [
            {
              text: `Hash ${nsec3.hashAlgorithmName || nsec3.hashAlgorithm || 'desconocido'}${Number.isFinite(nsec3.iterations) ? ` · iteraciones ${nsec3.iterations}` : ''}${nsec3.salt ? ` · salt ${nsec3.salt}` : ''}`,
              status: nsec3Legacy || !nsec3Configured ? 'warning' : 'ok',
              tag: quantumResistanceTagForAlgorithm(nsec3.hashAlgorithmName || nsec3.hashAlgorithm)
            }
          ]
        : []
    }
  ];

  const summaryLines = [
    valid ? 'DNSSEC válido.' : (parent || child ? 'DNSSEC parcial.' : 'No se detectó DNSSEC.'),
    parent ? 'DS presente en el padre.' : 'No se detectó DS en el padre.',
    child ? 'DNSKEY presente en el hijo.' : 'No se detectó DNSKEY en el hijo.'
  ];

  if (dsRecords.length) {
    summaryLines.push(`DS: ${dsRecords.map(record => formatDnssecRecordSummary(record, 'ds')).filter(Boolean).join(' | ')}`);
  }
  if (dnskeyRecords.length) {
    summaryLines.push(`DNSKEY: ${dnskeyRecords.map(record => formatDnssecRecordSummary(record, 'dnskey')).filter(Boolean).join(' | ')}`);
  }
  if (Array.isArray(google.algorithms) && google.algorithms.length) {
    summaryLines.push(`Algoritmos: ${[...new Set(google.algorithms.filter(Boolean))].join(', ')}`);
  }
  if (Array.isArray(google.digests) && google.digests.length) {
    summaryLines.push(`Digests: ${[...new Set(google.digests.filter(Boolean))].join(', ')}`);
  }
  if (nsec3.present) {
    summaryLines.push(`NSEC3: ${nsec3.configured ? 'presente' : 'parcial'}${nsec3.hashAlgorithmName ? ` · ${nsec3.hashAlgorithmName}` : ''}`);
  } else {
    summaryLines.push('NSEC3: no detectado');
  }
  if (Array.isArray(nsec3.notes) && nsec3.notes.length) {
    summaryLines.push(...nsec3.notes);
  }

  const hasLegacySignals = Boolean(dsLegacy || dnskeyLegacy || nsec3Legacy);
  const dnssecStatus = !valid
    ? 'fail'
    : (hasLegacySignals ? 'warning' : 'ok');

  return {
    status: dnssecStatus,
    valid,
    parentStatus: parent ? 'ok' : 'fail',
    childStatus: child ? 'ok' : 'fail',
    dsStatus: dsRecords.length ? (dsLegacy ? 'warning' : 'ok') : 'fail',
    dnskeyStatus: dnskeyRecords.length ? (dnskeyLegacy ? 'warning' : 'ok') : 'fail',
    nsec3Status: nsec3.present ? 'warning' : 'info',
    sections,
    summaryLines
  };
}

async function detectDkimSupport(domain) {
  const selectorCandidates = [
    'default',
    'selector1',
    'selector2',
    'google',
    'mail',
    'dkim',
    'smtp',
    's1',
    's2',
    'k1',
    'mta',
    'mandrill',
    'sendgrid',
    'zoho',
    'amazonses',
    'protection'
  ];
  const matches = [];
  const checkedSelectors = [];
  const mark = values => Array.isArray(values) && values.some(row => /v=DKIM1/i.test(String(row)));
  try {
    const baseRecords = await resolveTxtRecords(`_domainkey.${domain}`, 'local').catch(() => []);
    checkedSelectors.push('_domainkey');
    if (mark(baseRecords)) {
      matches.push({ selector: null, records: baseRecords.slice() });
    }
    for (const selector of selectorCandidates) {
      checkedSelectors.push(selector);
      const records = await resolveTxtRecords(`${selector}._domainkey.${domain}`, 'local').catch(() => []);
      if (mark(records)) {
        matches.push({ selector, records: records.slice() });
      }
    }
    return {
      supported: matches.length > 0,
      matches,
      checkedSelectors
    };
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
      return {
        supported: false,
        matches: [],
        checkedSelectors
      };
    }
    throw e;
  }
}

async function resolveDnsvizMeta(domain) {
  const cached = cacheGet(dnsvizMetaCache, `dnsviz:${domain}`, 30 * 60 * 1000);
  if (cached) return cached;
  const baseUrl = `https://dnsviz.net/d/${domain}/dnssec/`;
  let currentUrl = baseUrl;
  let page = null;
  for (let i = 0; i < 4; i += 1) {
    page = await fetchPage(currentUrl, { timeout: 20000 }).catch(() => null);
    if (!page) break;
    if (page.statusCode >= 300 && page.statusCode < 400 && page.headers?.location) {
      currentUrl = page.headers.location.startsWith('http')
        ? page.headers.location
        : new URL(page.headers.location, currentUrl).toString();
      continue;
    }
    break;
  }

  const finalUrl = currentUrl;
  const svgUrl = new URL('auth_graph.svg?download=1', finalUrl).toString();
  const pngUrl = new URL('auth_graph.png?download=1', finalUrl).toString();
  const body = String(page?.body || '');
  const jsPathMatch = body.match(new RegExp(`/d/${domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/[^/]+/dnssec/auth_graph\\.js`));
  const jsUrl = jsPathMatch ? new URL(jsPathMatch[0], finalUrl).toString() : null;
  const updated =
    body.match(/Updated:\s*([^<\n]+)/i)?.[1]?.trim() ||
    body.match(/Updated\s+([0-9:-]+\sUTC[^<\n]*)/i)?.[1]?.trim() ||
    '';
  const observations = [];
  if (/nsec3/i.test(body)) observations.push('NSEC3 mencionado en el reporte');
  if (/fallback/i.test(body) && /tcp/i.test(body)) observations.push('Fallback por TCP mencionado');
  if (/tcp/i.test(body) && !observations.includes('Fallback por TCP mencionado')) {
    observations.push('TCP presente en la cadena de validación');
  }
  if (/delegation/i.test(body)) observations.push('Delegación visible');
  if (/insecure/i.test(body)) observations.push('Zona no segura mencionada');

  let notices = null;
  if (jsUrl) {
    const jsBody = await fetchText(jsUrl, { timeout: 20000 }).catch(() => null);
    if (jsBody) {
      const noticesMatch = jsBody.match(/var notices = (\{[\s\S]*?\});\s*if \(noticesElement\.nodeType != 1\)/);
      if (noticesMatch) {
        try {
          notices = JSON.parse(noticesMatch[1]);
          const dnssecNotices = notices?.notices || {};
          const warningTexts = Array.isArray(dnssecNotices.warnings) ? dnssecNotices.warnings : [];
          const errorTexts = Array.isArray(dnssecNotices.errors) ? dnssecNotices.errors : [];
          const secureItems = notices?.['DNSKEY/DS/NSEC status']?.SECURE || [];
          const insecureItems = notices?.['delegation status']?.INSECURE || [];
          const summaryBits = [
            errorTexts.length ? `${errorTexts.length} error(es) DNSViz` : null,
            warningTexts.length ? `${warningTexts.length} warning(s) DNSViz` : null,
            secureItems.length ? `${secureItems.length} elemento(s) seguros` : null,
            insecureItems.length ? `${insecureItems.length} delegación(es) insegura(s)` : null
          ].filter(Boolean);
          if (summaryBits.length) observations.push(`DNSViz: ${summaryBits.join(' · ')}`);
          warningTexts.forEach(text => observations.push(`Aviso DNSViz: ${text}`));
          errorTexts.forEach(text => observations.push(`Error DNSViz: ${text}`));
        } catch (e) {}
      }
    }
  }
  return {
    domain,
    pageUrl: finalUrl,
    svgUrl,
    pngUrl,
    updated: updated || null,
    observations,
    warningCount: Array.isArray(notices?.notices?.warnings) ? notices.notices.warnings.length : 0,
    errorCount: Array.isArray(notices?.notices?.errors) ? notices.notices.errors.length : 0,
    warnings: Array.isArray(notices?.notices?.warnings) ? notices.notices.warnings.slice() : [],
    errors: Array.isArray(notices?.notices?.errors) ? notices.notices.errors.slice() : [],
    notices,
    available: Boolean(page && page.statusCode >= 200 && page.statusCode < 400)
  };
}

async function summarizeWifiCountry(countryCode) {
  const code = String(countryCode || '').trim().toLowerCase();
  const entries = WIFI_6GHZ_STATUS_BY_CCTLD[code];
  if (!entries || !entries.length) {
    return {
      status: 'pending',
      label: 'Próximamente',
      notes: ['Sin dato hardcodeado para este ccTLD.']
    };
  }

  const statuses = [...new Set(entries.map(item => item.status).filter(Boolean))];
  const notes = entries.flatMap(item => item.note ? [item.note] : []);
  return {
    status: statuses.includes('FULL_5925_7125')
      ? 'ok'
      : statuses.includes('CONSULTATION')
        ? 'warning'
        : statuses.includes('LOW_5925_6425')
          ? 'warning'
          : 'info',
    label: statuses.map(formatWifiStatusLabel).join(' · '),
    territories: entries.map(item => item.territory),
    entries,
    notes
  };
}

function extractPulseSection(html, title) {
  const titlePattern = escapeRegExp(title);
  const titleRegex = new RegExp(
    `<h3>\\s*${titlePattern}\\s*<\\/h3>([\\s\\S]*?)(?=<h3>|<section|<div class="flow datapoint card dark noborder">|<section id=|$)`,
    'i'
  );
  const match = String(html || '').match(titleRegex);
  if (!match) return null;
  return match[1];
}

function extractPulseMetric(html, title) {
  const block = extractPulseSection(html, title);
  if (!block) return null;
  const primary = block.match(/<div class="primary">([\s\S]*?)<\/div>/i)?.[1] || '';
  const secondary = block.match(/<div class="secondary">([\s\S]*?)<\/div>/i)?.[1] || '';
  const label = block.match(/<div class="label">([\s\S]*?)<\/div>/i)?.[1] || '';
  return {
    value: decodeHtmlEntities(primary),
    average: decodeHtmlEntities(secondary),
    label: decodeHtmlEntities(label)
  };
}

function extractPulseListMetrics(html, title) {
  const block = extractPulseSection(html, title);
  if (!block) return [];
  const items = [];
  const listItemRegex = /<li>([\s\S]*?)<\/li>/gi;
  let match;
  while ((match = listItemRegex.exec(block))) {
    const itemBlock = match[1];
    const primary = itemBlock.match(/<div class="primary">([\s\S]*?)<\/div>/i)?.[1] || '';
    const label = itemBlock.match(/<div class="label">([\s\S]*?)<\/div>/i)?.[1] || '';
    if (primary || label) {
      items.push({
        value: decodeHtmlEntities(primary),
        label: decodeHtmlEntities(label)
      });
    }
  }
  return items;
}

async function summarizePulseCountry(countryCode) {
  const code = String(countryCode || '').trim().toLowerCase();
  if (!code) {
    return {
      available: false,
      notes: ['Falta ccTLD para consultar Pulse.']
    };
  }
  const cached = cacheGet(pulseCache, `pulse:${code}`, 24 * 60 * 60 * 1000);
  if (cached) return cached;
  const url = `https://pulse.internetsociety.org/en/reports/${encodeURIComponent(code)}/`;
  try {
    const page = await fetchPage(url, { timeout: 20000 });
    const html = String(page?.body || '');
    const dnssecCoverage = extractPulseMetric(html, 'DNSSEC coverage');
    const dnssecAdoption = extractPulseMetric(html, 'Adoption of DNSSEC');
    const ipv6Adoption = extractPulseMetric(html, 'Adoption of IPv6');
    const domainUse = extractPulseMetric(html, 'Country-level domain use');
    const resilienceScore = extractPulseMetric(html, 'Internet Resilience Score');
    const roaItems = extractPulseListMetrics(html, 'ROA');
    const rov = extractPulseListMetrics(html, 'ROV')[0] || null;
    const value = {
      available: Boolean(html),
      sourceUrl: url,
      dnssecCoverage,
      dnssecAdoption,
      ipv6Adoption,
      domainUse,
      resilienceScore,
      roaItems,
      rov,
      notes: []
    };
    if (dnssecCoverage?.value) value.notes.push(`DNSSEC coverage ${dnssecCoverage.value}`);
    if (dnssecAdoption?.value) value.notes.push(`DNSSEC adoption ${dnssecAdoption.value}`);
    if (ipv6Adoption?.value) value.notes.push(`IPv6 adoption ${ipv6Adoption.value}`);
    if (resilienceScore?.value) value.notes.push(`Internet resilience score ${resilienceScore.value}`);
    cacheSet(pulseCache, `pulse:${code}`, value);
    return value;
  } catch (e) {
    const value = {
      available: false,
      sourceUrl: url,
      error: errorMessage(e),
      notes: ['No se pudo recuperar Pulse.']
    };
    cacheSet(pulseCache, `pulse:${code}`, value);
    return value;
  }
}

async function fetchCachedDnsvizSvg(svgUrl, domain) {
  const cacheKey = `svg:${domain}`;
  const cached = cacheGet(dnsvizSvgCache, cacheKey, 30 * 60 * 1000);
  if (cached) return cached;
  const graph = await fetchText(svgUrl, { timeout: 20000 }).catch(() => '');
  if (graph && /<svg[\s>]/i.test(graph)) {
    cacheSet(dnsvizSvgCache, cacheKey, graph);
    return graph;
  }
  return '';
}

async function fetchWebsite(domain) {
  const cached = cacheGet(htmlCache, domain);
  if (cached) return cached;
  const targets = [`https://${domain}`, `http://${domain}`];
  for (const target of targets) {
    try {
      const page = await fetchPage(target);
      if (page.statusCode && page.statusCode >= 200 && page.statusCode < 400) {
        const value = { url: target, ...page };
        cacheSet(htmlCache, domain, value);
        cacheSet(headerCache, domain, { headers: page.headers, statusCode: page.statusCode });
        return value;
      }
    } catch (e) {}
  }
  throw new Error('Servicio no disponible');
}

async function rpkiValidity(ip) {
  try {
    const routes = await resolveOriginRoutesViaCymru(ip).catch(() => []);
    let chosen = routes[0] || null;
    if (!chosen) {
      const info = await fetchJSON(`https://stat.ripe.net/data/network-info/data.json?resource=${ip}`);
      const prefix = info?.data?.prefix || info?.data?.resource || null;
      const asnEntry = info?.data?.asns?.[0];
      const asn =
        typeof asnEntry === 'number'
          ? asnEntry
          : typeof asnEntry === 'object'
          ? asnEntry.asn || asnEntry.id
          : null;
      if (asn && prefix) chosen = { asn, prefix };
    }

    if (!chosen) return { state: 'unknown', asn: null, prefix: null, routes: [] };

    const ripe = await fetchJSON(
      `https://stat.ripe.net/data/rpki-validation/data.json?resource=${encodeURIComponent(chosen.asn)}&prefix=${encodeURIComponent(chosen.prefix)}`
    ).catch(() => null);
    const status = String(ripe?.data?.status || ripe?.status || ripe?.state || 'unknown').toLowerCase();
    const description = ripe?.data?.description || ripe?.description || null;
    return {
      state: ['valid', 'invalid_asn', 'invalid_length', 'unknown'].includes(status) ? status : 'unknown',
      reason: description,
      asn: chosen.asn || null,
      prefix: chosen.prefix || null,
      routes
    };
  } catch (e) {
    return { state: 'error', asn: null };
  }
}

async function handleRpki(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { v4, v6 } = await resolveAddresses(domain);
    const ips = [...v4, ...v6];
    if (!ips.length) return sendJSON(res, 200, { domain, error: 'Sin direcciones IP' });
    const results = [];
    for (const ip of ips) {
      const details = await rpkiValidity(ip);
      results.push({ ip, ...details });
    }
    const overall = results.length && results.every(r => r.state === 'valid');
    sendJSON(res, 200, { domain, results, valid: Boolean(overall) });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleRouting(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { v4, v6 } = await resolveAddresses(domain);
    const ips = [...v4, ...v6];
    if (!ips.length) return sendJSON(res, 200, { domain, error: 'Sin direcciones IP' });
    const results = [];
    for (const ip of ips) {
      const details = await rpkiValidity(ip);
      results.push({
        ip,
        asn: details.asn,
        prefix: details.prefix,
        state: details.state,
        reason: details.reason || null,
        routes: details.routes || []
      });
    }
    sendJSON(res, 200, { domain, results });
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
      `https://validator.w3.org/nu/?doc=${encodeURIComponent(`https://${domain}`)}&out=json`
    );
    const messages = Array.isArray(data.messages) ? data.messages : [];
    const errors = messages.filter(m => m.type === 'error').length;
    const warnings = messages.filter(m => m.type !== 'error').length;
    sendJSON(res, 200, { domain, errors, warnings });
  } catch (e) {
    sendJSON(res, 200, { domain, unavailable: true, note: errorMessage(e) });
  }
}

async function handleHeaders(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const httpsRes = await fetchHeaders(`https://${domain}`);
    const httpRes = await fetchHeaders(`http://${domain}`, true).catch(
      () => null
    );
    const hstsHeader = httpsRes.headers['strict-transport-security'] || '';
    const hstsMatch = String(hstsHeader).match(/max-age=(\d+)/i);
    const hstsMaxAge = hstsMatch ? Number(hstsMatch[1]) : null;
    const result = {
      domain,
      https: httpsRes.statusCode >= 200 && httpsRes.statusCode < 400,
      redirect:
        httpRes &&
        httpRes.statusCode >= 300 &&
        httpRes.statusCode < 400 &&
        typeof httpRes.headers.location === 'string' &&
        httpRes.headers.location.startsWith('https://'),
      hsts: Boolean(hstsHeader),
      hstsMaxAge,
      hstsStrict: Boolean(hstsHeader) && (hstsMaxAge === null || hstsMaxAge >= 31536000),
      csp: Boolean(httpsRes.headers['content-security-policy']),
      xfo: Boolean(httpsRes.headers['x-frame-options']),
      xcto: Boolean(httpsRes.headers['x-content-type-options']),
      referrer: Boolean(httpsRes.headers['referrer-policy']),
      permissions: Boolean(httpsRes.headers['permissions-policy']),
      xxss: Boolean(httpsRes.headers['x-xss-protection']),
      compression: Boolean(httpsRes.headers['content-encoding']),
      server: httpsRes.headers['server'] || '',
      headers: httpsRes.headers
    };
    sendJSON(res, 200, result);
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleCaa(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await resolveCaaRecords(domain, 'local');
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
    const records = await resolveTlsaRecords(domain, 'local');
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
    socket.setTimeout(REQUEST_TIMEOUT_MS, () => {
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
    const { v4: ipv4, v6: ipv6 } = await resolveAddresses(domain);
    const geo = [];
    const ips = [...ipv4, ...ipv6].slice(0, 5);
    for (const ip of ips) {
      try {
        const info = await lookupIpMeta(ip);
        geo.push(info);
      } catch (e) {}
    }
    sendJSON(res, 200, { domain, ipv4, ipv6, geo });
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
        const seen = new Set();
        let cert = socket.getPeerCertificate(true);
        while (cert && Object.keys(cert).length) {
          if (seen.has(cert.fingerprint256)) break;
          seen.add(cert.fingerprint256);
          chain.push({
            subject: cert.subject,
            issuer: cert.issuer,
            valid_from: cert.valid_from,
            valid_to: cert.valid_to,
            serialNumber: cert.serialNumber,
            fingerprint256: cert.fingerprint256,
            subjectaltname: cert.subjectaltname
          });
          if (!cert.issuerCertificate || cert.issuerCertificate === cert) break;
          cert = cert.issuerCertificate;
        }
        const protocol = socket.getProtocol();
        socket.end();
        sendJSON(res, 200, { domain, protocol, chain });
      }
    );
    socket.on('error', e => {
      if (settled) return;
      settled = true;
      sendJSON(res, 200, { domain, error: errorMessage(e) });
    });
    socket.setTimeout(REQUEST_TIMEOUT_MS, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      sendJSON(res, 200, { domain, error: 'Timeout' });
    });
  } catch (e) {
    if (!settled) sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDnsRecords(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = {};
    records.A = await resolveDnsValue(domain, 'A', 'local').catch(() => []);
    records.AAAA = await resolveDnsValue(domain, 'AAAA', 'local').catch(() => []);
    records.MX = await resolveMxRecords(domain, 'local').catch(() => []);
    records.NS = await resolveNsRecords(domain, 'local').catch(() => []);
    records.TXT = await resolveTxtRecords(domain, 'local').catch(() => []);
    records.CAA = await resolveCaaRecords(domain, 'local').catch(() => []);
    records.CNAME = await resolveDnsValue(domain, 'CNAME', 'local').catch(() => []);
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleCookies(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const cookies = page.headers['set-cookie'] || [];
    sendJSON(res, 200, { domain, cookies });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleCrawlRules(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const urls = [`https://${domain}/robots.txt`, `http://${domain}/robots.txt`];
    for (const url of urls) {
      try {
        const data = await fetchPage(url);
        if (data.statusCode && data.statusCode < 400) {
          return sendJSON(res, 200, {
            domain,
            found: true,
            content: data.body
          });
        }
      } catch (e) {}
    }
    sendJSON(res, 200, { domain, found: false, content: '' });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleQuality(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(
      `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://${domain}`
    );
    const lighthouse = data.lighthouseResult?.categories || {};
    sendJSON(res, 200, {
      domain,
      performance: lighthouse.performance?.score,
      accessibility: lighthouse.accessibility?.score,
      bestPractices: lighthouse['best-practices']?.score,
      seo: lighthouse.seo?.score,
      pwa: lighthouse.pwa?.score || null
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleServerLocation(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { ip } = await resolveFirstIp(domain);
    if (!ip) return sendJSON(res, 200, { domain, error: 'Sin dirección IP' });
    const info = await lookupIpMeta(ip);
    sendJSON(res, 200, {
      domain,
      ip,
      city: info.city,
      region: info.region,
      country: info.country,
      latitude: info.latitude,
      longitude: info.longitude,
      timezone: info.timezone
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleAssociatedHosts(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const text = await fetchText(`https://api.hackertarget.com/hostsearch/?q=${domain}`);
    if (!text || /error/i.test(text))
      return sendJSON(res, 200, { domain, hosts: [], error: 'Sin datos' });
    const hosts = text
      .trim()
      .split('\n')
      .map(line => {
        const [host, ip] = line.split(',');
        return { host, ip };
      })
      .filter(h => h.host);
    sendJSON(res, 200, { domain, hosts });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function followRedirects(url, limit = 5, chain = []) {
  if (limit < 0) return chain;
  const { headers, statusCode } = await fetchPage(url, { method: 'HEAD' });
  const entry = { url, statusCode, location: headers.location || null };
  chain.push(entry);
  if (statusCode && statusCode >= 300 && statusCode < 400 && headers.location) {
    const next = headers.location.startsWith('http')
      ? headers.location
      : new URL(headers.location, url).toString();
    return followRedirects(next, limit - 1, chain);
  }
  return chain;
}

async function handleRedirectChain(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const chain = await followRedirects(`http://${domain}`);
    sendJSON(res, 200, { domain, chain });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleTxtRecords(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await resolveTxtRecords(domain, 'local');
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND')
      sendJSON(res, 200, { domain, records: [] });
    else sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleServerStatus(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchHeaders(`https://${domain}`);
    sendJSON(res, 200, {
      domain,
      statusCode: page.statusCode,
      location: page.headers?.location || null
    });
  } catch (e) {
    try {
      const page = await fetchHeaders(`http://${domain}`, true);
      sendJSON(res, 200, {
        domain,
        statusCode: page.statusCode,
        location: page.headers?.location || null
      });
    } catch (err) {
      sendJSON(res, 200, { domain, error: errorMessage(err) });
    }
  }
}

async function handleOpenPorts(domain, res) {
  domain = normalizeDomain(domain);
  const ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 8080];
  const results = [];
  await Promise.all(
    ports.map(
      port =>
        new Promise(resolve => {
          const socket = net.createConnection({ host: domain, port, timeout: 4000 });
          socket.on('connect', () => {
            results.push({ port, open: true });
            socket.destroy();
            resolve();
          });
          socket.on('timeout', () => {
            socket.destroy();
            resolve();
          });
          socket.on('error', () => {
            resolve();
          });
        })
    )
  );
  sendJSON(res, 200, { domain, ports: results });
}

async function handleTraceroute(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await runLocalTraceroute(domain);
    sendJSON(res, 200, {
      domain,
      command: 'traceroute',
      hops: data.hops,
      lines: data.lines
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), command: 'traceroute' });
  }
}

async function handlePing(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await runLocalPing(domain, 4);
    sendJSON(res, 200, {
      domain,
      command: 'ping',
      summary: data.summary,
      lines: data.lines
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), command: 'ping' });
  }
}

async function handlePingV6(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await runLocalPing(domain, 6);
    sendJSON(res, 200, {
      domain,
      command: 'ping6',
      summary: data.summary,
      lines: data.lines
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: e?.message || errorMessage(e), command: 'ping6' });
  }
}

async function handleCarbon(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(`https://api.websitecarbon.com/site?url=https://${domain}`);
    sendJSON(res, 200, { domain, data });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleServerInfo(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { ip } = await resolveFirstIp(domain);
    if (!ip) return sendJSON(res, 200, { domain, error: 'Sin dirección IP' });
    const info = await lookupIpMeta(ip);
    sendJSON(res, 200, {
      domain,
      ip,
      asn: info.asn,
      org: info.org || info.isp,
      network: info.network,
      isp: info.isp,
      country: info.country,
      city: info.city
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDomainInfo(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(`https://rdap.org/domain/${domain}`);
    const events = Array.isArray(data.events) ? data.events : [];
    const creation = events.find(e => e.eventAction === 'registration')?.eventDate || null;
    const expiration = events.find(e => e.eventAction === 'expiration')?.eventDate || null;
    sendJSON(res, 200, {
      domain,
      registry: data.registryName || null,
      status: data.status || [],
      creation,
      expiration
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDnsSecurity(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const google = await dnssecGoogle(domain, 'local');
    const algorithms = [...new Set(google.algorithms.filter(Boolean))];
    sendJSON(res, 200, {
      domain,
      methods: { google },
      valid: google.parent && google.child,
      algorithms
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

function analyzeSiteFeatures(html) {
  const lower = html.toLowerCase();
  return {
    hasForms: /<form/i.test(lower),
    hasLogin: /login|iniciar sesi[oó]n|sign in/.test(lower),
    hasSearch: /type="search"/.test(lower) || /search/.test(lower),
    hasVideo: /<video|youtube.com\/embed/.test(lower),
    hasAnalytics: /google-analytics|gtag\(|googletagmanager/.test(lower),
    hasEcommerce: /cart|checkout|woocommerce/.test(lower)
  };
}

function detectTechStack(html) {
  const lower = html.toLowerCase();
  const stack = [];
  if (/wp-content|wordpress/.test(lower)) stack.push('WordPress');
  if (/drupal/.test(lower)) stack.push('Drupal');
  if (/joomla/.test(lower)) stack.push('Joomla');
  if (/shopify/.test(lower)) stack.push('Shopify');
  if (/react/.test(lower)) stack.push('React');
  if (/vue/.test(lower)) stack.push('Vue.js');
  if (/angular/.test(lower)) stack.push('Angular');
  if (/bootstrap/.test(lower)) stack.push('Bootstrap');
  if (/jquery/.test(lower)) stack.push('jQuery');
  return [...new Set(stack)];
}

function extractLinks(html, domain) {
  const links = [];
  const regex = /<a\s+[^>]*href=["']([^"'#]+)["'][^>]*>/gi;
  let match;
  while ((match = regex.exec(html))) {
    const href = match[1];
    const internal = href.startsWith('/') || href.includes(domain);
    links.push({ href, internal });
  }
  return links;
}

function extractSocialTags(html) {
  const tags = {};
  const metaRegex = /<meta\s+([^>]+)>/gi;
  let match;
  while ((match = metaRegex.exec(html))) {
    const attrs = match[1];
    const propertyMatch = attrs.match(/property=["']([^"']+)["']/i);
    const nameMatch = attrs.match(/name=["']([^"']+)["']/i);
    const contentMatch = attrs.match(/content=["']([^"']*)["']/i);
    const key = propertyMatch?.[1] || nameMatch?.[1];
    if (key && contentMatch) tags[key] = contentMatch[1];
  }
  return tags;
}

async function handleSiteFeatures(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const features = analyzeSiteFeatures(page.body);
    sendJSON(res, 200, { domain, features });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDnsServer(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const servers = await dns.resolveNs(domain);
    sendJSON(res, 200, { domain, servers });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleTechStack(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const stack = detectTechStack(page.body);
    sendJSON(res, 200, { domain, stack });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleListedPages(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const urls = [`https://${domain}/sitemap.xml`, `http://${domain}/sitemap.xml`];
    for (const url of urls) {
      try {
        const data = await fetchPage(url);
        if (data.statusCode && data.statusCode < 400) {
          const matches = [...data.body.matchAll(/<loc>([^<]+)<\/loc>/gi)].map(m => m[1]);
          return sendJSON(res, 200, { domain, pages: matches });
        }
      } catch (e) {}
    }
    sendJSON(res, 200, { domain, pages: [] });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleLinkedPages(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const links = extractLinks(page.body, domain);
    sendJSON(res, 200, { domain, links });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleSocialTags(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const tags = extractSocialTags(page.body);
    sendJSON(res, 200, { domain, tags });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleEmailConfig(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const [txt, mx] = await Promise.all([
      resolveTxtRecords(domain, 'local').catch(() => []),
      resolveMxRecords(domain, 'local').catch(() => [])
    ]);
    const spfRecords = extractTxtRecords(txt).filter(row => /^v=spf1\b/i.test(row));
    const dmarcRecords = extractTxtRecords(
      await resolveTxtRecords(`_dmarc.${domain}`, 'local').catch(() => [])
    ).filter(row => /^v=dmarc1\b/i.test(row));
    const dkim = await detectDkimSupport(domain);
    sendJSON(res, 200, {
      domain,
      spf: spfRecords.length > 0,
      spfPolicy: spfRecords[0] ? parseSpfPolicy(spfRecords[0]) : { valid: false, strict: false, policy: 'missing' },
      dmarc: dmarcRecords.length > 0,
      dmarcPolicy: dmarcRecords[0]
        ? parseDmarcPolicy(dmarcRecords[0])
        : { valid: false, strict: false, policy: 'missing' },
      dkim: Boolean(dkim?.supported),
      dkimDetails: dkim,
      mx: mx.map(r => ({ exchange: r.exchange, priority: r.priority }))
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleFirewall(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const headers = page.headers;
    const server = (headers['server'] || '').toLowerCase();
    const wafHeaders = Object.values(headers)
      .join(' ')
      .toLowerCase();
    const detections = [];
    if (server.includes('cloudflare') || wafHeaders.includes('cloudflare')) detections.push('Cloudflare');
    if (server.includes('sucuri') || wafHeaders.includes('sucuri')) detections.push('Sucuri');
    if (server.includes('akamai') || wafHeaders.includes('akamai')) detections.push('Akamai');
    if (wafHeaders.includes('mod_security') || wafHeaders.includes('modsecurity')) detections.push('ModSecurity');
    sendJSON(res, 200, {
      domain,
      waf: detections,
      detected: detections.length > 0
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleHttpSecurity(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const cached = cacheGet(headerCache, domain);
    const headers = cached ? cached.headers : (await fetchWebsite(domain)).headers;
    const security = {
      hsts: Boolean(headers['strict-transport-security']),
      csp: Boolean(headers['content-security-policy']),
      xfo: Boolean(headers['x-frame-options']),
      xcto: Boolean(headers['x-content-type-options']),
      xxss: Boolean(headers['x-xss-protection']),
      referrer: Boolean(headers['referrer-policy'])
    };
    sendJSON(res, 200, { domain, security });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleArchive(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(
      `https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=5&fl=timestamp,original,statuscode`
    );
    const entries = Array.isArray(data)
      ? data.slice(1).map(item => ({ timestamp: item[0], original: item[1], status: item[2] }))
      : [];
    sendJSON(res, 200, { domain, entries });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleRanking(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(`https://tranco-list.eu/api/ranks/domain/${domain}`);
    sendJSON(res, 200, { domain, rank: data.rank || null, date: data.list_date || null });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Sin información' });
  }
}

async function handleBlock(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const resolvers = [
      {
        name: 'Google',
        url: `https://dns.google/resolve?name=${domain}&type=A`
      },
      {
        name: 'Cloudflare',
        url: `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
        headers: { accept: 'application/dns-json' }
      },
      {
        name: 'Quad9',
        url: `https://dns.quad9.net/dns-query?name=${domain}&type=A`,
        headers: { accept: 'application/dns-json' }
      }
    ];
    const results = [];
    for (const resolver of resolvers) {
      try {
        const data = await fetchJSON(resolver.url, { headers: resolver.headers });
        const answers = Array.isArray(data.Answer)
          ? data.Answer.filter(a => a.type === 1)
          : [];
        results.push({ resolver: resolver.name, blocked: answers.length === 0 });
      } catch (e) {
        results.push({ resolver: resolver.name, blocked: true });
      }
    }
    sendJSON(res, 200, { domain, results });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleMalware(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const body = `host=${encodeURIComponent(domain)}`;
    const data = await fetchJSON('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });
    const entries = Array.isArray(data?.urls) ? data.urls.slice(0, 10) : [];
    sendJSON(res, 200, { domain, entries, threat: data?.query_status });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleTlsCiphers(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const suites = [];
    const protocols = ['TLSv1.3', 'TLSv1.2'];
    for (const version of protocols) {
      await new Promise(resolve => {
        const socket = tls.connect(
          {
            host: domain,
            servername: domain,
            port: 443,
            rejectUnauthorized: false,
            minVersion: version,
            maxVersion: version
          },
          () => {
            const cipher = socket.getCipher();
            if (cipher) suites.push({ protocol: socket.getProtocol(), cipher: cipher.name });
            socket.end();
            resolve();
          }
        );
        socket.on('error', () => resolve());
        socket.setTimeout(Math.min(REQUEST_TIMEOUT_MS, 7000), () => {
          socket.destroy();
          resolve();
        });
      });
    }
    sendJSON(res, 200, { domain, suites });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleTlsConfig(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(
      `https://tls-observatory.services.mozilla.com/api/v1/analyze?host=${domain}`
    );
    sendJSON(res, 200, { domain, data });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleTlsSimulation(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const scenarios = [];
    const clients = [
      { name: 'Modern Browser', minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' },
      { name: 'Legacy Browser', minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' }
    ];
    for (const client of clients) {
      await new Promise(resolve => {
        const socket = tls.connect(
          {
            host: domain,
            servername: domain,
            port: 443,
            rejectUnauthorized: false,
            minVersion: client.minVersion,
            maxVersion: client.maxVersion
          },
          () => {
            const cipher = socket.getCipher();
            scenarios.push({
              client: client.name,
              protocol: socket.getProtocol(),
              cipher: cipher ? cipher.name : null,
              success: true
            });
            socket.end();
            resolve();
          }
        );
        socket.on('error', () => {
          scenarios.push({ client: client.name, success: false });
          resolve();
        });
        socket.setTimeout(Math.min(REQUEST_TIMEOUT_MS, 7000), () => {
          socket.destroy();
          scenarios.push({ client: client.name, success: false });
          resolve();
        });
      });
    }
    sendJSON(res, 200, { domain, scenarios });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleScreenshot(domain, res) {
  domain = normalizeDomain(domain);
  const encoded = encodeURIComponent(`https://${domain}`);
  const imageUrl = `https://image.thum.io/get/png/${encoded}`;
  sendJSON(res, 200, { domain, imageUrl });
}

async function handleWifiSpectrum(variantId, res) {
  const cleanId = String(variantId || '').trim();
  if (!cleanId) return sendJSON(res, 200, { error: 'Falta variantId' });
  try {
    const sourceUrl = `https://api.cert.wi-fi.org/api/certificate/download/public?variantId=${encodeURIComponent(cleanId)}`;
    const text = await fetchText(sourceUrl, { timeout: 20000 });
    const parsed = parseWifiSpectrumCertificate(text, sourceUrl);
    sendJSON(res, 200, {
      variantId: cleanId,
      available: Boolean(text && text.length),
      ...parsed
    });
  } catch (e) {
    sendJSON(res, 200, {
      variantId: cleanId,
      available: false,
      error: errorMessage(e),
      sourceUrl: `https://api.cert.wi-fi.org/api/certificate/download/public?variantId=${encodeURIComponent(cleanId)}`
    });
  }
}

async function handleDnsviz(domain, res, format = '', mode = 'remote') {
  domain = normalizeDomain(domain);
  try {
    const meta = await resolveDnsvizMeta(domain);
    const chain = await dnssecChain(domain, mode);
    if (format === 'svg') {
      const graph = await fetchCachedDnsvizSvg(meta.svgUrl, domain);
      if (graph && /<svg[\s>]/i.test(graph)) {
        return sendSVG(res, 200, graph);
      }
      if (meta.pageUrl) {
        return sendSVG(
          res,
          200,
          placeholderSvg(
            'DNSViz no disponible',
            'No se pudo recuperar el gráfico SVG de DNSViz, pero la cadena y las observaciones siguen disponibles.'
          )
        );
      }
      return sendSVG(
        res,
        200,
        placeholderSvg('DNSViz no disponible', 'No se pudo recuperar el gráfico SVG de DNSViz.')
      );
    }
    sendJSON(res, 200, { ...meta, chain });
  } catch (e) {
    if (format === 'svg') {
      return sendSVG(
        res,
        200,
        placeholderSvg('DNSViz no disponible', 'La consulta DNSSEC o el gráfico no respondieron a tiempo.')
      );
    }
    sendJSON(res, 200, {
      domain,
      available: false,
      error: errorMessage(e),
      pageUrl: `https://dnsviz.net/d/${domain}/dnssec/`,
      svgUrl: `https://dnsviz.net/d/${domain}/dnssec/auth_graph.svg?download=1`,
      pngUrl: `https://dnsviz.net/d/${domain}/dnssec/auth_graph.png?download=1`,
      chain: []
    });
  }
}

const STARTUP_SELF_TEST_DOMAIN = 'practicallyunhackable.com';
const STARTUP_SELF_TEST_ROUTES = [
  ['headers', d => `/headers/${d}`],
  ['tlsinfo', d => `/tlsinfo/${d}`],
  ['sslchain', d => `/sslchain/${d}`],
  ['caa', d => `/caa/${d}`],
  ['ipv4', d => `/ipv4/${d}`],
  ['ipv6', d => `/ipv6/${d}`],
  ['dnssec', d => `/dnssec/${d}`],
  ['dnsviz', d => `/dnsviz/${d}`],
  ['dnsrecords', d => `/dnsrecords/${d}`],
  ['txtrecords', d => `/txtrecords/${d}`],
  ['mx', d => `/mx/${d}`],
  ['mailipv6', d => `/mailipv6/${d}`],
  ['maildnssec', d => `/maildnssec/${d}`],
  ['spf', d => `/spf/${d}`],
  ['dmarc', d => `/dmarc/${d}`],
  ['dkim', d => `/dkim/${d}`],
  ['starttls', d => `/starttls/${d}`],
  ['smtputf8', d => `/smtputf8/${d}`],
  ['rpki', d => `/rpki/${d}`],
  ['routing', d => `/routing/${d}`],
  ['serverinfo', d => `/serverinfo/${d}`],
  ['serverstatus', d => `/serverstatus/${d}`],
  ['redirectchain', d => `/redirectchain/${d}`],
  ['openports', d => `/openports/${d}`],
  ['ping', d => `/ping/${d}`],
  ['pingv6', d => `/pingv6/${d}`],
  ['traceroute', d => `/traceroute/${d}`],
  ['sitefeatures', d => `/sitefeatures/${d}`],
  ['cookies', d => `/cookies/${d}`],
  ['listedpages', d => `/listedpages/${d}`],
  ['linkedpages', d => `/linkedpages/${d}`],
  ['socialtags', d => `/socialtags/${d}`],
  ['quality', d => `/quality/${d}`],
  ['archive', d => `/archive/${d}`],
  ['ranking', d => `/ranking/${d}`]
];

async function runStartupSelfTest(baseUrl) {
  const domain = encodeURIComponent(STARTUP_SELF_TEST_DOMAIN);
  console.log(`[selftest] iniciando dominio=${STARTUP_SELF_TEST_DOMAIN}`);
  const results = [];
  async function timedFetch(target, timeoutMs = SELFTEST_TIMEOUT_MS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(target, {
        signal: controller.signal,
        headers: { accept: 'application/json' }
      });
    } finally {
      clearTimeout(timer);
    }
  }
  for (const [name, pathFn] of STARTUP_SELF_TEST_ROUTES) {
    try {
      const response = await timedFetch(`${baseUrl}${pathFn(domain)}`);
      const data = await response.json();
      const state = data?.error ? 'error' : 'ok';
      const note = data?.error || data?.status || data?.policyStatus || data?.available || '';
      results.push({ name, state, note });
      console.log(`[selftest] ${name}: ${state}${note ? ` - ${note}` : ''}`);
    } catch (e) {
      const message = errorMessage(e);
      results.push({ name, state: 'error', note: message });
      console.log(`[selftest] ${name}: error - ${message}`);
    }
  }
  try {
    const wifi = await timedFetch(`${baseUrl}/wifispectrum/WFA115006`, SELFTEST_TIMEOUT_MS);
    const wifiData = await wifi.json();
    console.log(
      `[selftest] wifispectrum: ${wifiData?.error ? 'error' : 'ok'}${wifiData?.certId ? ` - ${wifiData.certId}` : ''}`
    );
  } catch (e) {
    console.log(`[selftest] wifispectrum: error - ${errorMessage(e)}`);
  }
  const ok = results.filter(item => item.state === 'ok').length;
  const error = results.filter(item => item.state === 'error').length;
  const compliance = results.length ? Math.round((ok / results.length) * 100) : 0;
  console.log(`[selftest] resumen ok=${ok} error=${error} cumplimiento=${compliance}%`);
}

const server = http.createServer(async (req, res) => {
  const parsed = new URL(req.url, 'http://localhost');
  const segments = parsed.pathname.split('/').filter(Boolean);
  if (segments[0] === 'partials' && segments[1]) {
    try {
      const filePath = path.resolve(PARTIALS_DIR, segments[1]);
      if (!filePath.startsWith(`${PARTIALS_DIR}${path.sep}`)) {
        return sendJSON(res, 400, { error: 'Ruta inválida' });
      }
      const html = await fs.readFile(filePath, 'utf8');
      return sendHTML(res, 200, html);
    } catch (e) {
      return sendJSON(res, 404, { error: 'Fragmento no encontrado' });
    }
  }
  if (segments.length === 0 || (segments.length === 1 && segments[0] === 'index.html')) {
    try {
      const html = await fs.readFile(INDEX_PATH, 'utf8');
      return sendHTML(res, 200, html);
    } catch (e) {
      return sendHTML(res, 500, '<h1>No se pudo cargar index.html</h1>');
    }
  }
  if (segments[0] === 'dnsviz' && segments[1]) {
    return handleDnsviz(segments[1], res, parsed.searchParams.get('format') || '', parsed.searchParams.get('resolver') || 'remote');
  }
  if (segments[0] === 'mx' && segments[1]) return handleMx(segments[1], res);
  if (segments[0] === 'smtputf8' && segments[1]) return handleSmtpUtf8(segments[1], res);
  if (segments[0] === 'starttls' && segments[1]) return handleStarttls(segments[1], res);
  if (segments[0] === 'spf' && segments[1]) return handleSpf(segments[1], res);
  if (segments[0] === 'dmarc' && segments[1]) return handleDmarc(segments[1], res);
  if (segments[0] === 'dnssec' && segments[1]) return handleDnssec(segments[1], res);
  if (segments[0] === 'dkim' && segments[1]) return handleDkim(segments[1], parsed.searchParams.get('selector') || 'support', res);
  if (segments[0] === 'ipv4' && segments[1]) return handleIpv4(segments[1], res);
  if (segments[0] === 'ipv6' && segments[1]) return handleIpv6(segments[1], res);
  if (segments[0] === 'maildnssec' && segments[1]) return handleMailDnssec(segments[1], res);
  if (segments[0] === 'mailipv6' && segments[1]) return handleMailIpv6(segments[1], res);
  if (segments[0] === 'rpki' && segments[1]) return handleRpki(segments[1], res);
  if (segments[0] === 'routing' && segments[1]) return handleRouting(segments[1], res);
  if (segments[0] === 'whois' && segments[1]) return handleWhois(segments[1], res);
  if (segments[0] === 'w3c' && segments[1]) return handleW3C(segments[1], res);
  if (segments[0] === 'headers' && segments[1]) return handleHeaders(segments[1], res);
  if (segments[0] === 'caa' && segments[1]) return handleCaa(segments[1], res);
  if (segments[0] === 'tlsa' && segments[1]) return handleTlsa(segments[1], res);
  if (segments[0] === 'securitytxt' && segments[1])
    return handleSecurityTxt(segments[1], res);
  if (segments[0] === 'tlsinfo' && segments[1]) return handleTls(segments[1], res);
  if (segments[0] === 'ipinfo' && segments[1]) return handleIpInfo(segments[1], res);
  if (segments[0] === 'sslchain' && segments[1]) return handleSslChain(segments[1], res);
  if (segments[0] === 'dnsrecords' && segments[1]) return handleDnsRecords(segments[1], res);
  if (segments[0] === 'cookies' && segments[1]) return handleCookies(segments[1], res);
  if (segments[0] === 'crawlrules' && segments[1]) return handleCrawlRules(segments[1], res);
  if (segments[0] === 'quality' && segments[1]) return handleQuality(segments[1], res);
  if (segments[0] === 'serverlocation' && segments[1])
    return handleServerLocation(segments[1], res);
  if (segments[0] === 'associatedhosts' && segments[1])
    return handleAssociatedHosts(segments[1], res);
  if (segments[0] === 'redirectchain' && segments[1])
    return handleRedirectChain(segments[1], res);
  if (segments[0] === 'txtrecords' && segments[1]) return handleTxtRecords(segments[1], res);
  if (segments[0] === 'serverstatus' && segments[1])
    return handleServerStatus(segments[1], res);
  if (segments[0] === 'openports' && segments[1]) return handleOpenPorts(segments[1], res);
  if (segments[0] === 'ping' && segments[1]) return handlePing(segments[1], res);
  if (segments[0] === 'pingv6' && segments[1]) return handlePingV6(segments[1], res);
  if (segments[0] === 'traceroute' && segments[1]) return handleTraceroute(segments[1], res);
  if (segments[0] === 'carbon' && segments[1]) return handleCarbon(segments[1], res);
  if (segments[0] === 'serverinfo' && segments[1]) return handleServerInfo(segments[1], res);
  if (segments[0] === 'domaininfo' && segments[1]) return handleDomainInfo(segments[1], res);
  if (segments[0] === 'dnssecurity' && segments[1])
    return handleDnsSecurity(segments[1], res);
  if (segments[0] === 'sitefeatures' && segments[1])
    return handleSiteFeatures(segments[1], res);
  if (segments[0] === 'dnsserver' && segments[1]) return handleDnsServer(segments[1], res);
  if (segments[0] === 'techstack' && segments[1]) return handleTechStack(segments[1], res);
  if (segments[0] === 'listedpages' && segments[1]) return handleListedPages(segments[1], res);
  if (segments[0] === 'linkedpages' && segments[1]) return handleLinkedPages(segments[1], res);
  if (segments[0] === 'socialtags' && segments[1]) return handleSocialTags(segments[1], res);
  if (segments[0] === 'emailconfig' && segments[1])
    return handleEmailConfig(segments[1], res);
  if (segments[0] === 'firewall' && segments[1]) return handleFirewall(segments[1], res);
  if (segments[0] === 'httpsecurity' && segments[1])
    return handleHttpSecurity(segments[1], res);
  if (segments[0] === 'archive' && segments[1]) return handleArchive(segments[1], res);
  if (segments[0] === 'ranking' && segments[1]) return handleRanking(segments[1], res);
  if (segments[0] === 'cctlds') return handleCctldReport(res, parsed.searchParams.get('resolver') || 'local');
  if (segments[0] === 'block' && segments[1]) return handleBlock(segments[1], res);
  if (segments[0] === 'malware' && segments[1]) return handleMalware(segments[1], res);
  if (segments[0] === 'tlsciphers' && segments[1])
    return handleTlsCiphers(segments[1], res);
  if (segments[0] === 'tlsconfig' && segments[1])
    return handleTlsConfig(segments[1], res);
  if (segments[0] === 'tlssimulation' && segments[1])
    return handleTlsSimulation(segments[1], res);
  if (segments[0] === 'screenshot' && segments[1])
    return handleScreenshot(segments[1], res);
  if (segments[0] === 'wifispectrum' && segments[1])
    return handleWifiSpectrum(segments[1], res);
  sendJSON(res, 404, { error: 'Not found' });
});

const PORT = process.env.PORT || 4000;
const HOST = process.env.HOST || '127.0.0.1';
server.listen(PORT, HOST, () =>
  console.log(`Servidor escuchando en ${HOST}:${PORT}`)
);

if (process.env.STARTUP_SELF_TEST === '1') {
  setTimeout(() => {
    runStartupSelfTest(`http://${HOST}:${PORT}`).catch(e =>
      console.log(`[selftest] fatal - ${errorMessage(e)}`)
    );
  }, 1200);
}

setTimeout(() => {
  refreshCctldReport().catch(e => console.log(`[cctld] error - ${errorMessage(e)}`));
}, 0);
setInterval(() => {
  refreshCctldReport().catch(e => console.log(`[cctld] error - ${errorMessage(e)}`));
}, 15 * 60 * 1000).unref();
