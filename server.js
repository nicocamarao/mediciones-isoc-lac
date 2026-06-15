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
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 25000);
const INTERNETNL_BATCH_BASE_URL = String(process.env.INTERNETNL_BATCH_BASE_URL || 'http://localhost:8080/api/batch/v2').replace(/\/+$/, '');
const INTERNETNL_BATCH_AUTH = String(process.env.INTERNETNL_BATCH_AUTH || '').trim();
const INTERNETNL_BATCH_USER = String(process.env.INTERNETNL_BATCH_USER || '').trim();
const INTERNETNL_BATCH_PASSWORD = String(process.env.INTERNETNL_BATCH_PASSWORD || '').trim();
const INTERNETNL_BATCH_MAX_WAIT_MS = Number(process.env.INTERNETNL_BATCH_MAX_WAIT_MS || 120000);
const INTERNETNL_BATCH_POLL_MS = Number(process.env.INTERNETNL_BATCH_POLL_MS || 2000);
const INTERNETNL_BATCH_TLS_SERVERNAME = String(process.env.INTERNETNL_BATCH_TLS_SERVERNAME || '').trim();
const INTERNETNL_BATCH_INSECURE_TLS = ['1', 'true', 'yes'].includes(String(process.env.INTERNETNL_BATCH_INSECURE_TLS || '').trim().toLowerCase());
const LOCAL_APP_BASE_URL = String(
  process.env.LOCAL_APP_BASE_URL ||
    `http://${process.env.HOST || '127.0.0.1'}:${process.env.PORT || 4000}`
).replace(/\/+$/, '');
const INDEX_PATH = path.join(__dirname, 'index.html');
const PARTIALS_DIR = path.join(__dirname, 'partials');
const LOCALES_DIR = path.join(__dirname, 'locales');
const PULSE_SNAPSHOT_DIR = path.join(__dirname, 'data', 'pulse-html');
const PULSE_HARDCODED_REPORTS = require('./data/pulse-hardcoded.json');
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
  jm: [{ territory: 'Jamaica', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  mx: [{ territory: 'Mexico', status: 'LOW_5925_6425' }],
  ni: [{ territory: 'Nicaragua', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  pa: [{ territory: 'Panama', status: 'FULL_5925_7125', note: 'Public consultation became part of the full-band regional set.' }],
  py: [{ territory: 'Paraguay', status: 'LOW_5925_6425', note: 'Confirmed by CONATEL Resolution 1035/2025' }],
  pe: [{ territory: 'Peru', status: 'FULL_5925_7125' }],
  do: [{ territory: 'Dominican Republic', status: 'FULL_5925_7125' }],
  bb: [{ territory: 'Barbados', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
  bs: [{ territory: 'Bahamas', status: 'NO_PUBLIC_ADOPTION_FOUND' }],
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

function detectCcTld(domain) {
  const labels = String(normalizeDomain(domain) || '')
    .toLowerCase()
    .split('.')
    .filter(Boolean);
  const tld = labels[labels.length - 1] || '';
  return /^[a-z]{2}$/.test(tld) ? tld : null;
}

function sendHTML(res, status, html) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(html);
}

function sendText(res, status, text, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'Content-Type': contentType,
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store'
  });
  res.end(text);
}

function sendAsset(res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const contentTypes = {
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.ttf': 'font/ttf',
    '.eot': 'application/vnd.ms-fontobject'
  };
  return fs.readFile(filePath).then(buffer => {
    res.writeHead(200, {
      'Content-Type': contentTypes[ext] || 'application/octet-stream',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=86400'
    });
    res.end(buffer);
  });
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

function internetNlBatchConfigError() {
  return 'Configura INTERNETNL_BATCH_BASE_URL y las credenciales de Basic Auth en INTERNETNL_BATCH_AUTH o INTERNETNL_BATCH_USER/INTERNETNL_BATCH_PASSWORD.';
}

function getInternetNlBatchAuthHeader() {
  if (INTERNETNL_BATCH_AUTH) {
    return `Basic ${Buffer.from(INTERNETNL_BATCH_AUTH, 'utf8').toString('base64')}`;
  }
  if (INTERNETNL_BATCH_USER || INTERNETNL_BATCH_PASSWORD) {
    return `Basic ${Buffer.from(`${INTERNETNL_BATCH_USER}:${INTERNETNL_BATCH_PASSWORD}`, 'utf8').toString('base64')}`;
  }
  return '';
}

function getInternetNlBatchHeaders() {
  const authorization = getInternetNlBatchAuthHeader();
  if (!authorization) return null;
  return {
    Authorization: authorization,
    Accept: 'application/json',
    'Content-Type': 'application/json'
  };
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function fetchJsonResponse(target, options = {}) {
  return new Promise((resolve, reject) => {
    const url = typeof target === 'string' ? new URL(target) : target;
    const lib = pickLib(url);
    const requestOptions = {
      method: options.method || 'GET',
      headers: options.headers || {}
    };
    if (url.protocol === 'https:') {
      if (INTERNETNL_BATCH_TLS_SERVERNAME) {
        requestOptions.servername = INTERNETNL_BATCH_TLS_SERVERNAME;
        if (!requestOptions.headers.Host && !requestOptions.headers.host) {
          requestOptions.headers.Host = INTERNETNL_BATCH_TLS_SERVERNAME;
        }
      }
      if (INTERNETNL_BATCH_INSECURE_TLS) requestOptions.rejectUnauthorized = false;
    }
    const req = lib.request(
      url,
      requestOptions,
      r => {
        let data = '';
        r.on('data', chunk => (data += chunk));
        r.on('end', () => {
          let json = null;
          if (data) {
            try {
              json = JSON.parse(data);
            } catch (error) {
              return resolve({
                statusCode: r.statusCode,
                headers: r.headers,
                body: data,
                json: null
              });
            }
          }
          resolve({
            statusCode: r.statusCode,
            headers: r.headers,
            body: data,
            json
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
  });
}

function normalizeBatchStatus(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'passed' || value === 'ok') return 'ok';
  if (value === 'warning' || value === 'info') return value;
  if (value === 'failed') return 'fail';
  if (value === 'error') return 'error';
  return 'info';
}

function prettifyBatchKey(value) {
  return String(value || '')
    .replace(/_/g, ' ')
    .replace(/\b([a-z])/g, letter => letter.toUpperCase())
    .trim();
}

function buildInternetNlDomains(domain, type = 'web') {
  const normalized = normalizeDomain(domain);
  const domains = new Set();
  if (normalized) domains.add(normalized);
  if (type === 'web' && normalized) {
    if (normalized.startsWith('www.')) {
      domains.add(normalized.replace(/^www\./, ''));
    } else {
      domains.add(`www.${normalized}`);
    }
  }
  return [...domains];
}

function summarizeInternetNlDomain(domainName, domainData) {
  const score = Number.isFinite(domainData?.scoring?.percentage)
    ? domainData.scoring.percentage
    : null;
  const reportUrl = domainData?.report?.url || null;
  const categories = Object.entries(domainData?.results?.categories || {}).map(([name, category]) => ({
    text: prettifyBatchKey(name),
    status: normalizeBatchStatus(category?.status),
    note: category?.verdict || ''
  }));
  const tests = Object.entries(domainData?.results?.tests || {}).map(([name, test]) => ({
    text: prettifyBatchKey(name),
    status: normalizeBatchStatus(test?.status),
    note: test?.verdict || ''
  }));
  const lines = [
    score !== null ? `Puntaje: ${score}/100` : null,
    reportUrl ? `Informe: ${reportUrl}` : null,
    domainData?.status ? `Estado: ${domainData.status}` : null
  ].filter(Boolean);
  const sectionItems = categories.length ? categories : tests;
  const status = (() => {
    if (domainData?.status === 'error') return 'error';
    if (domainData?.status === 'cancelled') return 'fail';
    const categoryStatuses = Object.values(domainData?.results?.categories || {}).map(cat => normalizeBatchStatus(cat?.status));
    if (categoryStatuses.includes('fail')) return 'fail';
    if (categoryStatuses.includes('warning')) return 'warning';
    if (categoryStatuses.includes('error')) return 'error';
    if (typeof score === 'number') {
      if (score >= 90) return 'ok';
      if (score >= 70) return 'warning';
      return 'fail';
    }
    if (domainData?.status === 'done') return 'ok';
    return 'info';
  })();
  return {
    domain: domainName,
    status,
    score,
    reportUrl,
    lines,
    sections: [
      {
        label: `Resultados · ${domainName}`,
        status,
        note: reportUrl ? 'El informe web de Internet.nl abre sin autenticación.' : 'Batch completó la evaluación del dominio.',
        items: sectionItems
      }
    ]
  };
}

async function registerInternetNlBatch(type, domains, name) {
  const headers = getInternetNlBatchHeaders();
  if (!headers) throw new Error(internetNlBatchConfigError());
  const url = new URL('requests', `${INTERNETNL_BATCH_BASE_URL}/`);
  const response = await fetchJsonResponse(url, {
    method: 'POST',
    headers,
    timeout: REQUEST_TIMEOUT_MS * 2,
    body: JSON.stringify({ type, domains, name })
  });
  if (response.statusCode && response.statusCode >= 400) {
    const message = response.json?.error?.msg || response.body || 'Internet.nl Batch rechazó la solicitud.';
    throw new Error(message);
  }
  const request = response.json?.request || response.json;
  if (!request?.request_id) {
    throw new Error('Internet.nl no devolvió request_id.');
  }
  return request;
}

async function fetchInternetNlRequest(requestId) {
  const headers = getInternetNlBatchHeaders();
  if (!headers) throw new Error(internetNlBatchConfigError());
  const url = new URL(`requests/${requestId}`, `${INTERNETNL_BATCH_BASE_URL}/`);
  const response = await fetchJsonResponse(url, { headers, timeout: REQUEST_TIMEOUT_MS * 2 });
  if (response.statusCode === 404) return { pending: true };
  if (response.statusCode && response.statusCode >= 400) {
    const message = response.json?.error?.msg || response.body || 'No se pudo consultar el estado del lote.';
    throw new Error(message);
  }
  return response.json?.request || response.json;
}

async function fetchInternetNlResults(requestId, technical = false) {
  const headers = getInternetNlBatchHeaders();
  if (!headers) throw new Error(internetNlBatchConfigError());
  const suffix = technical ? 'results_technical' : 'results';
  const url = new URL(`requests/${requestId}/${suffix}`, `${INTERNETNL_BATCH_BASE_URL}/`);
  const response = await fetchJsonResponse(url, { headers, timeout: REQUEST_TIMEOUT_MS * 2 });
  if (response.statusCode === 200) return response.json;
  if (
    response.statusCode === 400 &&
    /(being generated|not yet `done`)/i.test(response.json?.error?.msg || response.body || '')
  ) {
    return { pending: true };
  }
  if (response.statusCode === 404) {
    return { pending: true };
  }
  const message = response.json?.error?.msg || response.body || 'No se pudo obtener el resultado de Internet.nl.';
  throw new Error(message);
}

async function waitForInternetNlResults(requestId) {
  const deadline = Date.now() + INTERNETNL_BATCH_MAX_WAIT_MS;
  let request = null;
  while (Date.now() <= deadline) {
    request = await fetchInternetNlRequest(requestId);
    if (request?.pending) {
      await sleep(INTERNETNL_BATCH_POLL_MS);
      continue;
    }
    const status = String(request?.status || '').toLowerCase();
    if (['done', 'cancelled', 'error'].includes(status)) {
      if (status === 'done') {
        const results = await fetchInternetNlResults(requestId);
        if (results?.pending) {
          await sleep(INTERNETNL_BATCH_POLL_MS);
          continue;
        }
        return { request, results };
      }
      return { request, results: null };
    }
    await sleep(INTERNETNL_BATCH_POLL_MS);
  }
  return { request, results: null, timedOut: true };
}

async function handleInternetNl(domain, res, type = 'web') {
  const normalizedType = type === 'mail' ? 'mail' : 'web';
  const domains = buildInternetNlDomains(domain, normalizedType);
  const requestName = `mediciones-isoc-lac: ${normalizedType} ${domains[0] || domain}`;
  try {
    const request = await registerInternetNlBatch(normalizedType, domains, requestName);
    const { request: currentRequest, results, timedOut } = await waitForInternetNlResults(request.request_id);
    const requestState = currentRequest || request;
    if (!results) {
      return sendJSON(res, 200, {
        domain: normalizeDomain(domain),
        type: normalizedType,
        status: timedOut ? 'pending' : normalizeBatchStatus(requestState.status),
        lines: [
          `Solicitud registrada: ${request.request_id}`,
          `Estado actual: ${requestState.status}`,
          timedOut ? 'El resultado todavía no está listo. Puedes volver a intentar más tarde.' : null
        ].filter(Boolean),
        request: requestState,
        domains,
        pending: true
      });
    }

    const perDomain = Object.entries(results.domains || {}).map(([domainName, domainData]) =>
      summarizeInternetNlDomain(domainName, domainData)
    );
    const overallStatus = perDomain.some(item => item.status === 'fail')
      ? 'fail'
      : perDomain.some(item => item.status === 'warning')
        ? 'warning'
        : perDomain.some(item => item.status === 'error')
          ? 'error'
          : perDomain.some(item => item.status === 'ok')
            ? 'ok'
            : 'info';
    const scores = perDomain.map(item => item.score).filter(value => Number.isFinite(value));
    const score = scores.length ? Math.round(scores.reduce((acc, value) => acc + value, 0) / scores.length) : null;

    sendJSON(res, 200, {
      domain: normalizeDomain(domain),
      type: normalizedType,
      status: overallStatus,
      lines: [
        `Solicitud ${request.request_id}`,
        `Estado: ${requestState.status}`,
        score !== null ? `Puntaje medio: ${score}/100` : null,
        perDomain.length ? `Dominios: ${perDomain.map(item => `${item.domain} (${item.status})`).join(' · ')}` : null
      ].filter(Boolean),
      sections: perDomain.map(item => ({
        label: item.domain,
        status: item.status,
        note: item.reportUrl ? `Informe: ${item.reportUrl}` : `Puntaje: ${item.score ?? 'n/a'}/100`,
        items: item.sections[0]?.items || []
      })),
      request: requestState,
      domains,
      results,
      technical: await fetchInternetNlResults(request.request_id, true).catch(() => null)
    });
  } catch (e) {
    sendJSON(res, 200, {
      domain: normalizeDomain(domain),
      type: normalizedType,
      status: 'error',
      error: e.message || errorMessage(e),
      message: e.message || 'No se pudo consultar Internet.nl Batch.'
    });
  }
}

async function fetchLocalJson(pathname, options = {}) {
  const url = new URL(pathname, `${LOCAL_APP_BASE_URL}/`);
  const response = await fetchJsonResponse(url, {
    ...options,
    headers: {
      Accept: 'application/json',
      ...(options.headers || {})
    }
  });
  if (response.statusCode && response.statusCode >= 400) {
    const message = response.json?.error || response.body || `HTTP ${response.statusCode}`;
    throw new Error(message);
  }
  return response.json || {};
}

function normalizeCompatStatus(status) {
  const value = String(status || '').toLowerCase();
  if (['ok', 'passed', 'secure', 'valid', 'supports', 'enabled'].includes(value)) return 'ok';
  if (['warning', 'info', 'partial', 'partial_ok'].includes(value)) return 'warning';
  if (['fail', 'failed', 'invalid', 'insecure', 'bogus', 'error', 'no'].includes(value)) return 'fail';
  return 'info';
}

function statusScore(status) {
  const value = normalizeCompatStatus(status);
  if (value === 'ok') return 2;
  if (value === 'warning' || value === 'info') return 1;
  return 0;
}

function verdictFromStatus(status) {
  const value = normalizeCompatStatus(status);
  if (value === 'ok') return 'passed';
  if (value === 'warning') return 'warning';
  if (value === 'info') return 'info';
  return 'failed';
}

async function buildLocalCompatBundle(domain, type = 'web') {
  const normalizedType = type === 'mail' ? 'mail' : 'web';
  const cleanDomain = normalizeDomain(domain);
  const isWeb = normalizedType === 'web';
  const source = {};

  if (isWeb) {
    const [headers, ipv6, dnssec, dnsviz, tls, sslchain, tlsa, caa, rpki, routing, securitytxt] = await Promise.all([
      fetchLocalJson(`/headers/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
      fetchLocalJson(`/ipv6/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
      fetchLocalJson(`/dnssec/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
      fetchLocalJson(`/dnsviz/${encodeURIComponent(cleanDomain)}?resolver=local`).catch(error => ({ error: error.message })),
      fetchLocalJson(`/tlsinfo/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
      fetchLocalJson(`/sslchain/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
      fetchLocalJson(`/tlsa/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
      fetchLocalJson(`/caa/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
      fetchLocalJson(`/rpki/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
      fetchLocalJson(`/routing/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
      fetchLocalJson(`/securitytxt/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message }))
    ]);

    source.headers = headers;
    source.ipv6 = ipv6;
    source.dnssec = dnssec;
    source.dnsviz = dnsviz;
    source.tls = tls;
    source.sslchain = sslchain;
    source.tlsa = tlsa;
    source.caa = caa;
    source.rpki = rpki;
    source.routing = routing;
    source.securitytxt = securitytxt;

    const webIpv6Ok = Boolean(ipv6?.present);
    const dnssecOk = Boolean(dnssec?.valid || dnssec?.assessment?.valid);
    const httpsOk = Boolean(headers?.https);
    const hstsOk = Boolean(headers?.hstsStrict);
    const tlsOk = Boolean(tls?.protocol && ['TLSv1.2', 'TLSv1.3'].includes(tls.protocol));
    const appsecprivOk = Boolean(headers?.csp || headers?.xfo || headers?.xcto || headers?.referrer || headers?.permissions);
    const rpkiBad = Array.isArray(rpki?.results) && rpki.results.some(item => String(item.state || '').startsWith('invalid'));
    const rpkiAny = Array.isArray(rpki?.results) && rpki.results.length > 0;
    const rpkiOk = rpkiAny && !rpkiBad && rpki.results.every(item => item.state === 'valid');

    const categories = {
      web_ipv6: {
        status: webIpv6Ok ? 'passed' : 'failed',
        verdict: webIpv6Ok ? 'IPv6 visible' : 'No IPv6 visible'
      },
      web_dnssec: {
        status: dnssecOk ? 'passed' : 'failed',
        verdict: dnssecOk ? 'DNSSEC visible' : 'DNSSEC not validated'
      },
      web_https: {
        status: httpsOk ? (hstsOk && tlsOk ? 'passed' : 'warning') : 'failed',
        verdict: httpsOk ? 'HTTPS available' : 'HTTP only'
      },
      web_appsecpriv: {
        status: appsecprivOk ? 'warning' : 'failed',
        verdict: appsecprivOk ? 'Security headers present' : 'Security headers missing'
      },
      web_rpki: {
        status: rpkiOk ? 'passed' : (rpkiBad ? 'failed' : 'info'),
        verdict: rpkiOk ? 'RPKI valid' : (rpkiBad ? 'RPKI invalid' : 'RPKI inconclusive')
      }
    };

    const tests = {
      ipv6_present: {
        status: verdictFromStatus(ipv6?.present ? 'ok' : 'fail'),
        verdict: ipv6?.present ? 'AAAA records present' : 'No AAAA records'
      },
      dnssec_valid: {
        status: verdictFromStatus(dnssecOk ? 'ok' : 'fail'),
        verdict: dnssecOk ? 'DNSSEC chain validated' : 'DNSSEC chain incomplete'
      },
      tls_protocol: {
        status: verdictFromStatus(tlsOk ? 'ok' : 'warning'),
        verdict: tls?.protocol ? `Protocol ${tls.protocol}` : 'No TLS protocol reported'
      },
      hsts: {
        status: verdictFromStatus(hstsOk ? 'ok' : 'fail'),
        verdict: hstsOk ? 'HSTS strict' : 'HSTS absent or weak'
      },
      csp: {
        status: verdictFromStatus(headers?.csp ? 'ok' : 'fail'),
        verdict: headers?.csp ? 'CSP present' : 'CSP absent'
      },
      rpki_valid: {
        status: verdictFromStatus(rpkiOk ? 'ok' : (rpkiBad ? 'fail' : 'info')),
        verdict: rpkiOk ? 'Valid route origin' : (rpkiBad ? 'Invalid route origin' : 'No RPKI verdict')
      }
    };

    const score = Math.round(
      (Object.values(categories).filter(entry => normalizeCompatStatus(entry.status) === 'ok').length /
        Object.keys(categories).length) *
        100
    );

    return {
      domain: cleanDomain,
      type: normalizedType,
      request: { status: 'done', type: normalizedType, bundle: 'local' },
      status: Object.values(categories).some(entry => normalizeCompatStatus(entry.status) === 'fail')
        ? 'fail'
        : Object.values(categories).some(entry => normalizeCompatStatus(entry.status) === 'warning')
          ? 'warning'
          : 'ok',
      scoring: { percentage: score },
      results: { categories, tests, custom: {} },
      lines: [
        `Dominio: ${cleanDomain}`,
        `IPv6: ${ipv6?.present ? 'sí' : 'no'}`,
        `DNSSEC: ${dnssecOk ? 'sí' : 'no'}`,
        `HTTPS: ${httpsOk ? 'sí' : 'no'}`,
        `RPKI: ${rpkiOk ? 'válido' : (rpkiBad ? 'inválido' : 'sin dato')}`
      ],
      sections: [
        {
          label: isWeb ? 'Web local' : 'Correo local',
          status: Object.values(categories).some(entry => normalizeCompatStatus(entry.status) === 'fail')
            ? 'fail'
            : Object.values(categories).some(entry => normalizeCompatStatus(entry.status) === 'warning')
              ? 'warning'
              : 'ok',
          note: 'Resumen local inspirado en el desglose de Internet.nl.',
          items: Object.entries(categories).map(([key, entry]) => ({
            text: prettifyBatchKey(key),
            status: normalizeCompatStatus(entry.status),
            note: entry.verdict
          }))
        }
      ],
      technical: {
        headers,
        ipv6,
        dnssec,
        dnsviz,
        tls,
        sslchain,
        tlsa,
        caa,
        rpki,
        routing,
        securitytxt
      }
    };
  }

  const [mailIpv6, mailDnssec, spf, dmarc, dkim, starttls, tls, rpki, routing, mx] = await Promise.all([
    fetchLocalJson(`/mailipv6/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
    fetchLocalJson(`/maildnssec/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
    fetchLocalJson(`/spf/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
    fetchLocalJson(`/dmarc/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
    fetchLocalJson(`/dkim/${encodeURIComponent(cleanDomain)}?selector=support`).catch(error => ({ error: error.message })),
    fetchLocalJson(`/starttls/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
    fetchLocalJson(`/tlsinfo/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
    fetchLocalJson(`/rpki/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
    fetchLocalJson(`/routing/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message })),
    fetchLocalJson(`/mx/${encodeURIComponent(cleanDomain)}`).catch(error => ({ error: error.message }))
  ]);

  source.mailIpv6 = mailIpv6;
  source.mailDnssec = mailDnssec;
  source.spf = spf;
  source.dmarc = dmarc;
  source.dkim = dkim;
  source.starttls = starttls;
  source.tls = tls;
  source.rpki = rpki;
  source.routing = routing;
  source.mx = mx;

  const mailIpv6Ok = Boolean(mailIpv6?.present);
  const domainDnssecOk = Boolean(mailDnssec?.domainDnssec?.secure);
  const spfOk = spf?.policyStatus === 'strict' || spf?.policyStatus === 'weak';
  const dmarcOk = dmarc?.policyStatus === 'strict' || dmarc?.policyStatus === 'weak';
  const dkimOk = Boolean(dkim?.supported);
  const starttlsOk = Array.isArray(starttls?.results) && starttls.results.some(item => item.status === 'supports');
  const rpkiBad = Array.isArray(rpki?.results) && rpki.results.some(item => String(item.state || '').startsWith('invalid'));
  const rpkiAny = Array.isArray(rpki?.results) && rpki.results.length > 0;
  const rpkiOk = rpkiAny && !rpkiBad && rpki.results.every(item => item.state === 'valid');

  const categories = {
    mail_ipv6: {
      status: mailIpv6Ok ? 'passed' : 'failed',
      verdict: mailIpv6Ok ? 'MX IPv6 visible' : 'MX IPv6 missing'
    },
    mail_dnssec: {
      status: domainDnssecOk ? 'passed' : 'failed',
      verdict: domainDnssecOk ? 'DNSSEC on domain and MX' : 'DNSSEC missing'
    },
    mail_auth: {
      status: spfOk && dmarcOk && dkimOk ? 'passed' : (spfOk || dmarcOk || dkimOk ? 'warning' : 'failed'),
      verdict: 'SPF / DMARC / DKIM'
    },
    mail_starttls: {
      status: starttlsOk ? 'passed' : 'failed',
      verdict: starttlsOk ? 'STARTTLS visible' : 'STARTTLS missing'
    },
    mail_rpki: {
      status: rpkiOk ? 'passed' : (rpkiBad ? 'failed' : 'info'),
      verdict: rpkiOk ? 'RPKI valid' : (rpkiBad ? 'failed route origin' : 'RPKI inconclusive')
    }
  };

  const tests = {
    mail_ipv6_present: {
      status: verdictFromStatus(mailIpv6Ok ? 'ok' : 'fail'),
      verdict: mailIpv6Ok ? 'IPv6 on MX present' : 'No IPv6 on MX'
    },
    mail_dnssec_valid: {
      status: verdictFromStatus(domainDnssecOk ? 'ok' : 'fail'),
      verdict: domainDnssecOk ? 'DNSSEC visible' : 'DNSSEC absent'
    },
    spf_present: {
      status: verdictFromStatus(spfOk ? 'ok' : 'fail'),
      verdict: spf?.policyStatus ? `SPF ${spf.policyStatus}` : 'SPF absent'
    },
    dmarc_present: {
      status: verdictFromStatus(dmarcOk ? 'ok' : 'fail'),
      verdict: dmarc?.policyStatus ? `DMARC ${dmarc.policyStatus}` : 'DMARC absent'
    },
    dkim_present: {
      status: verdictFromStatus(dkimOk ? 'ok' : 'fail'),
      verdict: dkimOk ? 'DKIM supported' : 'DKIM not detected'
    },
    starttls_enabled: {
      status: verdictFromStatus(starttlsOk ? 'ok' : 'fail'),
      verdict: starttlsOk ? 'STARTTLS visible' : 'STARTTLS absent'
    },
    rpki_valid: {
      status: verdictFromStatus(rpkiOk ? 'ok' : (rpkiBad ? 'fail' : 'info')),
      verdict: rpkiOk ? 'Valid route origin' : (rpkiBad ? 'Invalid route origin' : 'No RPKI verdict')
    }
  };

  const score = Math.round(
    (Object.values(categories).filter(entry => normalizeCompatStatus(entry.status) === 'ok').length /
      Object.keys(categories).length) *
      100
  );

  return {
    domain: cleanDomain,
    type: normalizedType,
    request: { status: 'done', type: normalizedType, bundle: 'local' },
    status: Object.values(categories).some(entry => normalizeCompatStatus(entry.status) === 'fail')
      ? 'fail'
      : Object.values(categories).some(entry => normalizeCompatStatus(entry.status) === 'warning')
        ? 'warning'
        : 'ok',
    scoring: { percentage: score },
    results: { categories, tests, custom: {} },
    lines: [
      `Dominio: ${cleanDomain}`,
      `IPv6: ${mailIpv6Ok ? 'sí' : 'no'}`,
      `DNSSEC: ${domainDnssecOk ? 'sí' : 'no'}`,
      `Auth: ${spfOk || dmarcOk || dkimOk ? 'parcial o sí' : 'no'}`,
      `STARTTLS: ${starttlsOk ? 'sí' : 'no'}`
    ],
    sections: [
      {
        label: 'Correo local',
        status: Object.values(categories).some(entry => normalizeCompatStatus(entry.status) === 'fail')
          ? 'fail'
          : Object.values(categories).some(entry => normalizeCompatStatus(entry.status) === 'warning')
            ? 'warning'
            : 'ok',
        note: 'Resumen local inspirado en el desglose de Internet.nl.',
        items: Object.entries(categories).map(([key, entry]) => ({
          text: prettifyBatchKey(key),
          status: normalizeCompatStatus(entry.status),
          note: entry.verdict
        }))
      }
    ],
    technical: {
      mx,
      mailIpv6,
      mailDnssec,
      spf,
      dmarc,
      dkim,
      starttls,
      tls,
      rpki,
      routing
    }
  };
}

async function handleCompatBundle(domain, res, type = 'web') {
  try {
    const bundle = await buildLocalCompatBundle(domain, type);
    sendJSON(res, 200, bundle);
  } catch (e) {
    sendJSON(res, 200, {
      domain: normalizeDomain(domain),
      type: type === 'mail' ? 'mail' : 'web',
      status: 'error',
      error: e.message || errorMessage(e),
      message: e.message || 'No se pudo construir el bundle local.'
    });
  }
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
  const pulseCountry = detectCcTld(domain);
  const pulseCountryCode = pulseCountry ? pulseCountry.toUpperCase() : null;
  const wifi = await summarizeWifiCountry(domain).catch(() => ({
    status: 'pending',
    label: 'Próximamente',
    notes: ['No se pudo resolver el bloque Wi‑Fi.']
  }));
  const pulse = await summarizePulseCountry(domain).catch(() => ({
    available: false,
    notes: ['No se pudo recuperar Pulse.']
  }));
  const backendCommands = [
    `dig +short NS ${domain}`,
    `dig +short DS ${domain}`,
    `dig +short DNSKEY ${domain}`,
    `dig +short NSEC3PARAM ${domain}`,
    `dig +trace +dnssec ${domain}`,
    ...ns.slice(0, 6).flatMap(host => [`dig +short A ${host}`, `dig +short AAAA ${host}`]),
    `curl -L https://dnsviz.net/d/${domain}/dnssec/`,
    `curl -L https://dnsviz.net/d/${domain}/dnssec/auth_graph.svg?download=1`,
    pulseCountryCode ? `curl -L https://pulse.internetsociety.org/en/reports/${pulseCountryCode}/` : null
  ].filter(Boolean);
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
    backend: {
      source: 'Equivalente de consultas backend usadas para generar el reporte.',
      commands: [...new Set(backendCommands)],
      notes: [
        'NS, DS, DNSKEY y NSEC3PARAM se resuelven con caché local.',
        'DNSViz se consulta aparte para obtener grafo, avisos y errores.',
        'Pulse se recupera con caché independiente por ccTLD.'
      ]
    },
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

function buildCctldErrorItem(tld, mode, message) {
  const domain = normalizeDomain(tld);
  const errorLines = [`Error al generar el reporte: ${message}`];
  return {
    tld: domain,
    nsCount: 0,
    ipv4NsCount: 0,
    ipv6NsCount: 0,
    dnssec: {
      parent: false,
      child: false,
      valid: false,
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
        notes: errorLines.slice()
      },
      assessment: {
        status: 'error',
        summaryLines: errorLines.slice(),
        sections: []
      }
    },
    nsDetails: [],
    wifi: {
      status: 'pending',
      label: 'Próximamente',
      notes: errorLines.slice()
    },
    pulse: {
      available: false,
      notes: errorLines.slice(),
      sourceUrl: `https://pulse.internetsociety.org/en/reports/${encodeURIComponent(domain)}/`
    },
    dnsviz: {
      available: false,
      pageUrl: `https://dnsviz.net/d/${domain}/dnssec/`,
      svgUrl: `https://dnsviz.net/d/${domain}/dnssec/auth_graph.svg?download=1`,
      observations: errorLines.slice(),
      warningCount: 0,
      errorCount: 1,
      warnings: errorLines.slice(),
      errors: errorLines.slice(),
      notices: {
        warnings: errorLines.slice(),
        errors: errorLines.slice()
      }
    },
    status: 'fail',
    dnssecValid: false,
    refreshedAt: new Date().toISOString(),
    error: message,
    mode
  };
}

async function getCachedCctldPulse(tld, mode = 'local') {
  const domain = normalizeDomain(tld);
  if (!domain) return null;

  const cached = cacheGet(cctldCache, `${mode}:${domain}`, 15 * 60 * 1000);
  if (cached?.pulse) return cached.pulse;

  const inMemoryReport = Array.isArray(cctldReportState.items)
    ? cctldReportState.items.find(item => normalizeDomain(item?.tld) === domain)
    : null;
  if (inMemoryReport?.pulse) {
    return inMemoryReport.pulse;
  }

  const refreshed = await summarizeCctld(domain, mode).catch(() => null);
  if (refreshed?.pulse) return refreshed.pulse;

  const afterRefresh = cacheGet(cctldCache, `${mode}:${domain}`, 15 * 60 * 1000);
  return afterRefresh?.pulse || null;
}

async function refreshCctldReport(mode = 'local') {
  if (cctldRefreshPromises.has(mode)) return cctldRefreshPromises.get(mode);
  cctldDebugState.active = true;
  cctldDebugState.lastMode = mode;
  cctldDebugState.lastStartedAt = new Date().toISOString();
  cctldDebugState.lastFinishedAt = null;
  cctldDebugState.lastError = null;
  cctldDebugState.lastFailures = 0;
  console.log(`[cctld] refresh start mode=${mode}`);
  const promise = (async () => {
    const items = await withConcurrency(LACNIC_CCTLDS, 4, async tld => {
      try {
        return await summarizeCctld(tld, mode);
      } catch (e) {
        const message = errorMessage(e);
        cctldDebugState.lastFailures += 1;
        cctldDebugState.lastError = {
          tld: normalizeDomain(tld),
          message,
          at: new Date().toISOString()
        };
        console.log(`[cctld] ${normalizeDomain(tld)} fallback - ${message}`);
        return buildCctldErrorItem(tld, mode, message);
      }
    });
    cctldReportState.items = items;
    cctldReportState.generatedAt = new Date().toISOString();
    cctldReportState.mode = mode;
    cctldDebugState.lastItems = items.length;
    cctldDebugState.lastFinishedAt = cctldReportState.generatedAt;
    cctldDebugState.active = false;
    console.log(`[cctld] refresh ok items=${items.length} failures=${cctldDebugState.lastFailures}`);
    return cctldReportState;
  })().catch(e => {
    const message = errorMessage(e);
    cctldDebugState.active = false;
    cctldDebugState.lastError = {
      tld: null,
      message,
      at: new Date().toISOString()
    };
    console.log(`[cctld] refresh fatal - ${message}`);
    throw e;
  }).finally(() => {
    cctldDebugState.active = false;
    cctldRefreshPromises.delete(mode);
  });
  cctldRefreshPromises.set(mode, promise);
  return promise;
}

const cctldDebugState = {
  active: false,
  lastMode: 'local',
  lastStartedAt: null,
  lastFinishedAt: null,
  lastItems: 0,
  lastFailures: 0,
  lastError: null
};

const cctldReportState = {
  generatedAt: null,
  items: [],
  mode: 'local'
};

async function handleCctldReport(res, mode = 'local') {
  if (!cctldReportState.items.length || cctldReportState.mode !== mode) {
    if (!cctldRefreshPromises.has(mode)) {
      refreshCctldReport(mode).catch(e => console.log(`[cctld] error - ${errorMessage(e)}`));
    }
  }
  sendJSON(res, 200, {
    ...cctldReportState,
    generating: cctldRefreshPromises.has(mode),
    debug: { ...cctldDebugState }
  });
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

function htmlToVisibleText(value) {
  return decodeHtmlEntities(
    String(value || '')
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<\/(p|div|li|h[1-6]|tr|td|th|section|article|ul|ol)>/gi, '\n')
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\r/g, '\n')
  )
    .replace(/\n[ \t]+/g, '\n')
    .replace(/[ \t]+\n/g, '\n');
}

function htmlToVisibleLines(value) {
  return String(value || '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<\/(p|div|li|h[1-6]|tr|td|th|section|article|ul|ol)>/gi, '\n')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\r/g, '\n')
    .split('\n')
    .map(line => decodeHtmlEntities(line).replace(/[ \t]+/g, ' ').trim())
    .filter(Boolean)
    .join('\n');
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
    if (record.algorithm !== null && record.algorithm !== undefined) pieces.push(`alg ${record.algorithm}`);
    if (record.keyTag !== null && record.keyTag !== undefined) pieces.push(`keytag ${record.keyTag}`);
    if (record.algorithmName) pieces.push(record.algorithmName);
    if (record.digestName) pieces.push(`digest ${record.digestName}`);
    else if (record.digestType !== null && record.digestType !== undefined) pieces.push(`digest ${record.digestType}`);
  } else if (kind === 'dnskey') {
    if (record.algorithm !== null && record.algorithm !== undefined) pieces.push(`alg ${record.algorithm}`);
    if (record.flags !== null && record.flags !== undefined) pieces.push(`flags ${record.flags}`);
    if (record.algorithmName) pieces.push(record.algorithmName);
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
  const algorithmRank = record => {
    const algo = Number(record?.algorithm);
    const name = String(record?.algorithmName || '').toUpperCase();
    if (algo === 8 || algo === 13 || /ECDSA\/P256\/SHA-256|ECDSA\/P384\/SHA-384/i.test(name)) return 0;
    if (/SHA-1|DSA|RSA\/SHA-1/i.test(name)) return 2;
    return 1;
  };
  const sortByPriority = records => [...records].sort((left, right) => {
    const diff = algorithmRank(left) - algorithmRank(right);
    if (diff) return diff;
    return String(left?.algorithm || left?.algorithmName || '').localeCompare(String(right?.algorithm || right?.algorithmName || ''));
  });
  const dsRecordsSorted = sortByPriority(dsRecords);
  const dnskeyRecordsSorted = sortByPriority(dnskeyRecords);
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
      items: dsRecordsSorted.map(record => ({
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
      items: dnskeyRecordsSorted.map(record => ({
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
    const dsSummary = dsRecordsSorted.map(record => formatDnssecRecordSummary(record, 'ds')).filter(Boolean);
    summaryLines.push(`DS: ${dsSummary.slice(0, 2).join(' | ')}${dsSummary.length > 2 ? ` · +${dsSummary.length - 2} más` : ''}`);
  }
  if (dnskeyRecords.length) {
    const dnskeySummary = dnskeyRecordsSorted.map(record => formatDnssecRecordSummary(record, 'dnskey')).filter(Boolean);
    summaryLines.push(`DNSKEY: ${dnskeySummary.slice(0, 2).join(' | ')}${dnskeySummary.length > 2 ? ` · +${dnskeySummary.length - 2} más` : ''}`);
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
  let noticeSections = [];
  if (jsUrl) {
    const jsBody = await fetchText(jsUrl, { timeout: 20000 }).catch(() => null);
    if (jsBody) {
      const noticesMatch = jsBody.match(/var notices = (\{[\s\S]*?\});\s*if \(noticesElement\.nodeType != 1\)/);
      if (noticesMatch) {
        try {
          notices = JSON.parse(noticesMatch[1]);
          noticeSections = extractDnsvizNoticeSections(notices);
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
    noticeSections,
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
      label: 'Info no disponible',
      notes: ['Info no disponible.']
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

function buildPulseCountryFromSnapshot(countryCode, html, sourceUrl) {
  const code = String(countryCode || '').trim().toUpperCase();
  const dnssecCoverage = extractPulseMetricAlias(html, ['Cobertura de DNSSEC', 'DNSSEC coverage']);
  const dnssecAdoption = extractPulseMetricAlias(html, ['Adopción de DNSSEC', 'Adoption of DNSSEC']);
  const ipv6Adoption = extractPulseMetricAlias(html, ['Adopción de IPv6', 'Adoption of IPv6']);
  const internetPenetration = extractPulseMetricAlias(html, ['Penetración de Internet', 'Internet penetration']);
  const downloadSpeed = extractPulseMetricAlias(html, ['Velocidad de descarga promedio', 'Average download speed']);
  const internetCost = extractPulseMetricAlias(html, ['Costo promedio de Internet', 'Average cost of Internet']);
  const mobileCoverage = extractPulseMetricAlias(html, ['Cobertura móvil 4G y 5G', 'Mobile 4G and 5G coverage']);
  const activeNetworks = extractPulseMetricAlias(html, ['Redes activas', 'Active networks']);
  const internationalConnectivity = extractPulseMetricAlias(html, ['Conexiones internacionales', 'International connections']);
  const dataCenters = extractPulseMetricAlias(html, ['Centros de datos', 'Data centers']);
  const ixp = extractPulseMetricAlias(html, ['Puntos de intercambio de Internet (IXP)', 'Internet exchange points (IXP)']);
  const localCaching = extractPulseMetricAlias(html, ['Contenido almacenado en caché local', 'Locally cached content']);
  const domainUse = extractPulseMetricAlias(html, ['Uso de dominios a nivel del país', 'Country-level domain use']);
  const resilienceScore = extractPulseMetricAlias(html, ['Índice de resiliencia de Internet', 'Internet Resilience Score']);
  const roaItems = extractPulseListMetricsAlias(html, ['ROA']);
  const rov = extractPulseListMetricsAlias(html, ['ROV'])[0] || null;
  const value = {
    available: Boolean(html),
    hardcoded: true,
    country: code,
    sourceUrl,
    dnssecCoverage,
    dnssecAdoption,
    ipv6Adoption,
    internetPenetration,
    downloadSpeed,
    internetCost,
    mobileCoverage,
    activeNetworks,
    internationalConnectivity,
    dataCenters,
    ixp,
    localCaching,
    domainUse,
    resilienceScore,
    roaItems,
    rov,
    reportHighlights: [],
    reportLines: [],
    displayCards: null,
    notes: []
  };
  if (dnssecCoverage?.value) value.notes.push(`DNSSEC coverage ${dnssecCoverage.value}`);
  if (dnssecAdoption?.value) value.notes.push(`DNSSEC adoption ${dnssecAdoption.value}`);
  if (ipv6Adoption?.value) value.notes.push(`IPv6 adoption ${ipv6Adoption.value}`);
  if (internetPenetration?.value) value.notes.push(`Internet penetration ${internetPenetration.value}`);
  if (downloadSpeed?.value) value.notes.push(`Average download speed ${downloadSpeed.value}`);
  if (internetCost?.value) value.notes.push(`Internet cost ${internetCost.value}`);
  if (mobileCoverage?.value) value.notes.push(`Mobile coverage ${mobileCoverage.value}`);
  if (activeNetworks?.value) value.notes.push(`Active networks ${activeNetworks.value}`);
  if (internationalConnectivity?.value) value.notes.push(`International connectivity ${internationalConnectivity.value}`);
  if (dataCenters?.value) value.notes.push(`Data centers ${dataCenters.value}`);
  if (ixp?.value) value.notes.push(`IXP ${ixp.value}`);
  if (localCaching?.value) value.notes.push(`Local caching ${localCaching.value}`);
  if (resilienceScore?.value) value.notes.push(`Internet resilience score ${resilienceScore.value}`);
  if (
    value.available &&
    !dnssecCoverage?.value &&
    !dnssecAdoption?.value &&
    !ipv6Adoption?.value &&
    !internetPenetration?.value &&
    !downloadSpeed?.value &&
    !internetCost?.value &&
    !mobileCoverage?.value &&
    !activeNetworks?.value &&
    !internationalConnectivity?.value &&
    !dataCenters?.value &&
    !ixp?.value &&
    !localCaching?.value &&
    !domainUse?.value &&
    !resilienceScore?.value &&
    !(Array.isArray(roaItems) && roaItems.length) &&
    !rov
  ) {
    value.notes.push('Snapshot local disponible, pero no se pudieron extraer métricas visibles.');
  }
  if (value.available && (dnssecCoverage?.value || dnssecAdoption?.value || ipv6Adoption?.value || domainUse?.value || resilienceScore?.value)) {
    value.notes.push('Métricas Pulse extraídas desde snapshot HTML local.');
  }
  value.displayCards = buildPulseDisplayCards(htmlToVisibleText(html), [], value);
  return value;
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

function extractPulseMetricFromText(html, title) {
  const text = htmlToVisibleLines(html);
  if (!text) return null;
  const lines = text
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean);
  const titleIndex = lines.findIndex(line => new RegExp(`^${escapeRegExp(title)}$`, 'i').test(line));
  if (titleIndex < 0) return null;
  const window = lines.slice(titleIndex + 1, titleIndex + 14);
  const numericLines = window.filter(line => {
    const normalized = String(line || '').trim();
    return (
      /^<\s*\d+(?:[.,]\d+)?%?$/.test(normalized) ||
      /^\d[\d.,\s]*%$/.test(normalized) ||
      /^\d[\d.,\s]*\s*(?:Mbps|Gbps|Kbps|ms)\b/i.test(normalized) ||
      /^\d+\s*\/\s*\d+$/.test(normalized) ||
      (/^\d[\d\s.,]*$/.test(normalized) && !/^\d{4}$/.test(normalized))
    );
  });
  const value = numericLines[0] || window.find(line => /\d/.test(line)) || null;
  const averageLabelIndex = window.findIndex(line => /average/i.test(line));
  const average = averageLabelIndex >= 0
    ? (window.slice(averageLabelIndex + 1).find(line => /\d/.test(line)) || null)
    : (numericLines[1] || null);
  const label = window.find(line => /[A-Za-z]/.test(line) && !/average/i.test(line) && !line.includes(value || '')) || null;
  return {
    value: value ? decodeHtmlEntities(value) : null,
    average: average ? decodeHtmlEntities(average) : null,
    label: label ? decodeHtmlEntities(label) : null
  };
}

function extractPulseMetric(html, title) {
  const block = extractPulseSection(html, title);
  if (block) {
    const primary = block.match(/<div class="primary">([\s\S]*?)<\/div>/i)?.[1] || '';
    const secondary = block.match(/<div class="secondary">([\s\S]*?)<\/div>/i)?.[1] || '';
    const label = block.match(/<div class="label">([\s\S]*?)<\/div>/i)?.[1] || '';
    const value = decodeHtmlEntities(primary);
    const average = decodeHtmlEntities(secondary);
    const labelValue = decodeHtmlEntities(label);
    if (value || average || labelValue) {
      return { value, average, label: labelValue };
    }
  }
  return extractPulseMetricFromText(html, title);
}

function extractPulseListMetrics(html, title) {
  const block = extractPulseSection(html, title);
  if (block) {
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
    if (items.length) return items;
  }
  const text = htmlToVisibleLines(html);
  if (!text) return [];
  const lines = text
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean);
  const titleIndex = lines.findIndex(line => new RegExp(`^${escapeRegExp(title)}$`, 'i').test(line));
  if (titleIndex < 0) return [];
  const window = lines.slice(titleIndex + 1, titleIndex + 24);
  const items = [];
  let current = null;
  for (const line of window) {
    if (!line) continue;
    if (/^(ROA|ROV)\b/i.test(line) && current) {
      items.push(current);
      current = { value: '', label: line };
      continue;
    }
    if (!current) {
      current = { value: '', label: '' };
    }
    if (!current.value && /\d/.test(line)) {
      current.value = line;
      continue;
    }
    if (!current.label && /[A-Za-z]/.test(line) && !/average/i.test(line)) {
      current.label = line;
      continue;
    }
    if (current.value && current.label) {
      items.push(current);
      current = null;
    }
  }
  if (current && (current.value || current.label)) items.push(current);
  return items.filter(item => item.value || item.label).slice(0, 8);
}

function extractPulseMetricAlias(html, titles) {
  const list = Array.isArray(titles) ? titles : [titles];
  for (const title of list) {
    const value = extractPulseMetric(html, title);
    if (value?.value || value?.average || value?.label) return value;
  }
  return null;
}

function extractPulseListMetricsAlias(html, titles) {
  const list = Array.isArray(titles) ? titles : [titles];
  for (const title of list) {
    const value = extractPulseListMetrics(html, title);
    if (value?.length) return value;
  }
  return [];
}

function mergePulseCountryMetrics(target, source) {
  if (!target || !source) return target;
  const keys = [
    'dnssecCoverage',
    'dnssecAdoption',
    'ipv6Adoption',
    'internetPenetration',
    'downloadSpeed',
    'internetCost',
    'mobileCoverage',
    'activeNetworks',
    'internationalConnectivity',
    'dataCenters',
    'ixp',
    'localCaching',
    'domainUse',
    'resilienceScore',
    'displayCards',
    'roaItems',
    'rov'
  ];
  keys.forEach(key => {
    const value = source[key];
    if (value === undefined || value === null) return;
    if (key === 'roaItems') {
      if (!Array.isArray(target.roaItems) || !target.roaItems.length) {
        target.roaItems = Array.isArray(value) ? value.slice() : [];
      }
      return;
    }
    if (key === 'rov') {
      if (!target.rov) target.rov = value;
      return;
    }
    if (!target[key] || (!target[key].value && !target[key].label && !target[key].average)) {
      target[key] = value;
    }
  });
  return target;
}

function makePulseCard(label, value, note, tone = 'info') {
  if (value === undefined || value === null || value === '') return null;
  return {
    label,
    value: String(value),
    note: note ? String(note) : '',
    tone
  };
}

function buildPulseDisplayCards(reportText, reportHighlights, fields = {}) {
  const text = String(reportText || '');
  const joinedHighlights = Array.isArray(reportHighlights) ? reportHighlights.join(' · ') : '';
  const cards = {
    overview: [],
    security: [],
    universalidad: [],
    accesibilidad: []
  };
  const add = (group, label, value, note, tone = 'info') => {
    const card = makePulseCard(label, value, note, tone);
    if (card) cards[group].push(card);
  };

  const datacenterMatch = joinedHighlights.match(/hay\s+([\d.,\s]+)\s+centros de datos y hay\s+([\d.,\s]+)\s+IXP activos/i);
  if (datacenterMatch) {
    add('overview', 'Centros de datos', datacenterMatch[1].trim(), `${datacenterMatch[2].trim()} IXP activos`, 'ok');
  }
  const populationMatch = joinedHighlights.match(/población de [^0-9]*?([\d][\d.,\s]+)/i);
  if (populationMatch) {
    add('overview', 'Población', populationMatch[1].trim(), 'Dato destacado del reporte', 'info');
  }
  const internetUsersMatch = joinedHighlights.match(/Aproximadamente\s+(\d+)%\s+de la población es usuaria de Internet/i);
  if (internetUsersMatch) {
    add('overview', 'Uso de Internet', `${internetUsersMatch[1]}%`, 'Población usuaria de Internet', 'ok');
  }
  const cachingMatch = joinedHighlights.match(/se puede accede al\s+(\d+)%\s+en un servidor local o en caché/i);
  if (cachingMatch) {
    add('overview', 'Caché local', `${cachingMatch[1]}%`, 'Top 1000 sitios accesibles localmente', 'ok');
  }
  const cybersecurityMatch = text.match(/Índice de ciberseguridad global[\s\S]*?(\d+(?:[.,]\d+)?)\s*\/\s*100/i);
  if (cybersecurityMatch) {
    add('overview', 'Ciberseguridad', `${cybersecurityMatch[1]} / 100`, 'Índice de ciberseguridad global', 'warning');
  }
  const egovMatch = text.match(/Calificación de los servicios públicos digitales[\s\S]*?(\d+(?:[.,]\d+)?)/i);
  if (egovMatch) {
    add('overview', 'Servicios públicos digitales', egovMatch[1], 'Preparación del ecosistema de gobierno electrónico', 'info');
  }
  const marketMatch = text.match(/Competencia de mercado[\s\S]*?\n([A-Za-zÁÉÍÓÚÑñüÜ]+)\s*\n/i);
  if (marketMatch) {
    add('overview', 'Competencia de mercado', marketMatch[1].trim(), 'Evaluación cualitativa', 'info');
  }

  if (fields.dnssecCoverage?.value) {
    add('security', 'Cobertura DNSSEC', fields.dnssecCoverage.value, fields.dnssecCoverage.average ? `Promedio Américas ${fields.dnssecCoverage.average}` : fields.dnssecCoverage.label, fields.dnssecCoverage.value.includes('<') ? 'warning' : 'ok');
  }
  if (fields.dnssecAdoption?.value) {
    add('security', 'Adopción DNSSEC', fields.dnssecAdoption.value, fields.dnssecAdoption.average ? `Promedio Américas ${fields.dnssecAdoption.average}` : fields.dnssecAdoption.label, 'ok');
  }
  if (fields.roaItems?.length) {
    const roaIpv4 = fields.roaItems.find(item => /IPv4/i.test(String(item?.label || '')))?.value || null;
    const roaIpv6 = fields.roaItems.find(item => /IPv6/i.test(String(item?.label || '')))?.value || null;
    const roaValue = [roaIpv4, roaIpv6].filter(Boolean).join(' / ') || fields.roaItems.map(item => item.value).filter(Boolean).slice(0, 2).join(' / ');
    add('security', 'ROA', roaValue, 'Prefijos protegidos por RPKI', 'ok');
  }
  if (fields.rov?.value) {
    add('security', 'ROV', fields.rov.value, fields.rov.label || 'Validación de origen de rutas', 'ok');
  }
  if (fields.resilienceScore?.value) {
    add('security', 'Resiliencia', fields.resilienceScore.value, fields.resilienceScore.label || 'Índice general de resiliencia de Internet', 'info');
  }
  const routingMatch = text.match(/Incidentes de seguridad del enrutamiento[\s\S]*?(\d+)\s*incidentes/i);
  if (routingMatch) {
    add('security', 'Incidentes de enrutamiento', routingMatch[1], 'Observados en el último período visible', 'warning');
  }

  if (fields.ipv6Adoption?.value) {
    add('universalidad', 'IPv6', fields.ipv6Adoption.value, fields.ipv6Adoption.average ? `Promedio Américas ${fields.ipv6Adoption.average}` : fields.ipv6Adoption.label, 'ok');
  }
  if (fields.mobileCoverage?.value) {
    add('universalidad', 'Cobertura móvil 4G', fields.mobileCoverage.value, fields.mobileCoverage.label || 'Acceso a 4G', 'ok');
    if (fields.mobileCoverage.average) {
      add('universalidad', 'Cobertura móvil 5G', fields.mobileCoverage.average, 'Segundo valor visible en el reporte', 'warning');
    }
  }

  if (fields.internetPenetration?.value) {
    add('accesibilidad', 'Penetración de Internet', fields.internetPenetration.value, fields.internetPenetration.average ? `Promedio Américas ${fields.internetPenetration.average}` : fields.internetPenetration.label, 'ok');
  }
  if (fields.downloadSpeed?.value) {
    add('accesibilidad', 'Velocidad de descarga', fields.downloadSpeed.value, fields.downloadSpeed.average ? `Mobile ${fields.downloadSpeed.average}` : fields.downloadSpeed.label, 'info');
  }
  if (fields.internetCost?.value) {
    add('accesibilidad', 'Costo promedio', fields.internetCost.value, fields.internetCost.label || 'Porcentaje del ingreso promedio', 'ok');
  }
  if (fields.localCaching?.value) {
    add('accesibilidad', 'Caché local', fields.localCaching.value, fields.localCaching.average ? `Promedio Américas ${fields.localCaching.average}` : fields.localCaching.label, 'ok');
  }
  if (fields.dataCenters?.value) {
    add('accesibilidad', 'Centros de datos', fields.dataCenters.value, fields.dataCenters.label || 'Cantidad visible en el reporte', 'info');
  }
  if (fields.ixp?.value) {
    add('accesibilidad', 'IXP', fields.ixp.value, fields.ixp.average ? `Promedio Américas ${fields.ixp.average}` : fields.ixp.label, 'info');
  }
  if (fields.activeNetworks?.value) {
    add('accesibilidad', 'Redes activas', fields.activeNetworks.value, fields.activeNetworks.label || 'Infraestructura visible en el reporte', 'info');
  }
  if (fields.internationalConnectivity?.value) {
    add('accesibilidad', 'Conectividad internacional', fields.internationalConnectivity.value, fields.internationalConnectivity.label || 'Conexiones internacionales visibles', 'info');
  }
  if (fields.domainUse?.value) {
    add('accesibilidad', 'Uso de dominios', fields.domainUse.value, fields.domainUse.label || 'ccTLD registrado', 'info');
  }

  return cards;
}

function parsePulseHardcodedReport(countryCode, hardcodedReport, sourceUrl) {
  const code = String(countryCode || '').trim().toUpperCase();
  const reportHighlights = Array.isArray(hardcodedReport?.highlights) ? hardcodedReport.highlights.slice() : [];
  const reportLines = Array.isArray(hardcodedReport?.reportLines) ? hardcodedReport.reportLines.slice() : [];
  const reportText = [...reportHighlights, ...reportLines].join('\n');
  const value = {
    available: true,
    hardcoded: true,
    country: code,
    sourceUrl: hardcodedReport?.sourceUrl || sourceUrl,
    dnssecCoverage: extractPulseMetricFromText(reportText, 'Cobertura de DNSSEC'),
    dnssecAdoption: extractPulseMetricFromText(reportText, 'Adopción de DNSSEC'),
    ipv6Adoption: extractPulseMetricFromText(reportText, 'Adopción de IPv6'),
    internetPenetration: extractPulseMetricFromText(reportText, 'Penetración de Internet'),
    downloadSpeed: extractPulseMetricFromText(reportText, 'Velocidad de descarga promedio'),
    internetCost: extractPulseMetricFromText(reportText, 'Costo promedio de Internet'),
    mobileCoverage: extractPulseMetricFromText(reportText, 'Cobertura móvil 4G y 5G'),
    activeNetworks: extractPulseMetricFromText(reportText, 'Redes activas'),
    internationalConnectivity: extractPulseMetricFromText(reportText, 'Conexiones internacionales'),
    dataCenters: extractPulseMetricFromText(reportText, 'Centros de datos'),
    ixp: extractPulseMetricFromText(reportText, 'Puntos de intercambio de Internet (IXP)'),
    localCaching: extractPulseMetricFromText(reportText, 'Contenido almacenado en caché local'),
    domainUse: extractPulseMetricFromText(reportText, 'Uso de dominios a nivel del país'),
    resilienceScore: extractPulseMetricFromText(reportText, 'Índice de resiliencia de Internet'),
    roaItems: extractPulseListMetrics(reportText, 'ROA'),
    rov: extractPulseListMetrics(reportText, 'ROV')[0] || null,
    reportHighlights,
    reportLines,
    displayCards: null,
    notes: []
  };
  if (value.dnssecCoverage?.value) value.notes.push(`DNSSEC coverage ${value.dnssecCoverage.value}`);
  if (value.dnssecAdoption?.value) value.notes.push(`DNSSEC adoption ${value.dnssecAdoption.value}`);
  if (value.ipv6Adoption?.value) value.notes.push(`IPv6 adoption ${value.ipv6Adoption.value}`);
  if (value.internetPenetration?.value) value.notes.push(`Internet penetration ${value.internetPenetration.value}`);
  if (value.downloadSpeed?.value) value.notes.push(`Average download speed ${value.downloadSpeed.value}`);
  if (value.internetCost?.value) value.notes.push(`Internet cost ${value.internetCost.value}`);
  if (value.mobileCoverage?.value) value.notes.push(`Mobile coverage ${value.mobileCoverage.value}`);
  if (value.activeNetworks?.value) value.notes.push(`Active networks ${value.activeNetworks.value}`);
  if (value.internationalConnectivity?.value) value.notes.push(`International connectivity ${value.internationalConnectivity.value}`);
  if (value.dataCenters?.value) value.notes.push(`Data centers ${value.dataCenters.value}`);
  if (value.ixp?.value) value.notes.push(`IXP ${value.ixp.value}`);
  if (value.localCaching?.value) value.notes.push(`Local caching ${value.localCaching.value}`);
  if (value.domainUse?.value) value.notes.push(`Country-level domain use ${value.domainUse.value}`);
  if (value.resilienceScore?.value) value.notes.push(`Internet resilience score ${value.resilienceScore.value}`);
  if (value.roaItems.length) value.notes.push(`ROA entries ${value.roaItems.length}`);
  if (value.rov?.value) value.notes.push(`ROV ${value.rov.value}`);
  if (
    !value.dnssecCoverage?.value &&
    !value.dnssecAdoption?.value &&
    !value.ipv6Adoption?.value &&
    !value.internetPenetration?.value &&
    !value.downloadSpeed?.value &&
    !value.internetCost?.value &&
    !value.mobileCoverage?.value &&
    !value.activeNetworks?.value &&
    !value.internationalConnectivity?.value &&
    !value.dataCenters?.value &&
    !value.ixp?.value &&
    !value.localCaching?.value &&
    !value.domainUse?.value &&
    !value.resilienceScore?.value &&
    !value.roaItems.length &&
    !value.rov
  ) {
    value.notes.push('Snapshot local disponible, pero no se pudieron extraer métricas visibles.');
  }
  value.displayCards = buildPulseDisplayCards(reportText, reportHighlights, value);
  return value;
}

async function summarizePulseCountry(countryCode) {
  const code = String(countryCode || '').trim().toUpperCase();
  if (!code) {
    return {
      available: false,
      notes: ['Falta ccTLD para consultar Pulse.']
    };
  }
  const cached = cacheGet(pulseCache, `pulse:${code}`, 24 * 60 * 60 * 1000);
  if (cached) return cached;
  const sourceUrl = `https://pulse.internetsociety.org/es/reports/${encodeURIComponent(code.toLowerCase())}/`;
  const snapshotPath = path.join(PULSE_SNAPSHOT_DIR, `${code.toLowerCase()}.html`);
  const hardcodedReport = PULSE_HARDCODED_REPORTS[String(code).toLowerCase()] || null;
  const remoteEnabled = !['0', 'false', 'no'].includes(String(process.env.PULSE_REMOTE_FALLBACK || '1').trim().toLowerCase());
  const parsePulseHtml = html => {
    const value = buildPulseCountryFromSnapshot(code, html, sourceUrl);
    value.snapshotPath = snapshotPath;
    if (hardcodedReport) {
      const hardcodedValue = parsePulseHardcodedReport(code, hardcodedReport, sourceUrl);
      mergePulseCountryMetrics(value, hardcodedValue);
      value.hardcoded = false;
      value.reportHighlights = hardcodedValue.reportHighlights.slice();
      value.reportLines = hardcodedValue.reportLines.slice();
      value.notes.unshift(`Pulse duro local cargado para ${code}.`);
      value.notes = [...new Set(value.notes)];
    }
    return value;
  };

  const buildHardcodedOnly = () => {
    if (!hardcodedReport) return null;
    const value = parsePulseHardcodedReport(code, hardcodedReport, sourceUrl);
    value.notes.unshift(`Pulse duro local cargado para ${code}.`);
    return value;
  };

  if (remoteEnabled) {
    try {
      const html = await fetchText(sourceUrl, {
        timeout: 20000,
        headers: {
          'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
          'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'accept-language': 'es-ES,es;q=0.9,en;q=0.8'
        }
      });
      const value = parsePulseHtml(html);
      value.available = Boolean(html);
      value.hardcoded = false;
      value.notes.unshift('Pulse remoto recuperado desde el backend.');
      cacheSet(pulseCache, `pulse:${code}`, value);
      return value;
    } catch (remoteError) {
      const remoteFailure = errorMessage(remoteError);
      try {
        const html = await fs.readFile(snapshotPath, 'utf8');
        const value = parsePulseHtml(html);
        value.notes.unshift(`Fallback snapshot local: ${path.relative(__dirname, snapshotPath)}`);
        value.notes.unshift(`Pulse remoto no disponible: ${remoteFailure}`);
        cacheSet(pulseCache, `pulse:${code}`, value);
        return value;
      } catch (snapshotError) {
        const hardcodedOnly = buildHardcodedOnly();
        const value = hardcodedOnly || {
          available: false,
          hardcoded: false,
          country: code,
          sourceUrl,
          snapshotPath,
          error: errorMessage(snapshotError),
          notes: [
            `Pulse remoto no disponible: ${remoteFailure}`,
            'No existe snapshot local para este país.'
          ]
        };
        if (hardcodedOnly) {
          value.error = errorMessage(snapshotError);
          value.snapshotPath = snapshotPath;
        }
        cacheSet(pulseCache, `pulse:${code}`, value);
        return value;
      }
    }
  }

  try {
    const html = await fs.readFile(snapshotPath, 'utf8');
    const value = parsePulseHtml(html);
    value.notes.unshift(`Snapshot local: ${path.relative(__dirname, snapshotPath)}`);
    cacheSet(pulseCache, `pulse:${code}`, value);
    return value;
  } catch (e) {
    const hardcodedOnly = buildHardcodedOnly();
    const value = hardcodedOnly || {
      available: false,
      hardcoded: false,
      country: code,
      sourceUrl,
      snapshotPath,
      error: errorMessage(e),
      notes: ['No existe snapshot local para este país.']
    };
    if (hardcodedOnly) {
      value.error = errorMessage(e);
      value.snapshotPath = snapshotPath;
    }
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

function normalizeDnsvizSectionLabel(label) {
  const value = String(label || '').trim();
  const map = {
    secure: 'Seguro',
    insecure: 'Inseguro',
    bogus: 'Inválido',
    warning: 'Advertencia',
    error: 'Error',
    non_existent: 'No existente',
    'non-existent': 'No existente',
    nonexistent: 'No existente',
    rrset: 'RRset',
    delegation: 'Delegación'
  };
  return map[value.toLowerCase()] || value
    .replace(/_/g, ' ')
    .replace(/\b([a-z])/g, (_, letter) => letter.toUpperCase())
    .trim();
}

function translateDnsvizSectionTitle(title) {
  const value = String(title || '').trim();
  const map = {
    'rrset status': 'Estado de RRset',
    'dnskey/ds/nsec status': 'Estado DNSKEY/DS/NSEC',
    'delegation status': 'Estado de delegación',
    notices: 'Avisos'
  };
  return map[value.toLowerCase()] || value;
}

function parseDnsvizNoticeEntry(entry) {
  const raw = String(entry || '').trim();
  if (!raw) {
    return { raw: '', text: '', algorithm: null, id: null };
  }
  const algIdMatch = raw.match(/\(alg(?:orithm)?\s*=?\s*(\d+),\s*id\s*=?\s*(\d+)\)/i);
  const algMatch = raw.match(/\balg(?:orithm)?\s*=?\s*(\d+)\b/i);
  const idMatch = raw.match(/\bid\s*=?\s*(\d+)\b/i);
  const text = raw
    .replace(/\(\s*alg(?:orithm)?\s*=?\s*\d+\s*,\s*id\s*=?\s*\d+\s*\)/i, '')
    .replace(/\(\s*alg(?:orithm)?\s*=?\s*\d+\s*\)/i, '')
    .replace(/\s+/g, ' ')
    .trim();
  return {
    raw,
    text: text || raw,
    algorithm: algIdMatch ? Number(algIdMatch[1]) : (algMatch ? Number(algMatch[1]) : null),
    id: algIdMatch ? Number(algIdMatch[2]) : (idMatch ? Number(idMatch[1]) : null)
  };
}

function extractDnsvizNoticeSections(notices) {
  const topLevel = notices && typeof notices === 'object' ? notices : {};
  const sections = [];

  Object.entries(topLevel).forEach(([sectionTitle, sectionValue]) => {
    if (sectionTitle === 'notices' || !sectionValue || typeof sectionValue !== 'object') return;
    const groups = Object.entries(sectionValue)
      .map(([groupName, items]) => {
        const list = Array.isArray(items) ? items : [];
        if (!list.length) return null;
        return {
          label: normalizeDnsvizSectionLabel(groupName),
          tone: String(groupName || '').toLowerCase().includes('warning')
            ? 'warning'
            : (String(groupName || '').toLowerCase().includes('error') ? 'error' : 'info'),
          count: list.length,
          items: list.map(parseDnsvizNoticeEntry)
        };
      })
      .filter(Boolean);
    if (groups.length) sections.push({ title: translateDnsvizSectionTitle(sectionTitle), groups });
  });

  const noticeBucket = topLevel.notices && typeof topLevel.notices === 'object' ? topLevel.notices : {};
  const noticeGroups = [];
  if (Array.isArray(noticeBucket.warnings) && noticeBucket.warnings.length) {
    noticeGroups.push({
      label: 'Advertencias',
      tone: 'warning',
      count: noticeBucket.warnings.length,
      items: noticeBucket.warnings.map(parseDnsvizNoticeEntry)
    });
  }
  if (Array.isArray(noticeBucket.errors) && noticeBucket.errors.length) {
    noticeGroups.push({
      label: 'Errores',
      tone: 'error',
      count: noticeBucket.errors.length,
      items: noticeBucket.errors.map(parseDnsvizNoticeEntry)
    });
  }
  if (noticeGroups.length) {
    sections.push({ title: 'Avisos', groups: noticeGroups });
  }

  return sections;
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
    const summary = await summarizeRpkIps([...v4, ...v6]);
    if (!summary.results.length) return sendJSON(res, 200, { domain, error: 'Sin direcciones IP' });
    sendJSON(res, 200, { domain, results: summary.results, valid: Boolean(summary.valid) });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function summarizeRpkIps(ips) {
  const cleanIps = [...new Set((ips || []).map(ip => String(ip || '').trim()).filter(Boolean))];
  if (!cleanIps.length) {
    return { status: 'info', valid: false, results: [] };
  }
  const results = await Promise.all(
    cleanIps.map(async ip => {
      const details = await rpkiValidity(ip);
      return { ip, ...details };
    })
  );
  const anyInvalid = results.some(r => String(r.state || '').startsWith('invalid'));
  const anyValid = results.some(r => r.state === 'valid');
  const allValid = results.length && results.every(r => r.state === 'valid');
  return {
    status: anyInvalid ? 'fail' : (allValid ? 'ok' : (anyValid ? 'warning' : 'info')),
    valid: Boolean(allValid),
    results
  };
}

async function collectMxIps(domain) {
  const mx = await resolveMxRecords(domain, 'local').catch(() => []);
  const ips = (await Promise.all(
    mx.map(async record => {
      const { exchange } = normalizeMxRecord(record);
      if (!exchange) return [];
      const { v4, v6 } = await resolveAddresses(exchange).catch(() => ({ v4: [], v6: [] }));
      return [...v4, ...v6];
    })
  )).flat();
  return { mx, ips };
}

function writeSseEvent(res, event, data) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

async function buildMiniData(domain, emitProgress = () => {}) {
  domain = normalizeDomain(domain);
  const pulseCountry = detectCcTld(domain);
  const pulseCountryCode = pulseCountry ? pulseCountry.toUpperCase() : null;
  const pulseEligible = Boolean(pulseCountry);
  const emit = typeof emitProgress === 'function' ? emitProgress : () => {};
  const progress = (stage, status, message, extra = {}) => {
    emit({
      stage,
      status,
      message,
      ...extra
    });
  };

  progress('start', 'info', `Iniciando mini para ${domain}.`);

  const ipv4Promise = resolveDnsValue(domain, 'A', 'local')
    .then(records => {
      progress(
        'ipv4',
        records.length ? 'ok' : 'warning',
        records.length ? `IPv4 listo: ${records.length} registro(s) A.` : 'IPv4 sin registros A.'
      );
      return records;
    })
    .catch(error => {
      progress('ipv4', 'fail', `IPv4 sin respuesta: ${errorMessage(error)}`);
      return [];
    });

  const dnssecPromise = dnssecGoogle(domain, 'local')
    .then(raw => {
      const assessment = buildDnssecAssessment(raw || {});
      progress(
        'dnssec',
        assessment.valid ? 'ok' : 'warning',
        assessment.valid ? 'DNSSEC validado.' : 'DNSSEC parcial o ausente.'
      );
      return raw || {};
    })
    .catch(error => {
      progress('dnssec', 'fail', `DNSSEC sin respuesta: ${errorMessage(error)}`);
      return {};
    });

  const domainRpkiPromise = resolveAddresses(domain)
    .then(value => summarizeRpkIps([...(value.v4 || []), ...(value.v6 || [])]))
    .then(summary => {
      progress(
        'rpki-domain',
        summary.status || 'info',
        summary.valid ? 'RPKI del dominio validado.' : 'RPKI del dominio parcial o sin cobertura.'
      );
      return summary;
    })
    .catch(error => {
      progress('rpki-domain', 'fail', `RPKI del dominio sin respuesta: ${errorMessage(error)}`);
      return { status: 'info', valid: false, results: [] };
    });

  const mxInfoPromise = collectMxIps(domain)
    .then(info => {
      progress(
        'mx',
        info.mx.length ? 'ok' : 'info',
        info.mx.length ? `MX listos: ${info.mx.length} servidor(es).` : 'No se detectaron MX visibles.'
      );
      return info;
    })
    .catch(error => {
      progress('mx', 'fail', `MX sin respuesta: ${errorMessage(error)}`);
      return { mx: [], ips: [] };
    });

  const dnsvizPromise = resolveDnsvizMeta(domain)
    .then(dnsviz => {
      progress(
        'dnsviz',
        dnsviz.available ? 'ok' : 'info',
        dnsviz.available ? 'DNSViz listo.' : 'DNSViz no disponible todavía.'
      );
      return dnsviz;
    })
    .catch(error => {
      progress('dnsviz', 'info', `DNSViz sin respuesta: ${errorMessage(error)}`);
      return {
        domain,
        pageUrl: `https://dnsviz.net/d/${domain}/dnssec/`,
        svgUrl: '',
        observations: [],
        warningCount: 0,
        errorCount: 0,
        warnings: [],
        errors: [],
        available: false
      };
    });

  const headersPromise = summarizeHttpHeaders(domain)
    .then(headers => {
      progress(
        'headers',
        headers.https ? 'ok' : 'warning',
        headers.https ? 'Cabeceras HTTP listas.' : 'Cabeceras HTTP incompletas.'
      );
      return headers;
    })
    .catch(error => {
      progress('headers', 'fail', `Cabeceras HTTP sin respuesta: ${errorMessage(error)}`);
      return {
        domain,
        error: errorMessage(error),
        https: false,
        redirect: false,
        hsts: false,
        hstsMaxAge: null,
        hstsStrict: false,
        csp: false,
        xfo: false,
        xcto: false,
        referrer: false,
        permissions: false,
        xxss: false,
        compression: false,
        server: '',
        headers: {},
        findings: []
      };
    });

  const ipv6Promise = resolveDnsValue(domain, 'AAAA', 'local')
    .then(records => {
      progress(
        'ipv6',
        records.length ? 'ok' : 'warning',
        records.length ? `IPv6 listo: ${records.length} registro(s) AAAA.` : 'IPv6 sin registros AAAA.'
      );
      return records;
    })
    .catch(error => {
      progress('ipv6', 'fail', `IPv6 sin respuesta: ${errorMessage(error)}`);
      return [];
    });

  const mailIpv6Promise = collectMxIps(domain)
    .then(info => (info.ips || []).filter(ip => String(ip || '').includes(':')))
    .then(records => {
      progress(
        'mailipv6',
        records.length ? 'ok' : 'warning',
        records.length ? `IPv6 en MX listo: ${records.length} dirección(es).` : 'MX sin IPv6 visible.'
      );
      return records;
    })
    .catch(error => {
      progress('mailipv6', 'fail', `IPv6 en MX sin respuesta: ${errorMessage(error)}`);
      return [];
    });

  const mxIpv4Promise = collectMxIps(domain)
    .then(info => (info.ips || []).filter(ip => String(ip || '').includes('.') && !String(ip || '').includes(':')))
    .then(records => {
      progress(
        'mailipv4',
        records.length ? 'ok' : 'warning',
        records.length ? `IPv4 en MX listo: ${records.length} dirección(es).` : 'MX sin IPv4 visible.'
      );
      return records;
    })
    .catch(error => {
      progress('mailipv4', 'fail', `IPv4 en MX sin respuesta: ${errorMessage(error)}`);
      return [];
    });

  const spfPromise = fetchLocalJson(`/spf/${encodeURIComponent(domain)}`)
    .then(data => {
      progress('spf', data?.supported || data?.present ? 'ok' : 'warning', data?.present ? 'SPF listo.' : 'SPF ausente.');
      return data || {};
    })
    .catch(error => {
      progress('spf', 'fail', `SPF sin respuesta: ${errorMessage(error)}`);
      return {};
    });

  const dmarcPromise = fetchLocalJson(`/dmarc/${encodeURIComponent(domain)}`)
    .then(data => {
      progress('dmarc', data?.present ? 'ok' : 'warning', data?.present ? 'DMARC listo.' : 'DMARC ausente.');
      return data || {};
    })
    .catch(error => {
      progress('dmarc', 'fail', `DMARC sin respuesta: ${errorMessage(error)}`);
      return {};
    });

  const dkimPromise = fetchLocalJson(`/dkim/${encodeURIComponent(domain)}?selector=support`)
    .then(data => {
      progress('dkim', data?.supported ? 'ok' : 'warning', data?.supported ? 'DKIM listo.' : 'DKIM no detectado.');
      return data || {};
    })
    .catch(error => {
      progress('dkim', 'fail', `DKIM sin respuesta: ${errorMessage(error)}`);
      return {};
    });

  const starttlsPromise = fetchLocalJson(`/starttls/${encodeURIComponent(domain)}`)
    .then(data => {
      progress('starttls', data?.supported ? 'ok' : 'warning', data?.supported ? 'STARTTLS listo.' : 'STARTTLS no detectado.');
      return data || {};
    })
    .catch(error => {
      progress('starttls', 'fail', `STARTTLS sin respuesta: ${errorMessage(error)}`);
      return {};
    });

  const tlsPromise = fetchLocalJson(`/tlsinfo/${encodeURIComponent(domain)}`)
    .then(data => {
      progress('tls', data?.error ? 'warning' : 'ok', data?.error ? 'TLS con observaciones.' : 'TLS listo.');
      return data || {};
    })
    .catch(error => {
      progress('tls', 'fail', `TLS sin respuesta: ${errorMessage(error)}`);
      return {};
    });

  const w3cPromise = fetchLocalJson(`/w3c/${encodeURIComponent(domain)}`)
    .then(data => {
      progress('w3c', data?.errors || data?.warnings ? 'warning' : 'ok', data?.errors || data?.warnings ? 'W3C con hallazgos.' : 'W3C listo.');
      return data || {};
    })
    .catch(error => {
      progress('w3c', 'fail', `W3C sin respuesta: ${errorMessage(error)}`);
      return {};
    });

  const wifiPromise = summarizeWifiCountry(domain)
    .then(data => {
      progress('wifi', data?.status || 'info', data?.label ? `6 GHz listo: ${data.label}.` : '6 GHz sin dato.');
      return data || {};
    })
    .catch(error => {
      progress('wifi', 'info', `6 GHz sin respuesta: ${errorMessage(error)}`);
      return { status: 'pending', label: 'Sin dato', notes: [] };
    });

  const emailConfigPromise = fetchLocalJson(`/emailconfig/${encodeURIComponent(domain)}`)
    .then(data => {
      progress('emailconfig', data?.error ? 'warning' : 'ok', data?.error ? 'Correo con observaciones.' : 'Correo configurado.');
      return data || {};
    })
    .catch(error => {
      progress('emailconfig', 'fail', `Correo sin respuesta: ${errorMessage(error)}`);
      return {};
    });

  const pulsePromise = pulseEligible
    ? getCachedCctldPulse(pulseCountryCode, 'local')
        .then(async pulse => {
          if (pulse) {
            progress(
              'pulse',
              pulse.available ? 'ok' : 'info',
              pulse.available
                ? `Pulse ${String(pulseCountryCode).toUpperCase()} reutilizado desde el reporte ccTLD.`
                : `Pulse ${String(pulseCountryCode).toUpperCase()} no disponible en el reporte ccTLD.`
            );
            return pulse;
          }
          progress(
            'pulse',
            'info',
            `Pulse ${String(pulseCountryCode).toUpperCase()} no estaba en caché; se actualizó desde el reporte ccTLD.`
          );
          const refreshedPulse = await getCachedCctldPulse(pulseCountryCode, 'local');
          return refreshedPulse || {
            available: false,
            country: pulseCountryCode,
            sourceUrl: `https://pulse.internetsociety.org/en/reports/${encodeURIComponent(pulseCountryCode)}/`,
            notes: ['No se pudo recuperar Pulse.']
          };
        })
        .catch(error => {
          progress('pulse', 'info', `Pulse sin respuesta: ${errorMessage(error)}`);
          return {
            available: false,
            sourceUrl: `https://pulse.internetsociety.org/en/reports/${encodeURIComponent(pulseCountryCode)}/`,
            notes: ['No se pudo recuperar Pulse.']
          };
        })
    : Promise.resolve({
        available: false,
        eligible: false,
        sourceUrl: null,
        notes: ['Dominio sin ccTLD; Pulse no aplica.']
      });

  const [ipv4Records, ipv6Records, dnssecRaw, domainRpki, mxInfo, dnsviz, pulse, headers, mailIpv6Records, mailIpv4Records, spf, dmarc, dkim, starttls, tls, w3c, wifi, emailConfig] = await Promise.all([
    ipv4Promise,
    ipv6Promise,
    dnssecPromise,
    domainRpkiPromise,
    mxInfoPromise,
    dnsvizPromise,
    pulsePromise,
    headersPromise,
    mailIpv6Promise,
    mxIpv4Promise,
    spfPromise,
    dmarcPromise,
    dkimPromise,
    starttlsPromise,
    tlsPromise,
    w3cPromise,
    wifiPromise,
    emailConfigPromise
  ]);

  const assessment = buildDnssecAssessment(dnssecRaw || {});
  const dsRecords = Array.isArray(dnssecRaw?.dsRecords) ? dnssecRaw.dsRecords : [];
  const dnskeyRecords = Array.isArray(dnssecRaw?.dnskeyRecords) ? dnssecRaw.dnskeyRecords : [];
  const dnssecAlgorithms = [
    ...dsRecords.map(record => {
      const summary = parseDnssecDsRecord(record);
      if (!summary) return null;
      const algorithm = Number.isFinite(summary.algorithm) ? `${summary.algorithm}` : 'desconocido';
      const name = summary.algorithmName ? ` (${summary.algorithmName})` : '';
      const digest = summary.digestName ? ` · ${summary.digestName}` : '';
      const keyTag = summary.keyTag !== null ? ` · keytag ${summary.keyTag}` : '';
      return `DS ${algorithm}${name}${keyTag}${digest}`;
    }),
    ...dnskeyRecords.map(record => {
      const summary = parseDnssecDnskeyRecord(record);
      if (!summary) return null;
      const algorithm = Number.isFinite(summary.algorithm) ? `${summary.algorithm}` : 'desconocido';
      const name = summary.algorithmName ? ` (${summary.algorithmName})` : '';
      const flags = summary.flags !== null ? ` · flags ${summary.flags}` : '';
      return `DNSKEY ${algorithm}${name}${flags}`;
    })
  ].filter(Boolean);
  const dnssecLines = [
    assessment.valid ? 'DNSSEC válido.' : 'DNSSEC no validado.',
    ...assessment.summaryLines.slice(0, 3)
  ].filter(Boolean);

  const mailRpkiPromise = summarizeRpkIps(mxInfo.ips || [])
    .then(summary => {
      progress(
        'rpki-mail',
        summary.status || 'info',
        summary.valid ? 'RPKI del correo validado.' : 'RPKI del correo parcial o sin cobertura.'
      );
      return summary;
    })
    .catch(error => {
      progress('rpki-mail', 'fail', `RPKI del correo sin respuesta: ${errorMessage(error)}`);
      return { status: 'info', valid: false, results: [] };
    });

  const smtpResultsPromise = Promise.all(
    (mxInfo.mx || []).map(async record => {
      const { exchange } = normalizeMxRecord(record);
      if (!exchange) return null;
      const result = await checkSmtpUtf8(exchange).catch(error => {
        progress('smtp', 'warning', `${exchange}: ${errorMessage(error)}`);
        return { status: 'connection-error', port: 25 };
      });
      progress(
        `smtp:${exchange}`,
        result.status === 'supports' ? 'ok' : (result.status === 'no' ? 'fail' : 'warning'),
        `${exchange}:${result.port || 25} → ${result.status}`
      );
      return {
        server: exchange,
        status: result.status,
        port: result.port || 25
      };
    })
  );

  const [mailRpki, smtpResultsRaw] = await Promise.all([mailRpkiPromise, smtpResultsPromise]);
  const smtpResults = smtpResultsRaw.filter(Boolean);
  const smtpSupports = smtpResults.some(item => item.status === 'supports');

  progress('done', 'ok', `Mini completado para ${domain}.`);

  return {
    domain,
    country: pulseEligible ? pulseCountryCode : null,
    ipv4: {
      status: ipv4Records.length ? 'ok' : 'fail',
      present: ipv4Records.length > 0,
      records: ipv4Records
    },
    ipv6: {
      status: ipv6Records.length ? 'ok' : 'fail',
      present: ipv6Records.length > 0,
      records: ipv6Records
    },
    dnssec: {
      status: assessment.status || (assessment.valid ? 'ok' : 'fail'),
      valid: assessment.valid,
      lines: dnssecLines,
      algorithms: dnssecAlgorithms.slice(0, 6)
    },
    rpki: {
      status: domainRpki.status === 'ok' && mailRpki.status === 'ok'
        ? 'ok'
        : (domainRpki.status === 'fail' || mailRpki.status === 'fail' ? 'fail' : 'info'),
      domain: domainRpki,
      mail: mailRpki
    },
    smtputf8: {
      status: smtpSupports ? 'ok' : (smtpResults.length ? 'fail' : 'info'),
      results: smtpResults.map(item => ({
        server: item.server,
        status: item.status,
        port: item.port || 25
      }))
    },
    dnsviz: {
      status: dnsviz.available ? 'ok' : 'info',
      ...dnsviz
    },
    mailipv6: {
      status: mailIpv6Records.length ? 'ok' : 'fail',
      present: mailIpv6Records.length > 0,
      records: mailIpv6Records
    },
    mailipv4: {
      status: mailIpv4Records.length ? 'ok' : 'fail',
      present: mailIpv4Records.length > 0,
      records: mailIpv4Records
    },
    email: {
      spf,
      dmarc,
      dkim,
      starttls,
      config: emailConfig
    },
    tls,
    w3c,
    wifi,
    headers,
    pulse: {
      available: Boolean(pulse.available),
      eligible: pulseEligible,
      country: pulseEligible ? pulseCountryCode : null,
      sourceUrl: pulse.sourceUrl || null,
      dnssecCoverage: pulse.dnssecCoverage || null,
      dnssecAdoption: pulse.dnssecAdoption || null,
      ipv6Adoption: pulse.ipv6Adoption || null,
      domainUse: pulse.domainUse || null,
      resilienceScore: pulse.resilienceScore || null,
      roaItems: Array.isArray(pulse.roaItems) ? pulse.roaItems : [],
      rov: pulse.rov || null,
      notes: Array.isArray(pulse.notes) ? pulse.notes : []
    },
    roas: Array.isArray(pulse.roaItems) ? pulse.roaItems : [],
    rov: pulse.rov || null
  };
}

async function handleMiniData(domain, res) {
  try {
    console.log(`[mini] data start domain=${normalizeDomain(domain)}`);
    const data = await buildMiniData(domain);
    console.log(`[mini] data ok domain=${normalizeDomain(domain)}`);
    sendJSON(res, 200, data);
  } catch (e) {
    console.log(`[mini] data error domain=${normalizeDomain(domain)} - ${errorMessage(e)}`);
    sendJSON(res, 200, { domain: normalizeDomain(domain), country: detectCcTld(domain), error: errorMessage(e) });
  }
}

async function handleMiniStream(domain, res) {
  const cleanDomain = normalizeDomain(domain);
  console.log(`[mini] stream start domain=${cleanDomain}`);
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.write(': mini stream ready\n\n');
  let closed = false;
  res.on('close', () => {
    closed = true;
  });
  const emit = payload => {
    if (closed) return;
    writeSseEvent(res, 'progress', payload);
  };
  try {
    const data = await buildMiniData(cleanDomain, emit);
    if (!closed) writeSseEvent(res, 'result', data);
    console.log(`[mini] stream result domain=${cleanDomain}`);
  } catch (e) {
    console.log(`[mini] stream error domain=${cleanDomain} - ${errorMessage(e)}`);
    if (!closed) {
      writeSseEvent(res, 'failure', {
        domain: cleanDomain,
        country: detectCcTld(cleanDomain),
        error: errorMessage(e)
      });
    }
  } finally {
    if (!closed) res.end();
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
    const [data, page] = await Promise.all([
      fetchJSON(`https://validator.w3.org/nu/?doc=${encodeURIComponent(`https://${domain}`)}&out=json`).catch(() => null),
      fetchWebsite(domain).catch(() => null)
    ]);
    const messages = Array.isArray(data?.messages) ? data.messages : [];
    const errors = messages.filter(m => m.type === 'error').length;
    const warnings = messages.filter(m => m.type !== 'error').length;
    const html = String(page?.body || '');
    const lower = html.toLowerCase();
    const attrMatches = name => new RegExp(`<${name}\\b[^>]*>`, 'gi');
    const scanIssues = [];
    const hasLang = /<html\b[^>]*\blang\s*=\s*["'][^"']+["']/i.test(html);
    if (!hasLang) scanIssues.push('La página no declara el idioma principal del contenido.');
    if (!/<title>\s*[^<]+<\/title>/i.test(html)) scanIssues.push('La página no tiene un título descriptivo.');
    if (/<img\b(?![^>]*\balt\s*=)/i.test(html)) scanIssues.push('Hay imágenes sin texto alternativo.');
    if (/<(input|select|textarea)\b(?![^>]*(?:aria-label|aria-labelledby|id|name|title)\s*=)/i.test(html)) {
      scanIssues.push('Hay campos de formulario sin etiqueta accesible.');
    }
    if (/<button\b(?![^>]*(?:aria-label|aria-labelledby))[^>]*>\s*<\/button>/i.test(html)) {
      scanIssues.push('Hay botones sin nombre accesible.');
    }
    if (/<a\b[^>]*href=([^>]+)>(\s|<\/?span|<\/?strong|<\/?em)*<\/a>/i.test(html)) {
      scanIssues.push('Hay enlaces sin nombre accesible.');
    }
    if (!/<h1\b/i.test(html)) scanIssues.push('La página no tiene encabezado principal.');
    const headingMatches = [...html.matchAll(/<h([1-6])\b/gi)].map(m => Number(m[1]));
    for (let i = 1; i < headingMatches.length; i += 1) {
      if (headingMatches[i] - headingMatches[i - 1] > 1) {
        scanIssues.push('La estructura de encabezados puede ser incorrecta.');
        break;
      }
    }
    if (!/<main\b/i.test(html) && !/role\s*=\s*["']main["']/i.test(html)) scanIssues.push('No se identifica la región principal del contenido.');
    if (/tabindex\s*=\s*["']([1-9]\d*)["']/i.test(html)) scanIssues.push('Se detectó tabindex positivo, lo que puede alterar el orden natural de navegación.');
    if (/<(div|span|li|img|p)\b[^>]*onclick\s*=/i.test(html)) scanIssues.push('Hay elementos no semánticos usados como controles interactivos.');
    if (/<iframe\b(?![^>]*\btitle\s*=)/i.test(html)) scanIssues.push('Hay iframes sin título descriptivo.');
    if (/<table\b[\s\S]*?(?<!<th\b)[\s\S]*?<\/table>/i.test(html) && !/<th\b/i.test(html)) scanIssues.push('Hay tablas sin encabezados estructurados.');
    if (/(aria-labelledby|aria-describedby)\s*=\s*["']([^"']+)["']/i.test(html)) {
      const refs = [...html.matchAll(/(?:aria-labelledby|aria-describedby)\s*=\s*["']([^"']+)["']/gi)]
        .flatMap(match => match[1].split(/\s+/).filter(Boolean));
      const missing = refs.some(id => !new RegExp(`id\\s*=\\s*["']${id}["']`, 'i').test(html));
      if (missing) scanIssues.push('Hay referencias ARIA a elementos inexistentes.');
    }
    if (/aria-hidden\s*=\s*["']true["'][\s\S]*?(<button\b|<a\b|<input\b|<select\b|<textarea\b)/i.test(html)) {
      scanIssues.push('Hay contenido interactivo oculto para tecnologías de asistencia.');
    }
    if (/<(audio|video)\b[^>]*\bautoplay\b(?![^>]*\bmuted\b)/i.test(html)) scanIssues.push('Hay multimedia con reproducción automática y sonido.');
    if (/<svg\b[^>]*\brole\s*=\s*["']button["'][\s\S]*?(?![^<]*<title>)/i.test(html)) {
      scanIssues.push('Hay íconos o SVG interactivos sin nombre accesible.');
    }
    sendJSON(res, 200, {
      domain,
      errors: errors + scanIssues.length,
      warnings: warnings,
      issues: scanIssues,
      htmlChecked: Boolean(html)
    });
  } catch (e) {
    sendJSON(res, 200, { domain, unavailable: true, note: errorMessage(e) });
  }
}

async function handleHeaders(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const result = await summarizeHttpHeaders(domain);
    sendJSON(res, 200, result);
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function summarizeHttpHeaders(domain) {
  domain = normalizeDomain(domain);
  const httpsRes = await fetchHeaders(`https://${domain}`);
  const httpRes = await fetchHeaders(`http://${domain}`, true).catch(() => null);
  const hstsHeader = httpsRes.headers['strict-transport-security'] || '';
  const hstsMatch = String(hstsHeader).match(/max-age=(\d+)/i);
  const hstsMaxAge = hstsMatch ? Number(hstsMatch[1]) : null;
  const https = httpsRes.statusCode >= 200 && httpsRes.statusCode < 400;
  const redirect =
    Boolean(
      httpRes &&
      httpRes.statusCode >= 300 &&
      httpRes.statusCode < 400 &&
      typeof httpRes.headers.location === 'string' &&
      httpRes.headers.location.startsWith('https://')
    );
  const result = {
    domain,
    https,
    redirect,
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
  result.findings = [
    {
      id: 'https',
      label: 'HTTPS',
      status: result.https ? 'ok' : 'fail',
      value: result.https ? 'present' : 'absent'
    },
    {
      id: 'redirect',
      label: 'Redirección',
      status: result.redirect ? 'ok' : 'warning',
      value: result.redirect ? 'forced' : 'notForced'
    },
    {
      id: 'hsts',
      label: 'HSTS',
      status: result.hstsStrict ? 'ok' : (result.hsts ? 'warning' : 'fail'),
      value: result.hstsStrict ? 'strong' : (result.hsts ? 'weak' : 'absent')
    },
    {
      id: 'csp',
      label: 'CSP',
      status: result.csp ? 'ok' : 'warning',
      value: result.csp ? 'present' : 'absent'
    },
    {
      id: 'xfo',
      label: 'X-Frame-Options',
      status: result.xfo ? 'ok' : 'warning',
      value: result.xfo ? 'present' : 'absent'
    },
    {
      id: 'xcto',
      label: 'X-Content-Type-Options',
      status: result.xcto ? 'ok' : 'warning',
      value: result.xcto ? 'present' : 'absent'
    },
    {
      id: 'referrer',
      label: 'Referrer-Policy',
      status: result.referrer ? 'ok' : 'warning',
      value: result.referrer ? 'present' : 'absent'
    },
    {
      id: 'permissions',
      label: 'Permissions-Policy',
      status: result.permissions ? 'ok' : 'warning',
      value: result.permissions ? 'present' : 'absent'
    },
    {
      id: 'xxss',
      label: 'X-XSS-Protection',
      status: result.xxss ? 'info' : 'warning',
      value: result.xxss ? 'present' : 'absent'
    }
  ];
  return result;
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
  if (segments[0] === 'locales' && segments[1]) {
    try {
      const langFile = String(segments[1]).replace(/\.properties$/i, '');
      const filePath = path.resolve(LOCALES_DIR, `${langFile}.properties`);
      if (!filePath.startsWith(`${LOCALES_DIR}${path.sep}`)) {
        return sendJSON(res, 400, { error: 'Ruta inválida' });
      }
      const text = await fs.readFile(filePath, 'utf8');
      return sendText(res, 200, text);
    } catch (e) {
      return sendJSON(res, 404, { error: 'Archivo de idioma no encontrado' });
    }
  }
  if (segments[0] === 'assets' && segments[1]) {
    try {
      const filePath = path.resolve(__dirname, 'assets', ...segments.slice(1));
      if (!filePath.startsWith(path.join(__dirname, 'assets') + path.sep)) {
        return sendJSON(res, 400, { error: 'Ruta inválida' });
      }
      return await sendAsset(res, filePath);
    } catch (e) {
      return sendJSON(res, 404, { error: 'Asset no encontrado' });
    }
  }
  if (segments[0] === 'images' && segments[1]) {
    try {
      const filePath = path.resolve(__dirname, 'images', ...segments.slice(1));
      if (!filePath.startsWith(path.join(__dirname, 'images') + path.sep)) {
        return sendJSON(res, 400, { error: 'Ruta inválida' });
      }
      return await sendAsset(res, filePath);
    } catch (e) {
      return sendJSON(res, 404, { error: 'Imagen no encontrada' });
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
  if (segments[0] === 'home' && segments.length === 1) {
    try {
      const html = await fs.readFile(INDEX_PATH, 'utf8');
      return sendHTML(res, 200, html);
    } catch (e) {
      return sendHTML(res, 500, '<h1>No se pudo cargar index.html</h1>');
    }
  }
  if (segments[0] === 'mini' && segments.length === 1) {
    try {
      const html = await fs.readFile(INDEX_PATH, 'utf8');
      return sendHTML(res, 200, html);
    } catch (e) {
      return sendHTML(res, 500, '<h1>No se pudo cargar index.html</h1>');
    }
  }
  if (segments[0] === 'mini' && segments[1] === 'stream' && segments[2]) {
    return handleMiniStream(segments[2], res);
  }
  if (segments[0] === 'situacion-lac' && segments.length === 1) {
    try {
      const html = await fs.readFile(INDEX_PATH, 'utf8');
      return sendHTML(res, 200, html);
    } catch (e) {
      return sendHTML(res, 500, '<h1>No se pudo cargar index.html</h1>');
    }
  }
  if (segments[0] === 'cctlds' && segments.length === 1) {
    try {
      const html = await fs.readFile(INDEX_PATH, 'utf8');
      return sendHTML(res, 200, html);
    } catch (e) {
      return sendHTML(res, 500, '<h1>No se pudo cargar index.html</h1>');
    }
  }
  if (segments[0] === 'mapa' && segments.length === 1) {
    try {
      const html = await fs.readFile(INDEX_PATH, 'utf8');
      return sendHTML(res, 200, html);
    } catch (e) {
      return sendHTML(res, 500, '<h1>No se pudo cargar index.html</h1>');
    }
  }
  if (segments[0] === 'referencias' && segments.length === 1) {
    try {
      const html = await fs.readFile(INDEX_PATH, 'utf8');
      return sendHTML(res, 200, html);
    } catch (e) {
      return sendHTML(res, 500, '<h1>No se pudo cargar index.html</h1>');
    }
  }
  if (segments[0] === 'about' && segments.length === 1) {
    try {
      const html = await fs.readFile(INDEX_PATH, 'utf8');
      return sendHTML(res, 200, html);
    } catch (e) {
      return sendHTML(res, 500, '<h1>No se pudo cargar index.html</h1>');
    }
  }
  if (segments[0] === 'revisar' && segments.length === 1) {
    try {
      const html = await fs.readFile(INDEX_PATH, 'utf8');
      return sendHTML(res, 200, html);
    } catch (e) {
      return sendHTML(res, 500, '<h1>No se pudo cargar index.html</h1>');
    }
  }
  if (segments[0] === 'mini' && segments[1] === 'data' && segments[2]) {
    return handleMiniData(segments[2], res);
  }
  if (segments[0] === 'api' && segments[1] === 'cctlds') {
    return handleCctldReport(res, parsed.searchParams.get('resolver') || 'local');
  }
  if (segments[0] === 'internetnl' && segments[1]) {
    return handleInternetNl(segments[1], res, parsed.searchParams.get('type') || 'web');
  }
  if (segments[0] === 'compat' && segments[1]) {
    return handleCompatBundle(segments[1], res, parsed.searchParams.get('type') || 'web');
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

setTimeout(() => {
  refreshCctldReport().catch(e => console.log(`[cctld] error - ${errorMessage(e)}`));
}, 0);
setInterval(() => {
  refreshCctldReport().catch(e => console.log(`[cctld] error - ${errorMessage(e)}`));
}, 15 * 60 * 1000).unref();
