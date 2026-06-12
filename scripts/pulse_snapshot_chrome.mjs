#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const SERVER_JS = path.join(ROOT, 'server.js');
const OUTPUT_DIR = path.join(ROOT, 'data', 'pulse-html');
const MANIFEST_PATH = path.join(ROOT, 'data', 'pulse-manifest.json');
const URL_TEMPLATE = 'https://pulse.internetsociety.org/es/reports/{code}/';
const DEFAULT_PORT = Number(process.env.PULSE_CHROME_PORT || 9222);
const DEFAULT_PROFILE_DIR = path.join(ROOT, 'data', 'pulse-chrome-profile');
const CHROME_CANDIDATES = [
  process.env.CHROME_BIN,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
].filter(Boolean);

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function findChromeBinary() {
  for (const candidate of CHROME_CANDIDATES) {
    if (await fileExists(candidate)) return candidate;
  }
  throw new Error('No encontré Google Chrome. Ajustá CHROME_BIN o instalá Chrome.');
}

async function extractCodes() {
  const source = await fs.readFile(SERVER_JS, 'utf8');
  const match = source.match(/const\s+LACNIC_CCTLDS\s*=\s*\[(.*?)\]\.sort\(/s);
  if (!match) {
    throw new Error('No se pudo leer LACNIC_CCTLDS desde server.js');
  }
  const codes = [...match[1].matchAll(/'([a-z]{2})'/gi)].map(item => item[1].toLowerCase());
  return codes;
}

function isChallengePage(page) {
  const haystack = `${page.title}\n${page.text}\n${page.html}`.toLowerCase();
  return (
    haystack.includes('verificación de seguridad en curso') ||
    haystack.includes('just a moment') ||
    haystack.includes('attention required') ||
    haystack.includes('cf-turnstile') ||
    haystack.includes('cf-chl') ||
    haystack.includes('cloudflare')
  );
}

function hasReportContent(page) {
  const haystack = `${page.title}\n${page.text}\n${page.html}`;
  return /DNSSEC coverage|Adoption of DNSSEC|Internet Resilience Score|Country-level domain use/i.test(haystack);
}

async function waitForChromeReady(port) {
  const versionUrl = `http://127.0.0.1:${port}/json/version`;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const res = await fetch(versionUrl);
      if (res.ok) {
        return await res.json();
      }
    } catch {
      // Keep waiting.
    }
    await sleep(1000);
  }
  throw new Error(`Chrome no levantó el endpoint CDP en ${versionUrl}`);
}

function createCdpClient(ws) {
  let nextId = 0;
  const pending = new Map();
  const listeners = new Map();

  ws.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const pendingEntry = pending.get(message.id);
      if (!pendingEntry) return;
      pending.delete(message.id);
      if (message.error) {
        pendingEntry.reject(new Error(message.error.message || 'CDP error'));
      } else {
        pendingEntry.resolve(message.result || {});
      }
      return;
    }
    const channel = message.sessionId || '__root__';
    const handlers = listeners.get(channel) || [];
    for (const handler of handlers) handler(message);
  });

  ws.addEventListener('error', event => {
    for (const { reject } of pending.values()) {
      reject(event?.error || new Error('WebSocket error'));
    }
    pending.clear();
  });

  function send(method, params = {}, sessionId) {
    const id = ++nextId;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      const payload = { id, method, params };
      if (sessionId) payload.sessionId = sessionId;
      ws.send(JSON.stringify(payload));
    });
  }

  function on(sessionId, handler) {
    const key = sessionId || '__root__';
    const list = listeners.get(key) || [];
    list.push(handler);
    listeners.set(key, list);
  }

  return { send, on };
}

async function createSession(client) {
  return createBlankSession(client);
}

async function readPageState(client, sessionId) {
  const result = await client.send(
    'Runtime.evaluate',
    {
      expression: `(() => ({
        title: document.title || '',
        text: document.body ? document.body.innerText || '' : '',
        html: document.documentElement ? document.documentElement.outerHTML || '' : ''
      }))()`,
      returnByValue: true
    },
    sessionId
  );
  return result.result?.value || result.value || {};
}

async function waitForPageReady(client, sessionId, code, url, promptIfNeeded) {
  const timeoutMs = Number(process.env.PULSE_PAGE_TIMEOUT_MS || 20000);
  const intervalMs = Number(process.env.PULSE_POLL_MS || 1000);
  const started = Date.now();
  let lastPage = null;

  await client.send('Page.navigate', { url }, sessionId);

  while (Date.now() - started < timeoutMs) {
    const page = await readPageState(client, sessionId);
    lastPage = page;
    if (!isChallengePage(page) && hasReportContent(page)) {
      return page.html;
    }
    if (!isChallengePage(page) && page.text && page.text.trim().length > 0) {
      if (Date.now() - started > 4000) {
        return page.html;
      }
    }
    if (isChallengePage(page)) {
      await promptIfNeeded(code, url);
    }
    await sleep(intervalMs);
  }

  if (lastPage && lastPage.html) {
    return lastPage.html;
  }
  throw new Error(`Timeout esperando ${code}.`);
}

async function createBlankSession(client) {
  const { targetId } = await client.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await client.send('Target.attachToTarget', { targetId, flatten: true });
  await client.send('Page.enable', {}, sessionId);
  await client.send('Runtime.enable', {}, sessionId);
  await client.send('Network.enable', {}, sessionId);
  await client.send(
    'Page.addScriptToEvaluateOnNewDocument',
    {
      source: `
        (() => {
          try {
            window.print = () => {};
            window.onbeforeprint = null;
            window.addEventListener('beforeprint', event => {
              try { event.stopImmediatePropagation(); } catch {}
              try { event.preventDefault(); } catch {}
            }, true);
          } catch {}
        })();
      `
    },
    sessionId
  );
  return { targetId, sessionId };
}

async function launchChrome(chromeBinary, port, userDataDir) {
  await fs.mkdir(userDataDir, { recursive: true });
  const args = [
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${userDataDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--new-window',
    'about:blank'
  ];
  const child = spawn(chromeBinary, args, {
    stdio: 'ignore',
    detached: false
  });
  child.on('error', err => {
    console.error(`[pulse] Chrome error: ${err.message}`);
  });
  return child;
}

async function main() {
  const chromeBinary = await findChromeBinary();
  const codes = await extractCodes();
  await fs.mkdir(OUTPUT_DIR, { recursive: true });
  const profileDir = process.env.PULSE_CHROME_PROFILE_DIR || DEFAULT_PROFILE_DIR;
  const port = DEFAULT_PORT;

  console.log(`[pulse] usando Chrome: ${chromeBinary}`);
  console.log(`[pulse] perfil: ${profileDir}`);
  console.log(`[pulse] puerto CDP: ${port}`);

  const chrome = await launchChrome(chromeBinary, port, profileDir);
  const version = await waitForChromeReady(port);
  const ws = new WebSocket(version.webSocketDebuggerUrl);

  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true });
    ws.addEventListener('error', reject, { once: true });
  });

  const client = createCdpClient(ws);
  const manifest = [];
  let success = 0;
  let failure = 0;

  try {
    for (const code of codes) {
      const { sessionId, targetId } = await createBlankSession(client);
      await client.send('Page.bringToFront', {}, sessionId).catch(() => {});
      const url = URL_TEMPLATE.replace('{code}', code.toLowerCase());
      const outputPath = path.join(OUTPUT_DIR, `${code.toLowerCase()}.html`);
      console.log(`[pulse] capturando ${code} ${url}`);
      try {
        const html = await waitForPageReady(client, sessionId, code, url, async () => {
          console.log('');
          console.log(`[pulse] ${code} está mostrando challenge de Cloudflare. Resolvelo en Chrome si hace falta; el script seguirá esperando automáticamente.`);
        });
        await fs.writeFile(outputPath, html, 'utf8');
        manifest.push({
          code,
          url,
          path: path.relative(ROOT, outputPath),
          ok: true,
          bytes: Buffer.byteLength(html, 'utf8'),
          method: 'chrome-cdp'
        });
        success += 1;
        console.log(`[pulse] ${code} ok (${Buffer.byteLength(html, 'utf8')} bytes)`);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        manifest.push({
          code,
          url,
          path: path.relative(ROOT, outputPath),
          ok: false,
          error: message,
          method: 'chrome-cdp'
        });
        failure += 1;
        console.error(`[pulse] ${code} error: ${message}`);
      } finally {
        await client.send('Target.closeTarget', { targetId }).catch(() => {});
      }
    }
  } finally {
    await fs.writeFile(
      MANIFEST_PATH,
      JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          success,
          failure,
          method: 'chrome-cdp',
          items: manifest
        },
        null,
        2
      ) + '\n',
      'utf8'
    );
    ws.close();
    chrome.kill('SIGTERM');
  }

  console.log(`[pulse] summary ok=${success} fail=${failure}`);
  console.log(`[pulse] manifest=${MANIFEST_PATH}`);
  return failure === 0 ? 0 : 1;
}

main().then(code => process.exit(code)).catch(error => {
  console.error(`[pulse] fatal: ${error instanceof Error ? error.stack || error.message : String(error)}`);
  process.exit(1);
});
