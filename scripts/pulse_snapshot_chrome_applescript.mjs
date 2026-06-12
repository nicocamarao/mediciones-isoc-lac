#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const SERVER_JS = path.join(ROOT, 'server.js');
const OUTPUT_DIR = path.join(ROOT, 'data', 'pulse-html');
const MANIFEST_PATH = path.join(ROOT, 'data', 'pulse-manifest.json');
const URL_TEMPLATE = 'https://pulse.internetsociety.org/es/reports/{code}/';

function extractCodes() {
  return fs
    .readFile(SERVER_JS, 'utf8')
    .then(source => {
      const match = source.match(/const\s+LACNIC_CCTLDS\s*=\s*\[(.*?)\]\.sort\(/s);
      if (!match) {
        throw new Error('No se pudo leer LACNIC_CCTLDS desde server.js');
      }
      return [...match[1].matchAll(/'([a-z]{2})'/gi)].map(item => item[1].toLowerCase());
    });
}

function runAppleScript(url) {
  const script = `
on run argv
  set theUrl to item 1 of argv
  set jsCode to "(() => JSON.stringify({title: document.title || '', text: document.body ? document.body.innerText || '' : '', html: document.documentElement ? document.documentElement.outerHTML || '' : '', url: location.href || '', readyState: document.readyState || ''}))()"
  tell application "Google Chrome"
    activate
    if not (exists front window) then make new window
    set theTab to active tab of front window
    set URL of theTab to theUrl
    repeat with _attempt from 1 to 60
      delay 1
      try
        set pageState to execute theTab javascript jsCode
        if pageState contains "DNSSEC coverage" or pageState contains "Adoption of DNSSEC" or pageState contains "Internet Resilience Score" or pageState contains "Country-level domain use" then
          return pageState
        end if
        if pageState contains "Verificación de seguridad en curso" or pageState contains "Just a moment" or pageState contains "Attention Required" or pageState contains "cf-turnstile" or pageState contains "Cloudflare" then
          -- Keep waiting. The browser may still be solving the challenge.
        end if
      end try
    end repeat
    try
      return execute theTab javascript jsCode
    on error errMsg
      return "{\"error\":\"" & errMsg & "\"}"
    end try
  end tell
end run
`;

  const proc = spawnSync('osascript', ['-e', script, url], {
    encoding: 'utf8',
    maxBuffer: 20 * 1024 * 1024
  });

  if (proc.status !== 0) {
    throw new Error((proc.stderr || proc.stdout || `osascript exit ${proc.status}`).trim());
  }

  const raw = (proc.stdout || '').trim();
  if (!raw) {
    throw new Error('Chrome no devolvió contenido.');
  }

  return JSON.parse(raw);
}

function normalizeState(state) {
  if (!state || typeof state !== 'object') {
    return {
      title: '',
      text: '',
      html: '',
      url: '',
      readyState: '',
      error: 'Estado inválido'
    };
  }
  return {
    title: String(state.title || ''),
    text: String(state.text || ''),
    html: String(state.html || ''),
    url: String(state.url || ''),
    readyState: String(state.readyState || ''),
    error: state.error ? String(state.error) : ''
  };
}

async function main() {
  const codes = await extractCodes();
  await fs.mkdir(OUTPUT_DIR, { recursive: true });

  const manifest = [];
  let success = 0;
  let failure = 0;

  for (const code of codes) {
    const url = URL_TEMPLATE.replace('{code}', code.toLowerCase());
    const outputPath = path.join(OUTPUT_DIR, `${code.toLowerCase()}.html`);
    console.log(`[pulse] capturando ${code} ${url}`);
    try {
      const page = normalizeState(runAppleScript(url));
      if (page.error) {
        throw new Error(page.error);
      }
      await fs.writeFile(outputPath, page.html, 'utf8');
      manifest.push({
        code,
        url,
        path: path.relative(ROOT, outputPath),
        ok: true,
        bytes: Buffer.byteLength(page.html, 'utf8'),
        title: page.title,
        readyState: page.readyState,
        method: 'chrome-applescript'
      });
      success += 1;
      console.log(`[pulse] ${code} ok (${Buffer.byteLength(page.html, 'utf8')} bytes)`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      manifest.push({
        code,
        url,
        path: path.relative(ROOT, outputPath),
        ok: false,
        error: message,
        method: 'chrome-applescript'
      });
      failure += 1;
      console.error(`[pulse] ${code} error: ${message}`);
    }
  }

  await fs.writeFile(
    MANIFEST_PATH,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        success,
        failure,
        method: 'chrome-applescript',
        items: manifest
      },
      null,
      2
    ) + '\n',
    'utf8'
  );

  console.log(`[pulse] summary ok=${success} fail=${failure}`);
  console.log(`[pulse] manifest=${MANIFEST_PATH}`);
  return failure === 0 ? 0 : 1;
}

main()
  .then(code => process.exit(code))
  .catch(error => {
    console.error(`[pulse] fatal: ${error instanceof Error ? error.stack || error.message : String(error)}`);
    process.exit(1);
  });
