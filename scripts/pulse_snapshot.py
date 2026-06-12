#!/usr/bin/env python3
"""Download Internet Society Pulse HTML snapshots for LACNIC countries."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import shutil
from pathlib import Path
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]
SERVER_JS = ROOT / "server.js"
OUTPUT_DIR = ROOT / "data" / "pulse-html"
MANIFEST_PATH = ROOT / "data" / "pulse-manifest.json"
URL_TEMPLATE = "https://pulse.internetsociety.org/es/reports/{code}/"


def extract_codes() -> list[str]:
    source = SERVER_JS.read_text(encoding="utf-8")
    match = re.search(
        r"const\s+LACNIC_CCTLDS\s*=\s*\[(.*?)\]\.sort\(",
        source,
        flags=re.S,
    )
    if not match:
        raise RuntimeError("No se pudo leer LACNIC_CCTLDS desde server.js")
    body = match.group(1)
    codes = re.findall(r"'([a-z]{2})'", body, flags=re.I)
    return [code.lower() for code in codes]


def download_html(code: str) -> tuple[bool, bytes | None, str]:
    url = URL_TEMPLATE.format(code=code.lower())
    user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    headers = [
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
        ("Accept-Language", "es-ES,es;q=0.9,en;q=0.8"),
        ("Cache-Control", "no-cache"),
        ("Pragma", "no-cache"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Referer", "https://pulse.internetsociety.org/"),
    ]
    if shutil.which("wget"):
        cmd = [
            "wget",
            "--quiet",
            "--output-document=-",
            "--server-response",
            "--max-redirect=20",
            "--timeout=20",
            "--tries=2",
            "--compression=auto",
            "--user-agent",
            user_agent,
        ]
        for key, value in headers:
            cmd.extend(["--header", f"{key}: {value}"])
        cmd.append(url)
    else:
        cmd = [
            "curl",
            "-L",
            "--fail",
            "--silent",
            "--show-error",
            "--http2",
            "--compressed",
            "--retry",
            "2",
            "--retry-delay",
            "1",
            "--connect-timeout",
            "20",
            "--max-time",
            "45",
            "--user-agent",
            user_agent,
        ]
        for key, value in headers:
            cmd.extend(["--header", f"{key}: {value}"])
        cmd.append(url)
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        return False, None, proc.stderr.decode("utf-8", errors="replace").strip() or f"curl exit {proc.returncode}"
    body = proc.stdout
    challenge_markers = [
        b"cf-mitigated",
        b"Just a moment",
        b"Attention Required",
        b"cloudflare",
    ]
    if any(marker.lower() in body.lower() for marker in challenge_markers):
        return False, None, "Pulse devolvió una página de challenge/bloqueo de Cloudflare."
    return True, body, ""


def main() -> int:
    codes = extract_codes()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    manifest: list[dict[str, object]] = []
    success = 0
    failure = 0

    for code in codes:
        ok, content, error = download_html(code)
        output_path = OUTPUT_DIR / f"{code}.html"
        entry: dict[str, object] = {
            "code": code,
            "url": URL_TEMPLATE.format(code=code.lower()),
            "path": str(output_path.relative_to(ROOT)),
            "ok": ok,
        }
        if ok and content is not None:
            output_path.write_bytes(content)
            entry["bytes"] = len(content)
            success += 1
            print(f"[pulse] {code} ok ({len(content)} bytes)")
        else:
            entry["error"] = error
            failure += 1
            print(f"[pulse] {code} error: {error}", file=sys.stderr)
        manifest.append(entry)

    MANIFEST_PATH.write_text(
        json.dumps(
            {
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "success": success,
                "failure": failure,
                "items": manifest,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"[pulse] summary ok={success} fail={failure} output={OUTPUT_DIR}")
    print(f"[pulse] manifest={MANIFEST_PATH}")
    return 0 if failure == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
