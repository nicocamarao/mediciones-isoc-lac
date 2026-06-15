# ISOC LAC Measurements

This repository is part of the ISOC LAC measurement effort: a regional, open-source project built to turn technical signals into actionable evidence for Latin America and the Caribbean.

It combines a Node.js backend and a web UI for domain measurements focused on DNS, email, web security, routing, accessibility, and ccTLD Pulse data.

The app is designed around two main experiences:

- `Home`: the full dashboard with grouped measurements and detailed breakdowns.
- `Mini`: a compact card-based view that surfaces the most relevant checks in a smaller layout.

Both views reuse the same measurement backend. Home is better for exploration and deep inspection, while Mini is meant for quick triage and a cleaner “at a glance” experience.

## Getting Started

Install dependencies and start the server:

```bash
npm install
npm start
```

By default, the app serves the web UI and the local measurement API from the same Node.js process.

## Main UI Routes

- `/home` - full dashboard
- `/mini` - compact dashboard
- `/mini/stream/:domain` - streamed Mini run for a single domain
- `/situacion-lac` - LAC status view
- `/cctlds` - ccTLD overview
- `/mapa` - map view
- `/referencias` - reference and help content
- `/about` - project information
- `/revisar` - review view

These routes are the visible face of the project: a practical interface for regional analysis, designed to help the community compare infrastructure, identify gaps, and track progress over time.

## Core API Endpoints

### DNS and IP

- `GET /ipv4/:domain` - returns A records
- `GET /ipv6/:domain` - returns AAAA records
- `GET /dnsrecords/:domain` - returns a DNS record summary
- `GET /txtrecords/:domain` - returns TXT records
- `GET /mx/:domain` - returns MX records
- `GET /dnssec/:domain` - evaluates DNSSEC and returns DS/DNSKEY status, algorithms, digests, and DNSViz metadata
- `GET /dnsviz/:domain` - returns DNSViz metadata and observations
- `GET /dnsviz/:domain?format=svg&resolver=local` - returns the DNSViz graph SVG
- `GET /dnsviz/:domain?format=png&resolver=local` - returns the DNSViz graph PNG when available
- `GET /securitytxt/:domain` - checks for `security.txt`
- `GET /caa/:domain` - returns CAA records
- `GET /tlsa/:domain` - returns TLSA records

### Email

- `GET /maildnssec/:domain` - checks DNSSEC for the mail side of the domain
- `GET /mailipv6/:domain` - checks AAAA visibility for MX hosts
- `GET /spf/:domain` - checks SPF presence and policy
- `GET /dmarc/:domain` - checks DMARC presence and policy
- `GET /dkim/:domain?selector=support` - checks DKIM support for the selected selector
- `GET /starttls/:domain` - checks STARTTLS support on MX hosts
- `GET /smtputf8/:domain` - checks whether MX hosts advertise `SMTPUTF8`
- `GET /emailconfig/:domain` - summarizes SPF, DMARC, DKIM, MX, and related mail configuration

### Routing and trust

- `GET /rpki/:domain` - validates the observed routes against RPKI/ROA
- `GET /routing/:domain` - summarizes route visibility, ASN/prefix data, and routing status

### Web security and quality

- `GET /headers/:domain` - summarizes HTTPS, HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and related headers
- `GET /tlsinfo/:domain` - returns the negotiated TLS protocol, cipher, and key details
- `GET /sslchain/:domain` - returns the certificate chain
- `GET /tlsconfig/:domain` - returns TLS configuration details
- `GET /tlsciphers/:domain` - returns TLS cipher suites
- `GET /tlssimulation/:domain` - simulates TLS compatibility scenarios
- `GET /w3c/:domain` - checks HTML and accessibility-related issues
- `GET /quality/:domain` - quality and performance summary
- `GET /crawlrules/:domain` - crawl and metadata checks
- `GET /cookies/:domain` - cookie inspection
- `GET /sitefeatures/:domain` - site feature detection
- `GET /httpsecurity/:domain` - HTTP security summary
- `GET /firewall/:domain` - firewall-related summary

### Infrastructure and context

- `GET /whois/:domain` - domain ownership and country hints
- `GET /ipinfo/:domain` - IP geolocation and network details
- `GET /serverinfo/:domain` - server and ASN data
- `GET /serverlocation/:domain` - server location summary
- `GET /associatedhosts/:domain` - associated hostnames
- `GET /redirectchain/:domain` - HTTP redirect chain
- `GET /openports/:domain` - common open port checks
- `GET /serverstatus/:domain` - basic HTTP response status
- `GET /ping/:domain` - IPv4 ping
- `GET /pingv6/:domain` - IPv6 ping
- `GET /traceroute/:domain` - traceroute
- `GET /carbon/:domain` - carbon-related data
- `GET /domaininfo/:domain` - general domain summary
- `GET /dnssecurity/:domain` - DNS security summary
- `GET /dnsserver/:domain` - authoritative DNS servers
- `GET /techstack/:domain` - detected technologies
- `GET /listedpages/:domain` - sitemap-listed pages
- `GET /linkedpages/:domain` - linked pages from the site
- `GET /socialtags/:domain` - social metadata
- `GET /archive/:domain` - archive.org style entries
- `GET /ranking/:domain` - ranking summary
- `GET /block/:domain` - blocklist checks
- `GET /malware/:domain` - malware checks
- `GET /screenshot/:domain` - screenshot URL helper

## Bundle and Compatibility Views

The project also exposes bundle-style endpoints used by the UI to combine local checks into a single payload:

- `GET /compat/:domain?type=web|mail`
- `GET /internetnl/:domain?type=web|mail`
- `GET /mini/data/:domain`

These routes power the dashboard and Mini view with consolidated data.

In practice, the bundle endpoints let the frontend present the story of a domain in one pass: what it publishes, what it protects, and where it still needs work.

## ccTLD Pulse and 6 GHz

The app includes ccTLD Pulse data and a hardcoded 6 GHz availability map:

- `GET /api/cctlds?resolver=local`
- `GET /pulse/:country` through the internal Pulse data pipeline
- ccTLD-specific Pulse snapshots are stored under `data/pulse-hardcoded.json`

Mini and Home use these sources to show DNSSEC coverage, DNSSEC adoption, ROV, and country-level 6 GHz status when a ccTLD applies.

This is especially useful for country-code TLDs, where the project can add a regional pulse layer alongside the individual domain checks.

## How the UI Uses the API

The `index.html` client fetches the same backend endpoints directly and renders:

- a full Home dashboard with larger grouped sections
- a compact Mini dashboard with cards, per-row status pills, and detail popups
- DNSViz graph previews and direct links to the DNSViz analyze page
- accessibility signals from the W3C scan
- routing, RPKI, and mail authentication summaries

The result is a single platform where technical measurements, policy signals, and operational context stay together instead of living in separate tools.

## Notes

- The server is intentionally self-contained, with a local backend plus UI.
- Some routes rely on external data sources such as RIPE Stat, DNSViz, and Internet Society Pulse.
- The Mini view is intentionally denser, but it uses the same measurement backend as Home.
