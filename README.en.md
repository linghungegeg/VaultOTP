<div align="center">

# VaultOTP

A lightweight web tool for centrally storing, managing, and using 2FA verification codes.

<p>
  <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue" />
  <img alt="Node.js" src="https://img.shields.io/badge/Node.js-20%2B-339933" />
  <img alt="SQLite" src="https://img.shields.io/badge/storage-SQLite-0f766e" />
  <img alt="PWA" src="https://img.shields.io/badge/PWA-ready-2563eb" />
  <img alt="i18n" src="https://img.shields.io/badge/i18n-中文%20%2F%20English-7c3aed" />
</p>

<p>
  <a href="README.md">简体中文</a> | English
</p>

</div>

## Overview

VaultOTP is a 2FA verification code manager for individuals and teams. It provides a user app, admin console, public utility pages, browser extension, and PWA offline support. It is designed for self-hosting and centralizes TOTP/HOTP entries, imports, exports, backups, and PAT-based API access in one web service.

Official website: [https://www.2fakey.icu/](https://www.2fakey.icu/)

## Features

- **Lightweight self-hosting**: a single Node.js web service without a heavy microservice stack.
- **SQLite persistence**: users, admin, groups, entries, PATs, audit logs, and site settings are persisted in SQLite by default.
- **Full user app**: groups, search, pinning, trash, batch organization, QR import, and backup export.
- **Admin console**: user management, site configuration, audit logs, and user detail inspection.
- **Clear security boundary**: user and admin surfaces are separated; admin Secret / OTP access goes through audited actions.
- **Algorithm coverage**: TOTP / HOTP, SHA-1 / SHA-256 / SHA-512, 6 / 8 digits, TOTP period, and HOTP counter.
- **Rich import support**: otpauth URI, Google Authenticator migration URI, QR images, camera scanning, and common readable export formats.
- **API / PAT**: create Personal Access Tokens and read entries or current codes through API calls.
- **PWA / offline support**: cache the app shell and keep usable entry access in weak or offline network conditions.
- **Chinese and English UI**: built-in Simplified Chinese and English copy.

## Supported Algorithms

| Type | Supported |
| --- | --- |
| OTP types | TOTP, HOTP |
| HMAC algorithms | SHA-1, SHA-256, SHA-512 |
| Code digits | 6 digits, 8 digits |
| TOTP parameters | Custom period, default 30 seconds |
| HOTP parameters | Counter |

## Supported Imports

| Source | Support |
| --- | --- |
| otpauth URI | Paste text, bulk text, and page extraction |
| Google Authenticator | `otpauth-migration://` migration URI |
| QR images | Upload and decode image files |
| Camera scanning | Real-time browser camera scanning |
| Aegis | Readable JSON export |
| 2FAS | Readable export |
| 2FAuth | Readable export |
| Bitwarden | Readable JSON export |
| LastPass | CSV export |
| Proton Pass | Readable JSON / CSV export |
| Raivo | Readable export |
| andOTP | Readable export |
| FreeOTP | Readable export |

## Screenshots

| Home | User App |
| --- | --- |
| <kbd><img src="img/Snipaste_2026-08-10_02-04-00.png" alt="VaultOTP Home" width="420" /></kbd> | <kbd><img src="img/Snipaste_2026-08-10_02-04-21.png" alt="VaultOTP User App" width="420" /></kbd> |

| Add Entry | Admin Console |
| --- | --- |
| <kbd><img src="img/Snipaste_2026-08-10_02-04-35.png" alt="VaultOTP Add Entry" width="420" /></kbd> | <kbd><img src="img/Snipaste_2026-08-10_02-07-20.png" alt="VaultOTP Admin Console" width="420" /></kbd> |

## Architecture

```text
Browser / PWA / Extension
        |
        | HTTPS
        v
Node.js Web Server
  - Public pages
  - User app
  - Admin console
  - REST API
        |
        v
SQLite Store
  - users / admin
  - sessions / PAT
  - groups / entries
  - audit logs / site settings
```

### Directory Layout

```text
web/        Web pages, API server, PWA files
extension/  Browser extension and shared i18n copy
img/        Screenshots, donation QR code, contact QR code
```

## Quick Deployment

### Requirements

- Node.js 20+
- SQLite support:
  - When Node.js supports `node:sqlite`, VaultOTP uses the built-in SQLite API first.
  - On Node.js 20, install the system `sqlite3` command as a fallback.

Ubuntu example:

```bash
sudo apt-get update
sudo apt-get install -y sqlite3
```

### Start the Service

```bash
HOST=127.0.0.1 \
PORT=4173 \
VAULTOTP_STORE_PATH=/var/lib/vaultotp/vaultotp-store.json \
node web/server.mjs
```

By default, the SQLite database is created next to `VAULTOTP_STORE_PATH`:

```text
/var/lib/vaultotp/vaultotp-store.sqlite
```

### Reverse Proxy

Use Nginx / Caddy / Traefik for HTTPS in production:

```nginx
server {
  listen 80;
  server_name example.com;

  location / {
    proxy_pass http://127.0.0.1:4173;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }
}
```

### systemd Example

```ini
[Unit]
Description=VaultOTP web service
After=network.target

[Service]
WorkingDirectory=/opt/vaultotp/current
ExecStart=/usr/bin/node /opt/vaultotp/current/web/server.mjs
Restart=always
Environment=HOST=127.0.0.1
Environment=PORT=4173
Environment=VAULTOTP_STORE_PATH=/var/lib/vaultotp/vaultotp-store.json

[Install]
WantedBy=multi-user.target
```

## Configuration

| Environment variable | Default | Description |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Listen host |
| `PORT` | `4173` | Listen port |
| `VAULTOTP_STORE_PATH` | `vaultotp-store.json` | Legacy JSON path and SQLite-derived path |
| `VAULTOTP_DB_PATH` | Derived from `VAULTOTP_STORE_PATH` | Explicit SQLite database path |
| `VAULTOTP_SQLITE_BIN` | `sqlite3` | sqlite3 command used by the Node 20 fallback |
| `VAULTOTP_DISABLE_DB` | unset | Set to `1` to fall back to JSON storage |

## Recommended Project

[Linghun](https://github.com/linghungegeg/Linghun) is a local-first, evidence-first AI coding terminal that connects models to real projects, real tools, real validation, and real context.

## License

VaultOTP is open-sourced under the [Apache License 2.0](LICENSE).

## Donation

<p align="center">
  <kbd><img src="img/zhanshang.png" alt="Donation QR code" width="260" /></kbd>
</p>

## Contact

<p align="center">
  <kbd><img src="img/wx.jpg" alt="WeChat contact QR code" width="260" /></kbd>
</p>
