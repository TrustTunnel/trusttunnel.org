# AGENTS.md

## Table of Contents

- [Project Overview](#project-overview)
- [Technical Context](#technical-context)
- [Project Structure](#project-structure)
- [Build And Test Commands](#build-and-test-commands)
- [Contribution Instructions](#contribution-instructions)
- [Code Guidelines](#code-guidelines)
    - [System Design](#system-design)
    - [Architecture](#architecture)
    - [Code Quality](#code-quality)
    - [Testing](#testing)
    - [Dependency Management](#dependency-management)
    - [Configuration & Documentation](#configuration--documentation)
    - [Other](#other)

## Project Overview

`trusttunnel.org` is the public website of the TrustTunnel VPN protocol. It
contains the product and privacy pages, plus `qr.html`, an import page that
decodes and encodes `tt://?` deep links and renders QR codes entirely in the
browser. The site serves prospective users, existing users, and administrators
who need to share a TrustTunnel endpoint configuration.

## Technical Context

- **Language/Version**: HTML5, CSS, and browser-compatible JavaScript with `var`/`function` syntax and modern browser APIs. The codec runs in browsers and in Node.js; CI uses Node.js 26.
- **Primary Dependencies**: Tailwind CSS loaded from a CDN by every page, QRious 4.0.2 loaded by `qr.html`, and the Node.js built-in test runner. There are no npm package dependencies.
- **Storage**: N/A. The site has no backend and stores no data.
- **Testing**: Node.js built-in test runner (`node:test` and `node:assert/strict`).
- **Target Platform**: Modern browsers, served as static files from GitHub Pages.
- **Project Type**: Static website.
- **Performance Goals**: N/A; no targets are documented.
- **Constraints**: No server runtime and no build step. `qr.html` must work as a standalone downloaded page after the codec is inlined.
- **Scale/Scope**: Public product site and one client-side deep-link/QR tool.

## Project Structure

```text
trusttunnel.org/
├── AGENTS.md               # Repository instructions for coding agents
├── index.html              # Product landing page
├── privacy.html            # Privacy policy
├── qr.html                 # Deep-link import, editor, and QR generator
├── assets/
│   ├── deeplink.js         # Deep-link codec; no DOM dependencies
│   ├── logo.png
│   ├── logo.svg
│   └── protocol-*.svg      # Protocol diagrams
├── tests/
│   └── deeplink.test.js    # Node tests for assets/deeplink.js
├── package.json            # npm test script
└── .github/workflows/
    ├── static.yml          # GitHub Pages deployment
    └── test.yml            # npm test on push and pull request
```

## Build And Test Commands

- **Build**: No build step. GitHub Pages deploys the repository root as-is.
- **Test**: `npm test` (Node.js 26; runs `node --test tests/`).
- **Lint**: No linter is configured in this repository.
- **Format**: No formatter is configured in this repository.
- **Run**: No run command is defined. Serve the repository root with any static HTTP server to preview the pages.

## Contribution Instructions

- You MUST run `npm test` with Node.js 26 after changing `assets/deeplink.js`, `qr.html`, or the tests.
- You MUST add or update tests in `tests/deeplink.test.js` for every codec change.
- You MUST verify every deep-link change against the public `TrustTunnel/TrustTunnel` repository at <https://github.com/TrustTunnel/TrustTunnel>. Compare tag numbers, value types, defaults, field order, and version handling in `DEEP_LINK.md`, `deeplink/src/types.rs`, `deeplink/src/encode.rs`, and `deeplink/src/decode.rs`. There is no automated cross-repository conformance check in CI; the golden URIs in `tests/deeplink.test.js` are static vectors, so this manual check is mandatory.
- You MUST update `assets/deeplink.js`, `qr.html`, and `tests/deeplink.test.js` together when a tag or field changes.
- You MUST generate golden URIs with the server reference implementation (`scripts/config_to_deeplink.py` in `TrustTunnel/TrustTunnel`) when adding a new field.
- You MUST keep `assets/deeplink.js` free of DOM access. DOM code belongs in `qr.html`.
- You MUST escape user-controlled values with `escapeHtml` before inserting them into the page, and the site MUST NOT send configuration data to a server.
- You MUST keep the QR page downloadable: `qr.html` inlines `assets/deeplink.js` when the download action runs.
- You MUST not add a build step, bundler, or npm runtime dependency unless the change requires it.
- When making changes to the project structure, ensure the Project Structure section in this file is updated and remains valid.
- If a prompt asks for a refactoring or improvement, add the resulting rule to the relevant Code Guidelines section of this file.
- After completing a task, verify the written code against the Code Guidelines in this file.

## Code Guidelines

### System Design

- The site is static and is served from GitHub Pages. There is no server runtime, database, or API.
- Marketing and privacy pages MUST remain readable without JavaScript. `qr.html` is an interactive tool and requires JavaScript.
- Keep the site dependency-light and fast. Prefer plain HTML and vanilla JavaScript over new frameworks or build tooling.
- The site is a consumer of the deep-link format. The public `TrustTunnel/TrustTunnel` repository owns the format and its reference implementations.

### Architecture

The site has three layers:

| Layer | Responsibility | Examples |
| --- | --- | --- |
| Pages | Presentation, forms, QR rendering | `index.html`, `privacy.html`, `qr.html` |
| Codec | `tt://?` URI encoding and decoding, TLV, base64url, varint, certificate conversion | `assets/deeplink.js` |
| Tests | Codec behavior and golden vectors | `tests/deeplink.test.js` |

```text
pages  →  assets/deeplink.js  →  (browser APIs)
tests  →  assets/deeplink.js
```

- `assets/deeplink.js` MUST NOT access the DOM. It exposes a UMD-style module for browsers and Node.js.
- `qr.html` owns all DOM interaction: reading form values, rendering configuration details, and drawing the QR code.
- Format knowledge (tag numbers, value encodings, defaults, field order) is duplicated between the site codec and the public server implementation. The manual conformance check in the Contribution Instructions is mandatory.
- The site omits `tls_profile` when it equals the default `TLS_PROFILE_CHROME` (wire value `0x00`). The server reference emits any explicitly present `tls_profile`. This omission is an intentional site-level canonicalization; do not treat it as a tag mismatch.

### Code Quality

- Browser code uses `var` and `function` declarations. Do not introduce ES modules or a bundler for `assets/deeplink.js`.
- Throw `Error` objects with user-facing messages from the codec. `qr.html` catches them and passes the message to `showError`.
- Use `escapeHtml` for every value inserted into the DOM.
- Use the deep-link field names (`hostname`, `addresses`, `custom_sni`, `client_random_auth_key`, `tls_profile`, and so on) as the configuration keys in the codec and in `qr.html`.
- `tls_profile` values are the frozen `TLS_PROFILE_*` objects (`{ id, label }`) from `assets/deeplink.js`. `TLS_PROFILES` is the only list of profiles: `qr.html` builds the select options and the display labels from it. Do not add profile names or labels in other places.
- Keep helpers small and local. Do not add abstractions with a single caller.

### Testing

- Tests use `node:test` and `node:assert/strict`, and live in `tests/deeplink.test.js`.
- Golden URIs MUST come from the server reference encoder, not from the site codec.
- When adding a field, update `assertConfigEqual` and `minimalDecoded`, add a golden URI, and add a round-trip test.
- Cover defaults, unknown tags, malformed payloads, version handling, and legacy `tt://` links.
- Run `npm test` with Node.js 26 to match CI.

### Dependency Management

- Do not add npm dependencies without a clear need. The codec and tests use only browser and Node.js built-ins.
- Pin CDN script versions. QRious is pinned to `4.0.2`; the unpinned Tailwind CDN URL in `qr.html` is a known exception.
- Do not add a bundler, transpiler, or CSS framework beyond the existing Tailwind CDN.

### Configuration & Documentation

- The site has no runtime configuration, environment variables, or secrets.
- The deep-link format source of truth is the public `TrustTunnel/TrustTunnel` repository: `DEEP_LINK.md`, `deeplink/src/types.rs`, `deeplink/src/encode.rs`, and `deeplink/src/decode.rs`.
- Update the affected HTML page when a user-visible page changes. There is no README or CHANGELOG in this repository.
- Deployment runs through `.github/workflows/static.yml`. Tests run through `.github/workflows/test.yml`.

### Other

- `qr.html` is designed to be downloaded and used offline. Any new browser asset it needs MUST be handled by the download path that inlines `assets/deeplink.js`.
- Never send, log, or persist a user's configuration, credentials, or subscription URL outside the browser.
