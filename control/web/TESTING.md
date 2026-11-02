# Browser interface checks

The panel has no build step. `app.js` imports `managed.js` as a browser module.

Run the cryptographic round-trip, exact-payload, fresh-key/IV and authenticated-field tamper checks with Node.js providing WebCrypto:

```sh
node --test control/web/test-managed.mjs
```

For the real Chromium interface checks, provide an installed Playwright module and its browser. An existing compatible Chromium executable can be selected separately:

```sh
PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs \
CHROMIUM_EXECUTABLE=/path/to/chromium \
node control/web/test-managed.mjs --browser
```

The script starts a temporary loopback HTTP fixture. It decrypts browser-produced envelopes with a fixture RSA key, validates metadata and secret sentinels, and exercises the REST wizard, queued-job polling, exact restore, schedule, readiness, controlled activation, subsequent protection check, S3 failure, expiry, identical network retry, persistent guarded resume, bilingual desktop/mobile layouts and existing demo routes. `UI_SCREENSHOT_DIR` optionally saves synthetic interface screenshots to a chosen local directory.

This transport simulates backend results. These checks do not establish real Docker behavior, storage-provider authentication, TLS/DNS restrictions, source interruption recovery, data/image preservation, persistent timers or live two-host acceptance. Run the Python regression suite and the separately specified integration acceptance before release.
