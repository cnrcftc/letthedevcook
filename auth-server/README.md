# Multix auth server

This is the Node.js backend used by Multix device pairing. It does not use Supabase or an external database.

## Local setup

Use Node.js 20 or newer:

```powershell
npm install
Copy-Item .env.example .env
```

Generate a signing key:

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Paste the 64-character value into `SESSION_SIGNING_KEY` in `.env`. Set `GOOGLE_CLIENT_ID` to a Google OAuth 2.0 Web application client ID.

Run:

```powershell
npm start
```

Check `http://localhost:3000/health`. It should return `{"ok":true,"service":"multix-auth"}`.

## Google configuration

In Google Cloud Console, create an OAuth 2.0 Client ID of type **Web application**. Add this exact Authorized JavaScript origin:

- `https://cnrcftc.github.io`

Use the same client ID in both `.env` and the inline configuration in the root `signin.html`. The client ID is public. Do not put a Google client secret in `signin.html`.

## Deployment

Deploy this folder as a Node.js web service on a host that supports Node.js 20+ and HTTPS. Set the variables from `.env.example` in the host's environment settings. Do not upload `.env` to GitHub.

After deployment:

- Set `API_BASE_URL` in `signin.html` to the backend's public HTTPS URL.
- Set `AUTH_API_HOST` in Multix's `main.cpp` to the backend hostname only, without `https://` or a trailing slash.
- Rebuild the Windows app.

The site remains at `https://cnrcftc.github.io/letthedevcook/`; the pairing page is `/signin.html`.

## Pairing flow

1. Multix calls `POST /api/pairings` and receives an ID, an 8-digit code, and a private polling token.
2. Multix opens `signin.html?code=12345678`. The user may open the same page on another device and enter the code manually.
3. Google Identity Services returns an ID token to the page.
4. The backend verifies the Google ID token, its audience, expiry, verified-email flag, and nonce.
5. The website approves the pairing. It never receives the polling token or Multix session token.
6. Multix polls `GET /api/pairings/:id/status`, receives a signed 30-day session, and saves it with Windows DPAPI.
7. Multix checks saved sessions with `GET /api/me` and signs out through `POST /api/logout`.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/api/pairings` | Create device pairing |
| POST | `/api/pairings/approve` | Approve using Google ID token |
| GET | `/api/pairings/:id/status` | Poll with private pairing token |
| POST | `/api/pairings/:id/complete` | Confirm session delivery |
| GET | `/api/me` | Validate a saved session |
| POST | `/api/logout` | Revoke a session until server restart |

## Persistence and security limits

Pairings and revocation records are kept in memory. A server restart cancels pending pairings and clears the in-memory revocation list. Signed sessions remain valid for up to 30 days while the signing key stays unchanged. Use one backend instance; this in-memory version is not suitable for multiple instances or horizontal scaling.

The backend uses HTTPS deployment, exact website-origin checks, request rate limits, Google ID-token verification, one-time 8-digit codes, and HMAC-SHA-256 session signatures. The desktop app stores its session with Windows DPAPI. Do not send Roblox account cookies or `.ROBLOSECURITY` values to this backend.
