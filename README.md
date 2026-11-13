# letthedevcook
website made by cnrcftc

## Multix device sign-in

The static website is hosted with GitHub Pages. The Multix sign-in page is `signin.html`.
The Node.js API lives in `auth-server/` and must run as a separate HTTPS web service.
GitHub Pages cannot run the Node.js backend.

### Backend setup

1. Use Node.js 20 or newer.
2. Open `auth-server/` and run `npm install`.
3. Copy `.env.example` to `.env` and fill in the Google Web Client ID and a generated session signing key.
4. Deploy `auth-server/` to a Node.js host with HTTPS.
5. Set `API_BASE_URL` and `GOOGLE_CLIENT_ID` in the inline script in `signin.html`.
6. Set `AUTH_API_HOST` in the Multix C++ source to the backend hostname, without the scheme.
7. Rebuild Multix after changing its auth host.

See [auth-server/README.md](auth-server/README.md) for the complete setup and security notes.

Do not commit `.env` or place a Google client secret in the website code.
