# Relay — Unified Inbox

Relay is a full-stack unified inbox. The frontend lives in the repository root; the production backend is in `server/`.

## What is real
- Gmail connection uses Google's OAuth flow — Relay never asks for the user's Gmail password.
- Gmail inbox messages are loaded through the Gmail API after consent.
- Gmail replies are sent through the Gmail API.
- Phone ownership can be verified through Twilio Verify.
- OAuth tokens are encrypted at rest with AES-256-GCM.
- Sessions use an HTTP-only signed cookie.

## Important phone/SMS limitation
A normal website cannot read a person's carrier SMS history just because they typed a phone number. iOS/Android and mobile carriers do not expose that private inbox to arbitrary websites. The phone field here verifies ownership. To make SMS conversations genuinely available, Relay needs a messaging provider/number it controls (for example a Twilio number) or a companion mobile app with the appropriate OS permissions.

## Run locally
```bash
cd server
cp .env.example .env
npm install
npm start
```

Then open `http://localhost:3000`.

Create a Google OAuth web application and set its redirect URI to:
`http://localhost:3000/auth/gmail/callback`

Generate a 32-byte encryption key for `APP_ENCRYPTION_KEY` and put it in the environment as 64 hexadecimal characters. Never commit `.env` or OAuth secrets.

## Production
`render.yaml` is included for deployment as a Node web service. Set the environment variables in the hosting provider, including the public Gmail callback URL:
`https://YOUR-SERVICE.example/auth/gmail/callback`

The same service serves both the frontend and backend, so the deployed app is one real website instead of a GitHub Pages static mock.
