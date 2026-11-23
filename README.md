# Private Portal + Instagram Connection

This starter app provides:
- Member registration and login for **your own website**
- Password hashing with bcrypt (passwords are never shown to admins)
- An admin-only member directory
- Instagram authorization through Meta's official Instagram Login flow
- Server-side storage of the authorized account's access token
- CSRF checks, login rate limiting, secure session cookies in production, and security headers

## Important Instagram limitation

The Instagram API with Instagram Login is intended for eligible **Instagram professional (Business or Creator) accounts**. It does not provide general password access or a way to retrieve a user's Instagram password. Personal-account support is not guaranteed. See Meta's official docs:
- https://developers.facebook.com/docs/instagram/platform/instagram-api/
- https://developers.facebook.com/docs/instagram/platform/instagram-api/reference/ig-user/

## Run locally

1. Install Node.js 20 or newer.
2. In this folder run `npm install`.
3. Copy `.env.example` to `.env`.
4. Set a long random `SESSION_SECRET`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`.
5. Run `npm start`.
6. Open `http://localhost:3000`.

The administrator account is created on first startup. Keep `.env` private.

## Configure Instagram / Meta

1. Create/configure an app in Meta for Developers and add the Instagram API with Instagram Login product.
2. Configure the Instagram OAuth redirect URI to exactly match `META_REDIRECT_URI`.
3. Add the app ID and app secret to `.env`.
4. Set `BASE_URL` and `META_REDIRECT_URI` to your deployed HTTPS domain before production.
5. Ensure the permissions and app review / access requirements match your intended users and use case.

This implementation requests only `instagram_business_basic` and displays the authorized professional account's username. Meta may require app roles/testers or app review before people outside the app roles can authorize.

## Deploy

Deploy the Node app to a host that supports persistent storage, HTTPS, environment variables, and Node 20+. The `data/` directory contains SQLite database and session files, so use persistent disk storage. For a multi-instance deployment, replace SQLite/session storage with managed PostgreSQL and a shared session store.

## Security checklist before public launch

- Use HTTPS and set `NODE_ENV=production`.
- Use a unique, long `SESSION_SECRET`.
- Use a unique admin password and protect the hosting account.
- Keep `.env` and Meta app secret out of source control.
- Restrict admin access and add account recovery / email verification before opening registration publicly.
- Add token encryption at rest and a documented token deletion/retention policy before storing real users' tokens.
- Review Meta Platform Terms and privacy requirements; publish a privacy policy and obtain informed consent.
- Do not ask users for their Instagram password. Authorization must happen on Instagram/Meta's own domain.

This is a starter project, not a security audit or a one-click hosted website. You still need to configure a Meta developer app and deploy it to obtain a public URL.
