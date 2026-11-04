# Kigali Car Rent Backend

NestJS API for the Kigali Car Rent website. The frontend is maintained in
[EllaHervee/kigali-car-rent-frontend](https://github.com/EllaHervee/kigali-car-rent-frontend).

## Configure

For local development, fill in `backend/.env` with your private values. That
file is ignored by Git. Render does not read this local file; set production
values in the Render service's Environment page.

Set these environment variables in the backend host:

- `DATABASE_URL`: pooled Neon PostgreSQL connection string.
- `ADMIN_EMAIL`: administrator email address.
- `ADMIN_PASSWORD`: private admin password of at least 12 characters.
- `NODE_ENV=production`.
- `EMAIL_PROVIDER=smtp` to send verification emails over SMTP.
- `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=465`, and `SMTP_SECURE=true` for Gmail.
- `SMTP_USER`: the Gmail account used to send messages.
- `SMTP_PASS`: private Google App Password for that account (not the regular Google password).
- `EMAIL_FROM`: sender address authorized for that Gmail account.
- `APP_BASE_URL`: public HTTPS origin of the frontend.
- Mobile Money provider credentials when payments are enabled.

The API initializes its PostgreSQL state table on the first request and seeds
the 30-car catalog when the database has no cars. Existing fleet records are
preserved. Set `DATABASE_URL` as a private environment variable in Render; do
not commit the connection string.

Email-based sign-ups remain pending until the recipient opens the one-time
verification link, which expires after 24 hours. Phone-based sign-ups continue
without email verification. For Gmail, enable 2-Step Verification and create
an App Password in your Google Account. Set `SMTP_PASS` as a private
environment variable in Render; never commit or share the App Password. The
verification email is sent from `SMTP_USER` to the address entered during
sign-up.

## Run and verify

```powershell
npm install
npm run start:dev
npm test
npm run build
```
