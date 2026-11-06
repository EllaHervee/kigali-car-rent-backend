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
- `RESEND_API_KEY`: Resend API key used to deliver verification and reset emails.
- `AUTH_EMAIL_FROM`: a sender address verified in Resend.
- `FRONTEND_URL`: public frontend URL used to create email links.
- `NODE_ENV=production`.
- Mobile Money provider credentials when payments are enabled.

The API initializes its PostgreSQL state table on the first request and seeds
the 30-car catalog when the database has no cars. Existing fleet records are
preserved. Set `DATABASE_URL` as a private environment variable in Render; do
not commit the connection string.

Users can sign up using an email address or Rwanda phone number. Password-based
accounts must verify their email before logging in. The same email delivery
settings are required for verification links and password reset links. If email
delivery is not configured, set `RESEND_API_KEY` and `AUTH_EMAIL_FROM` in the
Render service and use a sender address verified in Resend. Set `FRONTEND_URL`
to the deployed frontend's public origin so email links return to the site.

Customers can request a password reset from the login dialog. Reset links expire
after one hour and can be used once.

Admins use the same login form with `ADMIN_EMAIL` and `ADMIN_PASSWORD`; a
successful admin login opens the dashboard.
Customers can permanently delete their account from their signed-in account
page. Account deletion keeps existing booking and payment records.

## Run and verify

```powershell
npm install
npm run start:dev
npm test
npm run build
```
