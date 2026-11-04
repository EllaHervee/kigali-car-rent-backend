# Kigali Car Rent Backend

NestJS API for the Kigali Car Rent website. The frontend is maintained in
[EllaHervee/kigali-car-rent-frontend](https://github.com/EllaHervee/kigali-car-rent-frontend).

## Configure

Set these environment variables in the backend host:

- `DATABASE_URL`: pooled Neon PostgreSQL connection string.
- `ADMIN_EMAIL`: administrator email address.
- `ADMIN_PASSWORD`: private admin password of at least 12 characters.
- `NODE_ENV=production`.
- `RESEND_API_KEY`: private API key for sending verification emails through Resend.
- `EMAIL_FROM`: sender address verified with Resend, such as `Kigali Car Rent <no-reply@your-domain.com>`.
- `APP_BASE_URL`: public HTTPS origin of the frontend, such as `https://your-site.vercel.app`.
- Mobile Money provider credentials when payments are enabled.

The API initializes its PostgreSQL state table on the first request and seeds
the 30-car catalog when the database has no cars. Existing fleet records are
preserved. Set `DATABASE_URL` as a private environment variable in Render; do
not commit the connection string.

Email-based sign-ups remain pending until the recipient opens the one-time
verification link, which expires after 24 hours. Phone-based sign-ups continue
without email verification. Verify the sender domain in Resend, then configure
the three email variables in Render. Keep API keys private and never commit
them.

## Run and verify

```powershell
npm install
npm run start:dev
npm test
npm run build
```
