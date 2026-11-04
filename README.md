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
- Mobile Money provider credentials when payments are enabled.

The API initializes its PostgreSQL state table on the first request and seeds
the 30-car catalog when the database has no cars. Existing fleet records are
preserved. Set `DATABASE_URL` as a private environment variable in Render; do
not commit the connection string.

Users can sign up and log in using either their email address or Rwanda phone
number. Email verification is disabled.

Admins use the same login form with `ADMIN_EMAIL` and `ADMIN_PASSWORD`; a
successful admin login opens the dashboard.
Customers can update their display name from their signed-in account page.

## Run and verify

```powershell
npm install
npm run start:dev
npm test
npm run build
```
