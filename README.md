# Kigali Car Rent Backend

NestJS API for the Kigali Car Rent website. The frontend is maintained in
[EllaHervee/kigali-car-rent-frontend](https://github.com/EllaHervee/kigali-car-rent-frontend).

## Configure

Set these environment variables in the backend host:

- `DATABASE_URL`: pooled Neon PostgreSQL connection string.
- `ADMIN_PASSWORD`: private admin password of at least 12 characters.
- `NODE_ENV=production`.
- Mobile Money provider credentials when payments are enabled.

The API initializes its PostgreSQL state table on the first request.

## Run and verify

```powershell
npm install
npm run start:dev
npm test
npm run build
```
