# Aura Table Deployment

## Local development

```powershell
cd "F:\WEB DEV\projects\Demo Resturent Website"
npm install
npm run dev
```

Open `http://localhost:3000`.

## Production environment variables

Set these on Render, Railway, VPS, or your hosting panel:

```text
NODE_ENV=production
PORT=3000
WEB_CONCURRENCY=4
DATABASE_URL=postgres://user:password@host:5432/aura_table
ADMIN_USER=admin
ADMIN_PASSWORD=use-a-long-random-password
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=restaurant@example.com
SMTP_PASS=smtp-password
NOTIFY_FROM=restaurant@example.com
NOTIFY_TO=owner@example.com
FRONTEND_ORIGINS=https://your-vercel-site.vercel.app
```

For local testing, keep `NODE_ENV=development`. The default admin login is:

```text
Username: admin
Password: change-this-password
```

For production, never use the default password. Set a strong `ADMIN_PASSWORD`, otherwise login is blocked for safety.

## Database

The backend automatically creates tables on startup when `DATABASE_URL` is set. You can also run `database/schema.sql` manually in PostgreSQL.

## Admin panel

Open:

```text
/admin.html
```

Use `ADMIN_USER` and `ADMIN_PASSWORD`.

## Heavy traffic notes

Use PostgreSQL for production. Local JSON storage is only for development. Put the Node app behind Nginx or your platform load balancer, enable HTTPS, and use Cloudflare or platform rate limiting for extra protection.
