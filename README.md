# Aura Table Website

## Start Website With Backend

Double-click:

```text
start-server.bat
```

Then open:

```text
http://localhost:3400
```

Admin panel:

```text
http://localhost:3400/admin.html
```

Local admin login:

```text
Username: admin
Password: change-this-password
```

Do not open `admin.html` directly from the folder or with Live Server, because the admin panel needs the Node backend API.

## Vercel Frontend + Separate Backend

If the frontend is on Vercel and the backend is on Render/Railway, edit `config.js` before deploying:

```js
window.AURA_API_BASE = "https://your-backend-url.onrender.com";
```

Then open:

```text
https://your-vercel-site.vercel.app/admin.html
```
