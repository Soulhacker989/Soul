# RennMatrix License Panel (Flask + SQLite)

This package connects the supplied `index.html` panel to a server-side API. It includes license-key storage, expiry/device-limit checks, session heartbeat, script storage, admin-token protection, and reseller login endpoints expected by the current panel UI.

## Important security setup

1. Use HTTPS in production.
2. Set a strong `ADMIN_TOKEN` environment variable on your host. Generate one with:
   `python -c "import secrets; print(secrets.token_urlsafe(48))"`
3. In the panel's API settings, enter your deployed API URL and the exact same admin token. Never publish the admin token in a public repository or share it with resellers.
4. Back up `panel.sqlite3`. On PythonAnywhere, store it at a persistent path under your home directory and set `PANEL_DB` to that path.
5. The HTML panel stores its own UI settings in browser localStorage. Do not treat browser-side login as a security boundary; the backend token is the actual admin API guard.

## Local test

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
export ADMIN_TOKEN="paste-a-long-random-secret-here"
python app.py
```

Open `http://127.0.0.1:5000`. In panel settings, set API URL to `http://127.0.0.1:5000` and Admin token to the value of `ADMIN_TOKEN`. (For production, use HTTPS.)

## PythonAnywhere deployment (WSGI)

1. Upload this folder to your PythonAnywhere home directory, e.g. `/home/YOURUSERNAME/rennmatrix_panel`.
2. Create a virtualenv and install dependencies: `pip install -r requirements.txt`.
3. In the Web tab, create a Flask app or configure a manual WSGI app; point the WSGI file to this folder's `wsgi.py`.
4. Edit the WSGI file/environment configuration so `ADMIN_TOKEN` is set to a strong random value before importing `app`. Example at the top of the WSGI file (replace the value; do not commit it):
   `os.environ['ADMIN_TOKEN'] = 'YOUR_LONG_RANDOM_SECRET'`
5. Set `PANEL_DB` to a persistent path such as `/home/YOURUSERNAME/panel.sqlite3` so database files survive code updates.
6. Reload the web app. In the panel's API settings, use the deployed HTTPS URL and the same admin token.

## API routes

- `GET /api/ping`
- `POST /api/auth` with `{ "key": "...", "hwid": "..." }`
- `POST /api/heartbeat` with `{ "sess": "..." }`
- `POST /api/payload` with `{ "token": "..." }`; `GET /api/payload` with `Authorization: Bearer ...` is also accepted
- Admin: `/api/admin/state`, `/api/admin/key`, `/api/admin/key/<code>`, `/api/admin/sync`, `/api/admin/meta`, `/api/admin/script/<name>`
- Reseller: `/api/rs/login`, `/api/rs/state`, `/api/rs/key`

## Notes / limitations

- The supplied panel UI's first-run login is stored in localStorage; it is not server-side account authentication. Use a trusted device and protect the backend admin token.
- Reseller credentials are currently read from the panel's reseller metadata, which the supplied UI stores in its existing format. For a public multi-user product, the next step should be moving reseller accounts to dedicated password-hash records and adding rate limiting/audit logs.
- The generated loader template inside the HTML contains placeholder HTTP functions. It will not run until you implement those functions for your specific Lua runtime. The existing `main.lua` has its own networking code; test it against the API only in an environment you control.
- Only upload Lua scripts you own or are authorized to distribute.
