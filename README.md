# InspireDownloader

A secure Flask-based admin-controlled landing page for an advanced TikTok video downloader. The backend serves a stylized HTML experience and offers a locked-down control panel so only the owner can adjust copy and theme in real-time.

## Features

- **Python Flask backend** with environment-protected admin routes and strict login lockout.
- **Dynamic content management** stored in `content_config.json`, editable through the admin dashboard.
- **Modern, dark neon front-end** crafted with HTML + CSS (Manrope typeface, gradients, glassmorphism accents).
- **Security headers + .env loading** out of the box.

## Getting Started

1. **Create and activate a virtual environment** (Python 3.11+ recommended):

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Prepare environment variables** (e.g. in `.env`):

   ```env
   APP_SECRET_KEY=generate_a_long_random_value
   ADMIN_USERNAME=your_admin_name
   ADMIN_PASSWORD_HASH=pbkdf2:sha256:...  # see below
   ```

   Generate a password hash safely using Python:

   ```bash
   python3 - <<'PY'
   from werkzeug.security import generate_password_hash
   print(generate_password_hash("your-strong-password"))
   PY
   ```

4. **Run the app**:

   ```bash
   flask --app app run --host 0.0.0.0 --port 8000
   ```

   The landing page lives at `http://localhost:8000/`. The admin panel is at `/admin` (login) and `/admin` (dashboard once authenticated).

### Environment configuration for GitHub clones

- Copy `.env.example` to `.env` and replace every placeholder with your secrets (see the example file for required variables).
- Never commit the `.env` file or real credentials.
- The repository includes `setup_cloudflare_tunnel.sh` for quickly bootstrapping a Cloudflare Tunnel (see below).

## Cloudflare Tunnel Integration (inspiredownloader.majictab.com)

Expose the application securely without opening firewall ports using [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/tunnel-guide/remote/). The steps below assume that:

- `majictab.com` is already added to your Cloudflare account (as an **orange-cloud** proxied zone).
- You have permission to create subdomains and tunnels.

1. **Install `cloudflared`** on the host that runs the Flask app, then authenticate with Cloudflare. Log in using the same account that manages `majictab.com`:

   ```bash
   cloudflared login
   ```

   Cloudflare will open a browser window; select `majictab.com`. This stores a cert in `~/.cloudflared/cert.pem`.

2. **Create a named tunnel** dedicated to the downloader (name can be anything, here we keep `inspiredownloader`):

   ```bash
   cloudflared tunnel create inspiredownloader
   ```

   Cloudflare returns a UUID and writes credentials to `~/.cloudflared/inspiredownloader.json`. Keep this file private.

3. **Configure routing** so the tunnel serves `https://inspiredownloader.majictab.com` and forwards traffic to your local Flask server on `http://localhost:8000`.

   Create or update `~/.cloudflared/config.yml` with:

   ```yaml
   tunnel: inspiredownloader
   credentials-file: /home/<user>/.cloudflared/inspiredownloader.json

   ingress:
     - hostname: inspiredownloader.majictab.com
       service: http://localhost:8000
     - service: http_status:404
   ```

4. **Publish DNS record automatically**. Cloudflare can create the CNAME for you via:

   ```bash
   cloudflared tunnel route dns inspiredownloader inspiredownloader.majictab.com
   ```

   Alternatively, add a CNAME record in the Cloudflare dashboard (`inspiredownloader` → `UUID.cfargotunnel.com`) with the proxy toggled **on**.

5. **Run the tunnel** (leave this process running alongside Flask):

   ```bash
   cloudflared tunnel run inspiredownloader
   ```

   You can also create a systemd service so it restarts automatically; see Cloudflare docs for examples.

6. **Test the deployment**:

   - Start the Flask server locally: `flask --app app run --host 0.0.0.0 --port 8000`
   - Start the tunnel (step 5).
   - Visit `https://inspiredownloader.majictab.com/` in the browser. You should see the landing page served securely over HTTPS.

When you stop the Flask server or tunnel, Cloudflare will report 502 errors for the subdomain until both services are back online.

### Automating tunnel setup (optional)

To help documentation readers reproduce the setup, the project ships with `setup_cloudflare_tunnel.sh`. After installing `cloudflared` and completing `cloudflared login`, run:

```bash
chmod +x setup_cloudflare_tunnel.sh
./setup_cloudflare_tunnel.sh
```

Override defaults (tunnel name, hostname, local service) by exporting environment variables before running the script, e.g.:

```bash
TUNNEL_NAME=mytunnel HOSTNAME=sub.example.com LOCAL_SERVICE=http://localhost:9000 ./setup_cloudflare_tunnel.sh
```

The script validates prerequisites, creates the tunnel if needed, writes `~/.cloudflared/config.yml`, and registers the DNS route so documentation remains accurate.

## Customizing Content

- Sign in to `/admin` and adjust fields (app name, hero copy, CTA, placeholder, colors, and feature bullets).
- Submitted values persist to `content_config.json`; the landing page consumes them immediately.

## Security Notes

- Login attempts lock for 10 minutes after 5 failures.
- Security headers restrict framing, mixed content, and script sources.
- Always serve via HTTPS (Cloudflare Tunnel handles TLS for you).

Enjoy building your advanced TikTok downloader experience!
