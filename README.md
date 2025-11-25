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

## Customizing Content

- Sign in to `/admin` and adjust fields (app name, hero copy, CTA, placeholder, colors, and feature bullets).
- Submitted values persist to `content_config.json`; the landing page consumes them immediately.

## Security Notes

- Login attempts lock for 10 minutes after 5 failures.
- Security headers restrict framing, mixed content, and script sources.
- Always serve via HTTPS (Cloudflare Tunnel handles TLS for you).

Enjoy building your advanced TikTok downloader experience!
