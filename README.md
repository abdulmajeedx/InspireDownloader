# InspireDownloader

A secure Flask-based admin-controlled landing page for an advanced TikTok video downloader. The backend serves a stylized HTML experience and offers a locked-down control panel so only the owner can adjust copy and theme in real-time.

## Features

<<<<<<< HEAD
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
=======
- **High-Quality Downloads**: Save TikTok videos in full HD without watermarks
- **Smart Link Recognition**: Automatically detects and processes TikTok URLs
- **Modern UI**: Dark neon design with customizable colors
- **Admin Panel**: Secure content management system
- **Multi-Language Support**: English and Arabic language support
- **No Login Required**: Direct downloads without authentication
- **Rapid Delivery**: Fast video processing and download

## Requirements

- Python 3.8+
- pip

## Installation

1. Clone the repository:
```bash
git clone https://github.com/abdulmajeedx/InspireDownloader.git
cd InspireDownloader
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your values
```

Generate your admin password hash:
```python
from werkzeug.security import generate_password_hash
print(generate_password_hash("your-strong-password"))
```

4. Compile translations:
```bash
pybabel compile -d translations
```

## Running the Application

Start the development server:
```bash
python3 app.py
```

The application will be available at `http://localhost:8000` (or the port specified in your .env file).

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

```env
APP_SECRET_KEY=your-secret-key-here
ADMIN_USERNAME=your_admin_user
ADMIN_PASSWORD_HASH=your-password-hash-here
PORT=8000
```

### Customization

Access the admin panel at `/admin` to customize:
- Application name
- Colors (primary, accent, background)
- Feature descriptions
- UI text

## Language Support

The application supports English and Arabic languages. Use the language switcher in the footer or add `?lang=en` or `?lang=ar` to the URL.

### Adding New Translations

1. Extract new strings:
```bash
pybabel extract -F babel.cfg -o messages.pot .
```

2. Update translation files:
```bash
pybabel update -i messages.pot -d translations
```

3. Edit the `.po` files in `translations/[lang]/LC_MESSAGES/`

4. Compile translations:
```bash
pybabel compile -d translations
```

## Security

- Admin panel protected by secure password hashing
- Login attempt limiting with temporary lockouts
- Security headers (CSP, X-Frame-Options, etc.)
- Session-based authentication

## License

This project is licensed under the same license as specified in the repository.

## Contributing

Feel free to submit issues and enhancement requests!
>>>>>>> 04f587f (Add multi-language support with Flask-Babel)
