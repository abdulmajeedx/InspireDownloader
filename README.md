# InspireDownloader

A modern TikTok video downloader with a customizable interface, multi-language support, and secure admin control panel.

## Features

- **High-Quality Downloads**: Save TikTok videos in full HD without watermarks
- **Smart Link Recognition**: Automatically detects and processes TikTok URLs
- **Quality Selection**: Choose between 720p, 1080p, 4K, or best quality
- **Modern UI**: Dark neon design with customizable colors
- **Admin Panel**: Secure content management system
- **Multi-Language Support**: English and Arabic with RTL support
- **Performance**: Redis caching for faster responses
- **Security**: Rate limiting to prevent abuse
- **No Login Required**: Direct downloads without authentication
- **Rapid Delivery**: Fast video processing and download

## Requirements

- Python 3.8+
- pip
- Redis (optional, for caching and rate limiting)

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

5. (Optional) Start Redis for caching and rate limiting:
```bash
# Ubuntu/Debian
sudo apt install redis-server
sudo systemctl start redis

# Or with Docker
docker run -d -p 6379:6379 redis:latest
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
REDIS_URL=redis://localhost:6379/0
```

### Customization

Access the admin panel at `/admin` to customize:
- Application name
- Colors (primary, accent, background)
- Feature descriptions
- UI text

## Language Support

The application supports English and Arabic languages. Use the language switcher in the footer or add `?lang=en` or `?lang=ar` to the URL.

### RTL Support

Arabic language includes full RTL support with:
- Proper text direction (`dir="rtl"`)
- RTL-specific fonts (Noto Sans Arabic)
- Adjusted layouts for right-to-left reading
- Proper alignment for Arabic text

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

## Performance Features

### Caching

When Redis is available, the application caches:
- Video metadata for 1 hour
- Reduces API calls to TikTok
- Improves response times for repeated downloads

### Rate Limiting

When Redis is available, rate limiting is enforced:
- 200 requests per day per IP
- 50 requests per hour per IP
- 10 download requests per minute per IP

## Security

- Admin panel protected by secure password hashing
- Login attempt limiting with temporary lockouts
- Security headers (CSP, X-Frame-Options, etc.)
- Session-based authentication
- Rate limiting to prevent abuse

## License

This project is licensed under the same license as specified in the repository.

## Contributing

Feel free to submit issues and enhancement requests!
