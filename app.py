import json
import os
import shutil
import tempfile
import time
from functools import wraps
from pathlib import Path

from babel import Locale
from dotenv import load_dotenv
from flask import (
    Flask,
    after_this_request,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_babel import Babel, gettext as _, ngettext, get_locale
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from yt_dlp import YoutubeDL
from yt_dlp.utils import DownloadError

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "content_config.json"
LOCKOUT_SECONDS = 600
MAX_LOGIN_ATTEMPTS = 5


DEFAULT_CONTENT = {
    "app_name": "InspireDownloader",
    "hero_title": "Advanced TikTok Video Downloader",
    "hero_subtitle": "Save TikTok videos in high quality with smart link recognition, metadata enrichment, and rapid delivery.",
    "primary_color": "#7B4BFF",
    "background_color": "#090E1A",
    "accent_color": "#17F1D1",
    "cta_text": "Download Now",
    "input_placeholder": "Paste your TikTok link here...",
    "feature_points": [
        "AI-powered link analysis to auto-detect best media quality",
        "Batch downloads with smart queueing and progress tracking",
        "Built-in privacy shield to strip watermarks & tracking codes",
    ],
}


def load_content() -> dict:
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open("r", encoding="utf-8") as config_file:
            try:
                data = json.load(config_file)
                if isinstance(data, dict):
                    merged = DEFAULT_CONTENT.copy()
                    merged.update(data)
                    return merged
            except json.JSONDecodeError:
                pass
    return DEFAULT_CONTENT.copy()


def persist_content(payload: dict) -> None:
    with CONFIG_PATH.open("w", encoding="utf-8") as config_file:
        json.dump(payload, config_file, ensure_ascii=False, indent=2)


def download_tiktok_video(url: str, quality: str = "best") -> tuple[Path, Path, dict]:
    """Download TikTok video with specified quality."""
    temp_dir = Path(tempfile.mkdtemp())
    video_path = temp_dir / "video.mp4"

    # Map quality to yt-dlp format strings
    quality_map = {
        "4k": "best[height<=2160]",
        "1080p": "best[height<=1080]",
        "720p": "best[height<=720]",
        "best": "best"
    }
    
    format_selector = quality_map.get(quality, "best")

    ydl_opts = {
        "format": format_selector,
        "outtmpl": str(video_path),
        "quiet": True,
        "no_warnings": True,
        "extract_flat": False,
    }

    with YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(url, download=True)
        return video_path, temp_dir, info.get("id", "")
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def is_valid_hex(color: str) -> bool:
    if not isinstance(color, str) or len(color) != 7 or not color.startswith("#"):
        return False
    try:
        int(color[1:], 16)
    except ValueError:
        return False
    return True


def require_env(var_name: str) -> str:
    value = os.getenv(var_name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable '{var_name}'. "
            "Set it in your environment or .env file before starting the app."
        )
    return value


def create_app() -> Flask:
    app = Flask(__name__)

    app.config["SECRET_KEY"] = require_env("APP_SECRET_KEY")
    admin_username = require_env("ADMIN_USERNAME")
    admin_password_hash = require_env("ADMIN_PASSWORD_HASH")

    # Redis configuration (optional)
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    try:
        redis_client = Redis.from_url(redis_url, decode_responses=True)
        # Test connection
        redis_client.ping()
    except Exception:
        # Fallback to in-memory storage if Redis is not available
        redis_client = None

    # Rate limiting (only if Redis is available)
    if redis_client:
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            storage_uri=redis_url,
            default_limits=["200 per day", "50 per hour"]
        )
    else:
        limiter = None

    # Babel configuration
    app.config["LANGUAGES"] = {"en": "English", "ar": "العربية"}
    app.config["BABEL_DEFAULT_LOCALE"] = "en"
    app.config["BABEL_DEFAULT_TIMEZONE"] = "UTC"

    def get_locale():
        # 1) Check URL parameter ?lang=xx
        if "lang" in request.args and request.args["lang"] in app.config["LANGUAGES"]:
            session["language"] = request.args["lang"]
        # 2) Check session
        if "language" in session and session["language"] in app.config["LANGUAGES"]:
            return session["language"]
        # 3) Check Accept-Language header
        return request.accept_languages.best_match(app.config["LANGUAGES"].keys(), app.config["BABEL_DEFAULT_LOCALE"])

    babel = Babel(app, locale_selector=get_locale)

    def login_required(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not session.get("is_admin"):
                flash(_("You must sign in to access this page."), "warning")
                return redirect(url_for("admin_login"))
            return view_func(*args, **kwargs)

        return wrapper

    @app.after_request
    def apply_security_headers(response):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "script-src 'self';",
        )
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        return response

    # Apply rate limiting decorator if available
    if limiter:
        @app.route("/", methods=["GET", "POST"])
        @limiter.limit("10 per minute")
        def landing_page():
            return landing_page_impl()
    else:
        @app.route("/", methods=["GET", "POST"])
        def landing_page():
            return landing_page_impl()

    def landing_page_impl():
        content = load_content()
        download_url = ""

        if request.method == "POST":
            download_url = request.form.get("video_url", "").strip()
            quality = request.form.get("quality", "best")
            
            # Check cache first (only if Redis is available)
            cache_key = f"tiktok:{download_url}:{quality}"
            cached_info = None
            if redis_client:
                cached_info = redis_client.get(cache_key)
            
            if not download_url:
                flash(_("Please paste a TikTok link before downloading."), "danger")
            elif "tiktok.com" not in download_url:
                flash(_("Only TikTok video URLs are supported at the moment."), "warning")
            else:
                try:
                    if cached_info and redis_client:
                        # Use cached metadata but still download the video
                        info = json.loads(cached_info)
                        video_path, temp_dir, _ = download_tiktok_video(download_url, quality)
                        # Update cache with fresh download info
                        redis_client.setex(cache_key, 3600, json.dumps(info))
                    else:
                        video_path, temp_dir, info = download_tiktok_video(download_url, quality)
                        # Cache the metadata for 1 hour (only if Redis is available)
                        if redis_client:
                            redis_client.setex(cache_key, 3600, json.dumps(info))
                except DownloadError as err:
                    flash(_("Unable to download this TikTok link. Please verify the URL."), "danger")
                except Exception:
                    flash(_("Unexpected error while downloading. Try again shortly."), "danger")
                else:
                    @after_this_request
                    def cleanup(response):
                        try:
                            if video_path.exists():
                                video_path.unlink()
                        finally:
                            shutil.rmtree(temp_dir, ignore_errors=True)
                        return response

                    title = info.get("title") or "tiktok-video"
                    download_name = secure_filename(f"{title}{video_path.suffix}") or f"download{video_path.suffix}"
                    return send_file(video_path, as_attachment=True, download_name=download_name)

        return render_template("index.html", content=content, download_url=download_url, get_locale=get_locale)

    @app.route("/api/content")
    def content_api():
        return jsonify(load_content())

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        locked_until = session.get("locked_until")
        current_time = time.time()
        content = load_content()
        if locked_until and current_time < locked_until:
            remaining = int(locked_until - current_time)
            flash(_("Account temporarily locked. Try again in %(seconds)s seconds.", seconds=remaining), "danger")
            return render_template("admin_login.html", content=content)

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if username == admin_username and check_password_hash(admin_password_hash, password):
                session.clear()
                session["is_admin"] = True
                session["login_attempts"] = 0
                return redirect(url_for("admin_dashboard"))

            session["login_attempts"] = session.get("login_attempts", 0) + 1
            if session["login_attempts"] >= MAX_LOGIN_ATTEMPTS:
                session["locked_until"] = current_time + LOCKOUT_SECONDS
                flash(_("Too many failed attempts. Login locked for 10 minutes."), "danger")
            else:
                attempts_left = MAX_LOGIN_ATTEMPTS - session["login_attempts"]
                flash(
                    _("Invalid credentials. %(count)s attempt(s) remaining before lockout.", count=attempts_left),
                    "danger",
                )
        return render_template("admin_login.html", content=content)

    @app.route("/admin/logout")
    @login_required
    def admin_logout():
        session.clear()
        flash(_("Signed out successfully."), "success")
        return redirect(url_for("admin_login"))

    @app.route("/admin", methods=["GET", "POST"])
    @login_required
    def admin_dashboard():
        content = load_content()
        feature_points_text = "\n".join(content.get("feature_points", []))

        if request.method == "POST":
            app_name = request.form.get("app_name", content["app_name"])
            hero_title = request.form.get("hero_title", content["hero_title"])
            hero_subtitle = request.form.get("hero_subtitle", content["hero_subtitle"])
            cta_text = request.form.get("cta_text", content["cta_text"])
            input_placeholder = request.form.get("input_placeholder", content["input_placeholder"])
            primary_color = request.form.get("primary_color", content["primary_color"])
            accent_color = request.form.get("accent_color", content["accent_color"])
            background_color = request.form.get("background_color", content["background_color"])
            feature_points_raw = request.form.get("feature_points", "")
            feature_points_text = feature_points_raw or feature_points_text

            draft_content = {
                "app_name": app_name,
                "hero_title": hero_title,
                "hero_subtitle": hero_subtitle,
                "cta_text": cta_text,
                "input_placeholder": input_placeholder,
                "primary_color": primary_color,
                "accent_color": accent_color,
                "background_color": background_color,
                "feature_points": [
                    point.strip()
                    for point in feature_points_raw.splitlines()
                    if point.strip()
                ]
                or content["feature_points"],
            }

            for color_value, label in (
                (primary_color, "Primary color"),
                (accent_color, "Accent color"),
                (background_color, "Background color"),
            ):
                if not is_valid_hex(color_value):
                    flash(_("%(label)s must be a valid HEX code (e.g., #112233).", label=label), "danger")
                    return render_template(
                        "admin_dashboard.html",
                        content=draft_content,
                        feature_points_text=feature_points_text,
                    )

            if not app_name.strip():
                flash(_("Application name cannot be empty."), "danger")
                return render_template(
                    "admin_dashboard.html",
                    content=draft_content,
                    feature_points_text=feature_points_text,
                )

            updated_content = {key: value.strip() if isinstance(value, str) else value for key, value in draft_content.items()}

            persist_content(updated_content)
            flash(_("Content updated successfully."), "success")
            return redirect(url_for("admin_dashboard"))

        return render_template(
            "admin_dashboard.html", content=content, feature_points_text=feature_points_text
        )

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8004)))
