import json
import os
import shutil
import tempfile
import time
from functools import wraps
from pathlib import Path

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


def download_tiktok_video(url: str) -> tuple[Path, Path, dict]:
    temp_dir = Path(tempfile.mkdtemp(prefix="tikdl_"))
    options = {
        "quiet": True,
        "no_warnings": True,
        "restrictfilenames": True,
        "outtmpl": str(temp_dir / "%(id)s.%(ext)s"),
        "format": "mp4/bestvideo+bestaudio/best",
        "noplaylist": True,
        "geo_bypass": True,
    }

    try:
        with YoutubeDL(options) as ydl:
            info = ydl.extract_info(url, download=True)
        video_id = info.get("id", "")
        candidates = list(temp_dir.glob(f"{video_id}.*")) if video_id else list(temp_dir.glob("*") )
        if not candidates:
            raise RuntimeError("Download completed but video file was not found.")
        return candidates[0], temp_dir, info
    except Exception:
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

    def login_required(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not session.get("is_admin"):
                flash("You must sign in to access this page.", "warning")
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

    @app.route("/", methods=["GET", "POST"])
    def landing_page():
        content = load_content()
        download_url = ""

        if request.method == "POST":
            download_url = request.form.get("video_url", "").strip()

            if not download_url:
                flash("Please paste a TikTok link before downloading.", "danger")
            elif "tiktok.com" not in download_url:
                flash("Only TikTok video URLs are supported at the moment.", "warning")
            else:
                try:
                    video_path, temp_dir, info = download_tiktok_video(download_url)
                except DownloadError as err:
                    flash("Unable to download this TikTok link. Please verify the URL.", "danger")
                except Exception:
                    flash("Unexpected error while downloading. Try again shortly.", "danger")
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

        return render_template("index.html", content=content, download_url=download_url)

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
            flash(f"Account temporarily locked. Try again in {remaining} seconds.", "danger")
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
                flash("Too many failed attempts. Login locked for 10 minutes.", "danger")
            else:
                attempts_left = MAX_LOGIN_ATTEMPTS - session["login_attempts"]
                flash(
                    f"Invalid credentials. {attempts_left} attempt(s) remaining before lockout.",
                    "danger",
                )
        return render_template("admin_login.html", content=content)

    @app.route("/admin/logout")
    @login_required
    def admin_logout():
        session.clear()
        flash("Signed out successfully.", "success")
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
                    flash(f"{label} must be a valid HEX code (e.g., #112233).", "danger")
                    return render_template(
                        "admin_dashboard.html",
                        content=draft_content,
                        feature_points_text=feature_points_text,
                    )

            if not app_name.strip():
                flash("Application name cannot be empty.", "danger")
                return render_template(
                    "admin_dashboard.html",
                    content=draft_content,
                    feature_points_text=feature_points_text,
                )

            updated_content = {key: value.strip() if isinstance(value, str) else value for key, value in draft_content.items()}

            persist_content(updated_content)
            flash("Content updated successfully.", "success")
            return redirect(url_for("admin_dashboard"))

        return render_template(
            "admin_dashboard.html", content=content, feature_points_text=feature_points_text
        )

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
