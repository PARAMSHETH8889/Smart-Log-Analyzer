"""
Smart Log Analyzer & Anomaly Detector - Application Entry Point.
"""

import os
from pathlib import Path
import click
from flask import Flask, render_template, request, jsonify

from config import config_by_name, Config
from models import db
from models.models import Log
from routes import dashboard_bp, logs_bp


def create_app(config_name: str = "default") -> Flask:
    """Application factory for Flask app."""
    app = Flask(__name__)
    cfg = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(cfg)

    # Ensure database and sample_data directories exist
    db_dir = Path(app.config.get("DB_PATH", Config.DB_PATH)).parent
    db_dir.mkdir(parents=True, exist_ok=True)
    Path(Config.SAMPLE_DATA_DIR).mkdir(parents=True, exist_ok=True)

    # Initialize extensions
    db.init_app(app)

    # Register blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(logs_bp)

    # Create tables
    with app.app_context():
        db.create_all()

    # HTTP Security Headers (OWASP Defense-in-Depth)
    @app.after_request
    def set_security_headers(response):
        # Prevent MIME type sniffing (stops executable script tricks disguised as images/text)
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent Clickjacking (disallow embedding within rogue external frames)
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        # Prevent URL/token leakage in the Referer header
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Restrict hardware permissions (camera, microphone, geolocation)
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        # Content Security Policy (permits verified CDNs for Bootstrap & Chart.js, Google Fonts, and self)
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self' https://*.supabase.co https://generativelanguage.googleapis.com; "
            "frame-ancestors 'self';"
        )
        response.headers["Content-Security-Policy"] = csp
        return response

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        if request.path.startswith(("/api/", "/upload")):
            return jsonify({
                "success": False,
                "message": "Endpoint not found.",
            }), 404
        return render_template("base.html", error_404=True), 404

    @app.errorhandler(413)
    def file_too_large(e):
        return jsonify({
            "success": False,
            "message": "File exceeds maximum allowed upload size (16 MB).",
        }), 413

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({
            "success": False,
            "message": "Too many requests. Please slow down.",
        }), 429

    @app.errorhandler(500)
    def internal_server_error(e):
        return jsonify({
            "success": False,
            "message": "Internal server error occurred. Please verify your log dataset schema.",
        }), 500

    @app.errorhandler(Exception)
    def handle_unexpected_exception(e):
        if request.path.startswith(("/api/", "/upload")):
            return jsonify({
                "success": False,
                "message": f"Server processing error: {str(e)}",
            }), 500
        return jsonify({"success": False, "message": "An unexpected server error occurred."}), 500

    # Custom CLI Commands
    @app.cli.command("init-db")
    def init_db_command():
        """Initialize local SQLite database tables."""
        with app.app_context():
            db.create_all()
            click.echo("[OK] Database tables initialized successfully.")

    @app.cli.command("seed")
    @click.option("--count", default=450, help="Number of records to generate")
    def seed_command(count):
        """Generate and seed synthetic logs into SQLite database."""
        from generate_sample_data import generate_logs, save_to_csv
        from services.log_parser import LogParser
        from services.anomaly_detector import AnomalyDetector

        csv_path = Config.SAMPLE_DATA_DIR / "sample_logs.csv"
        click.echo(f"[*] Generating {count} synthetic logs...")
        logs = generate_logs(count)
        save_to_csv(logs, csv_path)

        with app.app_context():
            val_result = LogParser.process_and_validate(csv_path)
            ingested = LogParser.ingest_records(val_result.valid_records, run_detection=True)
            anom_count = sum(1 for l in ingested if l.anomaly)
            click.echo(f"[OK] Successfully seeded {len(ingested)} logs. Detected {anom_count} anomalies.")

    @app.cli.command("detect")
    def detect_command():
        """Run non-AI anomaly detector across all database logs."""
        from services.anomaly_detector import AnomalyDetector
        with app.app_context():
            total, anom = AnomalyDetector.detect_and_update_all()
            click.echo(f"[OK] Anomaly detection complete: {anom} anomalies found across {total} logs.")

    return app


# Create default application instance
env = os.getenv("FLASK_ENV", "development")
app = create_app(env)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "127.0.0.1")
    debug = os.getenv("FLASK_DEBUG", "1") == "1"
    
    print("\n" + "=" * 65)
    print("  * SMART LOG ANALYZER & ANOMALY DETECTOR STARTED")
    print(f"  * Local Server: http://{host}:{port}")
    print("=" * 65 + "\n")
    
    app.run(host=host, port=port, debug=debug)

