"""
Log Management, Upload, Anomaly Inspection, and AI Explanation Routes.
"""

import io
import csv
from datetime import datetime
from typing import Dict, Any, List
from flask import (
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    Response,
    send_file,
)
from werkzeug.utils import secure_filename
from sqlalchemy import or_, desc, asc

from routes import logs_bp
from models import db
from models.models import Log
from services.validation import LogValidator
from services.log_parser import LogParser
from services.anomaly_detector import AnomalyDetector
from services.ai_service import GeminiAIService
from services.supabase_service import SupabaseService
from config import Config

# Whitelisted columns for dynamic sorting (prevents SQL/ORM injection)
ALLOWED_SORT_COLUMNS = {
    "id": Log.id,
    "timestamp": Log.timestamp,
    "source": Log.source,
    "event_type": Log.event_type,
    "severity": Log.severity,
    "status_code": Log.status_code,
    "anomaly": Log.anomaly,
    "anomaly_score": Log.anomaly_score,
    "created_at": Log.created_at,
}


@logs_bp.route("/logs")
def logs_view():
    """Render logs explorer page."""
    sources = [s[0] for s in db.session.query(Log.source).distinct().order_by(Log.source).all()]
    return render_template("logs.html", sources=sources)


@logs_bp.route("/logs/<int:log_id>")
def log_detail_view(log_id: int):
    """Render detailed log inspection view."""
    log = db.session.get(Log, log_id)
    if not log:
        return render_template("base.html", error_404=True), 404
    surrounding_context = GeminiAIService.get_surrounding_context(log, limit=3)
    gemini_ready = GeminiAIService.is_configured()
    return render_template(
        "log_detail.html",
        log=log,
        surrounding_context=surrounding_context,
        gemini_ready=gemini_ready,
    )


@logs_bp.route("/api/logs", methods=["GET"])
def get_logs_api():
    """
    Paginated JSON endpoint for querying and filtering logs.
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "").strip().upper()
    source = request.args.get("source", "").strip()
    anomaly_only = request.args.get("anomaly_only", "").lower() in ("true", "1", "yes")
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()
    sort_by = request.args.get("sort_by", "timestamp")
    sort_dir = request.args.get("sort_dir", "desc")

    query = Log.query

    # Search filter across message, endpoint, ip_address, event_type
    if search:
        query = query.filter(
            or_(
                Log.message.ilike(f"%{search}%"),
                Log.endpoint.ilike(f"%{search}%"),
                Log.ip_address.ilike(f"%{search}%"),
                Log.event_type.ilike(f"%{search}%"),
                Log.source.ilike(f"%{search}%"),
            )
        )

    # Severity filter
    if severity and severity != "ALL":
        query = query.filter(Log.severity == severity)

    # Source filter
    if source and source != "ALL":
        query = query.filter(Log.source == source)

    # Anomaly filter
    if anomaly_only:
        query = query.filter(Log.anomaly == True)

    # Date range filters
    if start_date:
        try:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d")
            query = query.filter(Log.timestamp >= start_dt)
        except ValueError:
            pass

    if end_date:
        try:
            end_dt = datetime.strptime(end_date, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59
            )
            query = query.filter(Log.timestamp <= end_dt)
        except ValueError:
            pass

    # Ordering with strict whitelisting to prevent query injection
    sort_column = ALLOWED_SORT_COLUMNS.get(sort_by, Log.timestamp)
    if sort_dir == "asc":
        query = query.order_by(asc(sort_column))
    else:
        query = query.order_by(desc(sort_column))

    paginated = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "items": [log.to_dict() for log in paginated.items],
        "total": paginated.total,
        "page": paginated.page,
        "pages": paginated.pages,
        "per_page": paginated.per_page,
        "has_next": paginated.has_next,
        "has_prev": paginated.has_prev,
    })


@logs_bp.route("/api/logs/<int:log_id>", methods=["GET"])
def get_single_log(log_id: int):
    """Return JSON details of a single log."""
    log = db.session.get(Log, log_id)
    if not log:
        return jsonify({"success": False, "message": "Log not found"}), 404
    return jsonify(log.to_dict())


@logs_bp.route("/api/logs/<int:log_id>/context", methods=["GET"])
def get_log_context(log_id: int):
    """Return surrounding log context for an anomaly."""
    log = db.session.get(Log, log_id)
    if not log:
        return jsonify({"success": False, "message": "Log not found"}), 404
    context = GeminiAIService.get_surrounding_context(log, limit=3)
    return jsonify({"target_id": log_id, "context": context})


@logs_bp.route("/upload", methods=["POST"])
def upload_logs():
    """
    Handle CSV log dataset upload, validation, and ingestion.
    Includes filename sanitization and MIME-type validation.
    """
    if "file" not in request.files:
        return jsonify({
            "success": False,
            "message": "No file part in the upload request.",
        }), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({
            "success": False,
            "message": "No file selected for upload.",
        }), 400

    # Sanitize filename (removes null bytes, path traversal attempts like ../../)
    sanitized_name = secure_filename(file.filename)
    if not sanitized_name:
        sanitized_name = "uploaded_logs.csv"

    # Validate file extension strictly
    if not sanitized_name.lower().endswith((".csv", ".txt", ".log")):
        return jsonify({
            "success": False,
            "message": "Invalid file format. Only CSV or structured log files are supported.",
        }), 400

    # Parse and validate uploaded content
    validation_result = LogParser.process_and_validate(file.stream)

    if not validation_result.is_valid and not validation_result.valid_records:
        return jsonify({
            "success": False,
            "total_processed": validation_result.total_processed,
            "imported_count": 0,
            "rejected_count": validation_result.rejected_count,
            "errors": validation_result.error_summary(),
            "message": "Upload failed. All records were rejected due to validation errors.",
        }), 422

    # Ingest valid records and execute deterministic anomaly detection
    ingested_logs = LogParser.ingest_records(
        validation_result.valid_records, run_detection=True
    )

    ingested_ids = [l.id for l in ingested_logs if l.id]
    if ingested_ids:
        anomalies_detected = Log.query.filter(
            Log.id.in_(ingested_ids), Log.anomaly == True
        ).count()
    else:
        anomalies_detected = 0

    return jsonify({
        "success": True,
        "total_processed": validation_result.total_processed,
        "imported_count": len(ingested_logs),
        "rejected_count": validation_result.rejected_count,
        "duplicate_count": validation_result.duplicate_count,
        "anomalies_detected": anomalies_detected,
        "errors": validation_result.error_summary()[:20],  # Return up to 20 errors
        "message": f"Successfully imported {len(ingested_logs)} logs. Detected {anomalies_detected} anomalies.",
    })


@logs_bp.route("/api/logs/<int:log_id>/analyze", methods=["POST"])
def analyze_log_ai(log_id: int):
    """
    Trigger Google Gemini AI explanation for an already flagged anomaly.
    """
    log = db.session.get(Log, log_id)
    if not log:
        return jsonify({"success": False, "message": "Log not found"}), 404

    # Enforce Rule: AI MUST NOT be invoked on non-anomalies
    if not log.anomaly:
        return jsonify({
            "success": False,
            "message": "AI analysis is strictly reserved for logs detected as anomalies by our algorithm.",
        }), 400

    surrounding = GeminiAIService.get_surrounding_context(log, limit=3)
    success, result, error_msg = GeminiAIService.explain_anomaly(
        log, surrounding_logs=surrounding
    )

    if not success:
        return jsonify({
            "success": False,
            "message": error_msg or "Failed to generate AI analysis.",
        }), 502

    return jsonify({
        "success": True,
        "data": result,
        "message": "Gemini AI explanation generated successfully.",
    })


@logs_bp.route("/api/logs/<int:log_id>", methods=["DELETE"])
def delete_log(log_id: int):
    """Delete a single log record."""
    log = db.session.get(Log, log_id)
    if not log:
        return jsonify({"success": False, "message": "Log not found"}), 404
    db.session.delete(log)
    db.session.commit()
    return jsonify({
        "success": True,
        "message": f"Log #{log_id} deleted successfully.",
    })


@logs_bp.route("/api/logs/batch-delete", methods=["POST"])
def batch_delete_logs():
    """Delete multiple or all logs."""
    data = request.get_json(silent=True) or {}
    log_ids = data.get("log_ids", [])
    clear_all = data.get("clear_all", False)

    if clear_all:
        deleted = Log.query.delete()
        db.session.commit()
        return jsonify({
            "success": True,
            "deleted_count": deleted,
            "message": f"All {deleted} logs have been purged from database.",
        })

    if not log_ids:
        return jsonify({
            "success": False,
            "message": "No log IDs provided for deletion.",
        }), 400

    deleted = Log.query.filter(Log.id.in_(log_ids)).delete(
        synchronize_session=False
    )
    db.session.commit()
    return jsonify({
        "success": True,
        "deleted_count": deleted,
        "message": f"Successfully deleted {deleted} selected log(s).",
    })


@logs_bp.route("/api/detect", methods=["POST"])
def run_detection_endpoint():
    """
    Re-execute deterministic anomaly detection over all existing logs.
    """
    data = request.get_json(silent=True) or {}
    custom_threshold = data.get("threshold")
    if custom_threshold is not None:
        try:
            custom_threshold = int(custom_threshold)
        except (ValueError, TypeError):
            custom_threshold = None

    total, anomalies = AnomalyDetector.detect_and_update_all(
        threshold=custom_threshold
    )
    return jsonify({
        "success": True,
        "total_logs": total,
        "anomalies_detected": anomalies,
        "threshold": custom_threshold or Config.ANOMALY_THRESHOLD,
        "message": f"Anomaly detection completed. {anomalies} of {total} logs flagged as anomalies.",
    })


@logs_bp.route("/export/anomalies", methods=["GET"])
def export_anomalies_csv():
    """Export all detected anomalies as downloadable CSV."""
    anomalies = (
        Log.query.filter_by(anomaly=True)
        .order_by(Log.timestamp.desc())
        .all()
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID",
        "Timestamp",
        "Source",
        "Event Type",
        "Severity",
        "IP Address",
        "Status Code",
        "Endpoint",
        "Message",
        "Anomaly Score",
        "Anomaly Reason",
        "AI Explanation",
        "AI Root Cause",
        "AI Next Step",
    ])

    for a in anomalies:
        writer.writerow([
            a.id,
            a.timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.timestamp else "",
            a.source,
            a.event_type,
            a.severity,
            a.ip_address or "",
            a.status_code or "",
            a.endpoint or "",
            a.message,
            a.anomaly_score,
            a.anomaly_reason or "",
            a.ai_explanation or "",
            a.ai_root_cause or "",
            a.ai_next_step or "",
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment;filename=anomalies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        },
    )


@logs_bp.route("/api/sync/supabase", methods=["POST"])
def sync_supabase_endpoint():
    """Sync existing logs and anomalies to Supabase."""
    if not SupabaseService.is_configured():
        return jsonify({
            "success": False,
            "message": "Supabase credentials are not configured. Please set SUPABASE_URL and SUPABASE_KEY in .env.",
        }), 400

    logs = Log.query.all()
    if not logs:
        return jsonify({
            "success": False,
            "message": "No logs in local database to sync.",
        })

    logs_payload = [l.to_supabase_log() for l in logs]
    logs_ins, err1 = SupabaseService.insert_logs(logs_payload)

    anomalies_payload = [l.to_supabase_anomaly() for l in logs if l.anomaly]
    anomalies_payload = [a for a in anomalies_payload if a is not None]
    anom_ins, err2 = SupabaseService.insert_anomalies(anomalies_payload)

    return jsonify({
        "success": True,
        "logs_synced": logs_ins,
        "anomalies_synced": anom_ins,
        "message": f"Successfully synced {logs_ins} logs and {anom_ins} anomalies to Supabase.",
    })
