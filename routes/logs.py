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
from services.data_cleaner import DataCleaner
from services.live_logger import LiveLogService
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
    Guarantees strict JSON response output with no HTML error leaks.
    """
    try:
        if "file" not in request.files:
            return jsonify({
                "success": False,
                "message": "No file attached to upload request.",
            }), 400

        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({
                "success": False,
                "message": "No file selected for upload.",
            }), 400

        # Sanitize filename
        sanitized_name = secure_filename(file.filename)
        if not sanitized_name:
            sanitized_name = "uploaded_logs.csv"

        # Validate file extension
        if not sanitized_name.lower().endswith((".csv", ".txt", ".log")):
            return jsonify({
                "success": False,
                "message": "Invalid file format. Please upload a .csv or structured text log file.",
            }), 400

        # Read file bytes safely
        file_bytes = file.read()
        if not file_bytes or not file_bytes.strip():
            return jsonify({
                "success": False,
                "message": "The uploaded CSV file is empty.",
            }), 400

        # Parse and validate uploaded content
        validation_result = LogParser.process_and_validate(file_bytes)

        if not validation_result.is_valid and not validation_result.valid_records:
            return jsonify({
                "success": False,
                "total_processed": validation_result.total_processed,
                "imported_count": 0,
                "rejected_count": validation_result.rejected_count,
                "errors": validation_result.error_summary(),
                "message": "Upload failed. All rows were rejected due to schema or parsing errors.",
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

        # Check if user requested immediate sync or if Supabase is configured
        auto_sync = request.form.get("sync_to_supabase", "").lower() in ("true", "1", "yes")
        supabase_synced = False
        supabase_msg = ""
        if auto_sync and SupabaseService.is_configured() and ingested_logs:
            try:
                logs_payload = [l.to_supabase_log() for l in ingested_logs]
                SupabaseService.insert_logs(logs_payload)
                anom_payload = [l.to_supabase_anomaly() for l in ingested_logs if l.anomaly]
                if anom_payload:
                    SupabaseService.insert_anomalies([a for a in anom_payload if a])
                supabase_synced = True
                supabase_msg = " and copied to Main Database (Supabase)"
            except Exception as sync_ex:
                supabase_msg = f" (Supabase sync note: {sync_ex})"

        return jsonify({
            "success": True,
            "total_processed": validation_result.total_processed,
            "imported_count": len(ingested_logs),
            "rejected_count": validation_result.rejected_count,
            "duplicate_count": validation_result.duplicate_count,
            "anomalies_detected": anomalies_detected,
            "supabase_synced": supabase_synced,
            "errors": validation_result.error_summary()[:20],
            "message": f"Successfully imported {len(ingested_logs)} logs{supabase_msg}. Detected {anomalies_detected} anomalies.",
        })

    except Exception as ex:
        db.session.rollback()
        return jsonify({
            "success": False,
            "message": f"Processing error: {str(ex)}",
            "errors": [{"row": "N/A", "field": "server", "message": str(ex)}],
        }), 500


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
    """
    Delete a single log record.
    Supports deleting from local database only OR permanently from main Supabase database.
    """
    log = db.session.get(Log, log_id)
    if not log:
        return jsonify({"success": False, "message": "Log not found"}), 404

    # Determine if user requested permanent deletion from Supabase
    purge_supabase = False
    req_json = request.get_json(silent=True) or {}
    if req_json.get("purge_supabase") is True or req_json.get("delete_from_supabase") is True:
        purge_supabase = True
    elif request.args.get("purge_supabase", "").lower() in ("true", "1", "yes"):
        purge_supabase = True

    supabase_deleted = False
    supabase_msg = ""
    if purge_supabase:
        if SupabaseService.is_configured():
            ok, err = SupabaseService.delete_log(log.uuid)
            if ok:
                supabase_deleted = True
                supabase_msg = " and permanently deleted from Supabase main cloud database"
            else:
                supabase_msg = f" (Supabase deletion notice: {err})"
        else:
            supabase_msg = " (Supabase not configured)"

    db.session.delete(log)
    db.session.commit()

    return jsonify({
        "success": True,
        "supabase_deleted": supabase_deleted,
        "message": f"Log #{log_id} successfully deleted from local database{supabase_msg}.",
    })


@logs_bp.route("/api/logs/batch-delete", methods=["POST", "DELETE"])
def batch_delete_logs():
    """
    Delete multiple logs or purge entire database.
    Supports deleting from local database only OR permanently from main Supabase database.
    """
    data = request.get_json(silent=True) or {}
    log_ids = data.get("log_ids", [])
    clear_all = data.get("clear_all", False) or request.args.get("clear_all", "").lower() in ("true", "1")
    purge_supabase = (
        data.get("purge_supabase", False)
        or data.get("delete_from_supabase", False)
        or request.args.get("purge_supabase", "").lower() in ("true", "1")
    )

    supabase_msg = ""
    if clear_all:
        total_count = Log.query.count()
        if purge_supabase:
            if SupabaseService.is_configured():
                ok, err = SupabaseService.purge_all_logs()
                if ok:
                    supabase_msg = " and permanently purged from Supabase main cloud database"
                else:
                    supabase_msg = f" (Supabase notice: {err})"
            else:
                supabase_msg = " (Supabase not configured)"

        deleted = Log.query.delete()
        db.session.commit()

        return jsonify({
            "success": True,
            "deleted_count": deleted,
            "supabase_purged": purge_supabase,
            "message": f"All {deleted} logs permanently deleted from local database{supabase_msg}.",
        })

    if not log_ids:
        return jsonify({
            "success": False,
            "message": "No log IDs provided for deletion.",
        }), 400

    # Retrieve UUIDs if deleting from Supabase
    if purge_supabase and SupabaseService.is_configured():
        targets = Log.query.filter(Log.id.in_(log_ids)).all()
        for t in targets:
            SupabaseService.delete_log(t.uuid)
        supabase_msg = " and permanently deleted from Supabase cloud database"

    deleted = Log.query.filter(Log.id.in_(log_ids)).delete(
        synchronize_session=False
    )
    db.session.commit()
    return jsonify({
        "success": True,
        "deleted_count": deleted,
        "supabase_purged": purge_supabase,
        "message": f"Successfully deleted {deleted} log(s) from local database{supabase_msg}.",
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


@logs_bp.route("/api/dataset/clean", methods=["POST"])
def clean_dataset_api():
    """
    Clean and process the existing dataset to ensure 100% schema conformity with Supabase columns.
    Fixes invalid timestamps, removes NaN/Inf values, sanitizes strings, and validates data types.
    """
    all_logs = Log.query.all()
    if not all_logs:
        return jsonify({
            "success": True,
            "message": "No records in local dataset to clean.",
            "cleaned_count": 0,
        })

    raw_dicts = [l.to_dict() for l in all_logs]
    table_name = SupabaseService.get_log_table_name() if SupabaseService.is_configured() else "smart Log analyser"
    cleaned_records, metrics = DataCleaner.clean_dataset(raw_dicts, table_name=table_name)

    # Update local records if needed (normalize fields)
    for log, cleaned in zip(all_logs, cleaned_records):
        if cleaned.get("status_code") is not None:
            log.status_code = cleaned["status_code"]
        if cleaned.get("event_type"):
            log.event_type = cleaned["event_type"]
        if cleaned.get("ip_address"):
            log.ip_address = cleaned["ip_address"]

    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"Successfully cleaned {len(cleaned_records)} records according to Supabase '{table_name}' column schema.",
        "table_name": table_name,
        "metrics": metrics,
    })


@logs_bp.route("/api/sync/supabase", methods=["POST"])
@logs_bp.route("/api/dataset/sync-supabase", methods=["POST"])
def sync_supabase_endpoint():
    """
    Clean dataset and synchronize all logs, anomalies, and AI analyses with Supabase cloud database.
    Guarantees zero invalid JSON errors.
    """
    if not SupabaseService.is_configured():
        return jsonify({
            "success": False,
            "message": "Supabase credentials are not configured. Please set SUPABASE_URL and SUPABASE_KEY in .env.",
        }), 400

    sync_result = SupabaseService.clean_and_sync_all_logs()
    status_code = 200 if sync_result.get("success") else 500
    return jsonify(sync_result), status_code


@logs_bp.route("/live")
def live_logs_view():
    """
    Render real-time Live Log Monitor UI.
    """
    local_ip = LiveLogService.get_local_ip()
    return render_template("live.html", local_ip=local_ip)


@logs_bp.route("/api/live/capture", methods=["POST"])
def capture_live_logs_api():
    """
    Capture live system/event logs directly from the computer, run anomaly detection,
    and persist them to the database.
    """
    data = request.get_json(silent=True) or {}
    count = int(data.get("count", 5))
    count = max(1, min(count, 30))
    channel = data.get("channel", "Application")

    result = LiveLogService.capture_and_ingest_live_logs(count=count, channel=channel)
    status_code = 200 if result.get("success") else 500
    return jsonify(result), status_code
