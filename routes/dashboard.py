"""
Dashboard Routes and Analytics Endpoints.
"""

from collections import Counter, defaultdict
from datetime import datetime
from flask import render_template, jsonify, redirect, url_for
from sqlalchemy import func

from routes import dashboard_bp
from models import db
from models.models import Log


@dashboard_bp.route("/")
def index():
    """Redirect root to dashboard."""
    return redirect(url_for("dashboard.dashboard_view"))


@dashboard_bp.route("/dashboard")
def dashboard_view():
    """Render main monitoring dashboard."""
    return render_template("dashboard.html")


@dashboard_bp.route("/api/stats")
def get_stats():
    """
    Compute and return real-time system metrics and Chart.js datasets.
    """
    total_logs = Log.query.count()
    if total_logs == 0:
        return jsonify({
            "total_logs": 0,
            "total_anomalies": 0,
            "critical_anomalies": 0,
            "error_rate": 0.0,
            "ai_analyses_count": 0,
            "timeline": {"labels": [], "total_series": [], "anomaly_series": []},
            "severity_distribution": {
                "INFO": 0,
                "WARNING": 0,
                "ERROR": 0,
                "CRITICAL": 0,
            },
            "anomalies_by_source": {},
            "recent_anomalies": [],
            "sources": [],
        })

    # Metric Cards Calculations
    total_anomalies = Log.query.filter_by(anomaly=True).count()
    critical_anomalies = (
        Log.query.filter_by(anomaly=True, severity="CRITICAL").count()
    )
    error_or_crit_count = Log.query.filter(
        Log.severity.in_(["ERROR", "CRITICAL"])
    ).count()
    error_rate = round((error_or_crit_count / total_logs) * 100, 1)

    ai_analyses_count = Log.query.filter(
        Log.ai_explanation.isnot(None)
    ).count()

    # 1. Severity Distribution
    severity_query = (
        db.session.query(Log.severity, func.count(Log.id))
        .group_by(Log.severity)
        .all()
    )
    severity_map = {"INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}
    for sev, count in severity_query:
        if sev in severity_map:
            severity_map[sev] = count

    # 2. Anomalies by Source
    source_anom_query = (
        db.session.query(Log.source, func.count(Log.id))
        .filter(Log.anomaly == True)
        .group_by(Log.source)
        .order_by(func.count(Log.id).desc())
        .all()
    )
    anomalies_by_source = {src: count for src, count in source_anom_query}

    # Distinct Sources
    sources_query = (
        db.session.query(Log.source).distinct().order_by(Log.source).all()
    )
    sources = [s[0] for s in sources_query]

    # 3. Timeline (Time Buckets)
    all_logs = Log.query.order_by(Log.timestamp.asc()).all()
    timeline_totals = defaultdict(int)
    timeline_anomalies = defaultdict(int)

    for l in all_logs:
        if l.timestamp:
            # Group into 15-minute or hourly buckets
            bucket = l.timestamp.strftime("%m-%d %H:%M")
            timeline_totals[bucket] += 1
            if l.anomaly:
                timeline_anomalies[bucket] += 1

    # Keep downsampled buckets if too many
    sorted_buckets = sorted(timeline_totals.keys())
    if len(sorted_buckets) > 25:
        step = len(sorted_buckets) // 25 + 1
        sampled_buckets = sorted_buckets[::step]
    else:
        sampled_buckets = sorted_buckets

    labels = sampled_buckets
    total_series = [timeline_totals[b] for b in labels]
    anomaly_series = [timeline_anomalies[b] for b in labels]

    # 4. Recent Anomalies
    recent_anom_objects = (
        Log.query.filter_by(anomaly=True)
        .order_by(Log.timestamp.desc())
        .limit(6)
        .all()
    )
    recent_anomalies = [l.to_dict() for l in recent_anom_objects]

    return jsonify({
        "total_logs": total_logs,
        "total_anomalies": total_anomalies,
        "critical_anomalies": critical_anomalies,
        "error_rate": error_rate,
        "ai_analyses_count": ai_analyses_count,
        "timeline": {
            "labels": labels,
            "total_series": total_series,
            "anomaly_series": anomaly_series,
        },
        "severity_distribution": severity_map,
        "anomalies_by_source": anomalies_by_source,
        "recent_anomalies": recent_anomalies,
        "sources": sources,
    })
