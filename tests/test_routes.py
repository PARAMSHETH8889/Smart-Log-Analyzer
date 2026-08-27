"""
Integration tests for Flask application routes and API endpoints.
"""

import io
import pytest
from app import create_app
from models import db
from models.models import Log
from datetime import datetime


@pytest.fixture
def app():
    """Create testing application instance with in-memory database."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_index_and_dashboard_routes(client):
    """Test root redirect and dashboard page render."""
    res_root = client.get("/")
    assert res_root.status_code == 302
    assert "/dashboard" in res_root.location

    res_dash = client.get("/dashboard")
    assert res_dash.status_code == 200
    assert b"LogGuard" in res_dash.data
    assert b"Monitoring Dashboard" in res_dash.data


def test_api_stats_empty_and_populated(client, app):
    """Test /api/stats endpoint when empty and after inserting records."""
    # 1. Empty state
    res_empty = client.get("/api/stats")
    assert res_empty.status_code == 200
    data_empty = res_empty.get_json()
    assert data_empty["total_logs"] == 0
    assert data_empty["total_anomalies"] == 0

    # 2. Add sample records
    with app.app_context():
        log1 = Log(
            timestamp=datetime(2026, 8, 26, 10, 0, 0),
            source="api-01",
            event_type="HTTP_REQUEST",
            severity="INFO",
            status_code=200,
            message="OK",
            anomaly=False,
            anomaly_score=10.0,
        )
        log2 = Log(
            timestamp=datetime(2026, 8, 26, 10, 1, 0),
            source="payment-01",
            event_type="PAYMENT",
            severity="ERROR",
            status_code=500,
            message="Payment failed",
            anomaly=True,
            anomaly_score=80.0,
            anomaly_reason="HTTP 500 error",
        )
        db.session.add_all([log1, log2])
        db.session.commit()

    res_pop = client.get("/api/stats")
    assert res_pop.status_code == 200
    data_pop = res_pop.get_json()
    assert data_pop["total_logs"] == 2
    assert data_pop["total_anomalies"] == 1
    assert data_pop["severity_distribution"]["INFO"] == 1
    assert data_pop["severity_distribution"]["ERROR"] == 1


def test_upload_csv_endpoint(client):
    """Test CSV file upload and validation processing via /upload route."""
    csv_content = """timestamp,source,event_type,severity,status_code,message
2026-08-26 10:00:00,api-server-01,HTTP_REQUEST,INFO,200,GET /api/v1/users ok
2026-08-26 10:00:05,payment-service,PAYMENT,ERROR,500,Payment gateway crash
"""
    data = {
        "file": (io.BytesIO(csv_content.encode("utf-8")), "test_logs.csv")
    }
    response = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data"
    )
    assert response.status_code == 200
    res_data = response.get_json()
    assert res_data["success"] is True
    assert res_data["total_processed"] == 2
    assert res_data["imported_count"] == 2
    assert res_data["anomalies_detected"] >= 1


def test_upload_malformed_csv(client):
    """Test uploading an unparseable or completely invalid file."""
    bad_csv = "just a random line with no headers or structure\nsecond bad line"
    data = {
        "file": (io.BytesIO(bad_csv.encode("utf-8")), "bad.csv")
    }
    response = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data"
    )
    assert response.status_code == 422
    res_data = response.get_json()
    assert res_data["success"] is False
    assert len(res_data["errors"]) > 0


def test_logs_filtering_and_pagination(client, app):
    """Test /api/logs with search queries, severity filters, and pagination."""
    with app.app_context():
        logs = [
            Log(
                timestamp=datetime(2026, 8, 26, 10, i, 0),
                source=f"source-{i%3}",
                event_type="HTTP_REQUEST",
                severity="INFO" if i < 8 else "ERROR",
                status_code=200 if i < 8 else 500,
                message=f"Log message number {i}",
                anomaly=(i >= 8),
                anomaly_score=10.0 if i < 8 else 75.0,
            )
            for i in range(12)
        ]
        db.session.add_all(logs)
        db.session.commit()

    # Query all
    res_all = client.get("/api/logs?page=1&per_page=5")
    assert res_all.status_code == 200
    d_all = res_all.get_json()
    assert d_all["total"] == 12
    assert len(d_all["items"]) == 5
    assert d_all["pages"] == 3

    # Query anomaly only
    res_anom = client.get("/api/logs?anomaly_only=true")
    d_anom = res_anom.get_json()
    assert d_anom["total"] == 4

    # Search keyword
    res_search = client.get("/api/logs?search=number+5")
    d_search = res_search.get_json()
    assert d_search["total"] == 1


def test_delete_log_endpoint(client, app):
    """Test deleting a single log record."""
    with app.app_context():
        log = Log(
            timestamp=datetime(2026, 8, 26, 10, 0, 0),
            source="api-01",
            event_type="LOGIN",
            severity="INFO",
            message="To be deleted",
        )
        db.session.add(log)
        db.session.commit()
        log_id = log.id

    res_del = client.delete(f"/api/logs/{log_id}")
    assert res_del.status_code == 200
    assert res_del.get_json()["success"] is True

    # Verify deleted
    with app.app_context():
        assert db.session.get(Log, log_id) is None


def test_export_anomalies_csv(client, app):
    """Test exporting anomalies to CSV."""
    with app.app_context():
        log = Log(
            timestamp=datetime(2026, 8, 26, 10, 0, 0),
            source="api-01",
            event_type="ERROR_EVENT",
            severity="CRITICAL",
            status_code=500,
            message="Crash",
            anomaly=True,
            anomaly_score=95.0,
            anomaly_reason="Critical failure",
        )
        db.session.add(log)
        db.session.commit()

    res = client.get("/export/anomalies")
    assert res.status_code == 200
    assert res.mimetype == "text/csv"
    assert b"Crash" in res.data
    assert b"Critical failure" in res.data
