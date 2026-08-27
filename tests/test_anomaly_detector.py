"""
Unit tests for Deterministic Non-AI Anomaly Detector.
"""

import pytest
from datetime import datetime, timedelta
from models.models import Log
from services.anomaly_detector import AnomalyDetector


def test_anomaly_detection_http_500():
    """Test that HTTP 500 error status combined with ERROR severity triggers anomaly detection."""
    log = Log(
        id=1,
        timestamp=datetime(2026, 8, 26, 10, 0, 0),
        source="payment-service",
        event_type="PAYMENT",
        severity="ERROR",
        status_code=500,
        message="Internal server error connecting to payment gateway",
    )
    detector = AnomalyDetector(threshold=50)
    results = detector.detect_batch([log])

    assert len(results) == 1
    tested_log = results[0]
    # HTTP 500 (+40) + ERROR (+20) = 60 >= 50 threshold
    assert tested_log.anomaly is True
    assert tested_log.anomaly_score >= 60.0
    assert "HTTP server error 500" in tested_log.anomaly_reason
    assert "ERROR severity" in tested_log.anomaly_reason


def test_anomaly_detection_critical_severity():
    """Test that CRITICAL severity logs trigger appropriate scoring and reasons."""
    log = Log(
        id=2,
        timestamp=datetime(2026, 8, 26, 10, 5, 0),
        source="database-01",
        event_type="DATABASE_QUERY",
        severity="CRITICAL",
        status_code=500,
        message="Deadlock detected: transaction rolled back",
    )
    detector = AnomalyDetector(threshold=50)
    results = detector.detect_batch([log])

    tested_log = results[0]
    # Status 500 (+40) + CRITICAL (+30) = 70 >= 50 threshold
    assert tested_log.anomaly is True
    assert tested_log.anomaly_score >= 70.0
    assert "CRITICAL severity" in tested_log.anomaly_reason


def test_normal_log_not_flagged():
    """Test that standard normal logs remain unflagged with low anomaly score."""
    normal_logs = [
        Log(
            id=i,
            timestamp=datetime(2026, 8, 26, 10, 0, 0) + timedelta(minutes=i * 2),
            source="api-server-01",
            event_type="HTTP_REQUEST",
            severity="INFO",
            status_code=200,
            message=f"GET /api/v1/users item {i}",
        )
        for i in range(15)
    ]

    detector = AnomalyDetector(threshold=50)
    results = detector.detect_batch(normal_logs)

    for l in results:
        assert l.anomaly is False
        assert l.anomaly_score < 50.0
        assert "Normal log activity" in l.anomaly_reason


def test_high_frequency_anomaly():
    """Test that an intense burst of requests in a short time window triggers frequency signal."""
    base_time = datetime(2026, 8, 26, 12, 0, 0)
    
    # 20 background normal logs across 2 hours
    logs = [
        Log(
            id=i,
            timestamp=base_time + timedelta(minutes=i * 5),
            source="web-server-01",
            event_type="HTTP_REQUEST",
            severity="INFO",
            status_code=200,
            message="Regular request",
        )
        for i in range(20)
    ]

    # Inject burst of 15 logs from auth-server within 30 seconds
    burst_time = base_time + timedelta(hours=1)
    burst_logs = [
        Log(
            id=100 + j,
            timestamp=burst_time + timedelta(seconds=j * 2),
            source="auth-server-01",
            event_type="AUTHENTICATION",
            severity="WARNING",
            status_code=401,
            message="Failed login attempt",
        )
        for j in range(15)
    ]
    logs.extend(burst_logs)

    detector = AnomalyDetector(threshold=50)
    results = detector.detect_batch(logs)

    # Check burst logs
    anomalies = [l for l in results if l.source == "auth-server-01" and l.anomaly]
    assert len(anomalies) > 0
    first_anom = anomalies[0]
    assert "burst" in first_anom.anomaly_reason or "frequency" in first_anom.anomaly_reason or "401" in first_anom.anomaly_reason


def test_custom_threshold():
    """Test that custom threshold configuration properly adjusts anomaly sensitivity."""
    log = Log(
        id=99,
        timestamp=datetime(2026, 8, 26, 10, 0, 0),
        source="api-01",
        event_type="HTTP_REQUEST",
        severity="ERROR",
        status_code=200,  # Only ERROR severity (+20)
        message="Transient worker failure",
    )
    # Default threshold (50) -> should NOT be anomaly
    detector_50 = AnomalyDetector(threshold=50)
    detector_50.detect_batch([log])
    assert log.anomaly is False

    # Lower threshold (15) -> SHOULD be anomaly
    detector_15 = AnomalyDetector(threshold=15)
    detector_15.detect_batch([log])
    assert log.anomaly is True
