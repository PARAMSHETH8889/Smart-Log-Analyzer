"""
Unit tests for Supabase Integration Service.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime
from models.models import Log
from services.supabase_service import SupabaseService


def test_supabase_not_configured_fallback(monkeypatch):
    """Test that if Supabase is unconfigured, methods return graceful errors without crashing."""
    monkeypatch.setenv("SUPABASE_URL", "")
    monkeypatch.setenv("SUPABASE_KEY", "")

    assert SupabaseService.is_configured() is False

    logs_inserted, err = SupabaseService.insert_logs([{"id": "test"}])
    assert logs_inserted == 0
    assert err is not None

    anom_inserted, err = SupabaseService.insert_anomalies([{"id": "test"}])
    assert anom_inserted == 0
    assert err is not None


def test_supabase_models_mapping():
    """Test that Log model methods properly format dictionaries for Supabase schemas."""
    log = Log(
        id=1,
        timestamp=datetime(2026, 8, 26, 10, 0, 0),
        source="payment-service",
        event_type="PAYMENT",
        severity="ERROR",
        status_code=500,
        ip_address="192.168.1.10",
        message="Payment timeout",
        anomaly=True,
        anomaly_score=85.0,
        anomaly_reason="HTTP 500 server error",
        ai_explanation="Payment service experienced gateway timeout.",
        ai_root_cause="Stripe connection drop.",
        ai_next_step="Check network link.",
    )

    # 1. Supabase Log schema
    sup_log = log.to_supabase_log()
    assert sup_log["source"] == "payment-service"
    assert sup_log["severity"] == "ERROR"
    assert sup_log["status_code"] == 500
    assert "timestamp" in sup_log

    # 2. Supabase Anomaly schema
    sup_anom = log.to_supabase_anomaly()
    assert sup_anom is not None
    assert sup_anom["is_anomaly"] is True
    assert sup_anom["anomaly_score"] == 85.0
    assert sup_anom["log_id"] == log.uuid

    # 3. Supabase AI Analysis schema
    sup_ai = log.to_supabase_ai(anomaly_uuid=sup_anom["id"])
    assert sup_ai is not None
    assert sup_ai["anomaly_id"] == sup_anom["id"]
    assert "Payment service experienced gateway timeout." in sup_ai["explanation"]
    assert "Stripe connection drop." in sup_ai["root_cause"]


def test_supabase_delete_and_purge_fallback(monkeypatch):
    """Test delete_log and purge_all_logs return safe errors when Supabase is unconfigured."""
    monkeypatch.setenv("SUPABASE_URL", "")
    monkeypatch.setenv("SUPABASE_KEY", "")

    ok, err = SupabaseService.delete_log("test-uuid")
    assert ok is False
    assert err is not None

    ok_purge, err_purge = SupabaseService.purge_all_logs()
    assert ok_purge is False
    assert err_purge is not None
