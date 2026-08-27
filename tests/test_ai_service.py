"""
Unit tests for Google Gemini AI Service.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime
from models.models import Log
from services.ai_service import GeminiAIService


def test_ai_service_rejects_non_anomaly():
    """Verify that AI analysis cannot be invoked on a non-anomalous log."""
    log = Log(
        id=1,
        timestamp=datetime(2026, 8, 26, 10, 0, 0),
        source="api-01",
        event_type="HTTP_REQUEST",
        severity="INFO",
        status_code=200,
        anomaly=False,
        anomaly_score=10.0,
        message="Standard request",
    )
    success, data, error = GeminiAIService.explain_anomaly(log)
    assert success is False
    assert "not flagged as an anomaly" in error


def test_ai_service_missing_api_key(monkeypatch):
    """Verify that missing API key returns a clear, graceful error without crashing."""
    monkeypatch.setenv("GEMINI_API_KEY", "")
    log = Log(
        id=2,
        timestamp=datetime(2026, 8, 26, 10, 0, 0),
        source="payment-service",
        event_type="PAYMENT",
        severity="ERROR",
        status_code=500,
        anomaly=True,
        anomaly_score=85.0,
        anomaly_reason="HTTP 500 and ERROR severity",
        message="Payment timeout",
    )
    with patch.object(GeminiAIService, "get_api_key", return_value=""):
        success, data, error = GeminiAIService.explain_anomaly(log)
        assert success is False
        assert "API key is missing" in error


def test_ai_prompt_builder():
    """Test that prompt contains target log attributes and surrounding context."""
    log = Log(
        id=3,
        timestamp=datetime(2026, 8, 26, 10, 0, 0),
        source="auth-server-01",
        event_type="LOGIN",
        severity="WARNING",
        status_code=401,
        ip_address="192.168.1.50",
        anomaly=True,
        anomaly_score=75.0,
        anomaly_reason="Burst rate authentication failure",
        message="Failed password check",
    )
    context = [
        {
            "relative_position": "PREVIOUS",
            "timestamp": "2026-08-26 09:59:58",
            "source": "auth-server-01",
            "severity": "WARNING",
            "status_code": 401,
            "message": "Attempt 1",
        },
        {
            "relative_position": "CURRENT_ANOMALY",
            "timestamp": "2026-08-26 10:00:00",
            "source": "auth-server-01",
            "severity": "WARNING",
            "status_code": 401,
            "message": "Attempt 2",
        },
    ]

    prompt = GeminiAIService.build_prompt(log, surrounding_logs=context)
    assert "auth-server-01" in prompt
    assert "192.168.1.50" in prompt
    assert "75.0/100" in prompt
    assert "PREVIOUS" in prompt
    assert "Do NOT evaluate whether this log is anomalous" in prompt


def test_ai_service_successful_mocked_generation(monkeypatch):
    """Test successful AI explanation parsing with mocked Gemini response."""
    log = Log(
        id=4,
        timestamp=datetime(2026, 8, 26, 10, 0, 0),
        source="payment-service",
        event_type="PAYMENT",
        severity="CRITICAL",
        status_code=503,
        anomaly=True,
        anomaly_score=90.0,
        anomaly_reason="HTTP 503 and CRITICAL severity",
        message="Upstream gateway unreachable",
    )

    mock_json_response = """{
        "explanation": "The payment gateway failed with HTTP 503 Service Unavailable, indicating complete outage of the upstream provider.",
        "likely_root_cause": "Network partition or connection timeout to the Stripe payment endpoint.",
        "recommended_next_step": "Check upstream API status page and verify circuit-breaker configurations."
    }"""

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = mock_json_response
    mock_client.models.generate_content.return_value = mock_response

    with patch.object(GeminiAIService, "get_api_key", return_value="mock-valid-api-key"), \
         patch("services.ai_service.db.session.commit"):
        
        with patch("google.genai.Client", return_value=mock_client):
            success, result, error = GeminiAIService.explain_anomaly(log, surrounding_logs=[])

            assert success is True
            assert result["explanation"].startswith("The payment gateway failed")
            assert "Stripe payment endpoint" in result["likely_root_cause"]
            assert "circuit-breaker" in result["recommended_next_step"]
            assert log.ai_explanation is not None
