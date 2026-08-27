"""
Unit tests for DataCleaner and JSON error prevention service.
"""

import math
import json
from datetime import datetime
from services.data_cleaner import DataCleaner
from services.ai_service import GeminiAIService


def test_sanitize_for_json_special_floats_and_types():
    """Test that NaN, Infinity, NumPy-like structures and datetimes are cleanly converted for JSON."""
    raw_payload = {
        "nan_val": float("nan"),
        "inf_val": float("inf"),
        "neg_inf": float("-inf"),
        "valid_float": 42.567891234,
        "valid_int": 100,
        "dt_obj": datetime(2026, 8, 27, 10, 30, 0),
        "string_with_null_bytes": "Hello\x00World\x1f!",
        "nested_list": [1, float("nan"), {"inner": float("inf")}],
    }

    sanitized = DataCleaner.sanitize_for_json(raw_payload)

    # Must be 100% serializable by standard json.dumps without error
    json_str = json.dumps(sanitized)
    assert json_str is not None

    reloaded = json.loads(json_str)
    assert reloaded["nan_val"] is None
    assert reloaded["inf_val"] is None
    assert reloaded["neg_inf"] is None
    assert reloaded["valid_float"] == 42.567891
    assert reloaded["valid_int"] == 100
    assert reloaded["dt_obj"] == "2026-08-27T10:30:00"
    assert reloaded["string_with_null_bytes"] == "HelloWorld!"
    assert reloaded["nested_list"][1] is None
    assert reloaded["nested_list"][2]["inner"] is None


def test_normalize_timestamp():
    """Test converting various date strings to standard ISO 8601 UTC."""
    assert DataCleaner.normalize_timestamp("2026-08-27 15:30:00") == "2026-08-27T15:30:00Z"
    assert DataCleaner.normalize_timestamp("27-08-2026 15:30:00") == "2026-08-27T15:30:00Z"
    assert DataCleaner.normalize_timestamp("2026-08-27") == "2026-08-27T00:00:00Z"
    assert DataCleaner.normalize_timestamp(None) is None
    assert DataCleaner.normalize_timestamp("nan") is None


def test_normalize_status_code():
    """Test extracting integer status codes from strings and edge cases."""
    assert DataCleaner.normalize_status_code(200) == 200
    assert DataCleaner.normalize_status_code("500") == 500
    assert DataCleaner.normalize_status_code("HTTP 404 Not Found") == 404
    assert DataCleaner.normalize_status_code(float("nan")) is None
    assert DataCleaner.normalize_status_code("invalid") is None
    assert DataCleaner.normalize_status_code(999) is None  # out of range


def test_clean_record_for_supabase_columns():
    """Test formatting specifically for 'smart Log analyser' table columns."""
    raw_record = {
        "timestamp": "2026-08-27 12:00:00",
        "ip_address": "192.168.1.100",
        "event_type": "login",
        "status_code": "200",
        "source": "web-admin",
        "endpoint": "/session/9999",
        "location": "India",
    }

    cleaned = DataCleaner.clean_record_for_supabase(raw_record, table_name="smart Log analyser")

    assert "id" in cleaned
    assert cleaned["timestamp"] == "2026-08-27T12:00:00Z"
    assert cleaned["ip_address"] == "192.168.1.100"
    assert cleaned["event_type"] == "LOGIN"
    assert cleaned["status_code"] == 200
    assert cleaned["user_agent"] == "Web-admin"
    assert cleaned["session_id"] == "9999"
    assert cleaned["location"] == "India"


def test_safe_parse_ai_json_prevents_invalid_json_errors():
    """Test that safe_parse_ai_json recovers from corrupted, markdown, or malformed JSON."""
    # 1. Standard markdown codeblock
    md_text = '```json\n{"explanation": "Valid test", "likely_root_cause": "Network drop", "recommended_next_step": "Restart service"}\n```'
    parsed1 = GeminiAIService.safe_parse_ai_json(md_text)
    assert parsed1["explanation"] == "Valid test"
    assert parsed1["likely_root_cause"] == "Network drop"
    assert parsed1["recommended_next_step"] == "Restart service"

    # 2. JSON with trailing commas (common LLM syntax error)
    trailing_comma_text = '{\n  "explanation": "Test comma",\n  "likely_root_cause": "Timeout",\n  "recommended_next_step": "Check logs",\n}'
    parsed2 = GeminiAIService.safe_parse_ai_json(trailing_comma_text)
    assert parsed2["explanation"] == "Test comma"
    assert parsed2["likely_root_cause"] == "Timeout"

    # 3. Plain conversational text from LLM (no JSON braces at all)
    plain_text = "The anomaly occurred because database connection timed out. Root cause: connection pool exhausted. Next step: increase pool size."
    parsed3 = GeminiAIService.safe_parse_ai_json(plain_text)
    assert len(parsed3["explanation"]) > 0
    assert len(parsed3["likely_root_cause"]) > 0
    assert len(parsed3["recommended_next_step"]) > 0

    # 4. Empty or None input
    parsed4 = GeminiAIService.safe_parse_ai_json("")
    assert "explanation" in parsed4
    assert "likely_root_cause" in parsed4
    assert "recommended_next_step" in parsed4
