"""
Unit tests for Log Validation and Parsing Services.
"""

import pytest
from datetime import datetime
from services.validation import LogValidator, ValidationResult, ValidationError
from services.log_parser import LogParser


def test_valid_log_parsing():
    """Test that standard, correctly-formatted log entries parse and validate successfully."""
    valid_csv = """timestamp,source,event_type,severity,ip_address,status_code,endpoint,message
2026-08-26 10:15:30,api-server-01,HTTP_REQUEST,INFO,192.168.1.10,200,/api/v1/users,GET /api/v1/users completed
2026-08-26 10:15:45,database-01,DATABASE_QUERY,WARNING,10.0.0.5,,,"Slow query execution (2500ms)"
"""
    result = LogParser.process_and_validate(valid_csv)
    assert result.is_valid is True
    assert result.total_processed == 2
    assert len(result.valid_records) == 2
    assert result.rejected_count == 0
    assert result.errors == []

    first = result.valid_records[0]
    assert first["source"] == "api-server-01"
    assert first["event_type"] == "HTTP_REQUEST"
    assert first["severity"] == "INFO"
    assert first["status_code"] == 200
    assert isinstance(first["timestamp"], datetime)


def test_missing_timestamp():
    """Test that a row missing the timestamp is rejected with a validation error."""
    csv_missing_ts = """timestamp,source,event_type,severity,message
,api-server-01,HTTP_REQUEST,INFO,Test message
2026-08-26 11:00:00,api-server-01,HTTP_REQUEST,INFO,Valid message
"""
    result = LogParser.process_and_validate(csv_missing_ts)
    assert len(result.valid_records) == 1
    assert result.rejected_count == 1
    assert any("timestamp" in err.field for err in result.errors)


def test_invalid_timestamp():
    """Test that malformed/unparseable timestamps are rejected."""
    csv_bad_ts = """timestamp,source,event_type,severity,message
invalid-not-a-date,api-server-01,LOGIN,INFO,User logged in
2026-99-99 99:99:99,api-server-01,LOGIN,INFO,User logged in
2026-08-26 12:00:00,api-server-01,LOGIN,INFO,Valid record
"""
    result = LogParser.process_and_validate(csv_bad_ts)
    assert len(result.valid_records) == 1
    assert result.rejected_count == 2
    assert all("timestamp" in err.field for err in result.errors)


def test_missing_required_field():
    """Test that missing required fields (source, event_type, severity) are rejected."""
    csv_missing_fields = """timestamp,source,event_type,severity,message
2026-08-26 10:00:00,,LOGIN,INFO,Missing source
2026-08-26 10:00:00,api-01,,INFO,Missing event_type
2026-08-26 10:00:00,api-01,LOGIN,,Missing severity
"""
    result = LogParser.process_and_validate(csv_missing_fields)
    assert len(result.valid_records) == 0
    assert result.rejected_count == 3
    assert len(result.errors) == 3


def test_invalid_severity_and_status():
    """Test that invalid severity values and out-of-range status codes are rejected."""
    csv_bad_enum = """timestamp,source,event_type,severity,status_code,message
2026-08-26 10:00:00,api-01,LOGIN,INVALID_SEVERITY,200,Bad severity
2026-08-26 10:00:01,api-01,LOGIN,INFO,999,Bad status code
2026-08-26 10:00:02,api-01,LOGIN,INFO,-50,Negative status code
2026-08-26 10:00:03,api-01,LOGIN,INFO,200,Valid record
"""
    result = LogParser.process_and_validate(csv_bad_enum)
    assert len(result.valid_records) == 1
    assert result.rejected_count == 3


def test_empty_dataset_and_file():
    """Test handling of completely empty files or empty datasets."""
    # Empty string
    res_empty = LogParser.process_and_validate("")
    assert res_empty.is_valid is False
    assert len(res_empty.errors) > 0

    # Header only
    res_header_only = LogParser.process_and_validate("timestamp,source,event_type,severity,message\n")
    assert res_header_only.is_valid is False
    assert len(res_header_only.valid_records) == 0


def test_duplicate_records_handling():
    """Test that duplicate log rows are identified and preserved in validation results."""
    csv_duplicates = """timestamp,source,event_type,severity,status_code,message
2026-08-26 10:00:00,api-01,LOGIN,INFO,200,User logged in
2026-08-26 10:00:00,api-01,LOGIN,INFO,200,User logged in
2026-08-26 10:00:05,api-01,LOGIN,INFO,200,User logged in second time
"""
    result = LogParser.process_and_validate(csv_duplicates)
    assert len(result.valid_records) == 3
    assert result.duplicate_count == 1
    assert result.total_processed == 3
