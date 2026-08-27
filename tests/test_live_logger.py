"""
Unit tests for LiveLogService.
"""

from services.live_logger import LiveLogService
from models.models import Log


def test_parse_wevtutil_text_parsing():
    """Test parsing raw wevtutil text output into standardized log entries."""
    sample_text = """
 Event[0]
  Log Name: Application
  Source: Test-App-Service
  Date: 2026-08-27T22:15:00.0000000Z
  Event ID: 4040
  Task: N/A
  Level: Error 
  Opcode: N/A
  Keyword: Classic, 
  User: N/A
  User Name: N/A
  Computer: DESKTOP-TEST
  Description: 
Failed to connect to backend microservice database on port 5432.
 

 Event[1]
  Log Name: Application
  Source: Test-Security-Provider
  Date: 2026-08-27T22:16:00.0000000Z
  Event ID: 1001
  Task: N/A
  Level: Information 
  Opcode: N/A
  Keyword: Classic, 
  User: N/A
  User Name: N/A
  Computer: DESKTOP-TEST
  Description: 
User session started successfully.
 
"""
    events = LiveLogService.parse_wevtutil_text(sample_text, log_channel="Application")
    assert len(events) == 2

    # Event 0: Error
    assert events[0]["source"] == "Test-App-Service"
    assert events[0]["severity"] == "ERROR"
    assert events[0]["status_code"] == 500
    assert "Failed to connect to backend" in events[0]["message"]

    # Event 1: Information
    assert events[1]["source"] == "Test-Security-Provider"
    assert events[1]["severity"] == "INFO"
    assert events[1]["status_code"] == 200
    assert "User session started" in events[1]["message"]


def test_capture_and_ingest_live_logs(app):
    """Test capturing and persisting live logs inside Flask app context."""
    with app.app_context():
        res = LiveLogService.capture_and_ingest_live_logs(count=3, channel="Application")
        assert res["success"] is True
        assert res["logs_captured"] > 0
        assert "items" in res

        # Verify records exist in database
        persisted = Log.query.filter(Log.event_type.in_(["WIN_APPLICATION", "LIVE_HEARTBEAT"])).all()
        assert len(persisted) >= 1
