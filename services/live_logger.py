"""
Live Log Capture and Streaming Service.

Captures real-time live events directly from the host computer:
- Windows Event Logs (Application, System, Security) via wevtutil
- Active System/Process diagnostics
- Real-time anomaly scoring & Supabase synchronization
- Server-Sent Events (SSE) streaming support
"""

import os
import re
import socket
import platform
import subprocess
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional

from models import db
from models.models import Log
from services.anomaly_detector import AnomalyDetector
from services.supabase_service import SupabaseService
from services.data_cleaner import DataCleaner


class LiveLogService:
    """
    Captures live system/machine logs from the host computer and provides real-time detection.
    """

    @classmethod
    def get_local_ip(cls) -> str:
        """Get local machine IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @classmethod
    def parse_wevtutil_text(cls, raw_text: str, log_channel: str = "Application") -> List[Dict[str, Any]]:
        """
        Parse raw output of `wevtutil qe <Channel> /f:text` into structured log dictionaries.
        """
        events: List[Dict[str, Any]] = []
        if not raw_text:
            return events

        # Split events by 'Event[' delimiter (with optional leading whitespace)
        event_blocks = re.split(r"(?m)^\s*Event\[\d+\]", raw_text)

        local_ip = cls.get_local_ip()

        for block in event_blocks:
            if not block.strip():
                continue

            date_m = re.search(r"Date:\s*(.+)", block)
            source_m = re.search(r"Source:\s*(.+)", block)
            level_m = re.search(r"Level:\s*(.+)", block)
            event_id_m = re.search(r"Event ID:\s*(\d+)", block)
            computer_m = re.search(r"Computer:\s*(.+)", block)
            desc_m = re.search(r"Description:\s*([\s\S]+)", block)

            raw_date = date_m.group(1).strip() if date_m else None
            source_name = source_m.group(1).strip() if source_m else f"Windows-{log_channel}"
            level_str = level_m.group(1).strip().lower() if level_m else "information"
            event_id_str = event_id_m.group(1).strip() if event_id_m else "100"
            description = desc_m.group(1).strip() if desc_m else "Windows Event Log Entry"

            # Clean description of null bytes and excessive whitespaces
            description = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", description)
            description = re.sub(r"\s+", " ", description).strip()
            if len(description) > 300:
                description = description[:300] + "..."

            # Map level to standard severity
            if "crit" in level_str:
                severity = "CRITICAL"
                status_code = 503
            elif "err" in level_str:
                severity = "ERROR"
                status_code = 500
            elif "warn" in level_str:
                severity = "WARNING"
                status_code = 403
            else:
                severity = "INFO"
                status_code = 200

            # Parse timestamp to standard ISO format
            normalized_ts = DataCleaner.normalize_timestamp(raw_date) or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            try:
                event_code = int(event_id_str)
            except ValueError:
                event_code = 100

            event_dict = {
                "timestamp": normalized_ts,
                "source": source_name[:50],
                "event_type": f"WIN_{log_channel.upper()}",
                "severity": severity,
                "status_code": status_code,
                "ip_address": local_ip,
                "endpoint": f"/system/{log_channel.lower()}/{event_code}",
                "message": description or f"Windows {log_channel} Event {event_code} from {source_name}",
            }
            events.append(event_dict)

        return events

    @classmethod
    def capture_from_host(cls, count: int = 6, channel: str = "Application") -> List[Dict[str, Any]]:
        """
        Execute native host log capture.
        Falls back smoothly to system diagnostics if wevtutil is unavailable.
        """
        captured: List[Dict[str, Any]] = []

        if platform.system().lower() == "windows":
            try:
                # Try wevtutil
                cmd = ["wevtutil", "qe", channel, f"/c:{count}", "/rd:true", "/f:text"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
                if res.returncode == 0 and res.stdout:
                    captured = cls.parse_wevtutil_text(res.stdout, log_channel=channel)
            except Exception as ex:
                print(f"[LiveLogService] wevtutil capture note: {ex}")

        # Fallback / augment with host live status telemetry if needed
        if not captured:
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            local_ip = cls.get_local_ip()
            hostname = platform.node() or "Local-PC"
            os_name = f"{platform.system()} {platform.release()}"

            captured = [
                {
                    "timestamp": now_iso,
                    "source": f"Host-{hostname}",
                    "event_type": "LIVE_HEARTBEAT",
                    "severity": "INFO",
                    "status_code": 200,
                    "ip_address": local_ip,
                    "endpoint": "/system/diagnostics",
                    "message": f"Active PC heartbeat from {hostname} running {os_name} (Network: {local_ip}).",
                }
            ]

        return captured[:count]

    @classmethod
    def capture_and_ingest_live_logs(cls, count: int = 5, channel: str = "Application") -> Dict[str, Any]:
        """
        Capture live logs from host computer, run anomaly detection, save to DB and sync to Supabase.
        """
        raw_events = cls.capture_from_host(count=count, channel=channel)
        if not raw_events:
            return {
                "success": False,
                "message": "No live events captured from the computer.",
                "logs_captured": 0,
                "anomalies_detected": 0,
            }

        # Convert to Log models and persist
        log_objects: List[Log] = []
        for ev in raw_events:
            # Parse timestamp to datetime
            dt = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00")).replace(tzinfo=None)
            log_obj = Log(
                timestamp=dt,
                source=ev["source"],
                event_type=ev["event_type"],
                severity=ev["severity"],
                status_code=ev.get("status_code"),
                ip_address=ev.get("ip_address"),
                endpoint=ev.get("endpoint"),
                message=ev["message"],
            )
            log_objects.append(log_obj)

        db.session.add_all(log_objects)
        db.session.commit()

        # Run anomaly detection on newly ingested logs
        detector = AnomalyDetector()
        all_logs = Log.query.all()
        detector.detect_batch(all_logs)
        db.session.commit()

        # Count anomalies in this batch
        anom_count = sum(1 for l in log_objects if l.anomaly)

        # Optionally copy to Supabase Cloud
        supabase_synced = False
        if SupabaseService.is_configured():
            try:
                logs_payload = [l.to_supabase_log() for l in log_objects]
                SupabaseService.insert_logs(logs_payload)
                anoms_payload = [l.to_supabase_anomaly() for l in log_objects if l.anomaly]
                if anoms_payload:
                    SupabaseService.insert_anomalies([a for a in anoms_payload if a])
                supabase_synced = True
            except Exception as ex:
                print(f"[LiveLogService Supabase Notice] {ex}")

        return {
            "success": True,
            "message": f"Successfully captured {len(log_objects)} live log(s) from computer. Flagged {anom_count} anomaly(ies).",
            "logs_captured": len(log_objects),
            "anomalies_detected": anom_count,
            "supabase_synced": supabase_synced,
            "items": [l.to_dict() for l in log_objects],
        }
