"""
Data Cleaner and Sanitization Service.

Cleans, normalizes, and validates log datasets to match Supabase database column schemas.
Prevents JSON serialization errors (NaN, Inf, NumPy types, corrupted timestamps, unescaped chars).
"""

import re
import math
import uuid
from datetime import datetime, date, time
from typing import Any, Dict, List, Optional, Tuple, Union


class DataCleaner:
    """
    Cleans raw log records and prepares them for Supabase column schemas and JSON serialization.
    """

    DEFAULT_LOCATION = "Global"
    DEFAULT_SESSION_ID = "1000"
    DEFAULT_EVENT_TYPE = "SYSTEM_EVENT"
    DEFAULT_SEVERITY = "INFO"

    @classmethod
    def sanitize_for_json(cls, obj: Any) -> Any:
        """
        Recursively convert data structures to strict JSON-serializable standard types.
        Handles:
        - NaN, Infinity, -Infinity -> None
        - NumPy ints/floats/bools -> Python int/float/bool
        - Datetime, date, time, UUID -> ISO string
        - Unescaped control characters -> sanitized string
        """
        if obj is None:
            return None

        # Check float special cases (NaN, Inf)
        if isinstance(obj, float):
            if math.isnan(obj) or math.isinf(obj):
                return None
            return round(obj, 6)

        # Basic types
        if isinstance(obj, bool):
            return obj
        if isinstance(obj, int):
            return int(obj)

        # Datetime & UUID
        if isinstance(obj, (datetime, date, time)):
            return obj.isoformat()
        if isinstance(obj, uuid.UUID):
            return str(obj)

        # String sanitization
        if isinstance(obj, str):
            # Remove null bytes and unprintable control characters (keep \t, \n, \r)
            cleaned_str = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", obj)
            return cleaned_str.strip()

        # Dictionaries
        if isinstance(obj, dict):
            return {
                str(k): cls.sanitize_for_json(v)
                for k, v in obj.items()
                if k is not None
            }

        # Lists, tuples, sets
        if isinstance(obj, (list, tuple, set)):
            return [cls.sanitize_for_json(item) for item in obj]

        # NumPy type handling (if numpy is present)
        type_str = type(obj).__name__
        if "int" in type_str:
            try:
                return int(obj)
            except Exception:
                pass
        if "float" in type_str:
            try:
                val = float(obj)
                return None if (math.isnan(val) or math.isinf(val)) else val
            except Exception:
                pass
        if "bool" in type_str:
            return bool(obj)
        if hasattr(obj, "tolist"):
            return cls.sanitize_for_json(obj.tolist())

        # Fallback to string representation
        return str(obj)

    @classmethod
    def normalize_timestamp(cls, val: Any) -> Optional[str]:
        """
        Convert arbitrary timestamp input into standard ISO 8601 UTC string (YYYY-MM-DDTHH:MM:SSZ).
        """
        if val is None:
            return None

        if isinstance(val, datetime):
            return val.strftime("%Y-%m-%dT%H:%M:%SZ")

        val_str = str(val).strip()
        if not val_str or val_str.lower() in ("nan", "nat", "none", "null", "n/a"):
            return None

        # Common timestamp parsing formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y/%m/%d %H:%M:%S",
            "%d-%m-%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%Y-%m-%d",
            "%d-%m-%Y",
            "%m/%d/%Y %H:%M:%S",
        ]

        cleaned_str = val_str.replace("Z", "").strip()
        for fmt in formats:
            try:
                dt = datetime.strptime(cleaned_str, fmt.replace("Z", ""))
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue

        # Try ISO fallback
        try:
            dt = datetime.fromisoformat(val_str)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

        return val_str

    @classmethod
    def normalize_status_code(cls, val: Any) -> Optional[int]:
        """
        Clean and extract HTTP status code as a clean integer (e.g. 200, 404, 500).
        """
        if val is None:
            return None

        if isinstance(val, int):
            return val if 100 <= val <= 599 else None

        if isinstance(val, float):
            if math.isnan(val) or math.isinf(val):
                return None
            ival = int(val)
            return ival if 100 <= ival <= 599 else None

        val_str = str(val).strip()
        if not val_str or val_str.lower() in ("nan", "none", "null", "-", "n/a"):
            return None

        # Extract numeric code (e.g. "HTTP 500 Internal Error" -> 500)
        match = re.search(r"\b([1-5]\d\d)\b", val_str)
        if match:
            return int(match.group(1))

        try:
            code = int(float(val_str))
            return code if 100 <= code <= 599 else None
        except Exception:
            return None

    @classmethod
    def normalize_ip(cls, val: Any) -> Optional[str]:
        """
        Clean and sanitize IP addresses (IPv4 or IPv6).
        """
        if val is None:
            return None

        ip_str = str(val).strip()
        if not ip_str or ip_str.lower() in ("nan", "none", "null", "n/a", "-"):
            return None

        # Simple IPv4 pattern
        ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        if re.match(ipv4_pattern, ip_str):
            return ip_str

        # IPv6 basic pattern
        if ":" in ip_str and len(ip_str) >= 3:
            return ip_str

        return ip_str

    @classmethod
    def clean_record_for_supabase(
        cls, record: Dict[str, Any], table_name: str = "smart Log analyser"
    ) -> Dict[str, Any]:
        """
        Clean and format a single record specifically according to Supabase column schema.
        Handles both 'smart Log analyser' and standard 'logs' table schemas.
        """
        # Ensure UUID
        rec_id = record.get("id")
        if not rec_id or not isinstance(rec_id, str) or len(str(rec_id)) < 10:
            rec_id = str(uuid.uuid4())

        # Clean timestamp
        raw_ts = record.get("timestamp") or record.get("Timestamp") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        iso_ts = cls.normalize_timestamp(raw_ts)

        # Clean IP
        raw_ip = record.get("ip_address") or record.get("IP_Address") or record.get("ip") or "127.0.0.1"
        clean_ip = cls.normalize_ip(raw_ip) or "127.0.0.1"

        # Clean event type
        raw_event = record.get("event_type") or record.get("Request_Type") or record.get("event") or cls.DEFAULT_EVENT_TYPE
        clean_event = str(raw_event).strip().upper()

        # Clean status code
        raw_status = record.get("status_code") or record.get("Status_Code") or record.get("status")
        clean_status = cls.normalize_status_code(raw_status)

        # Clean source / user agent
        raw_source = record.get("source") or record.get("service") or record.get("User_Agent") or "api-service"
        clean_source = str(raw_source).strip()

        # Clean session ID
        raw_session = record.get("session_id") or record.get("Session_ID") or record.get("endpoint") or cls.DEFAULT_SESSION_ID
        session_str = str(raw_session).replace("/session/", "").replace("/", "").strip()
        if not session_str or session_str == "":
            session_str = cls.DEFAULT_SESSION_ID

        # Clean location
        raw_loc = record.get("location") or record.get("Location") or cls.DEFAULT_LOCATION
        clean_loc = str(raw_loc).strip() or cls.DEFAULT_LOCATION

        # Clean message / severity
        raw_msg = record.get("message") or record.get("Message") or f"Event {clean_event} on {clean_source}"
        clean_msg = str(raw_msg).strip()

        raw_sev = record.get("severity") or ("ERROR" if clean_status and clean_status >= 500 else "WARNING" if clean_status and clean_status >= 400 else "INFO")
        clean_sev = str(raw_sev).strip().upper()

        if table_name == "smart Log analyser":
            # Match exact Supabase column names of 'smart Log analyser'
            cleaned_row = {
                "id": str(rec_id),
                "timestamp": iso_ts,
                "ip_address": clean_ip,
                "event_type": clean_event,
                "status_code": clean_status,
                "user_agent": clean_source.capitalize(),
                "session_id": session_str,
                "location": clean_loc,
            }
        else:
            # Standard 'logs' table schema
            cleaned_row = {
                "id": str(rec_id),
                "timestamp": iso_ts,
                "source": clean_source,
                "event_type": clean_event,
                "severity": clean_sev,
                "status_code": clean_status,
                "ip_address": clean_ip,
                "message": clean_msg,
            }

        # Sanitize everything to ensure strict JSON validity
        return cls.sanitize_for_json(cleaned_row)

    @classmethod
    def clean_dataset(
        cls, records: List[Dict[str, Any]], table_name: str = "smart Log analyser"
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Clean an entire batch/dataset of log records for Supabase column conformity.
        Returns cleaned records and detailed processing metrics.
        """
        cleaned_records = []
        metrics = {
            "total_input": len(records),
            "cleaned_count": 0,
            "nulls_repaired": 0,
            "timestamps_normalized": 0,
            "status_codes_normalized": 0,
        }

        for rec in records:
            if not isinstance(rec, dict):
                continue

            cleaned = cls.clean_record_for_supabase(rec, table_name=table_name)
            cleaned_records.append(cleaned)
            metrics["cleaned_count"] += 1

            if cleaned.get("timestamp"):
                metrics["timestamps_normalized"] += 1
            if cleaned.get("status_code") is not None:
                metrics["status_codes_normalized"] += 1

        return cleaned_records, metrics
