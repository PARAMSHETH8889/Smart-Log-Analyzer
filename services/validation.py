"""
Log Validation Service.

Validates log entries and uploaded CSV data for schema conformity,
type integrity, required fields, timestamp parsing, enum restrictions,
and duplicates. Supports standard server log schemas and web access log formats.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Tuple
import re

VALID_SEVERITIES = {"INFO", "WARNING", "ERROR", "CRITICAL"}


@dataclass
class ValidationError:
    """Represents a validation failure for a specific row or the entire file."""
    row_number: Optional[int]
    field: str
    message: str
    raw_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "row": self.row_number if self.row_number is not None else "N/A",
            "field": self.field,
            "message": self.message,
        }


@dataclass
class ValidationResult:
    """Encapsulates the complete result of validating a log batch or file."""
    is_valid: bool
    total_processed: int
    valid_records: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[ValidationError] = field(default_factory=list)
    duplicate_count: int = 0

    @property
    def valid_count(self) -> int:
        return len(self.valid_records)

    @property
    def rejected_count(self) -> int:
        return self.total_processed - self.valid_count

    def error_summary(self) -> List[Dict[str, Any]]:
        return [err.to_dict() for err in self.errors]


class LogValidator:
    """
    Validates log records against schema, constraints, and business logic.
    """

    TIMESTAMP_FORMATS = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y/%m/%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    ]

    @classmethod
    def parse_timestamp(cls, raw_val: Any) -> Optional[datetime]:
        """
        Attempt to parse timestamp using multiple standard date/time formats.
        """
        if raw_val is None:
            return None
        if isinstance(raw_val, datetime):
            return raw_val

        str_val = str(raw_val).strip()
        if not str_val or str_val.lower() in ("nan", "none", "null"):
            return None

        # Clean trailing timezone Z for simple parsing if needed
        clean_str = str_val.replace("Z", "").strip()

        for fmt in cls.TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(clean_str, fmt.replace("Z", ""))
            except ValueError:
                continue

        # Try ISO fromisoformat fallback
        try:
            return datetime.fromisoformat(str_val)
        except Exception:
            return None

    @classmethod
    def normalize_row_dict(cls, row: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize dictionary keys from various CSV header conventions.
        """
        normalized = {}
        for k, v in row.items():
            if k is None:
                continue
            clean_k = str(k).strip().lower().replace("-", "_").replace(" ", "_")
            normalized[clean_k] = v.strip() if isinstance(v, str) else v
        return normalized

    @classmethod
    def validate_row(
        cls,
        raw_row: Dict[str, Any],
        row_number: Optional[int] = None,
        seen_keys: Optional[Set[Tuple]] = None,
    ) -> Tuple[Optional[Dict[str, Any]], List[ValidationError]]:
        """
        Validate a single dictionary representing a log row.
        Supports both standard schemas and web access log schemas.
        """
        errors: List[ValidationError] = []
        row = cls.normalize_row_dict(raw_row)

        # 1. Extract and Validate Timestamp
        raw_ts = (
            row.get("timestamp")
            or row.get("time")
            or row.get("datetime")
            or row.get("date")
        )
        if not raw_ts:
            errors.append(
                ValidationError(
                    row_number=row_number,
                    field="timestamp",
                    message="Missing required timestamp field.",
                    raw_data=raw_row,
                )
            )
            return None, errors

        parsed_ts = cls.parse_timestamp(raw_ts)
        if not parsed_ts:
            errors.append(
                ValidationError(
                    row_number=row_number,
                    field="timestamp",
                    message=f"Invalid timestamp format: '{raw_ts}'.",
                    raw_data=raw_row,
                )
            )
            return None, errors

        # 2. Extract and Validate Status Code
        raw_status = (
            row.get("status_code")
            or row.get("status")
            or row.get("code")
            or row.get("response_code")
        )
        status_code = None
        if raw_status is not None:
            raw_status_str = str(raw_status).strip()
            if raw_status_str and raw_status_str.lower() not in ("nan", "none", "null", ""):
                try:
                    status_code = int(float(raw_status_str))
                    if not (100 <= status_code <= 599):
                        errors.append(
                            ValidationError(
                                row_number=row_number,
                                field="status_code",
                                message=f"HTTP status code must be between 100 and 599. Got '{raw_status}'.",
                                raw_data=raw_row,
                            )
                        )
                except (ValueError, TypeError):
                    errors.append(
                        ValidationError(
                            row_number=row_number,
                            field="status_code",
                            message=f"Invalid status code numeric value: '{raw_status}'.",
                            raw_data=raw_row,
                        )
                    )

        # 3. Extract and Validate Event Type
        raw_event = (
            row.get("event_type")
            or row.get("request_type")
            or row.get("event")
            or row.get("method")
            or row.get("action")
            or row.get("type")
        )
        if not raw_event:
            errors.append(
                ValidationError(
                    row_number=row_number,
                    field="event_type",
                    message="Missing required event_type/request_type field.",
                    raw_data=raw_row,
                )
            )
            return None, errors
        event_type = str(raw_event).strip().upper()

        # 4. Extract and Validate Source
        user_agent = row.get("user_agent")
        location = row.get("location")
        session_id = row.get("session_id")

        if "source" in row:
            raw_source = row.get("source")
            if not raw_source or not str(raw_source).strip():
                errors.append(
                    ValidationError(
                        row_number=row_number,
                        field="source",
                        message="Missing required field 'source'.",
                        raw_data=raw_row,
                    )
                )
                return None, errors
            source = str(raw_source).strip()
        else:
            raw_source = (
                row.get("service")
                or row.get("server")
                or row.get("host")
            )
            if not raw_source:
                if user_agent and location:
                    source = f"web-{str(user_agent).lower().replace(' ', '-')}"
                elif user_agent:
                    source = f"web-{str(user_agent).lower()}"
                elif location:
                    source = f"web-{str(location).lower()}"
                else:
                    source = "web-server-01"
            else:
                source = str(raw_source).strip()

        # 5. Extract and Validate Severity
        if "severity" in row:
            raw_sev = row.get("severity")
            if not raw_sev or not str(raw_sev).strip():
                errors.append(
                    ValidationError(
                        row_number=row_number,
                        field="severity",
                        message="Missing required field 'severity'.",
                        raw_data=raw_row,
                    )
                )
                return None, errors
            sev_candidate = str(raw_sev).strip().upper()
            if sev_candidate not in VALID_SEVERITIES:
                errors.append(
                    ValidationError(
                        row_number=row_number,
                        field="severity",
                        message=f"Invalid severity '{raw_sev}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}.",
                        raw_data=raw_row,
                    )
                )
                return None, errors
            severity = sev_candidate
        else:
            raw_sev = (
                row.get("level")
                or row.get("log_level")
            )
            if not raw_sev:
                if status_code is not None:
                    if status_code >= 500:
                        severity = "ERROR"
                    elif status_code in (401, 403, 404):
                        severity = "WARNING"
                    else:
                        severity = "INFO"
                else:
                    severity = "INFO"
            else:
                sev_candidate = str(raw_sev).strip().upper()
                if sev_candidate not in VALID_SEVERITIES:
                    errors.append(
                        ValidationError(
                            row_number=row_number,
                            field="severity",
                            message=f"Invalid severity '{raw_sev}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}.",
                            raw_data=raw_row,
                        )
                    )
                    return None, errors
                severity = sev_candidate

        # 6. Extract IP Address
        raw_ip = (
            row.get("ip_address")
            or row.get("ip")
            or row.get("client_ip")
            or row.get("host_ip")
        )
        ip_address = str(raw_ip).strip() if raw_ip else None

        # 7. Extract Endpoint / URI
        raw_endpoint = (
            row.get("endpoint")
            or row.get("url")
            or row.get("path")
            or row.get("route")
            or row.get("uri")
        )
        if not raw_endpoint:
            if session_id:
                endpoint = f"/session/{session_id}"
            else:
                endpoint = f"/api/v1/{event_type.lower()}"
        else:
            endpoint = str(raw_endpoint).strip()

        # 8. Extract or Synthesize Message
        raw_msg = (
            row.get("message")
            or row.get("msg")
            or row.get("details")
            or row.get("description")
        )
        if not raw_msg:
            # Construct clear, descriptive message
            msg_parts = [f"{event_type} {endpoint}"]
            if status_code:
                msg_parts.append(f"HTTP {status_code}")
            if user_agent:
                msg_parts.append(f"Agent: {user_agent}")
            if location:
                msg_parts.append(f"Location: {location}")
            if session_id:
                msg_parts.append(f"Session: {session_id}")
            message = " | ".join(msg_parts)
        else:
            message = str(raw_msg).strip()

        if errors:
            return None, errors

        # Duplicate check key: (timestamp, source, event_type, message, status_code, ip_address)
        dup_key = (
            parsed_ts.isoformat() if parsed_ts else None,
            source,
            event_type,
            status_code,
            ip_address,
        )
        is_duplicate = False
        if seen_keys is not None:
            if dup_key in seen_keys:
                is_duplicate = True
            else:
                seen_keys.add(dup_key)

        cleaned_record = {
            "timestamp": parsed_ts,
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "ip_address": ip_address,
            "status_code": status_code,
            "endpoint": endpoint,
            "message": message,
            "is_duplicate": is_duplicate,
        }

        return cleaned_record, []

    @classmethod
    def validate_batch(
        cls, rows: List[Dict[str, Any]]
    ) -> ValidationResult:
        """
        Validate a collection of raw log rows.
        """
        if not rows:
            return ValidationResult(
                is_valid=False,
                total_processed=0,
                errors=[
                    ValidationError(
                        row_number=None,
                        field="file",
                        message="Dataset is empty. No log records found.",
                    )
                ],
            )

        valid_records: List[Dict[str, Any]] = []
        errors: List[ValidationError] = []
        seen_keys: Set[Tuple] = set()
        duplicate_count = 0

        for idx, row in enumerate(rows, start=1):
            if not isinstance(row, dict):
                errors.append(
                    ValidationError(
                        row_number=idx,
                        field="row",
                        message=f"Malformed row data structure at line {idx}.",
                    )
                )
                continue

            cleaned, row_errors = cls.validate_row(
                row, row_number=idx, seen_keys=seen_keys
            )
            if row_errors:
                errors.extend(row_errors)
            elif cleaned:
                if cleaned.get("is_duplicate"):
                    duplicate_count += 1
                valid_records.append(cleaned)

        return ValidationResult(
            is_valid=len(valid_records) > 0,
            total_processed=len(rows),
            valid_records=valid_records,
            errors=errors,
            duplicate_count=duplicate_count,
        )
