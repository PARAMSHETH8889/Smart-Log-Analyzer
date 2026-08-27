"""
Log Parser Service.

Handles CSV parsing, encoding normalization, batch validation,
and database persistence with deterministic anomaly detection trigger.
"""

import io
import csv
from typing import List, Dict, Any, Tuple, Union, BinaryIO, TextIO
from pathlib import Path

from services.validation import LogValidator, ValidationResult, ValidationError
from models import db
from models.models import Log


class LogParser:
    """
    Parses and ingests log files into validated database records.
    """

    @classmethod
    def parse_csv_stream(
        cls, file_stream: Union[BinaryIO, TextIO, str, bytes, Path]
    ) -> Tuple[List[Dict[str, Any]], List[ValidationError]]:
        """
        Safely parse CSV stream or file into raw dictionaries.
        """
        errors: List[ValidationError] = []
        raw_rows: List[Dict[str, Any]] = []

        try:
            # Handle Path
            if isinstance(file_stream, (str, Path)) and (
                isinstance(file_stream, Path) or (
                    "\n" not in str(file_stream) and Path(str(file_stream)).exists()
                )
            ):
                with open(file_stream, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            elif isinstance(file_stream, bytes):
                content = file_stream.decode("utf-8", errors="replace")
            elif hasattr(file_stream, "read"):
                raw_bytes = file_stream.read()
                if isinstance(raw_bytes, bytes):
                    content = raw_bytes.decode("utf-8", errors="replace")
                else:
                    content = str(raw_bytes)
            else:
                content = str(file_stream)

            if not content or not content.strip():
                return [], [
                    ValidationError(
                        row_number=None,
                        field="file",
                        message="Uploaded file is completely empty.",
                    )
                ]

            # Remove UTF-8 BOM if present
            if content.startswith("\ufeff"):
                content = content[1:]

            # Sniff delimiter (comma, tab, semicolon, pipe)
            sample = content[:4096]
            try:
                sniffer = csv.Sniffer()
                dialect = sniffer.sniff(sample, delimiters=",\t;|")
                delimiter = dialect.delimiter
            except Exception:
                delimiter = ","

            # Read with csv.DictReader for robust row-by-row parsing
            csv_file = io.StringIO(content)
            reader = csv.DictReader(csv_file, delimiter=delimiter)

            if not reader.fieldnames:
                return [], [
                    ValidationError(
                        row_number=None,
                        field="header",
                        message="CSV file has no header row or columns defined.",
                    )
                ]

            # Clean fieldnames (strip spaces and lowercase)
            cleaned_headers = {
                h: h.strip().lower() for h in reader.fieldnames if h
            }

            for row in reader:
                cleaned_row = {}
                for k, v in row.items():
                    if k is not None:
                        clean_key = cleaned_headers.get(k, k.strip().lower())
                        cleaned_row[clean_key] = v.strip() if isinstance(v, str) else v
                raw_rows.append(cleaned_row)

        except Exception as ex:
            errors.append(
                ValidationError(
                    row_number=None,
                    field="file_parsing",
                    message=f"Failed to parse CSV file structure: {str(ex)}",
                )
            )

        return raw_rows, errors

    @classmethod
    def process_and_validate(
        cls, file_input: Union[BinaryIO, TextIO, str, bytes, Path]
    ) -> ValidationResult:
        """
        Parse and validate CSV content.
        """
        raw_rows, parse_errors = cls.parse_csv_stream(file_input)

        if parse_errors:
            return ValidationResult(
                is_valid=False,
                total_processed=len(raw_rows),
                valid_records=[],
                errors=parse_errors,
            )

        validation_result = LogValidator.validate_batch(raw_rows)
        return validation_result

    @classmethod
    def ingest_records(
        cls,
        valid_records: List[Dict[str, Any]],
        run_detection: bool = False,
        detector_service: Any = None,
    ) -> List[Log]:
        """
        Persist validated log records into SQLite database with fast bulk insertion.
        Does NOT run heavy anomaly detection on upload unless explicitly requested.
        """
        if not valid_records:
            return []

        # Convert dicts into Log model objects in chunks for lightning-fast SQLite commit
        log_objects: List[Log] = []
        for rec in valid_records:
            log_obj = Log(
                timestamp=rec["timestamp"],
                source=rec["source"],
                event_type=rec["event_type"],
                severity=rec["severity"],
                ip_address=rec.get("ip_address"),
                status_code=rec.get("status_code"),
                endpoint=rec.get("endpoint"),
                message=rec["message"],
            )
            log_objects.append(log_obj)

        chunk_size = 2000
        for i in range(0, len(log_objects), chunk_size):
            chunk = log_objects[i : i + chunk_size]
            db.session.add_all(chunk)
            db.session.commit()

        if run_detection and log_objects:
            if detector_service is None:
                from services.anomaly_detector import AnomalyDetector
                detector_service = AnomalyDetector

            detector = detector_service()
            detector.detect_batch(log_objects)
            db.session.commit()

        return log_objects
