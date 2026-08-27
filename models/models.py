"""
SQLAlchemy ORM models for Smart Log Analyzer & Anomaly Detector.
"""

from datetime import datetime
from typing import Dict, Any, Optional
import uuid
from models import db


class Log(db.Model):
    """
    Represents an ingested server/system log record with its associated
    deterministic anomaly detection results and Gemini AI explanation.
    """

    __tablename__ = "logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    source = db.Column(db.String(100), nullable=False, index=True)
    event_type = db.Column(db.String(100), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)

    # Optional detailed attributes
    ip_address = db.Column(db.String(50), nullable=True)
    status_code = db.Column(db.Integer, nullable=True)
    message = db.Column(db.Text, nullable=False)
    endpoint = db.Column(db.String(255), nullable=True)

    # Deterministic Anomaly Detection fields (populated by Python algorithm)
    anomaly = db.Column(db.Boolean, default=False, nullable=False, index=True)
    anomaly_score = db.Column(db.Float, default=0.0, nullable=False)
    anomaly_reason = db.Column(db.Text, nullable=True)

    # Gemini AI fields (populated ONLY after an anomaly has been detected)
    ai_explanation = db.Column(db.Text, nullable=True)
    ai_root_cause = db.Column(db.Text, nullable=True)
    ai_next_step = db.Column(db.Text, nullable=True)
    ai_model = db.Column(db.String(100), nullable=True)
    ai_analyzed_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    def __init__(self, **kwargs):
        if "uuid" not in kwargs or not kwargs["uuid"]:
            kwargs["uuid"] = str(uuid.uuid4())
        super().__init__(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Convert log model instance to Python dictionary."""
        return {
            "id": self.id,
            "uuid": self.uuid,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if self.timestamp
            else None,
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity,
            "ip_address": self.ip_address,
            "status_code": self.status_code,
            "message": self.message,
            "endpoint": self.endpoint,
            "anomaly": self.anomaly,
            "anomaly_score": round(self.anomaly_score, 1),
            "anomaly_reason": self.anomaly_reason,
            "ai_explanation": self.ai_explanation,
            "ai_root_cause": self.ai_root_cause,
            "ai_next_step": self.ai_next_step,
            "ai_model": self.ai_model,
            "ai_analyzed_at": self.ai_analyzed_at.strftime("%Y-%m-%d %H:%M:%S")
            if self.ai_analyzed_at
            else None,
            "has_ai_analysis": bool(
                self.ai_explanation or self.ai_root_cause or self.ai_next_step
            ),
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if self.created_at
            else None,
        }

    def to_supabase_log(self) -> Dict[str, Any]:
        """Prepare log dictionary for Supabase `logs` table insertion."""
        log_id = self.uuid or str(uuid.uuid4())
        return {
            "id": log_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "ip_address": self.ip_address,
            "status_code": self.status_code,
            "message": self.message,
            "endpoint": self.endpoint,
            "created_at": (self.created_at or datetime.utcnow()).isoformat(),
            "updated_at": (self.updated_at or datetime.utcnow()).isoformat(),
        }

    def to_supabase_anomaly(self) -> Optional[Dict[str, Any]]:
        """Prepare anomaly record for Supabase `anomalies` table."""
        if not self.anomaly:
            return None
        log_id = self.uuid or str(uuid.uuid4())
        return {
            "id": str(uuid.uuid4()),
            "log_id": log_id,
            "is_anomaly": True,
            "anomaly_score": float(round(self.anomaly_score, 2)),
            "reason": self.anomaly_reason
            or "Deterministic anomaly detection flagged this log.",
            "detected_by": "Hybrid Rule-Based + Isolation Forest",
            "created_at": datetime.utcnow().isoformat(),
        }

    def to_supabase_ai(self, anomaly_uuid: str) -> Optional[Dict[str, Any]]:
        """Prepare AI analysis record for Supabase `ai_analysis` table."""
        if not (self.ai_explanation or self.ai_root_cause or self.ai_next_step):
            return None
        return {
            "id": str(uuid.uuid4()),
            "anomaly_id": anomaly_uuid,
            "explanation": self.ai_explanation,
            "root_cause": self.ai_root_cause,
            "next_step": self.ai_next_step,
            "model": self.ai_model or "gemini-2.5-flash",
            "created_at": (
                self.ai_analyzed_at or datetime.utcnow()
            ).isoformat(),
        }

    def __repr__(self) -> str:
        return f"<Log id={self.id} source='{self.source}' severity='{self.severity}' anomaly={self.anomaly}>"
