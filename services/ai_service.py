"""
Google Gemini AI Explanation Service.

This service is ONLY invoked for logs that have ALREADY been flagged
as anomalous by the deterministic Python anomaly detection algorithm.
The AI does NOT decide whether a log is anomalous; its role is strictly
to provide root-cause analysis, plain-English explanations, and
recommended next steps.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field

from config import Config
from models import db
from models.models import Log


class AnomalyExplanationSchema(BaseModel):
    """Structured response schema expected from Gemini."""
    explanation: str = Field(
        description="Plain-English explanation of why this anomaly occurred and why it matters."
    )
    likely_root_cause: str = Field(
        description="Identified probable technical root cause based on log message, status, and surrounding sequence."
    )
    recommended_next_step: str = Field(
        description="Actionable, prioritized troubleshooting or remediation step for an on-call engineer."
    )


class GeminiAIService:
    """
    Manages structured Gemini interactions for log anomaly explanations.
    """

    @classmethod
    def get_api_key(cls) -> str:
        """Retrieve Gemini API key from config or environment."""
        return Config.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY", "").strip()

    @classmethod
    def is_configured(cls) -> bool:
        """Check if a non-empty Gemini API key is available."""
        key = cls.get_api_key()
        return bool(key and key != "your_gemini_api_key_here")

    @classmethod
    def get_surrounding_context(
        cls, log: Log, limit: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Fetch up to `limit` logs before and after the target log around its timestamp,
        preferring the same source/IP to give temporal sequence context.
        """
        if not log or not log.timestamp:
            return []

        try:
            # Query previous logs
            prev_logs = (
                Log.query.filter(
                    Log.timestamp <= log.timestamp,
                    Log.id != log.id,
                    (Log.source == log.source) | (Log.ip_address == log.ip_address),
                )
                .order_by(Log.timestamp.desc())
                .limit(limit)
                .all()
            )
            prev_logs.reverse()

            # Query next logs
            next_logs = (
                Log.query.filter(
                    Log.timestamp >= log.timestamp,
                    Log.id != log.id,
                    (Log.source == log.source) | (Log.ip_address == log.ip_address),
                )
                .order_by(Log.timestamp.asc())
                .limit(limit)
                .all()
            )

            combined = []
            for l in prev_logs:
                d = l.to_dict()
                d["relative_position"] = "PREVIOUS"
                combined.append(d)

            current_dict = log.to_dict()
            current_dict["relative_position"] = "CURRENT_ANOMALY"
            combined.append(current_dict)

            for l in next_logs:
                d = l.to_dict()
                d["relative_position"] = "FOLLOWING"
                combined.append(d)

            return combined
        except Exception:
            return []

    @classmethod
    def build_prompt(
        cls, log: Log, surrounding_logs: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """
        Construct a focused, structured prompt for Gemini.
        Emphasizes that anomaly status was already deterministically determined.
        """
        context_str = ""
        if surrounding_logs and len(surrounding_logs) > 1:
            context_items = []
            for item in surrounding_logs:
                pos = item.get("relative_position", "")
                ts = item.get("timestamp", "N/A")
                src = item.get("source", "N/A")
                sev = item.get("severity", "N/A")
                code = item.get("status_code", "N/A")
                msg = item.get("message", "N/A")
                context_items.append(
                    f"- [{pos}] Time: {ts} | Source: {src} | Severity: {sev} | Status: {code} | Message: {msg}"
                )
            context_str = "\n".join(context_items)

        prompt = f"""You are a site reliability engineering and cybersecurity expert.
A log entry has ALREADY been flagged as anomalous by our programmatic Python anomaly detector.
Do NOT evaluate whether this log is anomalous. Assume it is confirmed anomalous.

Target Anomaly Log Data:
- Timestamp: {log.timestamp}
- Source Service: {log.source}
- Event Type: {log.event_type}
- Severity: {log.severity}
- IP Address: {log.ip_address or 'N/A'}
- HTTP Status Code: {log.status_code or 'N/A'}
- Endpoint: {log.endpoint or 'N/A'}
- Log Message: {log.message}
- Calculated Anomaly Score: {log.anomaly_score:.1f}/100
- Programmatic Detection Reason: {log.anomaly_reason}

Surrounding Event Timeline Context:
{context_str if context_str else 'No surrounding context available.'}

Instructions:
Analyze why this specific anomaly matters in a modern production architecture, pinpoint the most likely technical root cause, and formulate a clear, actionable remediation step.
Return your response as strict JSON adhering to this structure:
{{
  "explanation": "...",
  "likely_root_cause": "...",
  "recommended_next_step": "..."
}}
"""
        return prompt

    @classmethod
    def explain_anomaly(
        cls,
        log: Log,
        surrounding_logs: Optional[List[Dict[str, Any]]] = None,
        model_name: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """
        Execute Gemini API request to explain an anomaly.

        Returns:
            Tuple of (success: bool, result_dict: dict, error_message: Optional[str])
        """
        if not log.anomaly:
            return (
                False,
                {},
                "Log is not flagged as an anomaly. AI explanation is only available for anomalous logs.",
            )

        api_key = cls.get_api_key()
        if not api_key or api_key == "your_gemini_api_key_here":
            return (
                False,
                {},
                "Google Gemini API key is missing. Please set GEMINI_API_KEY in your .env file.",
            )

        if surrounding_logs is None:
            surrounding_logs = cls.get_surrounding_context(log)

        prompt = cls.build_prompt(log, surrounding_logs)
        selected_model = model_name or Config.GEMINI_MODEL or "gemini-2.5-flash"

        try:
            # Import official google-genai SDK
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=api_key)

            response = client.models.generate_content(
                model=selected_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=AnomalyExplanationSchema,
                    temperature=0.2,
                ),
            )

            raw_text = response.text or "{}"
            parsed_json = json.loads(raw_text)

            # Validate required fields
            explanation = parsed_json.get("explanation", "").strip()
            root_cause = parsed_json.get("likely_root_cause", "").strip()
            next_step = parsed_json.get("recommended_next_step", "").strip()

            if not explanation or not root_cause or not next_step:
                raise ValueError("Incomplete structured JSON returned by AI model.")

            # Update Log model
            log.ai_explanation = explanation
            log.ai_root_cause = root_cause
            log.ai_next_step = next_step
            log.ai_model = selected_model
            log.ai_analyzed_at = datetime.utcnow()
            db.session.commit()

            result = {
                "explanation": explanation,
                "likely_root_cause": root_cause,
                "recommended_next_step": next_step,
                "model": selected_model,
                "analyzed_at": log.ai_analyzed_at.strftime("%Y-%m-%d %H:%M:%S"),
            }
            return True, result, None

        except ImportError:
            return (
                False,
                {},
                "The 'google-genai' package is not installed. Run 'pip install google-genai'.",
            )
        except json.JSONDecodeError:
            return (
                False,
                {},
                "AI returned malformed or non-JSON output. Please retry.",
            )
        except Exception as ex:
            error_str = str(ex)
            # Sanitize error message to prevent leaking sensitive credentials
            if api_key and api_key in error_str:
                error_str = error_str.replace(api_key, "[REDACTED_API_KEY]")
            return (
                False,
                {},
                f"Gemini API request failed: {error_str}",
            )
