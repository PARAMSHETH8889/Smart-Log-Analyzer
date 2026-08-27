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
    def safe_parse_ai_json(cls, raw_text: str) -> Dict[str, str]:
        """
        Failsafe JSON parser with multi-tier recovery strategies.
        Guarantees that invalid JSON errors never bubble up to the user.
        """
        import re
        if not raw_text or not raw_text.strip():
            return {
                "explanation": "Anomalous event pattern detected requiring investigation.",
                "likely_root_cause": "System anomaly or threshold deviation.",
                "recommended_next_step": "Check application error logs and verify service dependencies.",
            }

        cleaned = raw_text.strip()
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        cleaned = cleaned.strip()

        # Tier 1: Direct JSON parse
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict):
                return {
                    "explanation": str(data.get("explanation") or "Anomalous event pattern detected."),
                    "likely_root_cause": str(data.get("likely_root_cause") or data.get("root_cause") or "System error or threshold deviation."),
                    "recommended_next_step": str(data.get("recommended_next_step") or data.get("next_step") or "Inspect surrounding logs and verify service status."),
                }
        except Exception:
            pass

        # Tier 2: Extract JSON substring between first '{' and last '}'
        first_b = cleaned.find("{")
        last_b = cleaned.rfind("}")
        if first_b != -1 and last_b != -1 and last_b > first_b:
            sub = cleaned[first_b : last_b + 1]
            try:
                data = json.loads(sub)
                if isinstance(data, dict):
                    return {
                        "explanation": str(data.get("explanation") or "Anomalous event pattern detected."),
                        "likely_root_cause": str(data.get("likely_root_cause") or data.get("root_cause") or "System error or threshold deviation."),
                        "recommended_next_step": str(data.get("recommended_next_step") or data.get("next_step") or "Inspect surrounding logs and verify service status."),
                    }
            except Exception:
                # Tier 3: Remove trailing commas
                fixed = re.sub(r",\s*([\}\]])", r"\1", sub)
                try:
                    data = json.loads(fixed)
                    if isinstance(data, dict):
                        return {
                            "explanation": str(data.get("explanation") or "Anomalous event pattern detected."),
                            "likely_root_cause": str(data.get("likely_root_cause") or data.get("root_cause") or "System error or threshold deviation."),
                            "recommended_next_step": str(data.get("recommended_next_step") or data.get("next_step") or "Inspect surrounding logs and verify service status."),
                        }
                except Exception:
                    pass

        # Tier 4: Regex field extraction
        def extract_field(patterns: List[str], text: str) -> Optional[str]:
            for pattern in patterns:
                m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
                if m:
                    val = m.group(1).strip().strip('"').strip("'")
                    val = val.replace('\\"', '"').replace('\\n', '\n')
                    if len(val) > 2:
                        return val
            return None

        explanation = extract_field([
            r'"explanation"\s*:\s*"((?:[^"\\]|\\.)*)"',
            r'explanation\s*:\s*([^\n\r]+)',
            r'Explanation:\s*([^\n\r]+)',
        ], cleaned)

        root_cause = extract_field([
            r'"likely_root_cause"\s*:\s*"((?:[^"\\]|\\.)*)"',
            r'"root_cause"\s*:\s*"((?:[^"\\]|\\.)*)"',
            r'likely_root_cause\s*:\s*([^\n\r]+)',
            r'Root Cause:\s*([^\n\r]+)',
        ], cleaned)

        next_step = extract_field([
            r'"recommended_next_step"\s*:\s*"((?:[^"\\]|\\.)*)"',
            r'"next_step"\s*:\s*"((?:[^"\\]|\\.)*)"',
            r'recommended_next_step\s*:\s*([^\n\r]+)',
            r'Next Step:\s*([^\n\r]+)',
        ], cleaned)

        return {
            "explanation": explanation or (cleaned[:300] if len(cleaned) > 20 else "Anomalous event pattern detected requiring review."),
            "likely_root_cause": root_cause or "High-severity HTTP status or unusual request frequency.",
            "recommended_next_step": next_step or "Inspect service logs, verify downstream APIs, and monitor traffic patterns.",
        }

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

        prompt = cls.build_prompt(log, surrounding_logs)
        primary_model = model_name or Config.GEMINI_MODEL or "gemini-3.5-flash-lite"
        candidate_models = [primary_model, "gemini-3.5-flash-lite", "gemini-3.6-flash"]
        # Deduplicate preserving order
        candidate_models = list(dict.fromkeys(candidate_models))

        try:
            # Import official google-genai SDK
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=api_key)

            response = None
            used_model = primary_model
            last_err = None

            for model in candidate_models:
                try:
                    response = client.models.generate_content(
                        model=model,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json",
                            temperature=0.2,
                        ),
                    )
                    used_model = model
                    break
                except Exception as ex:
                    last_err = ex
                    continue

            if response is None:
                raise last_err or RuntimeError("Gemini model generation failed.")

            raw_text = (response.text or "{}").strip()
            parsed_json = cls.safe_parse_ai_json(raw_text)

            explanation = parsed_json.get("explanation", "").strip() or "Anomalous event pattern detected."
            root_cause = parsed_json.get("likely_root_cause", "").strip() or "System error or threshold deviation."
            next_step = parsed_json.get("recommended_next_step", "").strip() or "Inspect surrounding logs and verify service status."

            # Update Log model
            log.ai_explanation = explanation
            log.ai_root_cause = root_cause
            log.ai_next_step = next_step
            log.ai_model = used_model
            log.ai_analyzed_at = datetime.utcnow()
            try:
                db.session.commit()
            except Exception:
                pass

            result = {
                "explanation": explanation,
                "likely_root_cause": root_cause,
                "recommended_next_step": next_step,
                "model": used_model,
                "analyzed_at": log.ai_analyzed_at.strftime("%Y-%m-%d %H:%M:%S"),
            }
            return True, result, None

        except ImportError:
            return (
                False,
                {},
                "The 'google-genai' package is not installed. Run 'pip install google-genai'.",
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
