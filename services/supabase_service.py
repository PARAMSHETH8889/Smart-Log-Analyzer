"""
Supabase Integration Service.

Manages connection and record persistence for external Supabase database
tables (`logs` / `smart Log analyser`, `anomalies`, and `ai_analysis`).
Handles schema differences, duplicate checks, errors, and graceful fallbacks.
"""

import os
from typing import List, Dict, Any, Tuple, Optional
from config import Config
from models.models import Log


class SupabaseService:
    """
    Client wrapper for Supabase database operations with dynamic schema adaptation.
    """

    _client = None
    _log_table_name = None
    _table_columns_cache = {}

    @classmethod
    def get_client(cls):
        """Lazy load and cache the Supabase client."""
        url = os.environ.get("SUPABASE_URL", Config.SUPABASE_URL or "").strip()
        key = os.environ.get("SUPABASE_KEY", Config.SUPABASE_KEY or "").strip()

        if not url or not key or url.startswith("https://your-project") or key.startswith("your_supabase"):
            return None

        if cls._client is not None:
            return cls._client

        try:
            from supabase import create_client, Client
            cls._client = create_client(url, key)
            return cls._client
        except Exception as ex:
            print(f"[SupabaseService] Initialization failed: {ex}")
            return None

    @classmethod
    def is_configured(cls) -> bool:
        """Check if Supabase credentials are configured."""
        url = os.environ.get("SUPABASE_URL", Config.SUPABASE_URL or "").strip()
        key = os.environ.get("SUPABASE_KEY", Config.SUPABASE_KEY or "").strip()
        return bool(
            url
            and key
            and not url.startswith("https://your-project")
            and not key.startswith("your_supabase")
        )

    @classmethod
    def get_log_table_name(cls) -> str:
        """Discover the active logs table name in Supabase."""
        if cls._log_table_name:
            return cls._log_table_name

        client = cls.get_client()
        if not client:
            return "logs"

        # Check candidate table names
        for candidate in ["logs", "smart Log analyser", "smart_log_analyzer", "smart_logs"]:
            try:
                res = client.table(candidate).select("id").limit(1).execute()
                cls._log_table_name = candidate
                return candidate
            except Exception:
                continue

        cls._log_table_name = "logs"
        return "logs"

    @classmethod
    def insert_logs(
        cls, log_records: List[Dict[str, Any]]
    ) -> Tuple[int, Optional[str]]:
        """
        Insert log records into Supabase logs table in batches.
        """
        client = cls.get_client()
        if not client:
            return 0, "Supabase client is not configured or unavailable."

        if not log_records:
            return 0, None

        table_name = cls.get_log_table_name()

        try:
            batch_size = 100
            inserted_count = 0

            for i in range(0, len(log_records), batch_size):
                chunk = log_records[i : i + batch_size]
                
                # Format chunk according to table columns if 'smart Log analyser'
                formatted_chunk = []
                for rec in chunk:
                    if table_name == "smart Log analyser":
                        item = {
                            "id": rec.get("id"),
                            "timestamp": rec.get("timestamp"),
                            "ip_address": rec.get("ip_address"),
                            "event_type": rec.get("event_type"),
                            "status_code": rec.get("status_code"),
                            "user_agent": rec.get("source", "").replace("web-", "").capitalize() if rec.get("source") else None,
                            "session_id": rec.get("endpoint", "").replace("/session/", "") if rec.get("endpoint") else "1000",
                            "location": "Global",
                        }
                    else:
                        item = rec
                    formatted_chunk.append(item)

                response = client.table(table_name).upsert(formatted_chunk, on_conflict="id").execute()
                if hasattr(response, "data") and response.data:
                    inserted_count += len(response.data)
                else:
                    inserted_count += len(formatted_chunk)

            return inserted_count, None
        except Exception as ex:
            return 0, f"Supabase logs insertion error ({table_name}): {str(ex)}"

    @classmethod
    def insert_anomalies(
        cls, anomaly_records: List[Dict[str, Any]]
    ) -> Tuple[int, Optional[str]]:
        """
        Insert anomaly records into Supabase `anomalies` table.
        """
        client = cls.get_client()
        if not client:
            return 0, "Supabase client is not configured."

        if not anomaly_records:
            return 0, None

        try:
            batch_size = 100
            inserted_count = 0

            for i in range(0, len(anomaly_records), batch_size):
                chunk = anomaly_records[i : i + batch_size]
                formatted_chunk = []
                for a in chunk:
                    # Provide backwards and forwards compatibility
                    item = {
                        "id": a.get("id"),
                        "log_id": a.get("log_id"),
                        "is_anomaly": True,
                        "is_anamoly": "true",
                    }
                    if "anomaly_score" in a:
                        item["anomaly_score"] = a["anomaly_score"]
                    if "reason" in a:
                        item["reason"] = a["reason"]
                    if "detected_by" in a:
                        item["detected_by"] = a["detected_by"]
                    formatted_chunk.append(item)

                try:
                    response = (
                        client.table("anomalies")
                        .upsert(formatted_chunk, on_conflict="id")
                        .execute()
                    )
                    if hasattr(response, "data") and response.data:
                        inserted_count += len(response.data)
                    else:
                        inserted_count += len(formatted_chunk)
                except Exception:
                    # Fallback to minimal schema if columns like reason/anomaly_score don't exist
                    minimal_chunk = [
                        {
                            "id": a.get("id"),
                            "log_id": a.get("log_id"),
                            "is_anomaly": True,
                            "is_anamoly": "true",
                        }
                        for a in formatted_chunk
                    ]
                    response = client.table("anomalies").upsert(minimal_chunk, on_conflict="id").execute()
                    inserted_count += len(minimal_chunk)

            return inserted_count, None
        except Exception as ex:
            return 0, f"Supabase anomalies insertion error: {str(ex)}"

    @classmethod
    def insert_ai_analyses(
        cls, ai_records: List[Dict[str, Any]]
    ) -> Tuple[int, Optional[str]]:
        """
        Insert AI analysis records into Supabase `ai_analysis` table.
        """
        client = cls.get_client()
        if not client:
            return 0, "Supabase client is not configured."

        if not ai_records:
            return 0, None

        try:
            batch_size = 100
            inserted_count = 0

            for i in range(0, len(ai_records), batch_size):
                chunk = ai_records[i : i + batch_size]
                formatted_chunk = []
                for r in chunk:
                    # If ai_analysis.id references anomalies(id), use anomaly_id as id
                    anom_id = r.get("anomaly_id")
                    formatted_chunk.append({
                        "id": anom_id or r.get("id"),
                        "anomaly_id": anom_id,
                        "explanation": r.get("explanation"),
                        "root_cause": r.get("root_cause"),
                        "next_step": r.get("next_step"),
                        "model": r.get("model", "gemini-2.5-flash"),
                    })

                response = (
                    client.table("ai_analysis")
                    .upsert(formatted_chunk, on_conflict="id")
                    .execute()
                )
                if hasattr(response, "data") and response.data:
                    inserted_count += len(response.data)
                else:
                    inserted_count += len(formatted_chunk)

            return inserted_count, None
        except Exception as ex:
            return 0, f"Supabase ai_analysis insertion error: {str(ex)}"

    @classmethod
    def sync_log(
        cls, log: Log
    ) -> Dict[str, Any]:
        """
        Sync a single log, its anomaly record (if anomalous), and AI analysis (if present).
        """
        if not cls.is_configured():
            return {
                "success": False,
                "message": "Supabase is not configured.",
            }

        # 1. Insert log
        log_data = [log.to_supabase_log()]
        logs_ins, err = cls.insert_logs(log_data)
        if err:
            return {"success": False, "error": err}

        # 2. Insert anomaly if flagged
        anomaly_uuid = None
        if log.anomaly:
            anom_data = log.to_supabase_anomaly()
            if anom_data:
                anomaly_uuid = anom_data["id"]
                anom_ins, err = cls.insert_anomalies([anom_data])
                if err:
                    return {"success": False, "error": err}

        # 3. Insert AI analysis if available
        if anomaly_uuid and (log.ai_explanation or log.ai_root_cause):
            ai_data = log.to_supabase_ai(anomaly_uuid=anomaly_uuid)
            if ai_data:
                ai_ins, err = cls.insert_ai_analyses([ai_data])
                if err:
                    return {"success": False, "error": err}

        return {
            "success": True,
            "message": f"Log {log.id} successfully synchronized with Supabase.",
        }
