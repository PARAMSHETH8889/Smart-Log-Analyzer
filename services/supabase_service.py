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
from services.data_cleaner import DataCleaner


class SupabaseService:
    """
    Client wrapper for Supabase database operations with dynamic schema adaptation and JSON sanitization.
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
        Clean, sanitize, and insert log records into Supabase logs table in batches.
        Guarantees schema matching and zero JSON serialization errors.
        """
        client = cls.get_client()
        if not client:
            return 0, "Supabase client is not configured or unavailable."

        if not log_records:
            return 0, None

        table_name = cls.get_log_table_name()

        try:
            batch_size = 500
            inserted_count = 0

            for i in range(0, len(log_records), batch_size):
                chunk = log_records[i : i + batch_size]
                
                # Clean each record according to target table columns and sanitize for JSON
                formatted_chunk = []
                for rec in chunk:
                    cleaned_item = DataCleaner.clean_record_for_supabase(rec, table_name=table_name)
                    formatted_chunk.append(cleaned_item)

                # Ensure strict JSON-serializability
                sanitized_payload = DataCleaner.sanitize_for_json(formatted_chunk)

                response = client.table(table_name).upsert(sanitized_payload, on_conflict="id").execute()
                if hasattr(response, "data") and response.data:
                    inserted_count += len(response.data)
                else:
                    inserted_count += len(sanitized_payload)

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
            batch_size = 500
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
                    sanitized_anoms = DataCleaner.sanitize_for_json(formatted_chunk)
                    response = (
                        client.table("anomalies")
                        .upsert(sanitized_anoms, on_conflict="id")
                        .execute()
                    )
                    if hasattr(response, "data") and response.data:
                        inserted_count += len(response.data)
                    else:
                        inserted_count += len(sanitized_anoms)
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
                    sanitized_min = DataCleaner.sanitize_for_json(minimal_chunk)
                    response = client.table("anomalies").upsert(sanitized_min, on_conflict="id").execute()
                    inserted_count += len(sanitized_min)

            return inserted_count, None
        except Exception as ex:
            return 0, f"Supabase anomalies insertion error: {str(ex)}"

    @classmethod
    def insert_ai_analyses(
        cls, ai_records: List[Dict[str, Any]]
    ) -> Tuple[int, Optional[str]]:
        """
        Insert AI analysis records into Supabase `ai_analysis` table with JSON sanitization.
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
                        "explanation": str(r.get("explanation") or "").strip(),
                        "root_cause": str(r.get("root_cause") or "").strip(),
                        "next_step": str(r.get("next_step") or "").strip(),
                        "model": str(r.get("model") or "gemini-3.5-flash-lite").strip(),
                    })

                sanitized_ai = DataCleaner.sanitize_for_json(formatted_chunk)
                response = (
                    client.table("ai_analysis")
                    .upsert(sanitized_ai, on_conflict="id")
                    .execute()
                )
                if hasattr(response, "data") and response.data:
                    inserted_count += len(response.data)
                else:
                    inserted_count += len(sanitized_ai)

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

    @classmethod
    def clean_and_sync_all_logs(cls) -> Dict[str, Any]:
        """
        Clean the entire local database according to Supabase column schema
        and push all logs, anomalies, and AI analyses to Supabase cloud tables.
        Guarantees zero invalid JSON errors.
        """
        if not cls.is_configured():
            return {
                "success": False,
                "message": "Supabase is not configured. Please verify SUPABASE_URL and SUPABASE_KEY.",
            }

        all_logs = Log.query.all()
        if not all_logs:
            return {
                "success": True,
                "message": "No local logs found to sync.",
                "logs_synced": 0,
                "anomalies_synced": 0,
                "ai_synced": 0,
            }

        raw_dicts = [l.to_supabase_log() for l in all_logs]
        table_name = cls.get_log_table_name()
        cleaned_logs, clean_metrics = DataCleaner.clean_dataset(raw_dicts, table_name=table_name)

        # 1. Sync cleaned logs
        logs_count, logs_err = cls.insert_logs(cleaned_logs)
        if logs_err:
            return {"success": False, "error": f"Failed syncing logs: {logs_err}"}

        # 2. Sync anomalies and AI analyses
        anom_records = []
        ai_records = []
        for l in all_logs:
            if l.anomaly:
                anom_dict = l.to_supabase_anomaly()
                if anom_dict:
                    anom_records.append(anom_dict)
                    ai_dict = l.to_supabase_ai(anomaly_uuid=anom_dict["id"])
                    if ai_dict:
                        ai_records.append(ai_dict)

        anom_count, anom_err = cls.insert_anomalies(anom_records)
        ai_count, ai_err = cls.insert_ai_analyses(ai_records)

        return {
            "success": True,
            "message": f"Successfully cleaned and synchronized {logs_count} logs, {anom_count} anomalies, and {ai_count} AI analyses with Supabase ({table_name}).",
            "table_name": table_name,
            "logs_synced": logs_count,
            "anomalies_synced": anom_count,
            "ai_synced": ai_count,
            "cleaning_metrics": clean_metrics,
        }

    @classmethod
    def delete_log(cls, log_uuid: str) -> Tuple[bool, Optional[str]]:
        """
        Permanently delete a log and its related anomaly & AI records from Supabase.
        """
        client = cls.get_client()
        if not client:
            return False, "Supabase is not configured."

        if not log_uuid:
            return False, "Invalid log UUID."

        table_name = cls.get_log_table_name()

        try:
            # 1. Delete associated anomalies & ai_analysis
            try:
                # Find anomaly IDs linked to this log
                anom_res = client.table("anomalies").select("id").eq("log_id", log_uuid).execute()
                if anom_res.data:
                    anom_ids = [a["id"] for a in anom_res.data if "id" in a]
                    for anom_id in anom_ids:
                        try:
                            client.table("ai_analysis").delete().eq("anomaly_id", anom_id).execute()
                        except Exception:
                            pass
                    client.table("anomalies").delete().eq("log_id", log_uuid).execute()
            except Exception:
                pass

            # 2. Delete main log record
            client.table(table_name).delete().eq("id", log_uuid).execute()
            return True, None
        except Exception as ex:
            return False, f"Supabase deletion error: {str(ex)}"

    @classmethod
    def purge_all_logs(cls) -> Tuple[bool, Optional[str]]:
        """
        Permanently delete ALL logs, anomalies, and AI analyses from Supabase tables.
        """
        client = cls.get_client()
        if not client:
            return False, "Supabase is not configured."

        table_name = cls.get_log_table_name()

        try:
            # Delete from child tables first
            try:
                client.table("ai_analysis").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
            except Exception:
                pass

            try:
                client.table("anomalies").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
            except Exception:
                pass

            # Delete from main logs table
            client.table(table_name).delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
            return True, None
        except Exception as ex:
            return False, f"Supabase purge error: {str(ex)}"
