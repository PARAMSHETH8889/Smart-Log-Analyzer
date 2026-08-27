"""
Supabase Integration Service.

Manages connection and record persistence for external Supabase database
tables (`logs`, `anomalies`, and `ai_analysis`).
Handles duplicate checks, errors, and graceful fallbacks.
"""

import os
from typing import List, Dict, Any, Tuple, Optional
from config import Config
from models.models import Log


class SupabaseService:
    """
    Client wrapper for Supabase database operations.
    """

    _client = None

    @classmethod
    def get_client(cls):
        """Lazy load and cache the Supabase client."""
        if cls._client is not None:
            return cls._client

        url = Config.SUPABASE_URL or os.getenv("SUPABASE_URL", "").strip()
        key = Config.SUPABASE_KEY or os.getenv("SUPABASE_KEY", "").strip()

        if not url or not key or url.startswith("https://your-project"):
            return None

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
        url = Config.SUPABASE_URL or os.getenv("SUPABASE_URL", "").strip()
        key = Config.SUPABASE_KEY or os.getenv("SUPABASE_KEY", "").strip()
        return bool(
            url
            and key
            and not url.startswith("https://your-project")
            and not key.startswith("your_supabase")
        )

    @classmethod
    def insert_logs(
        cls, log_records: List[Dict[str, Any]]
    ) -> Tuple[int, Optional[str]]:
        """
        Insert log records into Supabase `logs` table in batches.
        """
        client = cls.get_client()
        if not client:
            return 0, "Supabase client is not configured or unavailable."

        if not log_records:
            return 0, None

        try:
            # Batch in chunks of 100 to avoid payload limits
            batch_size = 100
            inserted_count = 0

            for i in range(0, len(log_records), batch_size):
                chunk = log_records[i : i + batch_size]
                # Upsert on id to safely handle duplicates
                response = client.table("logs").upsert(chunk, on_conflict="id").execute()
                if hasattr(response, "data") and response.data:
                    inserted_count += len(response.data)
                else:
                    inserted_count += len(chunk)

            return inserted_count, None
        except Exception as ex:
            return 0, f"Supabase logs insertion error: {str(ex)}"

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
                response = (
                    client.table("anomalies")
                    .upsert(chunk, on_conflict="id")
                    .execute()
                )
                if hasattr(response, "data") and response.data:
                    inserted_count += len(response.data)
                else:
                    inserted_count += len(chunk)

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
                response = (
                    client.table("ai_analysis")
                    .upsert(chunk, on_conflict="id")
                    .execute()
                )
                if hasattr(response, "data") and response.data:
                    inserted_count += len(response.data)
                else:
                    inserted_count += len(chunk)

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
