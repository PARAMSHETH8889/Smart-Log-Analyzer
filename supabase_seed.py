"""
Supabase Database Seeding Script.

Reads the synthetic dataset, validates records, executes the deterministic
Python anomaly detection algorithm, and seeds the Supabase tables (`logs`,
`anomalies`, `ai_analysis`).
"""

import sys
import os
from pathlib import Path
from typing import List

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from config import Config
from services.validation import LogValidator
from services.log_parser import LogParser
from services.anomaly_detector import AnomalyDetector
from services.supabase_service import SupabaseService
from services.ai_service import GeminiAIService
from models.models import Log


def run_seeding(
    csv_file: Path = BASE_DIR / "sample_data" / "sample_logs.csv",
    generate_if_missing: bool = True,
    run_ai_on_sample_anomalies: bool = False,
    ai_sample_limit: int = 3,
):
    """
    Execute full Supabase database seeding workflow.
    """
    print("=" * 60)
    print("      SUPABASE DATABASE SEEDING PROCESS")
    print("=" * 60)

    # 1. Check CSV file existence
    if not csv_file.exists():
        if generate_if_missing:
            print(f"[*] Dataset not found at {csv_file}. Generating fresh dataset...")
            from generate_sample_data import generate_logs, save_to_csv
            logs_raw = generate_logs(450)
            save_to_csv(logs_raw, csv_file)
            print(f"[OK] Generated 450 synthetic log records.")
        else:
            print(f"[!] Error: Dataset file '{csv_file}' does not exist.")
            sys.exit(1)

    # 2. Parse & Validate
    print(f"[*] Parsing and validating '{csv_file.name}'...")
    raw_rows, parse_errors = LogParser.parse_csv_stream(csv_file)
    val_result = LogValidator.validate_batch(raw_rows)

    total_logs = len(raw_rows)
    valid_logs_count = len(val_result.valid_records)
    rejected_logs_count = total_logs - valid_logs_count

    # 3. Create Log in-memory models for deterministic anomaly detection
    log_objects: List[Log] = []
    for rec in val_result.valid_records:
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

    # 4. Run Deterministic Anomaly Detection
    print("[*] Running deterministic Python Anomaly Detection algorithm...")
    detector = AnomalyDetector()
    detector.detect_batch(log_objects)

    anomalies_detected = sum(1 for l in log_objects if l.anomaly)

    # 5. Optionally run AI analysis on top N anomalies if Gemini is configured
    ai_analyses_generated = 0
    if run_ai_on_sample_anomalies and GeminiAIService.is_configured():
        print(f"[*] Generating Gemini AI explanations for top {ai_sample_limit} anomalies...")
        anomalous_logs = [l for l in log_objects if l.anomaly]
        for l in anomalous_logs[:ai_sample_limit]:
            surrounding = GeminiAIService.get_surrounding_context(l)
            success, res, err = GeminiAIService.explain_anomaly(
                l, surrounding_logs=surrounding
            )
            if success:
                ai_analyses_generated += 1

    # 6. Check Supabase Connectivity
    if not SupabaseService.is_configured():
        print("\n[!] NOTICE: Supabase credentials are not configured in .env.")
        print("[!] Please set SUPABASE_URL and SUPABASE_KEY to persist directly to Supabase.")
        print("\n--- Summary (Local Python Processing) ---")
        print(f"Total logs generated: {total_logs}")
        print(f"Valid logs: {valid_logs_count}")
        print(f"Rejected logs: {rejected_logs_count}")
        print(f"Logs inserted: 0 (Supabase not configured)")
        print(f"Anomalies detected: {anomalies_detected}")
        print(f"Anomalies inserted: 0 (Supabase not configured)")
        print(f"AI analyses inserted: 0")
        print("\nLocal processing completed. Run with configured .env to sync to Supabase.")
        return

    print("[*] Connecting to Supabase and seeding tables...")

    # A. Insert Logs
    supabase_logs_payload = [l.to_supabase_log() for l in log_objects]
    logs_inserted, log_err = SupabaseService.insert_logs(supabase_logs_payload)
    if log_err:
        print(f"[!] Warning inserting logs to Supabase: {log_err}")

    # B. Insert Anomalies
    anomalies_payload = [
        l.to_supabase_anomaly() for l in log_objects if l.anomaly
    ]
    # Filter out None
    anomalies_payload = [a for a in anomalies_payload if a is not None]
    anomalies_inserted, anom_err = SupabaseService.insert_anomalies(
        anomalies_payload
    )
    if anom_err:
        print(f"[!] Warning inserting anomalies to Supabase: {anom_err}")

    # C. Insert AI Analyses (if any were generated)
    ai_payload = []
    for anom_rec in anomalies_payload:
        matching_log = next(
            (l for l in log_objects if l.uuid == anom_rec["log_id"]), None
        )
        if matching_log and (
            matching_log.ai_explanation or matching_log.ai_root_cause
        ):
            ai_data = matching_log.to_supabase_ai(anomaly_uuid=anom_rec["id"])
            if ai_data:
                ai_payload.append(ai_data)

    ai_inserted, ai_err = SupabaseService.insert_ai_analyses(ai_payload)
    if ai_err:
        print(f"[!] Warning inserting AI analysis to Supabase: {ai_err}")

    # Print Final Assessment Required Output
    print("\n" + "=" * 40)
    print("Supabase Database Seeding")
    print("=" * 40)
    print(f"Total logs generated: {total_logs}")
    print(f"Valid logs: {valid_logs_count}")
    print(f"Rejected logs: {rejected_logs_count}")
    print(f"Logs inserted: {logs_inserted}")
    print(f"Anomalies detected: {anomalies_detected}")
    print(f"Anomalies inserted: {anomalies_inserted}")
    print(f"AI analyses inserted: {ai_inserted}")
    print("\nDatabase seeding completed successfully.")
    print("=" * 40)


if __name__ == "__main__":
    run_seeding()
