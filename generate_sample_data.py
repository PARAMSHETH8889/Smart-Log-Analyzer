"""
Synthetic Log Data Generator.

Generates realistic production log datasets with normal traffic and
approximately 5-10% known injected anomalies across diverse sources,
event types, and severity levels.
"""

import os
import random
import csv
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any

SOURCES = [
    "api-server-01",
    "api-server-02",
    "database-01",
    "auth-server-01",
    "payment-service",
    "web-server-01",
]

NORMAL_EVENT_TYPES = [
    "HTTP_REQUEST",
    "DATABASE_QUERY",
    "LOGIN",
    "LOGOUT",
    "API_REQUEST",
    "FILE_ACCESS",
    "PAYMENT",
    "AUTHENTICATION",
]

ENDPOINTS = [
    "/api/v1/users",
    "/api/v1/orders",
    "/api/v1/auth/login",
    "/api/v1/auth/logout",
    "/api/v1/products",
    "/api/v1/checkout",
    "/api/v1/inventory",
    "/healthz",
    "/metrics",
    "/static/app.js",
]

NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.25",
    "192.168.1.42",
    "10.0.0.15",
    "10.0.0.28",
    "172.16.0.5",
    "172.16.0.88",
    "203.0.113.19",
    "198.51.100.4",
]

SUSPICIOUS_IPS = [
    "45.33.32.156",
    "185.220.101.5",
    "194.26.29.112",
]


def generate_logs(total_count: int = 450) -> List[Dict[str, Any]]:
    """
    Generate synthetic log entries with controlled anomaly injections.
    """
    logs: List[Dict[str, Any]] = []
    base_time = datetime.now() - timedelta(hours=6)

    # Calculate anomaly target (approx 7-8%)
    target_anomalies = max(20, int(total_count * 0.08))
    normal_count = total_count - target_anomalies

    current_time = base_time

    # --------------------------------------------------------------------------
    # 1. Generate Normal Traffic
    # --------------------------------------------------------------------------
    for _ in range(normal_count):
        # Step forward randomly between 5 and 45 seconds
        current_time += timedelta(seconds=random.randint(5, 45))
        source = random.choice(SOURCES)
        event_type = random.choice(NORMAL_EVENT_TYPES)
        ip = random.choice(NORMAL_IPS)

        if event_type in ("HTTP_REQUEST", "API_REQUEST"):
            endpoint = random.choice(ENDPOINTS)
            status_code = random.choices([200, 201, 204, 301, 404], weights=[75, 10, 5, 5, 5])[0]
            severity = "INFO" if status_code < 400 else "WARNING"
            message = f"GET {endpoint} completed with HTTP {status_code}"
        elif event_type == "DATABASE_QUERY":
            endpoint = None
            status_code = None
            severity = "INFO"
            table = random.choice(["users", "orders", "sessions", "transactions"])
            duration_ms = random.randint(2, 45)
            message = f"SELECT * FROM {table} WHERE active = 1 (took {duration_ms}ms)"
        elif event_type in ("LOGIN", "AUTHENTICATION"):
            endpoint = "/api/v1/auth/login"
            status_code = random.choices([200, 401], weights=[90, 10])[0]
            severity = "INFO" if status_code == 200 else "WARNING"
            user_id = f"user_{random.randint(100, 999)}"
            message = f"User authentication {'succeeded' if status_code == 200 else 'invalid password'} for {user_id}"
        elif event_type == "LOGOUT":
            endpoint = "/api/v1/auth/logout"
            status_code = 200
            severity = "INFO"
            message = f"User session terminated gracefully"
        elif event_type == "PAYMENT":
            endpoint = "/api/v1/checkout"
            status_code = 200
            severity = "INFO"
            amt = random.randint(15, 250)
            message = f"Payment transaction processed successfully: ${amt}.00 USD"
        elif event_type == "FILE_ACCESS":
            endpoint = "/static/assets"
            status_code = 200
            severity = "INFO"
            message = f"Static asset read operation completed: index.css"
        else:
            endpoint = None
            status_code = 200
            severity = "INFO"
            message = f"Standard {event_type} event on {source}"

        logs.append({
            "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "ip_address": ip,
            "status_code": status_code,
            "endpoint": endpoint,
            "message": message,
        })

    # --------------------------------------------------------------------------
    # 2. Inject Known Anomalous Scenarios
    # --------------------------------------------------------------------------
    anomaly_time = base_time + timedelta(hours=2)

    # Scenario A: Payment Service Cascade 500 / 503 Outage (High Anomaly)
    for i in range(8):
        anomaly_time += timedelta(seconds=3)
        logs.append({
            "timestamp": anomaly_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "payment-service",
            "event_type": "PAYMENT",
            "severity": "ERROR" if i < 5 else "CRITICAL",
            "ip_address": "192.168.1.20",
            "status_code": random.choice([500, 502, 503]),
            "endpoint": "/api/v1/checkout",
            "message": f"Payment gateway connection timeout: upstream Stripe API unreachable (attempt {i+1}/8)",
        })

    # Scenario B: Auth Server Brute Force / Repeated 401 & 403 (Suspicious Burst)
    burst_ip = random.choice(SUSPICIOUS_IPS)
    anomaly_time = base_time + timedelta(hours=3, minutes=15)
    for i in range(10):
        anomaly_time += timedelta(seconds=2)
        logs.append({
            "timestamp": anomaly_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "auth-server-01",
            "event_type": "AUTHENTICATION",
            "severity": "WARNING" if i < 7 else "ERROR",
            "ip_address": burst_ip,
            "status_code": 401 if i < 8 else 403,
            "endpoint": "/api/v1/auth/login",
            "message": f"Failed password authentication attempt for admin account (burst attempt {i+1})",
        })

    # Scenario C: Database Deadlock & Resource Starvation (CRITICAL)
    anomaly_time = base_time + timedelta(hours=4, minutes=10)
    for i in range(5):
        anomaly_time += timedelta(seconds=4)
        logs.append({
            "timestamp": anomaly_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "database-01",
            "event_type": "DATABASE_QUERY",
            "severity": "CRITICAL",
            "ip_address": "10.0.0.15",
            "status_code": None,
            "endpoint": None,
            "message": f"Deadlock detected on table 'orders' while acquiring exclusive transaction lock: connection pool exhausted (active=100/100)",
        })

    # Scenario D: Rare Server Error / Kernel Panic Event
    anomaly_time = base_time + timedelta(hours=5, minutes=5)
    logs.append({
        "timestamp": anomaly_time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": "api-server-02",
        "event_type": "SERVER_ERROR",
        "severity": "CRITICAL",
        "ip_address": "192.168.1.42",
        "status_code": 500,
        "endpoint": "/api/v1/products",
        "message": "Out of Memory (OOM): Worker process killed by kernel while deserializing payload",
    })

    # Scenario E: Repeated 404 Vulnerability Probe
    probe_ip = SUSPICIOUS_IPS[1]
    anomaly_time = base_time + timedelta(hours=5, minutes=20)
    for path in ["/.env", "/wp-admin/login.php", "/phpmyadmin", "/api/v1/debug"]:
        anomaly_time += timedelta(seconds=1)
        logs.append({
            "timestamp": anomaly_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "web-server-01",
            "event_type": "HTTP_REQUEST",
            "severity": "WARNING",
            "ip_address": probe_ip,
            "status_code": 404,
            "endpoint": path,
            "message": f"File or route not found: GET {path} from scanner agent",
        })

    # Sort all logs chronologically
    logs.sort(key=lambda x: x["timestamp"])
    return logs


def save_to_csv(logs: List[Dict[str, Any]], output_path: Path) -> Path:
    """Save generated logs list to CSV file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "timestamp",
        "source",
        "event_type",
        "severity",
        "ip_address",
        "status_code",
        "endpoint",
        "message",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for log in logs:
            writer.writerow(log)

    return output_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate synthetic server log dataset with injected anomalies."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=450,
        help="Total number of log records to generate (default: 450)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="sample_data/sample_logs.csv",
        help="Target output CSV filepath",
    )

    args = parser.parse_args()
    target_path = Path(__file__).resolve().parent / args.output

    print(f"[*] Generating {args.count} synthetic log entries...")
    generated = generate_logs(total_count=args.count)
    saved_file = save_to_csv(generated, target_path)

    print(f"[OK] Successfully generated {len(generated)} logs.")
    print(f"[OK] Saved dataset to: {saved_file}")
