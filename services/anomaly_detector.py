"""
Deterministic Non-AI Anomaly Detection Engine.

Implements a hybrid approach combining explainable domain heuristics
(HTTP error codes, CRITICAL/ERROR severities, burst frequencies, rare events)
and scikit-learn Isolation Forest on log-derived numerical features.

AI is strictly NEVER used here to classify or detect anomalies.
"""

from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from models import db
from models.models import Log
from config import Config

# Severity mapping for numerical transformations
SEVERITY_SCORES = {
    "INFO": 1,
    "WARNING": 2,
    "ERROR": 3,
    "CRITICAL": 4,
}

# Configurable Signal Weights
DEFAULT_WEIGHTS = {
    "geo_high_risk": 60,
    "geo_spoofing_ip": 55,
    "bot_malicious_action": 50,
    "session_hijacking": 45,
    "severity_critical": 35,
    "high_frequency": 25,
    "status_repeated_404": 20,
    "isolation_forest": 15,
    "status_auth_fail": 15,
    "rare_event": 10,
    "severity_error": 10,
    "status_500_plus": 10,
}


class AnomalyDetector:
    """
    Programmatic, explainable anomaly detection engine.
    """

    def __init__(
        self,
        threshold: Optional[int] = None,
        contamination: Optional[float] = None,
        weights: Optional[Dict[str, int]] = None,
    ):
        self.threshold = threshold if threshold is not None else Config.ANOMALY_THRESHOLD
        self.contamination = (
            contamination
            if contamination is not None
            else Config.ISOLATION_FOREST_CONTAMINATION
        )
        self.weights = weights or DEFAULT_WEIGHTS.copy()

    def detect_batch(self, logs: List[Log]) -> List[Log]:
        """
        Execute full hybrid anomaly detection across a collection of logs.
        Calculates dataset statistics, executes Isolation Forest, computes
        explainable scores, and generates programmatic reasons.
        """
        if not logs:
            return []

        import re

        # Sort logs by timestamp for time-window frequency calculations
        sorted_logs = sorted(
            logs,
            key=lambda x: x.timestamp if x.timestamp else datetime.min
        )

        n_logs = len(sorted_logs)

        # 1. Extract geographic locations, IP associations, and event statistics
        extracted_locations: Dict[int, str] = {}
        ip_locations = defaultdict(set)
        ip_404_counts: Dict[str, int] = defaultdict(int)

        for idx, l in enumerate(sorted_logs):
            log_key = l.id or idx
            loc_val = ""
            if l.message:
                match = re.search(r"Location:\s*([^|]+)", l.message, re.IGNORECASE)
                if match:
                    loc_val = match.group(1).strip()
            if not loc_val and l.source and l.source.startswith("web-"):
                loc_cand = l.source.replace("web-", "").strip()
                if loc_cand.lower() in ("north korea", "germany", "brazil", "india", "usa", "france", "canada", "china"):
                    loc_val = loc_cand
            extracted_locations[log_key] = loc_val

            if l.ip_address and loc_val:
                ip_locations[l.ip_address].add(loc_val)

            if l.status_code == 404 and l.ip_address:
                ip_404_counts[l.ip_address] += 1

        loc_counts = Counter(loc for loc in extracted_locations.values() if loc)
        rare_loc_threshold = max(1, int(n_logs * 0.005))  # Less than 0.5% frequency

        event_counts = Counter(l.event_type for l in sorted_logs if l.event_type)
        source_counts = Counter(l.source for l in sorted_logs if l.source)
        rare_event_threshold = max(1, int(n_logs * 0.01))

        # 2. Sliding Window Frequency Analysis (5-minute window)
        source_window_counts: Dict[int, int] = {}
        timestamps = [
            l.timestamp.timestamp() if l.timestamp else 0.0 for l in sorted_logs
        ]

        window_start_idx = 0
        active_window_sources = defaultdict(int)
        for i, log in enumerate(sorted_logs):
            curr_ts = timestamps[i]
            cutoff = curr_ts - 300  # 300 seconds = 5 minutes
            
            while window_start_idx < i and timestamps[window_start_idx] < cutoff:
                prev_src = sorted_logs[window_start_idx].source
                active_window_sources[prev_src] -= 1
                if active_window_sources[prev_src] <= 0:
                    active_window_sources.pop(prev_src, None)
                window_start_idx += 1
            
            active_window_sources[log.source] += 1
            source_window_counts[log.id or i] = active_window_sources[log.source]

        freq_values = list(source_window_counts.values())
        if freq_values and len(freq_values) >= 10:
            high_freq_threshold = float(np.percentile(freq_values, 95))
            high_freq_threshold = max(5.0, high_freq_threshold)
        else:
            high_freq_threshold = 5.0

        # 3. Isolation Forest on Log-Derived Features
        isolation_forest_flags = self._run_isolation_forest(
            sorted_logs, event_counts, source_counts, source_window_counts
        )

        # 4. Evaluate Signals & Generate Explainable Scores
        for idx, log in enumerate(sorted_logs):
            log_key = log.id or idx
            signals_triggered: List[Tuple[str, int, str]] = []
            score = 0

            log_loc = extracted_locations.get(log_key, "")

            # Signal 1: High-Risk / Rare Geographic Origin
            if log_loc:
                is_high_risk = log_loc.lower() in ("north korea", "kp", "syria", "iran", "cuba")
                is_rare_geo = loc_counts.get(log_loc, 0) <= rare_loc_threshold
                if is_high_risk or is_rare_geo:
                    pts = self.weights.get("geo_high_risk", 60)
                    score += pts
                    signals_triggered.append(
                        (
                            "HIGH_RISK_GEO",
                            pts,
                            f"originates from high-risk/anomalous geographic location '{log_loc}'",
                        )
                    )

            # Signal 2: IP Multi-Country Geo-Spoofing
            countries_for_ip = ip_locations.get(log.ip_address, set())
            if len(countries_for_ip) >= 3:
                pts = self.weights.get("geo_spoofing_ip", 55)
                score += pts
                signals_triggered.append(
                    (
                        "GEO_SPOOFING_IP",
                        pts,
                        f"IP address {log.ip_address} exhibited rotating geographic hops across {len(countries_for_ip)} distinct countries",
                    )
                )

            # Signal 3: Malicious Automated Bot Operations
            is_bot = (log.source and "bot" in log.source.lower()) or (log.message and "agent: bot" in log.message.lower())
            if is_bot and log.event_type in ("DELETE", "PUT") and (log_loc.lower() == "north korea" or (log.status_code and log.status_code >= 400)):
                pts = self.weights.get("bot_malicious_action", 50)
                score += pts
                signals_triggered.append(
                    (
                        "MALICIOUS_BOT_ACTION",
                        pts,
                        f"automated Bot client attempted destructive HTTP {log.event_type} operation",
                    )
                )

            # Signal 4: Severity Level
            if log.severity == "CRITICAL":
                pts = self.weights.get("severity_critical", 35)
                score += pts
                signals_triggered.append(
                    ("CRITICAL_SEVERITY", pts, "has CRITICAL severity level")
                )
            elif log.severity == "ERROR":
                pts = self.weights.get("severity_error", 10)
                score += pts
                signals_triggered.append(
                    ("ERROR_SEVERITY", pts, "has ERROR severity level")
                )

            # Signal 5: Frequency Anomaly
            curr_freq = source_window_counts.get(log_key, 1)
            if curr_freq >= high_freq_threshold:
                pts = self.weights.get("high_frequency", 25)
                score += pts
                signals_triggered.append(
                    (
                        "FREQUENCY_BURST",
                        pts,
                        f"occurred during an unusually high burst of {curr_freq} events in 5 minutes from '{log.source}'",
                    )
                )

            # Signal 6: Suspicious HTTP Status / Repeated 404
            if log.status_code in (401, 403):
                pts = self.weights.get("status_auth_fail", 15)
                score += pts
                signals_triggered.append(
                    (
                        "HTTP_AUTH_DENIED",
                        pts,
                        f"returned authentication/authorization denial HTTP {log.status_code}",
                    )
                )
            elif log.status_code == 404:
                ip_count = ip_404_counts.get(log.ip_address or "", 0)
                if ip_count >= 3:
                    pts = self.weights.get("status_repeated_404", 20)
                    score += pts
                    signals_triggered.append(
                        (
                            "REPEATED_404",
                            pts,
                            f"part of a repeated 404 pattern ({ip_count} occurrences from IP {log.ip_address})",
                        )
                    )

            # Signal 7: HTTP 500+ Error
            if log.status_code and log.status_code >= 500:
                pts = self.weights.get("status_500_plus", 10)
                score += pts
                signals_triggered.append(
                    (
                        "HTTP_5XX_ERROR",
                        pts,
                        f"returned HTTP server error {log.status_code}",
                    )
                )

            # Signal 8: Rare Event Type
            if event_counts.get(log.event_type, 0) <= rare_event_threshold:
                pts = self.weights.get("rare_event", 10)
                score += pts
                signals_triggered.append(
                    (
                        "RARE_EVENT",
                        pts,
                        f"is an unusual event type '{log.event_type}' (occurring in <=1% of logs)",
                    )
                )

            # Signal 9: Isolation Forest Anomaly
            if isolation_forest_flags.get(log_key, False):
                pts = self.weights.get("isolation_forest", 15)
                score += pts
                signals_triggered.append(
                    (
                        "ISOLATION_FOREST",
                        pts,
                        "flagged as statistical outlier by Isolation Forest",
                    )
                )

            # Cap score between 0 and 100
            final_score = min(100.0, float(score))
            is_anomaly = final_score >= self.threshold

            # Programmatic Explainable Reason Generation
            if is_anomaly and signals_triggered:
                reasons_text = ", ".join(item[2] for item in signals_triggered)
                reason_str = (
                    f"Flagged with anomaly score {final_score:.0f}/100 because the log {reasons_text}."
                )
            elif is_anomaly:
                reason_str = (
                    f"Flagged with anomaly score {final_score:.0f}/100 exceeding threshold of {self.threshold}."
                )
            else:
                reason_str = f"Normal log activity (score: {final_score:.0f}/100)."

            # Update log model fields
            log.anomaly = is_anomaly
            log.anomaly_score = final_score
            log.anomaly_reason = reason_str

        return sorted_logs

    def _run_isolation_forest(
        self,
        logs: List[Log],
        event_counts: Counter,
        source_counts: Counter,
        source_window_counts: Dict[int, int],
    ) -> Dict[int, bool]:
        """
        Train IsolationForest on numerical and engineered log features.
        Returns a mapping of log_id/index -> is_outlier (bool).
        """
        flags: Dict[int, bool] = {}
        if len(logs) < 10:
            # Not enough samples for statistical modeling
            return flags

        try:
            feature_rows = []
            log_keys = []

            for idx, l in enumerate(logs):
                key = l.id or idx
                log_keys.append(key)

                # Feature 1: Status code (0 if None)
                status = float(l.status_code) if l.status_code else 0.0

                # Feature 2: Severity score (1-4)
                sev_score = float(SEVERITY_SCORES.get(l.severity, 1))

                # Feature 3: Rolling window frequency
                freq = float(source_window_counts.get(key, 1))

                # Feature 4: Overall source frequency
                src_freq = float(source_counts.get(l.source, 1))

                # Feature 5: Event frequency
                evt_freq = float(event_counts.get(l.event_type, 1))

                # Feature 6: Timestamp hour
                hour = float(l.timestamp.hour) if l.timestamp else 12.0

                # Feature 7: Message length
                msg_len = float(len(l.message)) if l.message else 0.0

                feature_rows.append([
                    status,
                    sev_score,
                    freq,
                    src_freq,
                    evt_freq,
                    hour,
                    msg_len,
                ])

            X = np.array(feature_rows, dtype=np.float32)

            # Fit Isolation Forest with fast parameters
            iso_forest = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=50,
                max_samples=min(512, len(logs)),
                n_jobs=-1,
            )
            predictions = iso_forest.fit_predict(X)

            # -1 indicates outlier, 1 indicates inlier
            for key, pred in zip(log_keys, predictions):
                flags[key] = (pred == -1)

        except Exception:
            # Fallback gracefully if sklearn encounters issues
            pass

        return flags

    @classmethod
    def detect_and_update_all(
        cls, threshold: Optional[int] = None
    ) -> Tuple[int, int]:
        """
        Query all logs in SQLite database, run anomaly detection, and persist results.
        Returns: Tuple of (total_logs, anomaly_count).
        """
        logs = Log.query.all()
        if not logs:
            return 0, 0

        detector = cls(threshold=threshold)
        detector.detect_batch(logs)
        db.session.commit()

        anomalies_count = sum(1 for l in logs if l.anomaly)
        return len(logs), anomalies_count
