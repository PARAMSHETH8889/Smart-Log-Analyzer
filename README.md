# Smart Log Analyzer & Anomaly Detector

A production-quality, assessment-friendly log observability and anomaly detection web application built with **Flask**, **SQLAlchemy**, **scikit-learn**, **Google Gemini AI**, and **Supabase**.

---

## 1. Project Overview

Modern cloud systems generate millions of log lines daily. Finding high-risk failures, security probes, and performance anomalies manually is impractical. 

**Smart Log Analyzer & Anomaly Detector** provides an end-to-end log observability platform that:
1. **Ingests & Validates** server logs from CSV uploads or streaming files.
2. **Deterministically Detects Anomalies** using a 100% programmatic hybrid algorithm (rule-based signals + Isolation Forest).
3. **Explains Flagged Anomalies with Google Gemini AI** to produce plain-English root causes and remediation steps using surrounding log timeline context.
4. **Visualizes Metrics & Detections** via a real-time responsive dashboard with interactive Chart.js graphs, full search/filter capabilities, and persistent **Light/Dark Mode**.
5. **Persists Data Dual-Engine**: Primary local SQLite database with optional external **Supabase Cloud Database** synchronization.

> [!IMPORTANT]
> **Core Assessment Rule**: AI **never** decides whether a log is anomalous. Anomaly detection is entirely deterministic and implemented in Python. Google Gemini is invoked **strictly after** an anomaly has already been flagged to assist engineers with root-cause analysis.

---

## 2. Architecture & Data Flow

```
+-------------------------------------------------------------------------+
|                                 USER                                    |
+-------------------------------------------------------------------------+
                                     │
                                     ▼ (CSV Upload / Dashboard)
+-------------------------------------------------------------------------+
|                       FLASK WEB APPLICATION                             |
+-------------------------------------------------------------------------+
                                     │
                                     ▼
+-------------------------------------------------------------------------+
|                     LOG PARSER & VALIDATOR                              |
|   - Schema validation, timestamp parsing, enum checking, deduplication |
+-------------------------------------------------------------------------+
                                     │
                                     ▼
+-------------------------------------------------------------------------+
|                  PRIMARY DATABASE (SQLite + SQLAlchemy)                 |
|   - Persists all valid logs, statuses, and metadata                     |
+-------------------------------------------------------------------------+
                                     │
                                     ▼
+-------------------------------------------------------------------------+
|            PROGRAMMATIC ANOMALY DETECTION ENGINE (Non-AI)               |
|   1. HTTP 5xx Server Errors (+40)                                       |
|   2. Suspicious Auth & 404 Probes (+15 / +20)                           |
|   3. High Severity Levels (CRITICAL +30, ERROR +20)                     |
|   4. Rolling Time-Window Frequency Burst (+20)                          |
|   5. Rare Event Detection (+15)                                         |
|   6. Scikit-learn Isolation Forest on numerical/log-derived features    |
|   --> Calculates 0-100 Score & Programmatic Transparent Reason          |
+-------------------------------------------------------------------------+
                                     │
                                     ▼ (Only for logs where anomaly == True)
+-------------------------------------------------------------------------+
|                   GOOGLE GEMINI AI EXPLANATION ENGINE                   |
|   - Inputs: Flagged anomaly + Surrounding log timeline (3 before / after)|
|   - Outputs: JSON Schema (Explanation, Likely Root Cause, Next Step)    |
+-------------------------------------------------------------------------+
                                     │
                  ┌──────────────────┴──────────────────┐
                  ▼                                     ▼
+-----------------------------------+ +-----------------------------------+
|       INTERACTIVE DASHBOARD       | |     SUPABASE CLOUD DATABASE     |
| - KPI Cards & 4 Chart.js Graphs   | | - logs (UUID, timestamptz)      |
| - Filterable Logs Explorer Table  | | - anomalies (FK -> logs.id)     |
| - Detailed Inspector + Timeline   | | - ai_analysis (FK -> anomalies) |
| - Light / Dark Mode Toggle (☀️/🌙)| | - Tables, Foreign Keys, Indexes |
+-----------------------------------+ +-----------------------------------+
```

---

## 3. Tech Stack

- **Backend Framework**: Python 3.11+, Flask 3.0+
- **Primary Database**: SQLite with SQLAlchemy ORM
- **External Cloud Database**: Supabase (PostgreSQL) with `supabase-py`
- **Data Validation & Parsing**: Python CSV, dataclasses, regex, pandas
- **Deterministic Anomaly Engine**: scikit-learn (`IsolationForest`), numpy
- **GenAI Explanation**: Google Gemini API via the official `google-genai` Python SDK
- **Frontend**: HTML5, CSS3 (CSS Variables Theme Engine), Vanilla JavaScript, Bootstrap 5.3 (CDN)
- **Data Visualizations**: Chart.js 4.4 (CDN)
- **Testing**: pytest, pytest-mock

---

## 4. Database Schema

### Local SQLite Database (`models/models.py`)

| Field | Type | Description |
|---|---|---|
| `id` | Integer (PK) | Auto-incrementing primary key |
| `uuid` | String(36) | Unique UUID for Supabase synchronization |
| `timestamp` | DateTime | Timestamp of the log event (Indexed) |
| `source` | String(100) | Service or host origin (Indexed) |
| `event_type` | String(100) | Category (LOGIN, HTTP_REQUEST, etc.) |
| `severity` | String(20) | Severity (`INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `ip_address` | String(50) | Client / Host IP address (Nullable) |
| `status_code` | Integer | HTTP status code (Nullable) |
| `endpoint` | String(255) | API route or resource endpoint |
| `message` | Text | Full log message payload |
| `anomaly` | Boolean | `True` if flagged by deterministic algorithm (Indexed) |
| `anomaly_score` | Float | Programmatic score between `0.0` and `100.0` |
| `anomaly_reason` | Text | Generated sentence citing triggered signals |
| `ai_explanation` | Text | Plain-English summary from Gemini (Nullable) |
| `ai_root_cause` | Text | Technical root cause from Gemini (Nullable) |
| `ai_next_step` | Text | Actionable remediation step from Gemini (Nullable) |
| `ai_model` | String(100) | Name of AI model used (e.g. `gemini-2.5-flash`) |
| `ai_analyzed_at` | DateTime | Timestamp when AI analysis was generated |
| `created_at` | DateTime | Ingestion timestamp |

### Supabase Relational Schema (`supabase_schema.sql`)

```
logs (id: UUID PK, timestamp: timestamptz, source: text, event_type: text, severity: text, ...)
  │
  └──< anomalies (id: UUID PK, log_id: UUID FK -> logs.id, is_anomaly: bool, anomaly_score: numeric, reason: text)
         │
         └──< ai_analysis (id: UUID PK, anomaly_id: UUID FK -> anomalies.id, explanation: text, root_cause: text, next_step: text)
```

---

## 5. Anomaly Detection Approach

### Why this approach was selected
Pure machine learning models or black-box classifiers often suffer from "silent false negatives" on critical domain-specific failures (e.g., HTTP 500 crashes or kernel deadlocks). Pure rule engines, on the other hand, miss multi-dimensional numerical outliers.

Our **hybrid approach** combines:
1. **Explainable Domain Rules**: Instantly and deterministically captures high-risk operational signals.
2. **scikit-learn Isolation Forest**: Isolates anomalies in numerical and time-series feature space (status codes, severities, burst frequencies, event rarities, message lengths, and temporal patterns).

### Signal Weights & Scoring

| Signal | Condition | Score Weight |
|---|---|---|
| **Signal 1: HTTP 5xx Error** | `status_code >= 500` (500, 502, 503, 504) | `+40` pts |
| **Signal 2: Suspicious Status** | `status_code in (401, 403)` or repeated `404` scans | `+15` to `+20` pts |
| **Signal 3: High Severity** | `CRITICAL` severity (`+30` pts) or `ERROR` severity (`+20` pts) | `+20` to `+30` pts |
| **Signal 4: Frequency Burst** | Rolling 5-minute request count per source/IP exceeding 95th percentile | `+20` pts |
| **Signal 5: Rare Event Type** | Infrequent event type ($\le 3\%$ occurrence in dataset) | `+15` pts |
| **Signal 6: Isolation Forest** | Outlier detection (`contamination=0.05`, `random_state=42`) | `+30` pts |

- **Score Calculation**: $\text{Final Score} = \min(100.0, \sum \text{triggered weights})$
- **Decision Rule**: `anomaly = (score >= ANOMALY_THRESHOLD)` (Default: `50.0`)
- **Programmatic Reason Generation**: The detector builds natural, explainable descriptions:
  * *Example*: `"Flagged with anomaly score 90/100 because the log returned HTTP server error 503, has CRITICAL severity level, and occurred during an unusually high burst of 8 events in 5 minutes from 'payment-service'."*

---

## 6. AI Architecture (Google Gemini Integration)

### What Gemini Does
- Evaluates **only** logs that have already been classified as anomalous.
- Receives the target anomaly details and **surrounding chronological logs** (3 before and 3 after from the same source/IP) for sequence reasoning.
- Generates structured JSON adhering to:
  ```json
  {
    "explanation": "Clear explanation of what happened and its impact.",
    "likely_root_cause": "Specific technical failure identified from context.",
    "recommended_next_step": "Actionable troubleshooting or remediation step."
  }
  ```

### What Gemini Does NOT Do
- AI **never** decides whether a log is anomalous or normal.
- AI is not used in the ingestion pipeline or table filtering.
- If Gemini fails, times out, or the API key is absent, the application **does not crash**; the anomaly score and reason remain intact, and the user can retry anytime.

---

## 7. Light / Dark Mode System

- **Switch Mechanism**: Toggle button (☀️ / 🌙) in the top navigation bar.
- **Persistence**: Saved automatically in browser `localStorage` and restored across page loads.
- **Implementation**: Dynamic CSS variables (`data-theme="light"` / `data-theme="dark"`).
- **Scope**: Uniformly styles dashboard KPI cards, navigation, sidebar, data tables, modals, score indicators, alerts, and Chart.js graphs without page reloads.

---

## 8. Setup & Installation

### Prerequisites
- Python 3.11 or higher
- pip package manager

### 1. Clone or Open Project Directory
```bash
cd smart-log-analyzer
```

### 2. Create Virtual Environment & Activate
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
# Windows (PowerShell)
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```
Edit `.env` and provide your credentials:
```env
GEMINI_API_KEY=your_gemini_api_key_here
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your_supabase_anon_key_here
ANOMALY_THRESHOLD=50
```

### 5. Generate Synthetic Dataset
```bash
python generate_sample_data.py
```
This generates 450 realistic logs in `sample_data/sample_logs.csv` with normal baseline traffic and 5-10% known injected anomaly scenarios.

### 6. Start the Web Application
```bash
python app.py
```
Access the web dashboard in your browser at: **`http://127.0.0.1:5000`**

---

## 9. Supabase Database Setup & Seeding

### 1. Execute SQL Schema
In your Supabase project dashboard, navigate to **SQL Editor**, open `supabase_schema.sql`, and execute the script to create:
- `public.logs` table and indexes
- `public.anomalies` table and foreign keys
- `public.ai_analysis` table and foreign keys

### 2. Run the Seed Script
```bash
python supabase_seed.py
```

**Expected CLI Output:**
```
========================================
Supabase Database Seeding
========================================
Total logs generated: 450
Valid logs: 450
Rejected logs: 0
Logs inserted: 450
Anomalies detected: 32
Anomalies inserted: 32
AI analyses inserted: 0

Database seeding completed successfully.
========================================
```

---

## 10. Running Automated Tests

Run the complete test suite with `pytest`:
```bash
pytest -v tests/
```

### Test Suite Coverage
- `test_validation.py`: Schema validation, timestamp formats, enum checking, duplicate rejection, and empty datasets.
- `test_anomaly_detector.py`: HTTP 500 detection, CRITICAL severity, high-frequency bursts, score weighting, and normal traffic non-flagging.
- `test_ai_service.py`: Gemini prompt construction, non-anomaly rejection, missing key graceful handling, and mocked response parsing.
- `test_routes.py`: Flask views, `/upload`, `/api/stats`, filtering/pagination, deletion, and CSV export.
- `test_supabase_service.py`: Supabase payload formatting, fallback handling, and error resiliency.

---

## 11. Assumptions & Limitations

- **Dataset Size**: The SQLite database and in-memory feature engineering are optimized for single-node assessment workloads (thousands of logs). For multi-gigabyte streams, streaming architectures (e.g. Kafka + ClickHouse) would be recommended.
- **Isolation Forest Baseline**: Isolation Forest requires a minimum of 10 log records to fit meaningful statistical partitions; for smaller batches, deterministic rule signals provide full anomaly coverage.
- **AI Quota**: In the event of Gemini API rate limits or network partitions, the deterministic anomaly result remains 100% intact, and AI generation can be retried at any time.
