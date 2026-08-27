-- ==============================================================================
-- SMART LOG ANALYZER & ANOMALY DETECTOR - SUPABASE SCHEMA DDL
-- Execute this script in the Supabase SQL Editor to provision tables & indexes.
-- ==============================================================================

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ------------------------------------------------------------------------------
-- TABLE 1: logs
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    ip_address TEXT,
    status_code INTEGER,
    message TEXT NOT NULL,
    endpoint TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for `logs`
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON public.logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_source ON public.logs (source);
CREATE INDEX IF NOT EXISTS idx_logs_severity ON public.logs (severity);

-- ------------------------------------------------------------------------------
-- TABLE 2: anomalies
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.anomalies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    log_id UUID NOT NULL REFERENCES public.logs(id) ON DELETE CASCADE,
    is_anomaly BOOLEAN NOT NULL DEFAULT true,
    anomaly_score NUMERIC,
    reason TEXT NOT NULL,
    detected_by TEXT NOT NULL DEFAULT 'Hybrid Rule-Based + Isolation Forest',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for `anomalies`
CREATE INDEX IF NOT EXISTS idx_anomalies_log_id ON public.anomalies (log_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_is_anomaly ON public.anomalies (is_anomaly);

-- ------------------------------------------------------------------------------
-- TABLE 3: ai_analysis
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.ai_analysis (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    anomaly_id UUID NOT NULL REFERENCES public.anomalies(id) ON DELETE CASCADE,
    explanation TEXT,
    root_cause TEXT,
    next_step TEXT,
    model TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for `ai_analysis`
CREATE INDEX IF NOT EXISTS idx_ai_analysis_anomaly_id ON public.ai_analysis (anomaly_id);

-- ------------------------------------------------------------------------------
-- Enable Row Level Security (RLS) policies (Permissive read/write for service)
-- ------------------------------------------------------------------------------
ALTER TABLE public.logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.anomalies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_analysis ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow public read-write for logs" ON public.logs FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for anomalies" ON public.anomalies FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for ai_analysis" ON public.ai_analysis FOR ALL USING (true) WITH CHECK (true);
