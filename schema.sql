-- LinkerAI Database Schema
-- Users Table (Super Admins)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    -- Generic hash for now
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
-- Credentials Table (LinkedIn & Google)
CREATE TABLE IF NOT EXISTS credentials (
    id SERIAL PRIMARY KEY,
    service_name VARCHAR(50) NOT NULL,
    -- 'linkedin', 'google'
    account_identifier VARCHAR(255),
    -- e.g., email or linkedin ID
    access_token TEXT,
    refresh_token TEXT,
    api_key TEXT,
    -- For Gemini
    client_id TEXT,
    client_secret TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
-- Posts Table (History)
CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    topic TEXT NOT NULL,
    generated_content TEXT,
    image_url TEXT,
    -- Or base64 if needed temporarily
    status VARCHAR(50) DEFAULT 'draft',
    -- 'draft', 'posted', 'failed'
    linkedin_post_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
-- Settings Table (Global Config)
CREATE TABLE IF NOT EXISTS settings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
-- Prompt Templates
CREATE TABLE IF NOT EXISTS prompt_templates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    model_preference VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Scheduled Jobs
CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    template_id INTEGER REFERENCES prompt_templates(id),
    cron_expression VARCHAR(100) NOT NULL,
    next_run_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) DEFAULT 'active',
    topic_preset TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Job Execution Logs
CREATE TABLE IF NOT EXISTS job_execution_logs (
    id SERIAL PRIMARY KEY,
    job_id INTEGER REFERENCES scheduled_jobs(id),
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50),
    message TEXT,
    generated_post_id INTEGER REFERENCES posts(id)
);
