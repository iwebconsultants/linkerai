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