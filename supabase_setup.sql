-- Run this in your Supabase SQL Editor

-- 1. Create USERS table
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(50) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100),
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Create TEST_ATTEMPTS table
CREATE TABLE IF NOT EXISTS test_attempts (
    attempt_id VARCHAR(50) PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    test_id VARCHAR(100) NOT NULL,
    test_type VARCHAR(20) DEFAULT 'PYQ', 
    subject VARCHAR(50), 
    year VARCHAR(4),
    session VARCHAR(10), 
    
    total_questions INT DEFAULT 0,
    attempted INT DEFAULT 0,
    correct INT DEFAULT 0,
    wrong INT DEFAULT 0,
    unattempted INT DEFAULT 0,
    
    score DECIMAL(10, 2) DEFAULT 0.00,
    max_score INT DEFAULT 0,
    accuracy DECIMAL(5, 2) DEFAULT 0.00,
    time_taken INT, 
    
    detailed_results JSONB, -- Stores the question-by-question data
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Create Indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_attempts ON test_attempts(user_id);
CREATE INDEX IF NOT EXISTS idx_test_subject ON test_attempts(subject);

-- 4. Set up Row Level Security (RLS) - Optional for internal API but recommended
-- By default, Supabase creates RLS on new tables. For this simple setup, 
-- you might want to disable it if you are just using the service_role key.
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE test_attempts DISABLE ROW LEVEL SECURITY;
