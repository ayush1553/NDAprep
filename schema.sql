-- NDA Prep Platform - Database Schema
-- Compatible with MySQL, PostgreSQL, and SQLite

-- 1. USERS TABLE
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(50) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100),
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. TEST_ATTEMPTS TABLE
CREATE TABLE IF NOT EXISTS test_attempts (
    attempt_id VARCHAR(50) PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    test_id VARCHAR(100) NOT NULL,
    test_type VARCHAR(20) DEFAULT 'PYQ', -- PYQ or Mock
    subject VARCHAR(50), -- MAT or GAT
    year VARCHAR(4),
    session VARCHAR(10), -- Session 1 or 2
    
    total_questions INT DEFAULT 0,
    attempted INT DEFAULT 0,
    correct INT DEFAULT 0,
    wrong INT DEFAULT 0,
    unattempted INT DEFAULT 0,
    
    score DECIMAL(10, 2) DEFAULT 0.00,
    max_score INT DEFAULT 0,
    accuracy DECIMAL(5, 2) DEFAULT 0.00,
    time_taken INT, -- stored in seconds
    
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Relationships
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Index for faster performance queries
CREATE INDEX idx_user_attempts ON test_attempts(user_id);
CREATE INDEX idx_test_subject ON test_attempts(subject);

-- SAMPLE INSERT (Optional Reference)
-- INSERT INTO users (user_id, email, password_hash) VALUES ('user_1', 'test@example.com', 'hashed_val_here');
