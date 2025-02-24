-- Go Go Gadget Database Setup Script
-- Initializes the MariaDB database for storing tasks and results

-- Create the Go Go Gadget database if it doesn't already exist
CREATE DATABASE IF NOT EXISTS gogogadget_db;
USE gogogadget_db;

-- Create the tasks table to store reachability check requests
CREATE TABLE IF NOT EXISTS tasks (
    task_id VARCHAR(50) PRIMARY KEY,          -- Unique identifier for each task (e.g., "task-123456789")
    host VARCHAR(255) NOT NULL,               -- Target host to check (e.g., "example.com")
    communities TEXT,                         -- Comma-separated list of SNMP communities (e.g., "public,private")
    complete BOOLEAN DEFAULT FALSE,           -- Indicates if the task is complete (FALSE = pending, TRUE = done)
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- Timestamp of task creation
);

-- Create the results table to store proxy check outcomes
CREATE TABLE IF NOT EXISTS results (
    id INT AUTO_INCREMENT PRIMARY KEY,        -- Auto-incrementing primary key for result entries
    task_id VARCHAR(50),                      -- Foreign key linking to the tasks table
    proxy_name VARCHAR(255),                  -- Name of the proxy submitting the result (e.g., "proxy1")
    result JSON,                              -- JSON object containing check results (e.g., {"ping": "10ms"})
    submitted TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Timestamp of result submission
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,  -- Cascade delete when task is removed
    INDEX idx_task_id (task_id),              -- Index on task_id for faster queries
    INDEX idx_proxy_name (proxy_name)         -- Index on proxy_name for faster queries
);

-- Grant necessary privileges to the Go Go Gadget user on the database (restricted for security)
GRANT SELECT, INSERT, UPDATE, DELETE ON gogogadget_db.* TO 'gogogadget_user'@'localhost' IDENTIFIED BY 'secure_password';
FLUSH PRIVILEGES;
