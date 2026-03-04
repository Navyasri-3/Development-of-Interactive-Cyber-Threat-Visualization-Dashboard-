CREATE DATABASE IF NOT EXISTS cyber_security;
USE cyber_security;
CREATE TABLE IF NOT EXISTS cyber_threat_logs (
    id INT PRIMARY KEY,
    timestamp DATETIME,
    source_ip VARCHAR(15),
    destination_ip VARCHAR(15),
    threat_type VARCHAR(50),
    severity VARCHAR(20),
    country VARCHAR(50),
    protocol VARCHAR(10),
    action VARCHAR(20)
);
TRUNCATE TABLE cyber_threat_logs;

INSERT INTO cyber_threat_logs (id, timestamp, source_ip, destination_ip, threat_type, severity, country, protocol, action) VALUES
(1,'2025-01-01 09:10:12','192.168.1.10','10.0.0.5','Brute Force','High','India','TCP','Blocked'),
(2,'2025-01-01 09:15:45','45.33.21.90','10.0.0.5','Brute Force','High','Russia','TCP','Blocked'),
(3,'2025-01-01 09:22:30','103.21.244.1','10.0.0.8','SQL Injection','Critical','India','HTTP','Blocked'),
(4,'2025-01-01 09:40:05','185.220.101.4','10.0.0.12','Malware Download','Critical','Germany','HTTP','Detected'),
(5,'2025-01-01 10:05:18','13.234.112.8','10.0.0.7','Phishing','Medium','India','SMTP','Allowed'),
(6,'2025-01-01 10:25:44','91.240.118.172','10.0.0.9','DDoS','High','Ukraine','UDP','Blocked'),
(7,'2025-01-01 10:50:02','8.34.56.77','10.0.0.10','Port Scan','Low','USA','TCP','Detected'),
(8,'2025-01-01 11:15:36','192.168.1.10','10.0.0.5','Brute Force','High','India','TCP','Blocked'),
(9,'2025-01-01 11:45:59','51.38.92.10','10.0.0.11','Ransomware','Critical','France','HTTP','Blocked'),
(10,'2025-01-01 12:10:21','103.21.244.1','10.0.0.8','SQL Injection','Critical','India','HTTP','Blocked');
-- 1️⃣ Use the database
USE cyber_security;

-- 2️⃣ Create devices table (if it doesn't exist)
CREATE TABLE IF NOT EXISTS devices (
    device_ip VARCHAR(15) PRIMARY KEY,
    device_name VARCHAR(50),
    location VARCHAR(50)
);

-- 3️⃣ Remove any old data from the table
TRUNCATE TABLE devices;

-- 4️⃣ Insert fresh device records
INSERT INTO devices (device_ip, device_name, location) VALUES
('10.0.0.5','Web Server 1','Mumbai'),
('10.0.0.7','Mail Server','Delhi'),
('10.0.0.8','Database Server','Bangalore'),
('10.0.0.9','Proxy Server','Kiev'),
('10.0.0.10','Firewall','New York'),
('10.0.0.11','File Server','Paris'),
('10.0.0.12','Application Server','Berlin');

-- 5️⃣ Verify the inserted data
SELECT * FROM devices;
-- Fetch all threat logs along with device name and location
SELECT 
    c.id,
    c.timestamp,
    c.source_ip,
    c.destination_ip,
    d.device_name,
    d.location,
    c.threat_type,
    c.severity,
    c.action
FROM cyber_threat_logs c
JOIN devices d
ON c.destination_ip = d.device_ip;
-- Count how many threats each device has faced
SELECT 
    d.device_name,
    COUNT(*) AS total_threats
FROM cyber_threat_logs c
JOIN devices d
ON c.destination_ip = d.device_ip
GROUP BY d.device_name;
-- List all high severity threats per device

SELECT 
    d.device_name,
    c.threat_type,
    c.severity,
    c.timestamp
FROM cyber_threat_logs c
JOIN devices d
ON c.destination_ip = d.device_ip
WHERE c.severity = 'High';
-- Count number of blocked, allowed, and detected actions per device
SELECT 
    d.device_name,
    c.action,
    COUNT(*) AS count_actions
FROM cyber_threat_logs c
JOIN devices d
ON c.destination_ip = d.device_ip
GROUP BY d.device_name, c.action;
-- Find which threat types occur most frequently

SELECT 
    c.threat_type,
    COUNT(*) AS count_threats
FROM cyber_threat_logs c
GROUP BY c.threat_type
ORDER BY count_threats DESC;
-- Count total threats originating from each country
SELECT 
    c.country,
    COUNT(*) AS total_threats
FROM cyber_threat_logs c
GROUP BY c.country
ORDER BY total_threats DESC;

git init
