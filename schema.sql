CREATE DATABASE IF NOT EXISTS security_login_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE security_login_db;

-- 1. Bảng users (thông tin tài khoản)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    is_locked BOOLEAN DEFAULT FALSE,
    locked_until DATETIME NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. Bảng login_logs (nhật ký đăng nhập)
-- status = pending: mật khẩu đúng nhưng đang chờ xác minh OTP (IP/vị trí lạ)
CREATE TABLE IF NOT EXISTS login_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    attempted_email VARCHAR(255) NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255) NOT NULL,
    status ENUM('success', 'failed', 'pending') NOT NULL,
    reason VARCHAR(255) NULL,
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT fk_user_logs FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_time (user_id, created_at),
    INDEX idx_user_status_time (user_id, status, created_at),
    INDEX idx_ip_time (ip_address, created_at),
    INDEX idx_ip_status_time (ip_address, status, created_at)
);

-- 3. Bảng blocked_ips (chặn tạm thời IP khi tấn công diện rộng / bot)
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip_address VARCHAR(45) PRIMARY KEY,
    reason VARCHAR(255) NOT NULL,
    blocked_until DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 4. Bảng captcha_flags (IP nào đang bị yêu cầu CAPTCHA; lưu phía server để không né được bằng cách bỏ cookie)
CREATE TABLE IF NOT EXISTS captcha_flags (
    ip_address VARCHAR(45) PRIMARY KEY,
    expires_at DATETIME NOT NULL
);

-- 5. Bảng otp_challenges (OTP xác minh IP lạ, lưu phía server dạng băm, có hạn dùng và giới hạn số lần thử)
CREATE TABLE IF NOT EXISTS otp_challenges (
    token CHAR(43) PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    otp_hash CHAR(64) NOT NULL,
    tries INT NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    CONSTRAINT fk_otp_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 6. Bảng alert_logs (đo thời gian từ lúc phát hiện đến lúc gửi xong cảnh báo)
CREATE TABLE IF NOT EXISTS alert_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    channel ENUM('email', 'telegram') NOT NULL,
    anomaly_type VARCHAR(255) NOT NULL,
    target VARCHAR(255) NULL,
    delivery ENUM('sent', 'simulated', 'error') NOT NULL,
    latency_ms INT NOT NULL,
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3)
);
