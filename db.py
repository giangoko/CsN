import os
import time
import hmac
import threading

import mysql.connector
from mysql.connector import Error, IntegrityError, pooling
from dotenv import load_dotenv

load_dotenv()

_pool = None
_pool_lock = threading.Lock()


def conn_kwargs(with_database=True):
    """Tham số kết nối MySQL (hỗ trợ MySQL cloud như Aiven qua TLS)."""
    kw = {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", 3306)),
        "user": os.getenv("DB_USER", "root"),
        "password": os.getenv("DB_PASSWORD", ""),
        "connection_timeout": 10,
    }
    if with_database:
        kw["database"] = os.getenv("DB_NAME", "security_login_db")
    ca = os.getenv("DB_SSL_CA")
    if ca:  # đường dẫn tới ca.pem (tuỳ chọn, để xác thực chứng chỉ máy chủ)
        kw["ssl_ca"] = ca
        kw["ssl_verify_cert"] = True
    return kw


def _get_pool():
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = pooling.MySQLConnectionPool(
                    pool_name="login_pool",
                    pool_size=int(os.getenv("DB_POOL_SIZE", 4)),
                    pool_reset_session=True,
                    autocommit=True,
                    **conn_kwargs(),
                )
    return _pool


def get_db_connection():
    """Lấy kết nối từ pool (tái sử dụng, nhanh hơn nhiều khi DB ở xa/qua TLS)."""
    pool = _get_pool()
    last = None
    for _ in range(20):
        try:
            conn = pool.get_connection()
            break
        except pooling.PoolError as e:  # pool tạm hết kết nối -> chờ một chút
            last = e
            time.sleep(0.1)
    else:
        raise last
    try:
        conn.ping(reconnect=True, attempts=2, delay=1)  # kết nối cũ có thể đã bị DB đóng
    except Error:
        conn.close()
        raise
    return conn


# ----------------------------------------------------------------------------
# Hàm tiện ích
# ----------------------------------------------------------------------------
def query_all(sql, params=()):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        cur.close()
        conn.close()


def query_one(sql, params=()):
    rows = query_all(sql, params)
    return rows[0] if rows else None


def execute(sql, params=()):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(sql, params)
        return cur.rowcount, cur.lastrowid
    finally:
        cur.close()
        conn.close()


# ----------------------------------------------------------------------------
# Người dùng
# ----------------------------------------------------------------------------
def get_user_by_email(email):
    return query_one("SELECT * FROM users WHERE email = %s", (email,))


def get_user_by_id(user_id):
    return query_one("SELECT * FROM users WHERE id = %s", (user_id,))


def create_user(email, password_hash):
    """Tạo tài khoản. Trả về id, hoặc None nếu email đã tồn tại."""
    try:
        _, uid = execute(
            "INSERT INTO users (email, password_hash, is_locked, created_at) VALUES (%s, %s, FALSE, NOW())",
            (email, password_hash),
        )
        return uid
    except IntegrityError:
        return None


def update_password_hash(user_id, new_hash):
    execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user_id))


def lock_user_account(user_id, minutes=15):
    execute(
        "UPDATE users SET is_locked = TRUE, locked_until = DATE_ADD(NOW(), INTERVAL %s MINUTE) WHERE id = %s",
        (minutes, user_id),
    )


def unlock_user_if_expired(user_id):
    execute(
        "UPDATE users SET is_locked = FALSE, locked_until = NULL "
        "WHERE id = %s AND is_locked = TRUE AND locked_until <= NOW()",
        (user_id,),
    )


# ----------------------------------------------------------------------------
# Nhật ký đăng nhập
# ----------------------------------------------------------------------------
def log_login_attempt(user_id, ip_address, user_agent, status, reason=None, attempted_email=None):
    """Ghi log mọi lượt đăng nhập (độ chính xác mili-giây để phát hiện bot)."""
    execute(
        "INSERT INTO login_logs (user_id, attempted_email, ip_address, user_agent, status, reason, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, NOW(3))",
        (user_id, (attempted_email or None) and attempted_email[:255], ip_address,
         (user_agent or "Unknown")[:255], status, reason),
    )


# ----------------------------------------------------------------------------
# Chặn IP / CAPTCHA
# ----------------------------------------------------------------------------
def block_ip_address(ip_address, reason, minutes=30):
    execute(
        """INSERT INTO blocked_ips (ip_address, reason, blocked_until)
           VALUES (%s, %s, DATE_ADD(NOW(), INTERVAL %s MINUTE))
           ON DUPLICATE KEY UPDATE reason = VALUES(reason),
                                   blocked_until = DATE_ADD(NOW(), INTERVAL %s MINUTE)""",
        (ip_address, reason, minutes, minutes),
    )


def is_ip_blocked(ip_address):
    return query_one(
        "SELECT * FROM blocked_ips WHERE ip_address = %s AND blocked_until > NOW()", (ip_address,)
    )


def set_captcha_required(ip_address, minutes=30):
    execute(
        """INSERT INTO captcha_flags (ip_address, expires_at)
           VALUES (%s, DATE_ADD(NOW(), INTERVAL %s MINUTE))
           ON DUPLICATE KEY UPDATE expires_at = DATE_ADD(NOW(), INTERVAL %s MINUTE)""",
        (ip_address, minutes, minutes),
    )


def is_captcha_required(ip_address):
    return query_one(
        "SELECT 1 AS x FROM captcha_flags WHERE ip_address = %s AND expires_at > NOW()", (ip_address,)
    ) is not None


# ----------------------------------------------------------------------------
# OTP xác minh IP/vị trí lạ (lưu phía server)
# ----------------------------------------------------------------------------
def create_otp_challenge(token, user_id, ip_address, otp_hash, ttl_seconds=300):
    execute("DELETE FROM otp_challenges WHERE expires_at < NOW() OR user_id = %s", (user_id,))
    execute(
        "INSERT INTO otp_challenges (token, user_id, ip_address, otp_hash, expires_at) "
        "VALUES (%s, %s, %s, %s, DATE_ADD(NOW(), INTERVAL %s SECOND))",
        (token, user_id, ip_address, otp_hash, ttl_seconds),
    )


def verify_otp_challenge(token, otp_hash, max_tries=5):
    """
    Trả về:
      None  -> challenge không tồn tại / hết hạn / đã thử quá số lần cho phép
      False -> OTP sai (đã tính 1 lần thử)
      dict  -> OTP đúng (challenge bị xoá, dùng một lần)
    """
    n, _ = execute(
        "UPDATE otp_challenges SET tries = tries + 1 WHERE token = %s AND tries < %s AND expires_at > NOW()",
        (token, max_tries),
    )
    if n == 0:
        return None
    row = query_one("SELECT user_id, ip_address, otp_hash FROM otp_challenges WHERE token = %s", (token,))
    if row and hmac.compare_digest(row["otp_hash"].encode(), otp_hash.encode()):
        execute("DELETE FROM otp_challenges WHERE token = %s", (token,))
        return row
    return False


# ----------------------------------------------------------------------------
# Nhật ký cảnh báo (đo thời gian phản ứng)
# ----------------------------------------------------------------------------
def log_alert(channel, anomaly_type, target, delivery, latency_ms):
    execute(
        "INSERT INTO alert_logs (channel, anomaly_type, target, delivery, latency_ms) VALUES (%s, %s, %s, %s, %s)",
        (channel, anomaly_type[:255], (target or "")[:255], delivery, latency_ms),
    )
