import os
import time

from db import (
    query_all, query_one, lock_user_account, block_ip_address, set_captcha_required
)
from alerting import send_account_locked_alert, send_widespread_attack_alert


def _i(name, default):
    return int(os.getenv(name, default))


def _f(name, default):
    return float(os.getenv(name, default))


# Các ngưỡng có thể chỉnh bằng biến môi trường -> dễ làm phần "phân tích ngưỡng" trong báo cáo
R1_MAX_GAP_SEC = _f("R1_MAX_GAP_SEC", 1.0)      # R1: khoảng cách giữa 2 lần thử < 1 giây
R1_MIN_CONSECUTIVE = _i("R1_MIN_CONSECUTIVE", 3)  # ... lặp lại >= 3 khoảng liên tiếp
R1_BLOCK_MIN = _i("R1_BLOCK_MIN", 30)
R2_MAX_FAILS = _i("R2_MAX_FAILS", 5)            # R2: >= 5 lần sai / 1 tài khoản
R2_WINDOW_SEC = _i("R2_WINDOW_SEC", 60)         # ... trong 1 phút
R2_LOCK_MIN = _i("R2_LOCK_MIN", 15)
R3_MAX_FAILS = _i("R3_MAX_FAILS", 20)           # R3: >= 20 lần thất bại / 1 IP
R3_WINDOW_SEC = _i("R3_WINDOW_SEC", 300)        # ... trong 5 phút
R3_MIN_TARGETS = _i("R3_MIN_TARGETS", 2)        # ... nhắm >= 2 tài khoản khác nhau
R3_BLOCK_MIN = _i("R3_BLOCK_MIN", 30)
CAPTCHA_MIN = _i("CAPTCHA_MIN", 30)             # thời gian IP bị yêu cầu CAPTCHA sau khi bị phát hiện


def evaluate_failed_login_rules(user, ip_address):
    """
    Chạy các quy tắc R1-R3 ngay sau khi một lượt đăng nhập THẤT BẠI đã được ghi log.
    Trả về dict: anomaly_detected, rule_triggered, rules, require_captcha, account_locked, ip_blocked
    """
    result = {
        "anomaly_detected": False,
        "rule_triggered": None,
        "rules": [],
        "require_captcha": False,
        "account_locked": False,
        "ip_blocked": False,
    }

    def flag(name):
        result["anomaly_detected"] = True
        result["rules"].append(name)
        result["rule_triggered"] = " + ".join(result["rules"])
        result["require_captcha"] = True

    # R1: tốc độ thử bất thường (bot). Chỉ xét các lần THẤT BẠI của IP này.
    rows = query_all(
        "SELECT created_at FROM login_logs WHERE ip_address = %s AND status = 'failed' "
        "ORDER BY created_at DESC LIMIT %s",
        (ip_address, R1_MIN_CONSECUTIVE + 1),
    )
    if len(rows) == R1_MIN_CONSECUTIVE + 1:
        fast = sum(
            1 for k in range(len(rows) - 1)
            if (rows[k]["created_at"] - rows[k + 1]["created_at"]).total_seconds() < R1_MAX_GAP_SEC
        )
        if fast >= R1_MIN_CONSECUTIVE:
            detected_at = time.perf_counter()
            name = f"R1 Tốc độ thử bất thường (khoảng cách < {R1_MAX_GAP_SEC:g}s)"
            flag(name)
            result["ip_blocked"] = True
            block_ip_address(ip_address, name, minutes=R1_BLOCK_MIN)
            send_widespread_attack_alert(ip_address, len(rows), "Tốc độ thử bất thường (Bot)", detected_at)

    # R2: brute-force / dictionary trên 1 tài khoản
    if user:
        row = query_one(
            "SELECT COUNT(*) AS fail_count FROM login_logs "
            "WHERE user_id = %s AND status = 'failed' AND created_at >= DATE_SUB(NOW(), INTERVAL %s SECOND)",
            (user["id"], R2_WINDOW_SEC),
        )
        if row["fail_count"] >= R2_MAX_FAILS:
            detected_at = time.perf_counter()
            name = f"R2 Brute-force/Dictionary (>= {R2_MAX_FAILS} lần sai/{R2_WINDOW_SEC}s)"
            flag(name)
            result["account_locked"] = True
            lock_user_account(user["id"], minutes=R2_LOCK_MIN)
            send_account_locked_alert(user["email"], ip_address, name, detected_at)

    # R3: tấn công diện rộng (credential stuffing) từ 1 IP. Bỏ qua nếu R1 đã chặn IP này.
    if not result["ip_blocked"]:
        stats = query_one(
            "SELECT COUNT(*) AS total_fails, COUNT(DISTINCT attempted_email) AS targets "
            "FROM login_logs WHERE ip_address = %s AND status = 'failed' "
            "AND created_at >= DATE_SUB(NOW(), INTERVAL %s SECOND)",
            (ip_address, R3_WINDOW_SEC),
        )
        if stats and stats["total_fails"] >= R3_MAX_FAILS and stats["targets"] >= R3_MIN_TARGETS:
            detected_at = time.perf_counter()
            name = f"R3 Tấn công diện rộng (>= {R3_MAX_FAILS} lần thất bại/{R3_WINDOW_SEC}s từ 1 IP)"
            flag(name)
            result["ip_blocked"] = True
            block_ip_address(ip_address, name, minutes=R3_BLOCK_MIN)
            send_widespread_attack_alert(ip_address, stats["total_fails"], name, detected_at)

    if result["require_captcha"]:
        set_captcha_required(ip_address, CAPTCHA_MIN)
    return result


def is_new_location_or_ip(user_id, ip_address):
    """
    R4: đăng nhập từ IP lạ. Chỉ so sánh IP (chưa tra GeoIP quốc gia/thành phố).
    Lần đăng nhập thành công đầu tiên của tài khoản được dùng làm mốc (baseline).
    """
    row = query_one(
        "SELECT COUNT(*) AS total_success, "
        "       COALESCE(SUM(ip_address = %s), 0) AS ip_success "
        "FROM login_logs WHERE user_id = %s AND status = 'success'",
        (ip_address, user_id),
    )
    if row["total_success"] == 0:
        return False
    return int(row["ip_success"]) == 0
