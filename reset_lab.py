"""Xoá trạng thái kiểm thử (log, chặn IP, khóa TK, tài khoản @test.com) để chạy lại simulator từ đầu."""
from db import execute


def reset():
    for table in ("otp_challenges", "captcha_flags", "blocked_ips", "alert_logs", "login_logs"):
        execute(f"DELETE FROM {table}")
    execute("UPDATE users SET is_locked = FALSE, locked_until = NULL")
    execute("DELETE FROM users WHERE email LIKE %s", ("%@test.com",))


if __name__ == "__main__":
    reset()
    print("✅ Đã reset trạng thái kiểm thử.")
