"""Cấp quyền admin: python make_admin.py email@example.com  (tài khoản phải được đăng ký trước)."""
import sys
from db import execute

if len(sys.argv) != 2:
    sys.exit("Cách dùng: python make_admin.py email@example.com")
n, _ = execute("UPDATE users SET is_admin = TRUE WHERE email = %s", (sys.argv[1].strip().lower(),))
print("✅ Đã cấp quyền admin." if n else "❌ Không tìm thấy tài khoản (hãy đăng ký trước).")
