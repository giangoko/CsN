import os
import mysql.connector
from dotenv import load_dotenv

from db import conn_kwargs

load_dotenv()


def _statements(path):
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if not ln.strip().startswith("--")]
    return [s.strip() for s in "\n".join(lines).split(";") if s.strip()]


def run_schema(schema_path=None):
    """
    Tạo bảng (idempotent). Nếu DB_MANAGED=1 (MySQL cloud/Docker đã tạo sẵn database)
    thì bỏ qua CREATE DATABASE / USE và kết nối thẳng vào database có sẵn.
    """
    schema_path = schema_path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
    managed = os.getenv("DB_MANAGED") == "1"
    conn = mysql.connector.connect(**conn_kwargs(with_database=managed))
    try:
        cur = conn.cursor()
        for cmd in _statements(schema_path):
            head = cmd.upper()
            if managed and (head.startswith("CREATE DATABASE") or head.startswith("USE ")):
                continue
            cur.execute(cmd)
        conn.commit()
        cur.close()
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        run_schema()
        print("✅ Đã khởi tạo CSDL và các bảng!")
    except Exception as e:
        print(f"❌ Lỗi kết nối/khởi tạo MySQL: {e}")
        print("-> Kiểm tra MySQL đã chạy chưa và thông tin DB_* trong file .env.")
