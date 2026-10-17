import os
import re
import hmac
import hashlib
import secrets
import ipaddress
from datetime import timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash,
    jsonify, abort, g
)
from flask_wtf.csrf import CSRFProtect, CSRFError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

from db import (
    get_user_by_email, get_user_by_id, create_user, update_password_hash,
    log_login_attempt, unlock_user_if_expired, is_ip_blocked, is_captcha_required,
    create_otp_challenge, verify_otp_challenge, query_all, query_one
)
from detection import evaluate_failed_login_rules, is_new_location_or_ip
from alerting import send_new_location_verification_email

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]  # bắt buộc: thiếu là báo lỗi ngay, không dùng khóa mặc định
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE") == "1",  # bật = 1 khi chạy HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)
csrf = CSRFProtect(app)

# LAB_MODE=1: bật API phục vụ kiểm thử tấn công giả lập và tin X-Forwarded-For do client tự gửi.
# TUYỆT ĐỐI tắt (mặc định) khi chạy thật.
LAB_MODE = os.getenv("LAB_MODE") == "1"

# Số proxy tin cậy đứng trước app (Nginx trong Docker = 1; Render: kiểm tra IP hiển thị ở Dashboard).
TRUSTED_PROXY_COUNT = int(os.getenv("TRUSTED_PROXY_COUNT", "0"))
if TRUSTED_PROXY_COUNT > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXY_COUNT, x_proto=1, x_host=1)

# Argon2: tự sinh salt ngẫu nhiên cho mỗi mật khẩu, có work factor cấu hình được
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
DUMMY_HASH = ph.hash("dummy-password-for-timing")  # băm giả để thời gian phản hồi không lộ email có tồn tại hay không

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

if os.getenv("AUTO_INIT_DB") == "1":
    from init_db import run_schema
    run_schema()


# ----------------------------------------------------------------------------
# Tiện ích
# ----------------------------------------------------------------------------
def get_client_ip():
    """IP client. Mặc định lấy remote_addr (đã được ProxyFix chỉnh nếu có proxy tin cậy)."""
    if LAB_MODE:
        fwd = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if fwd:
            try:
                return str(ipaddress.ip_address(fwd))
            except ValueError:
                pass
    return request.remote_addr or "127.0.0.1"


def generate_captcha():
    a, b = secrets.randbelow(9) + 1, secrets.randbelow(9) + 1
    session["captcha_answer"] = str(a + b)
    return f"{a} + {b} = ?"


def check_captcha(user_input):
    answer = session.pop("captcha_answer", None)  # dùng một lần
    return answer is not None and hmac.compare_digest(str(user_input).strip().encode(), answer.encode())


def otp_hash(token, otp):
    return hashlib.sha256(f"{token}:{otp}".encode()).hexdigest()


def verify_password(user, password):
    """Luôn tốn một lần băm Argon2 kể cả khi email không tồn tại."""
    stored = user["password_hash"] if user else DUMMY_HASH
    ok = False
    if len(password) <= 256:
        try:
            ok = ph.verify(stored, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            ok = False
    return bool(user) and ok


def finish_login(user):
    session.clear()  # chống session fixation
    session.permanent = True
    session["user_id"] = user["id"]
    session["user_email"] = user["email"]


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = get_user_by_id(session["user_id"]) if "user_id" in session else None
        if not user:
            session.clear()
            return redirect(url_for("login"))
        g.user = user
        return view(*args, **kwargs)
    return wrapper


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


@app.errorhandler(CSRFError)
def handle_csrf(e):
    flash("Phiên làm việc đã hết hạn, vui lòng thử lại.", "warning")
    return redirect(url_for("login"))


# ----------------------------------------------------------------------------
# Lõi xác thực (dùng chung cho form web và API lab)
# ----------------------------------------------------------------------------
def authenticate(email, password, captcha_input, via_api=False):
    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "Unknown")

    # 1. IP đang bị chặn?
    blocked = is_ip_blocked(ip)
    if blocked:
        return {"outcome": "blocked_ip", "status": 403,
                "message": f"Địa chỉ IP ({ip}) đang bị chặn tạm thời đến {blocked['blocked_until']}."}

    # 2. IP đang bị yêu cầu CAPTCHA? (trạng thái lưu ở server, không phụ thuộc cookie của client)
    if is_captcha_required(ip):
        if via_api:
            return {"outcome": "captcha_required", "status": 428, "message": "Yêu cầu xác thực CAPTCHA."}
        if not check_captcha(captcha_input):
            return {"outcome": "captcha_invalid", "status": 400, "message": "Mã xác thực CAPTCHA không chính xác!"}

    if not email or not password:
        return {"outcome": "invalid_input", "status": 400, "message": "Vui lòng nhập đầy đủ email và mật khẩu."}

    # 3. Tài khoản đang bị khóa tạm thời?
    user = get_user_by_email(email)
    if user:
        unlock_user_if_expired(user["id"])
        user = get_user_by_email(email)
        if user["is_locked"]:
            log_login_attempt(user["id"], ip, ua, "failed", "Tài khoản đang bị khóa tạm thời", email)
            return {"outcome": "locked", "status": 423,
                    "message": f"Tài khoản đang bị khóa tạm thời đến {user['locked_until']} do nghi ngờ bị tấn công."}

    # 4. Kiểm tra mật khẩu bằng Argon2
    if not verify_password(user, password):
        reason = "Sai mật khẩu" if user else "Email không tồn tại"
        log_login_attempt(user["id"] if user else None, ip, ua, "failed", reason, email)
        det = evaluate_failed_login_rules(user, ip)
        if det["account_locked"]:
            status, msg = 423, "Tài khoản đã bị khóa tạm thời do nhiều lần đăng nhập sai."
        elif det["ip_blocked"]:
            status, msg = 403, "Địa chỉ IP đã bị chặn tạm thời do hoạt động đáng ngờ."
        else:
            status, msg = 401, "Email hoặc mật khẩu không chính xác."
        res = {"outcome": "failed", "status": status, "message": msg}
        if LAB_MODE:
            res["detection"] = det  # chỉ lộ chi tiết phát hiện ở chế độ lab để đo đạc
        return res

    if ph.check_needs_rehash(user["password_hash"]):
        update_password_hash(user["id"], ph.hash(password))

    # 5. Mật khẩu đúng -> kiểm tra IP/vị trí lạ (R4)
    if is_new_location_or_ip(user["id"], ip):
        token = secrets.token_urlsafe(32)
        otp = f"{secrets.randbelow(10**6):06d}"
        create_otp_challenge(token, user["id"], ip, otp_hash(token, otp))
        log_login_attempt(user["id"], ip, ua, "pending", "Mật khẩu đúng nhưng IP/vị trí mới, chờ xác minh OTP", email)
        send_new_location_verification_email(user["email"], ip, otp)
        return {"outcome": "verify_location", "status": 202, "token": token, "email": user["email"],
                "message": "Phát hiện đăng nhập từ IP/vị trí mới. Đã gửi OTP qua email."}

    # 6. Hợp lệ
    log_login_attempt(user["id"], ip, ua, "success", "Đăng nhập hợp lệ", email)
    return {"outcome": "success", "status": 200, "user": user, "message": "Đăng nhập thành công"}


# ----------------------------------------------------------------------------
# Các route
# ----------------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not EMAIL_RE.match(email) or len(email) > 255:
            flash("Email không hợp lệ.", "danger")
        elif not (8 <= len(password) <= 128):
            flash("Mật khẩu phải dài từ 8 đến 128 ký tự.", "danger")
        elif get_user_by_email(email) or create_user(email, ph.hash(password)) is None:
            flash("Email này đã được đăng ký.", "danger")
        else:
            flash("Đăng ký thành công! Mật khẩu được lưu dưới dạng băm Argon2 kèm salt ngẫu nhiên.", "success")
            return redirect(url_for("login"))
        return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = get_client_ip()

    if request.method == "POST":
        res = authenticate(
            request.form.get("email", "").strip().lower(),
            request.form.get("password", ""),
            request.form.get("captcha", ""),
        )
        if res["outcome"] == "success":
            finish_login(res["user"])
            return redirect(url_for("dashboard"))
        if res["outcome"] == "verify_location":
            session.clear()
            session["pending_token"] = res["token"]
            session["pending_email"] = res["email"]
            flash("Phát hiện đăng nhập từ địa chỉ IP/vị trí lạ! Vui lòng nhập mã OTP vừa gửi tới email của bạn.", "warning")
            return redirect(url_for("verify_location"))
        flash(res["message"], "danger")
        status = res["status"]
    else:
        status = 403 if is_ip_blocked(ip) else 200
        if status == 403:
            flash("Địa chỉ IP của bạn đang bị chặn tạm thời.", "danger")

    need_captcha = status != 403 and is_captcha_required(ip)
    return render_template(
        "login.html",
        require_captcha=need_captcha,
        captcha_question=generate_captcha() if need_captcha else None,
    ), status


@app.route("/verify-location", methods=["GET", "POST"])
def verify_location():
    token = session.get("pending_token")
    if not token:
        return redirect(url_for("login"))

    if request.method == "POST":
        result = verify_otp_challenge(token, otp_hash(token, request.form.get("otp", "").strip()))
        if result is None:
            session.clear()
            flash("OTP đã hết hạn hoặc nhập sai quá nhiều lần. Vui lòng đăng nhập lại.", "danger")
            return redirect(url_for("login"))
        if result is False:
            flash("Mã xác minh OTP không đúng.", "danger")
        else:
            user = get_user_by_id(result["user_id"])
            log_login_attempt(user["id"], result["ip_address"], request.headers.get("User-Agent", "Unknown"),
                              "success", "Đã xác minh OTP vị trí mới", user["email"])
            finish_login(user)
            flash("Xác minh vị trí mới thành công!", "success")
            return redirect(url_for("dashboard"))

    return render_template("verify_otp.html", email=session.get("pending_email"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = g.user
    is_admin = bool(user["is_admin"])
    scope, params = ("", ()) if is_admin else ("WHERE l.user_id = %s", (user["id"],))

    logs = query_all(
        f"SELECT l.*, u.email FROM login_logs l LEFT JOIN users u ON l.user_id = u.id {scope} "
        "ORDER BY l.created_at DESC LIMIT 50", params)
    stats = {"success": 0, "failed": 0, "pending": 0}
    for r in query_all(
            f"SELECT l.status, COUNT(*) AS count FROM login_logs l {scope} GROUP BY l.status", params):
        stats[r["status"]] = r["count"]

    blocked_ips, alerts, alert_avg = [], [], None
    if is_admin:  # dữ liệu toàn hệ thống chỉ dành cho quản trị viên
        blocked_ips = query_all("SELECT * FROM blocked_ips WHERE blocked_until > NOW()")
        alerts = query_all("SELECT * FROM alert_logs ORDER BY created_at DESC LIMIT 20")
        alert_avg = query_one("SELECT COUNT(*) AS n, AVG(latency_ms) AS avg_ms FROM alert_logs")

    return render_template(
        "dashboard.html", email=user["email"], is_admin=is_admin, logs=logs, stats=stats,
        blocked_ips=blocked_ips, alerts=alerts, alert_avg=alert_avg, client_ip=get_client_ip(),
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ----------------------------------------------------------------------------
# API chỉ tồn tại khi LAB_MODE=1 (phục vụ attack_simulator.py)
# ----------------------------------------------------------------------------
def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


@app.route("/api/login", methods=["POST"])
@csrf.exempt
def api_login():
    if not LAB_MODE:
        abort(404)
    data = _json_body()
    res = authenticate(str(data.get("email", "")).strip().lower(), str(data.get("password", "")), "", via_api=True)
    body = {"status": res["outcome"], "message": res["message"]}
    if "detection" in res:
        body["detection"] = res["detection"]
    return jsonify(body), res["status"]


@app.route("/api/register", methods=["POST"])
@csrf.exempt
def api_register():
    if not LAB_MODE:
        abort(404)
    data = _json_body()
    email, password = str(data.get("email", "")).strip().lower(), str(data.get("password", ""))
    if not EMAIL_RE.match(email) or not (8 <= len(password) <= 128):
        return jsonify({"status": "invalid"}), 400
    if get_user_by_email(email) or create_user(email, ph.hash(password)) is None:
        return jsonify({"status": "exists"}), 409
    return jsonify({"status": "created"}), 201


@app.route("/api/lab/alert-stats")
def api_alert_stats():
    if not LAB_MODE:
        abort(404)
    rows = query_all("SELECT delivery, COUNT(*) AS n, AVG(latency_ms) AS avg_ms, MAX(latency_ms) AS max_ms "
                     "FROM alert_logs GROUP BY delivery")
    return jsonify([{k: (float(v) if k.endswith("_ms") and v is not None else v) for k, v in r.items()}
                    for r in rows])


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 5000)),
            debug=os.getenv("FLASK_DEBUG") == "1")
