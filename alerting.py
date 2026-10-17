import os
import time
import html
import smtplib
import threading
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests
from dotenv import load_dotenv

from db import log_alert

load_dotenv()

EMAIL_PROVIDER = os.getenv("EMAIL_PROVIDER", "smtp").lower()   # smtp | brevo
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_EMAIL = os.getenv("SMTP_EMAIL", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "") or SMTP_EMAIL
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

esc = html.escape


def _is_placeholder(value):
    return (not value) or "your_" in value


def _scrub(text):
    """Không để token/API key lọt vào log (thông báo lỗi của requests chứa nguyên URL)."""
    text = str(text)
    for secret in (TELEGRAM_BOT_TOKEN, BREVO_API_KEY, SMTP_PASSWORD):
        if secret:
            text = text.replace(secret, "***")
    return text


def _record(channel, anomaly_type, target, delivery, started):
    latency_ms = int((time.perf_counter() - started) * 1000)
    try:
        log_alert(channel, anomaly_type, target, delivery, latency_ms)
    except Exception as e:
        print(f"[ALERT-LOG ERROR] {_scrub(e)}")
    return latency_ms


def _send_email_sync(to_email, subject, html_body, anomaly_type, started):
    """Gửi email qua SMTP hoặc qua Brevo HTTP API (cloud miễn phí thường chặn cổng SMTP)."""
    if EMAIL_PROVIDER == "brevo":
        configured = not _is_placeholder(BREVO_API_KEY) and not _is_placeholder(EMAIL_SENDER)
    else:
        configured = not _is_placeholder(SMTP_EMAIL) and not _is_placeholder(SMTP_PASSWORD)

    if not configured:
        ms = _record("email", anomaly_type, to_email, "simulated", started)
        print(f"[ALERT-EMAIL SIMULATION] To: {to_email} | Subject: {subject} | {ms} ms")
        return

    try:
        if EMAIL_PROVIDER == "brevo":
            r = requests.post(
                "https://api.brevo.com/v3/smtp/email",
                headers={"api-key": BREVO_API_KEY, "accept": "application/json"},
                json={
                    "sender": {"name": "Security Alert", "email": EMAIL_SENDER},
                    "to": [{"email": to_email}],
                    "subject": subject,
                    "htmlContent": html_body,
                },
                timeout=8,
            )
            r.raise_for_status()
        else:
            msg = MIMEMultipart()
            msg["From"] = SMTP_EMAIL
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(html_body, "html", "utf-8"))
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=8) as server:
                server.starttls()
                server.login(SMTP_EMAIL, SMTP_PASSWORD)
                server.send_message(msg)
        ms = _record("email", anomaly_type, to_email, "sent", started)
        print(f"[ALERT-EMAIL SENT] To: {to_email} in {ms} ms")
    except Exception as e:
        _record("email", anomaly_type, to_email, "error", started)
        print(f"[ALERT-EMAIL ERROR] {_scrub(e)}")


def _send_telegram_sync(message, anomaly_type, started):
    if _is_placeholder(TELEGRAM_BOT_TOKEN) or _is_placeholder(TELEGRAM_CHAT_ID):
        ms = _record("telegram", anomaly_type, "admin", "simulated", started)
        print(f"[ALERT-TELEGRAM SIMULATION] {message!r} | {ms} ms")
        return
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=8,
        )
        r.raise_for_status()
        ms = _record("telegram", anomaly_type, "admin", "sent", started)
        print(f"[ALERT-TELEGRAM SENT] in {ms} ms")
    except Exception as e:
        _record("telegram", anomaly_type, "admin", "error", started)
        print(f"[ALERT-TELEGRAM ERROR] {_scrub(e)}")


def _spawn(fn, *args):
    threading.Thread(target=fn, args=args, daemon=True).start()


def send_account_locked_alert(to_email, ip_address, anomaly_type, detected_at=None):
    """Email cho chủ tài khoản + Telegram cho admin khi tài khoản bị khóa."""
    started = detected_at or time.perf_counter()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject = "[CẢNH BÁO BẢO MẬT] Tài khoản của bạn đã bị khóa tạm thời"
    html_body = f"""
    <h3>Cảnh báo phát hiện đăng nhập bất thường</h3>
    <p>Hệ thống vừa phát hiện dấu hiệu đăng nhập bất thường vào tài khoản của bạn:</p>
    <ul>
        <li><b>Tài khoản bị ảnh hưởng:</b> {esc(to_email)}</li>
        <li><b>Loại bất thường:</b> {esc(anomaly_type)}</li>
        <li><b>Địa chỉ IP nguồn:</b> {esc(ip_address)}</li>
        <li><b>Thời gian ghi nhận:</b> {now_str}</li>
        <li><b>Hành động tự động:</b> Khóa tạm thời tài khoản 15 phút và yêu cầu CAPTCHA.</li>
    </ul>
    """
    _spawn(_send_email_sync, to_email, subject, html_body, anomaly_type, started)

    tg_msg = (
        f"🚨 <b>CẢNH BÁO KHÓA TÀI KHOẢN</b>\n"
        f"• <b>Thời gian:</b> {now_str}\n"
        f"• <b>Tài khoản:</b> {esc(to_email)}\n"
        f"• <b>IP nguồn:</b> <code>{esc(ip_address)}</code>\n"
        f"• <b>Loại bất thường:</b> {esc(anomaly_type)}"
    )
    _spawn(_send_telegram_sync, tg_msg, anomaly_type, started)


def send_widespread_attack_alert(ip_address, failed_count, anomaly_type="Tấn công diện rộng / Bot", detected_at=None):
    """Telegram cho quản trị viên khi phát hiện tấn công diện rộng / bot."""
    started = detected_at or time.perf_counter()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tg_msg = (
        f"🔥 <b>CẢNH BÁO KHẨN CẤP: {esc(anomaly_type.upper())}</b>\n"
        f"• <b>Thời gian:</b> {now_str}\n"
        f"• <b>IP nguồn:</b> <code>{esc(ip_address)}</code>\n"
        f"• <b>Số lượt thất bại ghi nhận:</b> {failed_count} lượt\n"
        f"• <b>Hành động:</b> Đã tự động chặn IP trong 30 phút."
    )
    _spawn(_send_telegram_sync, tg_msg, anomaly_type, started)


def send_new_location_verification_email(to_email, ip_address, otp_code):
    """Email xác minh (OTP) khi đăng nhập đúng mật khẩu nhưng từ IP/vị trí lạ."""
    started = time.perf_counter()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject = "[XÁC MINH ĐĂNG NHẬP] Phát hiện đăng nhập từ vị trí/IP mới"
    html_body = f"""
    <h3>Xác minh đăng nhập từ thiết bị / vị trí mới</h3>
    <p>Hệ thống ghi nhận lượt đăng nhập hợp lệ nhưng từ một địa chỉ IP/vị trí chưa từng xuất hiện trước đây:</p>
    <ul>
        <li><b>Tài khoản:</b> {esc(to_email)}</li>
        <li><b>Địa chỉ IP mới:</b> {esc(ip_address)}</li>
        <li><b>Thời gian:</b> {now_str}</li>
    </ul>
    <p>Mã xác minh (OTP) của bạn là: <b style="font-size: 20px; color: #d9534f;">{esc(otp_code)}</b></p>
    <p>Mã có hiệu lực 5 phút. Nếu không phải bạn đăng nhập, hãy đổi mật khẩu ngay.</p>
    """
    if os.getenv("DEV_PRINT_OTP") == "1":  # CHỈ dùng khi dev/demo không có email thật
        print(f"[DEV] OTP cho {to_email}: {otp_code}")
    _spawn(_send_email_sync, to_email, subject, html_body, "Đăng nhập từ IP/vị trí lạ (OTP)", started)
