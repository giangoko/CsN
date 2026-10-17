"""
Kiểm thử tấn công giả lập chống lại CHÍNH hệ thống demo của nhóm (không dùng cho hệ thống của bên thứ ba).

Yêu cầu: server chạy với LAB_MODE=1.
  python attack_simulator.py                 # chạy với BASE_URL mặc định http://127.0.0.1:5000
  python attack_simulator.py --reset         # reset trạng thái (cần truy cập DB) rồi chạy
  BASE_URL=https://xxx.onrender.com python attack_simulator.py --reset
"""
import os
import sys
import time
import random
import string
import requests

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000").rstrip("/")
DETECTED = {403, 423, 428}          # mã trả về cho biết hệ thống đã chặn/khóa/yêu cầu CAPTCHA
HUMAN_DELAY = 1.1                   # người thật gõ tay > 1 giây; cũng tránh kích hoạt R1 khi test R2/R3

ACADEMIC_WORDLIST = [
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "admin123", "letmein", "welcome",
]


def random_password(length=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def api_login(email, password, ip):
    """Trả về (status_code, json, độ trễ của riêng request này tính bằng giây)."""
    t0 = time.perf_counter()
    resp = requests.post(f"{BASE_URL}/api/login", json={"email": email, "password": password},
                         headers={"X-Forwarded-For": ip}, timeout=15)
    latency = time.perf_counter() - t0
    try:
        body = resp.json()
    except ValueError:
        body = {}
    return resp.status_code, body, latency


def attack(name, passwords, email_for, ip, delay):
    """Thử lần lượt tới khi bị phát hiện. Trả về (detected, attempts, latency_của_request_phát_hiện)."""
    print(f"\n[{name}]")
    for n, pw in enumerate(passwords, start=1):
        code, body, latency = api_login(email_for(n), pw, ip)
        if code in DETECTED:
            print(f" -> Bị phát hiện ở lần thử thứ {n} (HTTP {code}). Độ trễ request phát hiện: {latency * 1000:.0f} ms")
            return True, n, latency
        if delay:
            time.sleep(delay)
    print(" -> KHÔNG bị phát hiện!")
    return False, len(passwords), None


def run_evaluation():
    if requests.get(f"{BASE_URL}/healthz", timeout=15).status_code != 200:
        sys.exit("Server không phản hồi /healthz")
    if "--reset" in sys.argv:
        from reset_lab import reset
        reset()
        print("Đã reset trạng thái kiểm thử.")

    print("=" * 70)
    print("KIỂM THỬ HỆ THỐNG PHÁT HIỆN ĐĂNG NHẬP BẤT THƯỜNG")
    print("=" * 70)

    for email, pw in (("victim_bf@test.com", "StrongPassword!2026"),
                      ("victim_dict@test.com", "StrongPassword!2026"),
                      ("normal_user@test.com", "NormalUserPass!123")):
        r = requests.post(f"{BASE_URL}/api/register", json={"email": email, "password": pw}, timeout=15)
        if r.status_code not in (201, 409):
            sys.exit(f"Không tạo được tài khoản test ({r.status_code}). Server đã bật LAB_MODE=1 chưa?")

    # Kịch bản 4 (chạy trước): người dùng hợp lệ -> đo False Positive
    total_legit = 5
    false_positives = 0
    print("\n[Kịch bản 4] Người dùng hợp lệ đăng nhập bình thường")
    for _ in range(total_legit):
        code, _, _ = api_login("normal_user@test.com", "NormalUserPass!123", "10.0.0.10")
        if code != 200:
            false_positives += 1
        time.sleep(HUMAN_DELAY)
    print(f" -> {total_legit - false_positives}/{total_legit} lượt hợp lệ thành công.")

    results = []   # (tên, detected, số lần thử, độ trễ)
    results.append(("KB1 Brute-force (R2)",) + attack(
        "Kịch bản 1: Brute-force vào victim_bf@test.com",
        [random_password() for _ in range(10)], lambda n: "victim_bf@test.com", "192.168.100.11", HUMAN_DELAY))
    results.append(("KB2 Dictionary (R2)",) + attack(
        "Kịch bản 2: Dictionary attack vào victim_dict@test.com",
        ACADEMIC_WORDLIST, lambda n: "victim_dict@test.com", "192.168.100.22", HUMAN_DELAY))
    # Gửi chậm hơn 1 giây để không bị R1 chặn trước -> kiểm chứng đúng quy tắc R3
    results.append(("KB3 Diện rộng (R3)",) + attack(
        "Kịch bản 3: Tấn công diện rộng nhiều tài khoản từ 1 IP (chậm, để kiểm chứng R3)",
        ["wrongpassword123"] * 25, lambda n: f"target_user_{n}@test.com", "203.0.113.99", HUMAN_DELAY))
    # Gửi dồn dập không nghỉ -> R1
    results.append(("KB5 Bot tốc độ cao (R1)",) + attack(
        "Kịch bản 5: Bot gửi dồn dập không nghỉ (R1)",
        ["wrongpassword123"] * 10, lambda n: f"bot_target_{n}@test.com", "203.0.113.50", 0))

    # Kịch bản 6: R4 - đăng nhập đúng mật khẩu từ IP lạ -> phải bị chặn bước OTP (202)
    print("\n[Kịch bản 6] Đăng nhập đúng mật khẩu nhưng từ IP lạ (R4)")
    code, _, _ = api_login("normal_user@test.com", "NormalUserPass!123", "10.0.0.77")
    r4_ok = code == 202
    print(f" -> HTTP {code}: {'ĐẠT (yêu cầu OTP)' if r4_ok else 'KHÔNG ĐẠT'}")

    n_attacks = len(results)
    tp = sum(1 for r in results if r[1])
    latencies = [r[3] for r in results if r[3] is not None]
    avg_ms = (sum(latencies) / len(latencies) * 1000) if latencies else 0

    print("\n" + "=" * 70)
    print("BÁO CÁO ĐÁNH GIÁ ĐỊNH LƯỢNG")
    print("=" * 70)
    for name, det, attempts, lat in results:
        print(f"  {name:<28} phát hiện: {'CÓ' if det else 'KHÔNG':<5} sau {attempts:>2} lần thử")
    print(f"  {'KB6 IP lạ (R4)':<28} yêu cầu OTP: {'CÓ' if r4_ok else 'KHÔNG'}")
    print("-" * 70)
    print(f"1. True Positive Rate : {tp / n_attacks * 100:.1f}% ({tp}/{n_attacks} kịch bản tấn công)")
    print(f"2. False Positive Rate: {false_positives / total_legit * 100:.1f}% ({false_positives}/{total_legit} lượt hợp lệ)")
    print(f"3. Độ trễ của request phát hiện (trung bình): {avg_ms:.0f} ms")
    try:
        stats = requests.get(f"{BASE_URL}/api/lab/alert-stats", timeout=15).json()
        print("4. Thời gian từ lúc phát hiện đến lúc gửi cảnh báo (alert_logs):")
        for s in stats:
            print(f"     - {s['delivery']:<9}: {s['n']} cảnh báo, TB {s['avg_ms']:.0f} ms, tối đa {s['max_ms']:.0f} ms")
        print("     (simulated = chưa cấu hình email/Telegram thật nên không đo được thời gian gửi thật)")
    except Exception as e:
        print(f"4. Không đọc được alert_logs: {e}")
    print("=" * 70)


if __name__ == "__main__":
    run_evaluation()
