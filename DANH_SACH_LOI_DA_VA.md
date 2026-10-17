# Danh sách lỗi đã vá so với bản gốc

## Bảo mật
| # | Lỗi trong bản gốc | Cách vá |
|---|---|---|
| 1 | `debug=True` + `host=0.0.0.0` (debugger cho phép chạy code từ xa) | Mặc định chạy `127.0.0.1`, debug chỉ bật khi `FLASK_DEBUG=1`; production dùng Gunicorn. |
| 2 | Tin `X-Forwarded-For` vô điều kiện, kẻ tấn công tự đổi IP để né chặn | Chỉ dùng `remote_addr` (qua `ProxyFix` với số proxy tin cậy). Header do client gửi chỉ được tin trong `LAB_MODE`. |
| 3 | **OTP lưu trong cookie session**: Flask chỉ *ký* cookie chứ không *mã hóa*, client đọc được OTP | OTP lưu ở server (bảng `otp_challenges`, dạng băm, dùng một lần), cookie chỉ giữ token ngẫu nhiên. |
| 4 | OTP không hết hạn, không giới hạn số lần thử (dò 1.000.000 mã), dùng `random` | `secrets`, hạn 5 phút, tối đa 5 lần thử, so sánh bằng `compare_digest`. |
| 5 | Trạng thái "yêu cầu CAPTCHA" lưu trong session, kẻ tấn công bỏ cookie là thoát; API JSON bỏ qua CAPTCHA | Cờ CAPTCHA lưu theo IP ở server (bảng `captcha_flags`); API trả `428` khi IP bị yêu cầu CAPTCHA. |
| 6 | Secret key mặc định cứng, mật khẩu DB lộ trong file `.env` gửi đi | Bắt buộc `FLASK_SECRET_KEY` từ môi trường, `.env.example` chỉ có giá trị mẫu, `.gitignore`/`.dockerignore` chặn `.env`. **Bạn cần đổi mật khẩu MySQL đã lộ.** |
| 7 | Không có CSRF, cookie thiếu cờ bảo vệ | Flask-WTF CSRF, cookie `HttpOnly`, `SameSite=Lax`, `Secure` khi HTTPS, hết hạn 30 phút, header bảo mật, logout bằng POST. |
| 8 | Lộ thông tin: JSON trả "Email không tồn tại"/"Sai mật khẩu"; cảnh báo nêu tên quy tắc phát hiện; thời gian phản hồi khác nhau giữa email có/không tồn tại | Thông báo chung; chi tiết chỉ ghi log; luôn tốn một lần băm Argon2 (băm giả khi không có user). |
| 9 | Session fixation | `session.clear()` trước khi cấp phiên. |
| 10 | Dashboard hiện log của mọi người cho bất kỳ ai đăng nhập | Người thường chỉ thấy log của mình; log toàn hệ thống, IP bị chặn, cảnh báo chỉ dành cho admin. |
| 11 | Token Telegram/khóa API có thể lọt vào log qua thông báo lỗi của `requests`; email chủ TK chèn thẳng vào HTML cảnh báo | Che bí mật trong log; `html.escape` mọi giá trị chèn vào email/Telegram. |
| 12 | `ph.verify` chỉ bắt `VerifyMismatchError` (hash hỏng làm app lỗi 500); không nâng cấp hash | Bắt thêm lỗi hash, giới hạn độ dài mật khẩu, `check_needs_rehash`. |

## Logic phát hiện
| # | Lỗi | Cách vá |
|---|---|---|
| 13 | R1 đếm cả lần đăng nhập **thành công** nên người dùng thật đăng nhập liền nhau có thể bị coi là bot | R1 chỉ xét lần thất bại. |
| 14 | R3 dùng `COALESCE(user_id, reason)` trộn số và chuỗi | Thêm cột `attempted_email`, đếm `COUNT(DISTINCT attempted_email)`. |
| 15 | Kịch bản 3 của simulator thực chất bị R1 chặn, R3 chưa từng được kiểm chứng | Tách thành 2 kịch bản: KB3 gửi chậm (>1s) để kiểm chứng đúng R3 (bị chặn ở lần thứ 20), KB5 gửi dồn dập để kiểm chứng R1. |
| 16 | Đăng nhập đúng nhưng từ IP lạ không được ghi log | Ghi log trạng thái mới `pending`, không tính vào số lần thất bại và không làm IP đó thành "quen" trước khi xác minh OTP. |
| 17 | Ngưỡng nằm rải rác trong code | Gom lên đầu `detection.py`, chỉnh bằng biến môi trường để làm phân tích ngưỡng. |

## Simulator
| # | Lỗi | Cách vá |
|---|---|---|
| 18 | "Thời gian phản ứng" tính cả các lần `sleep(1.1)` | Đo độ trễ riêng của request phát hiện bằng `perf_counter`; thêm bảng `alert_logs` đo thời gian từ lúc phát hiện đến lúc gửi xong cảnh báo (đúng định nghĩa ở mục 6.2). |
| 19 | Chạy lần 2 bị tính sai vì trạng thái khóa/chặn từ lần 1 còn nguyên | `--reset` (script `reset_lab.py`). |
| 20 | Chưa có kịch bản kiểm thử R4 | Thêm KB6 (đúng mật khẩu từ IP lạ, mong đợi `202`). |
| 21 | Simulator gọi form đăng nhập thường | Dùng `/api/login`, `/api/register` chỉ tồn tại khi `LAB_MODE=1` (trả 404 khi chạy thật). |

## Hạ tầng / triển khai
| # | Thay đổi |
|---|---|
| 22 | Mỗi truy vấn mở một kết nối MySQL mới (chậm khi DB ở cloud qua TLS) → dùng connection pool, tự kết nối lại khi DB đóng kết nối. |
| 23 | Hỗ trợ MySQL cloud (Aiven): `DB_MANAGED`, TLS, `AUTO_INIT_DB`. |
| 24 | Gmail SMTP bị Render miễn phí chặn → thêm gửi email qua Brevo HTTP API (`EMAIL_PROVIDER=brevo`). |
| 25 | Thêm `Dockerfile`, `docker-compose.yml` (private cloud), `nginx.conf` (rate limiting), `render.yaml`, `/healthz`. |
| 26 | Các template cũ không có token CSRF nên không dùng được → cung cấp bộ template mới trong `templates/`. **Hãy thay thư mục `templates` cũ bằng bản này.** |
