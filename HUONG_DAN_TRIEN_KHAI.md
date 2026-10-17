# Hướng dẫn dựng điện toán đám mây miễn phí và triển khai đề tài

Đề tài: *Hệ thống phát hiện và cảnh báo đăng nhập bất thường cho ứng dụng web trên nền tảng điện toán đám mây.*

Thầy yêu cầu trình bày theo đúng thứ tự: **(1) dựng đám mây riêng → (2) triển khai ứng dụng → (3) xác thực & băm mật khẩu → (4) định nghĩa đăng nhập bất thường → (5) phân tích kết quả.** Tài liệu này có hai cách, bạn nên làm cả hai:

| | Cách A: Private cloud trên máy bạn | Cách B: Cloud công khai miễn phí |
|---|---|---|
| Công cụ | Docker Compose (Nginx + Flask + MySQL) | GitHub + Render (app) + Aiven (MySQL) + Brevo (email) |
| Chi phí | 0đ, không cần thẻ | 0đ, thường không cần thẻ (kiểm tra lúc đăng ký) |
| Dùng để | Đúng yêu cầu "đám mây riêng" của thầy, demo chính | Đáp ứng mục tiêu "truy cập được qua Internet" trong đề tài |
| Hạn chế | Chỉ truy cập được trong máy/mạng LAN | App ngủ sau 15 phút không truy cập, mở lại mất khoảng 1 phút |

> Mình đã chạy thử bộ code này trên MariaDB 10.11 với gunicorn (simulator cho TPR 100%, FPR 0%, luồng OTP/CAPTCHA/CSRF hoạt động). Mình **chưa** chạy được Docker, Render, Aiven, Brevo thật trong môi trường của mình, nên các bước ở dưới là cấu hình chuẩn nhưng bạn cần tự kiểm tra khi làm. Giao diện các dịch vụ này đổi thường xuyên, nếu tên nút khác thì tìm mục tương đương.

---

## Cách A. Private cloud trên máy cục bộ (Docker Compose)

Kiến trúc (đây là hình để đưa vào báo cáo):

```
Trình duyệt ──8080──> [proxy: Nginx] ──mạng frontend──> [app: Flask+Gunicorn] ──mạng backend (internal)──> [db: MySQL]
                       giới hạn tốc độ                    Auth + Detection + Alerting                 volume dbdata
```

Chỉ `proxy` mở cổng ra ngoài. `db` nằm trong mạng `backend` ở chế độ `internal` nên không ai vào được từ bên ngoài.

### A1. Cài đặt
1. Cài **Docker Desktop** (Windows: bật WSL2 khi được hỏi). Kiểm tra: `docker --version` và `docker compose version`.
2. Giải nén thư mục dự án, mở terminal tại đó.
3. Tạo file cấu hình:
   - Windows: `copy .env.example .env`   |   Mac/Linux: `cp .env.example .env`
   - Mở `.env`, sửa **ít nhất 3 dòng**: `FLASK_SECRET_KEY`, `DB_ROOT_PASSWORD`, `DB_PASSWORD`.
   - Sinh khóa bí mật: `python -c "import secrets; print(secrets.token_hex(32))"`

### A2. Chạy
```bash
docker compose up -d --build
docker compose ps          # 3 dịch vụ phải ở trạng thái running/healthy
```
Mở http://localhost:8080, đăng ký tài khoản, đăng nhập. Bảng trong CSDL được app tự tạo lúc khởi động.

### A3. Bằng chứng cho báo cáo (chụp màn hình)
- `docker compose ps` và `docker network ls`: chứng minh có 3 dịch vụ, 2 mạng.
- Mật khẩu **không** lưu dạng rõ (tiêu chí "Độ an toàn của mật khẩu lưu trữ" trong mục 6.2):
  ```bash
  docker compose exec db sh -c 'mysql -uapp -p"$MYSQL_PASSWORD" security_login_db -e "SELECT email, LEFT(password_hash,60) AS hash FROM users"'
  ```
  Kết quả bắt đầu bằng `$argon2id$v=19$m=65536,t=2,p=2$...`, trong đó phần sau `p=2$` là **salt** ngẫu nhiên. Hãy đăng ký 2 tài khoản cùng một mật khẩu để cho thấy hai chuỗi băm khác nhau hoàn toàn.
- Dashboard hiển thị log, IP bị chặn, độ trễ cảnh báo.

### A4. Cấp quyền admin (để xem log toàn hệ thống)
Người dùng thường chỉ thấy log của chính mình. Đăng ký tài khoản admin trước, rồi:
```bash
docker compose exec app python make_admin.py email_cua_ban@gmail.com
```

### A5. Chạy kịch bản tấn công giả lập
```bash
# 1) Bật chế độ lab: mở .env, thêm dòng  LAB_MODE=1  rồi
docker compose up -d
# 2) Chạy simulator bên trong container app (có sẵn quyền truy cập DB để reset)
docker compose exec app python attack_simulator.py --reset
# 3) XONG PHẢI TẮT: xóa dòng LAB_MODE=1 khỏi .env rồi
docker compose up -d
```
Simulator chạy 6 kịch bản (người dùng hợp lệ, brute-force, dictionary, diện rộng, bot tốc độ cao, IP lạ) và in báo cáo TPR / FPR / độ trễ. Chạy 3 lần và lấy trung bình để số liệu đáng tin hơn.

> Lưu ý: trên Docker Desktop (Windows/Mac), mọi truy cập từ trình duyệt của bạn thường được app thấy là cùng một IP nội bộ (dạng 172.x), đây là đặc điểm của mạng ảo Docker. Vì vậy phần giả lập nhiều IP của simulator dùng `LAB_MODE`. Dashboard có dòng "IP hiện tại" để bạn kiểm tra app đang thấy IP nào.

### A6. Tắt / dọn
```bash
docker compose down          # tắt, giữ dữ liệu
docker compose down -v       # tắt và xóa luôn dữ liệu DB
```

---

## Cách B. Cloud công khai miễn phí (GitHub + Render + Aiven + Brevo)

Vì sao chọn các dịch vụ này:
- **Render** (web service miễn phí): có HTTPS sẵn, tự deploy từ GitHub. Gói miễn phí ngủ sau 15 phút không có truy cập, và có 750 giờ chạy mỗi tháng. Điểm cần nhớ: **Render miễn phí chặn cổng SMTP 25/465/587** (từ cuối tháng 9/2025), vì vậy gửi email bằng Gmail SMTP sẽ bị timeout. Code đã hỗ trợ gửi email qua **Brevo HTTP API** để tránh vấn đề này. Telegram dùng HTTPS nên không bị ảnh hưởng.
- **Aiven** (MySQL miễn phí): không cần thẻ, 1 CPU, 1 GB RAM, 1 GB đĩa, không giới hạn thời gian nhưng Aiven có thể tắt dịch vụ nếu lâu không dùng (có thông báo trước, bật lại được). Lý do không dùng PlanetScale như đề tài gợi ý: PlanetScale đã bỏ gói miễn phí.

### B1. Đưa code lên GitHub
1. Tạo repo mới trên GitHub (để Private cũng được).
2. Upload toàn bộ thư mục dự án. **Kiểm tra repo không chứa file `.env`** (`.gitignore` đã chặn sẵn).

### B2. Tạo MySQL miễn phí trên Aiven
1. Đăng ký tại aiven.io, tạo service **MySQL**, chọn gói **Free**.
2. Chờ trạng thái *Running*, mở trang service, chép lại: **Host, Port, User, Password, Database name** (thường là `avnadmin` và `defaultdb`). Cổng thường **không phải 3306**.
3. Aiven đã tạo sẵn database nên ta đặt `DB_MANAGED=1` (đã có trong `render.yaml`).

### B3. Tạo tài khoản gửi email (Brevo)
1. Đăng ký brevo.com (gói miễn phí có hạn mức email mỗi ngày, xem lại khi đăng ký).
2. Xác minh một **địa chỉ email người gửi** (Senders). Địa chỉ này là `EMAIL_SENDER`.
3. Vào mục *SMTP & API → API keys* tạo khóa, đó là `BREVO_API_KEY`.

### B4. Tạo Telegram Bot (cảnh báo cho admin)
1. Trong Telegram, chat với **@BotFather**, gõ `/newbot`, làm theo hướng dẫn, nhận **token**.
2. Mở chat với bot vừa tạo, gửi tin nhắn bất kỳ.
3. Mở trình duyệt: `https://api.telegram.org/bot<TOKEN>/getUpdates`, tìm `"chat":{"id": ...}`, số đó là `TELEGRAM_CHAT_ID`.

### B5. Triển khai lên Render
1. Đăng ký render.com bằng tài khoản GitHub.
2. **New → Blueprint**, chọn repo của bạn (Render đọc file `render.yaml`). Điền các biến được hỏi:
   `DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME` (từ Aiven), `BREVO_API_KEY, EMAIL_SENDER` (từ Brevo), `TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID`.
3. Deploy. Khi xong sẽ có địa chỉ dạng `https://anomalous-login-demo.onrender.com`.
4. Mở địa chỉ, đăng ký, đăng nhập. Sau khi đăng nhập, xem dòng **"IP hiện tại của bạn"** trên Dashboard:
   - Nếu hiện IP công cộng của bạn thì `TRUSTED_PROXY_COUNT=1` là đúng.
   - Nếu hiện một IP khác (của hạ tầng Render/CDN) thì đổi `TRUSTED_PROXY_COUNT` thành `2`, deploy lại, kiểm tra lại. Bước này quan trọng vì mọi quy tắc chặn IP dựa vào IP này; sai thì cả hệ thống sẽ coi mọi người là một IP.

### B6. Cấp quyền admin (Render miễn phí không có shell)
Chạy từ máy bạn, trỏ vào Aiven. Tạo `.env` cục bộ chỉ cần các dòng `FLASK_SECRET_KEY` (giá trị bất kỳ), `DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME`, rồi:
```bash
pip install -r requirements.txt
python make_admin.py email_cua_ban@gmail.com
```

### B7. Chạy simulator vào hệ thống trên cloud
1. Trên Render → Environment: thêm `LAB_MODE=1`, lưu (app tự khởi động lại).
2. Trên máy bạn (đã có `.env` trỏ Aiven như B6):
   ```bash
   # Windows PowerShell:  $env:BASE_URL="https://anomalous-login-demo.onrender.com"
   BASE_URL=https://anomalous-login-demo.onrender.com python attack_simulator.py --reset
   ```
3. **Xóa `LAB_MODE` trên Render ngay sau khi chạy xong.** Khi `LAB_MODE=1`, app tin header `X-Forwarded-For` do client tự gửi và mở API đăng ký/đăng nhập không có CSRF, tức là ai cũng né được chặn IP.
4. Nếu gửi email/Telegram thật thành công, bảng "Cảnh báo đã gửi" trên Dashboard (admin) sẽ hiện `sent` kèm độ trễ thật. Đây chính là số liệu cho tiêu chí "Thời gian phản ứng" (từ lúc phát hiện đến lúc gửi cảnh báo, mục tiêu < 5 giây).

### B8. Lưu ý khi dùng gói miễn phí
- Sau 15 phút không có truy cập, app ngủ, lần mở kế tiếp chờ khoảng 1 phút. Hãy mở trước buổi demo vài phút.
- Render có thể khởi động lại app bất kỳ lúc nào. Dữ liệu an toàn vì nằm ở Aiven, session do cookie ký bằng `FLASK_SECRET_KEY` nên không mất.
- Đừng để `FLASK_SECRET_KEY` đổi giữa các lần deploy (`generateValue` của Render chỉ sinh một lần).

---

## Cách C (tuỳ chọn). Máy ảo miễn phí của nhà cung cấp lớn
Đề tài có nhắc AWS EC2 Free Tier / Google Cloud Free Tier. Cách làm: tạo 1 máy ảo Ubuntu, cài Docker, rồi chạy đúng các lệnh của Cách A trên máy ảo đó (mở cổng 80/8080 trong firewall của nhà cung cấp). Đây là hướng gần mô hình IaaS nhất và không bị chặn SMTP như Render. Nhược điểm: thường yêu cầu thẻ thanh toán để đăng ký và điều khoản gói miễn phí thay đổi theo thời điểm, bạn cần đọc kỹ trang của nhà cung cấp trước khi làm.

---

## Nội dung báo cáo theo thứ tự thầy yêu cầu

1. **Private cloud**: sơ đồ Docker Compose ở trên, ảnh `docker compose ps`, giải thích 2 mạng tách biệt, DB không mở cổng, Nginx có rate limiting.
2. **Ứng dụng**: ứng dụng web có đăng ký / đăng nhập / dashboard nhật ký, mô tả vai trò user và admin.
3. **Xác thực**: Argon2id có salt (so sánh với MD5/SHA vốn là hàm băm nhanh), luồng đăng ký (băm rồi lưu) và đăng nhập (băm lại rồi so sánh, không giải mã ngược), ảnh chụp bảng `users`.
4. **Định nghĩa đăng nhập bất thường** (bảng này khớp với code, ngưỡng nằm ở đầu `detection.py` và chỉnh được bằng biến môi trường):

| Quy tắc | Định nghĩa | Ngưỡng mặc định | Phản ứng |
|---|---|---|---|
| R1 Bot | khoảng cách giữa các lần thất bại liên tiếp từ 1 IP | < 1 giây, 3 khoảng liên tiếp | chặn IP 30 phút, CAPTCHA, báo Telegram |
| R2 Brute-force / Dictionary | sai mật khẩu cùng 1 tài khoản | ≥ 5 lần / 60 giây | khóa TK 15 phút, CAPTCHA, email chủ TK + Telegram |
| R3 Diện rộng | thất bại từ 1 IP nhắm nhiều tài khoản | ≥ 20 lần / 5 phút, ≥ 2 tài khoản | chặn IP 30 phút, CAPTCHA, báo Telegram |
| R4 IP lạ | đúng mật khẩu nhưng IP chưa từng đăng nhập thành công | không có | OTP 6 số qua email (hạn 5 phút, tối đa 5 lần thử) |

5. **Phân tích**: kết quả simulator (TPR, FPR, số lần thử tới khi bị phát hiện, độ trễ), giải thích vì sao chọn từng ngưỡng (ví dụ ngưỡng 5 lần/phút cao hơn mức người thật hay gõ sai nhưng thấp hơn nhiều so với tốc độ của script), và một mục **Hạn chế** (xem dưới).

### Hạn chế nên nêu thẳng trong báo cáo
- **Khóa tài khoản có thể bị lợi dụng để từ chối dịch vụ**: kẻ xấu cố tình nhập sai để khóa nạn nhân (R2 đếm theo tài khoản, đúng theo đặc tả đề tài).
- **R4 chỉ so sánh IP**, chưa tra quốc gia/thành phố (GeoIP). Trong mạng nội bộ/Docker, IP là dải riêng nên không có ý nghĩa địa lý.
- **CAPTCHA là phép cộng đơn giản**, bot có thể giải. Hệ thống thật nên dùng reCAPTCHA/Cloudflare Turnstile.
- **Thông báo "tài khoản đang bị khóa"** cho biết tài khoản tồn tại (đây là yêu cầu của đề tài ở mục 3.3). Tương tự, form đăng ký báo "email đã đăng ký".
- Phát hiện dựa trên **luật cố định**, chưa dùng học máy; đủ cho phạm vi đồ án.
- Kịch bản 3 trong đề tài nói "nhiều IP", simulator giả lập bằng header trong `LAB_MODE` (một IP mỗi kịch bản). Muốn thử thật hơn có thể chạy simulator từ nhiều container.

---

## Xử lý sự cố thường gặp

| Hiện tượng | Nguyên nhân / cách xử lý |
|---|---|
| `KeyError: 'FLASK_SECRET_KEY'` | Chưa đặt `FLASK_SECRET_KEY` trong `.env` / biến môi trường Render. |
| App không kết nối được DB (Aiven) | Kiểm tra đúng **cổng** (không phải 3306), `DB_MANAGED=1`, `DB_NAME=defaultdb`. |
| Render: email cảnh báo không tới, log có timeout | Đang dùng `EMAIL_PROVIDER=smtp`. Đổi sang `brevo` và điền `BREVO_API_KEY`, `EMAIL_SENDER`. |
| Brevo trả lỗi 4xx | `EMAIL_SENDER` chưa được xác minh trong Brevo, hoặc API key sai. Log chỉ in mã lỗi, không in khóa. |
| Chưa có email thật nhưng cần demo OTP | Đặt `DEV_PRINT_OTP=1`, OTP sẽ in ra log của app (`docker compose logs app`). Tắt khi chạy thật. |
| Mọi người dùng bị coi là cùng một IP / bị chặn hàng loạt | `TRUSTED_PROXY_COUNT` sai, hãy xem dòng "IP hiện tại" trên Dashboard (bước B5.4). |
| Simulator báo "Không tạo được tài khoản test" | Server chưa bật `LAB_MODE=1`. |
| Chạy lại simulator thấy phát hiện ngay lần đầu | Chưa dọn trạng thái cũ, thêm `--reset`. |
| Muốn tạo lại bảng sau khi đổi schema | Đây là đồ án nên có thể `docker compose down -v` (Cách A), hoặc xóa các bảng trên Aiven rồi khởi động lại app. |
