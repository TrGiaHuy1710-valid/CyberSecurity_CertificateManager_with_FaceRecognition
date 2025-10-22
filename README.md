# CyberSecurity_AccountsManager_with_FaceRecognition
Cyber Security project using Face Recognition manage own user accounts

# CyberCecurity – Face Auth + Certificate Issuance & Verification (PostgreSQL + Tkinter)

> Ứng dụng desktop (Tkinter) cho đăng ký/nhận diện khuôn mặt, quản lý tài khoản sinh viên ràng buộc giáo viên, phát hành văn bằng số (certificate) kèm chữ ký số RSA, và tra cứu xác thực công khai **không cần đăng nhập**.

---

## Mục lục
- [Tổng quan](#tổng-quan)
- [Tính năng chính](#tính-năng-chính)
- [Kiến trúc & Luồng xử lý](#kiến-trúc--luồng-xử-lý)
- [Cấu trúc thư mục](#cấu-trúc-thư-mục)
- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Cấu hình CSDL](#cấu-hình-csdl)
- [Cài đặt & Chạy nhanh](#cài-đặt--chạy-nhanh)
- [Quy trình nghiệp vụ](#quy-trình-nghiệp-vụ)
- [Mô hình dữ liệu (phác thảo)](#mô-hình-dữ-liệu-phác-thảo)
- [Bảo mật & Tối ưu](#bảo-mật--tối-ưu)
- [Gỡ lỗi thường gặp](#gỡ-lỗi-thường-gặp)
- [Lộ trình mở rộng](#lộ-trình-mở-rộng)
- [Giấy phép](#giấy-phép)

---

## Tổng quan
**CyberCecurity** kết hợp:
- Đăng ký & xác minh khuôn mặt, lưu **face embeddings** vào PostgreSQL.
- Đăng ký tài khoản **Student** có ràng buộc **Teacher**:
  - Chỉ cho phép tạo khi **teacher_id tồn tại** và **face key** đã có trong `face_embeddings`.
- Phát hành **certificate** bằng chữ ký số **RSA**:
  - **Private key** lưu cục bộ trong thư mục `keys/` (không lưu DB).
  - **Public key** + **signature** + **message** (từ **cleaned text**) lưu vào DB, gắn với **identifier = school_code_student_id**.
- Trang **tra cứu công khai**: nhập `identifier` + tải file certificate → hệ thống tự lấy `public_key` & `signature` từ DB để verify **đúng/giả**.

---

## Tính năng chính
- **Face Register/Verify**: script CLI + hooks GUI.
- **User Management (GUI)**:
  - **Teacher**: CRUD certificates, search theo tên/MSSV, hiển thị bảng (Treeview).
  - **Student**: xem `certificate_text`, `identifier`, public key (rút gọn), signature (rút gọn).
- **RSA (rsq_mappingid.py)**:
  - Sinh/đọc khóa RSA; private key cất trong `keys/`.
  - Sinh `message` từ `certificate_text` đã **clean** và ký số.
- **Public Verification**:
  - Nhập **identifier** + upload file văn bằng để kiểm chứng chữ ký (✅/❌).

---

## Kiến trúc & Luồng xử lý
1. **Đăng ký khuôn mặt** → tạo `face_embeddings` với `key_id = {school_code}_{student_id}`.
2. **Đăng ký Student**:
   - Nhập `teacher_id` → **check** tồn tại.
   - **check** `face_embeddings.key_id` tồn tại.
   - **check** `username` chưa tồn tại.
   - **OK** → `INSERT` vào `students` với `face_key = identifier`.
3. **Teacher phát hành certificate**:
   - Chọn file văn bằng → **clean text** → sinh **message**.
   - RSA ký số bằng **private key** (trong `keys/`) → lưu `public_key`, `signature`, `message`, `cleaned_text`, `certificate_text` vào `certificates`.
4. **Student xem certificate**:
   - Lấy theo `identifier` → hiển thị `identifier` + public key/ signature rút gọn + `certificate_text`.
5. **Tra cứu công khai**:
   - Nhập `identifier` + upload file → verify với `public_key`/`signature` trong DB.

---

## Cấu trúc thư mục
CyberCecurity/
├─ keys/ # Lưu PRIVATE KEY (*.pem) – KHÔNG commit
├─ test_image/ # Ảnh mẫu
├─ face_embeddings.pkl # Cache embeddings (tuỳ chọn)
├─ face_intergration_gui.py # Ứng dụng Tkinter (GUI chính)
├─ face_register_pg.py # Đăng ký khuôn mặt (tạo embeddings → DB)
├─ face_verify_pg.py # Xác minh khuôn mặt (so khớp embeddings)
└─ rsq_mappingid.py # RSA keygen/sign/verify + clean message


> ⚠️ **Bảo mật**: Thư mục `keys/` chứa private keys, tuyệt đối **không commit** lên Git.

---

## Yêu cầu hệ thống
- **Python** 3.10+
- **PostgreSQL** 14+ (khuyến nghị 15/16)
- Thư viện Python:
  - Bắt buộc: `psycopg2-binary`, `cryptography`, `numpy`, `opencv-python`, `pillow`, `tkinter` (mặc định sẵn trên Windows Store Python).
  - Tuỳ chọn: `deepface` (nếu dùng pipeline của bạn).

---

## Cấu hình CSDL
Cấu hình trong mã (ví dụ `face_intergration_gui.py`):
```python
DB_CONFIG = {
  "host": "127.0.0.1",
  "user": "postgres",
  "password": "your_password",
  "dbname": "cybercecurity"
}

