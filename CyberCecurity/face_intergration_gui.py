# face_integration_gui.py
import os
import hashlib
import random
import psycopg2
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import re

# ====== IMPORT các module do bạn đã viết (từ file đã upload) ======
# Đăng ký khuôn mặt + chọn file/camera
from face_register_pg import get_embedding, insert_embedding, check_existing, capture_image, select_file  # :contentReference[oaicite:3]{index=3}
# Xác thực khuôn mặt
from face_verify_pg import verify_person  # :contentReference[oaicite:4]{index=4}
# Xác thực RSA certificate
from rsq_mappingid import get_clean_content, verify_signature  # :contentReference[oaicite:5]{index=5}


# ====== CẤU HÌNH CSDL (đồng bộ với các module đã có) ======
DB_CONFIG = {
    "host": "127.0.0.1",
    "user": "postgres",
    "password": "huyyuh",
    "dbname": "cyber_verify_certificate",
    "port": 5432
}


def get_conn():
    return psycopg2.connect(**DB_CONFIG)


# ====== KHỞI TẠO SCHEMA ======
DDL_STUDENTS = """
CREATE TABLE IF NOT EXISTS students (
    id SERIAL PRIMARY KEY,
    student_id TEXT UNIQUE,
    school_code TEXT,
    username TEXT UNIQUE,
    email TEXT,
    password_hash TEXT,
    face_key TEXT UNIQUE,            -- ví dụ: PKA_23010069
    public_key BYTEA,                -- PEM (nếu đã phát hành)
    advisor_teacher_id TEXT,         -- NEW: mã GV quản lý
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

DDL_TEACHERS = """
CREATE TABLE IF NOT EXISTS teachers (
    id SERIAL PRIMARY KEY,
    teacher_id TEXT UNIQUE,
    school_code TEXT,
    username TEXT UNIQUE,
    email TEXT,
    password_hash TEXT,
    public_key BYTEA,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

# NEW: Bảng certificates để lưu văn bằng + signature + liên kết identifier
DDL_CERTIFICATES = """
CREATE TABLE IF NOT EXISTS certificates (
    id SERIAL PRIMARY KEY,
    identifier TEXT UNIQUE,           -- ví dụ: PKA_23010069
    school_code TEXT,
    student_id TEXT,
    certificate_text TEXT,            -- bản gốc (hiển thị)
    cleaned_text TEXT,                -- clean để chuẩn hóa verify
    message BYTEA,                    -- bytes để ký/verify
    signature BYTEA,                  -- chữ ký số
    public_key BYTEA,                 -- PEM của người ký (nhà trường/GV)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

DDL_FACE_EMB = """
CREATE TABLE IF NOT EXISTS face_embeddings (
    id SERIAL PRIMARY KEY,
    ma_truong TEXT,
    ma_sv TEXT,
    key_id TEXT UNIQUE,
    embedding BYTEA,
    image_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""
# Index giúp search nhanh
DDL_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_face_embeddings_key ON face_embeddings(key_id);
CREATE INDEX IF NOT EXISTS idx_students_facekey ON students(face_key);
CREATE INDEX IF NOT EXISTS idx_cert_identifier ON certificates(identifier);
"""

def init_schema():
    conn = get_conn(); cur = conn.cursor()
    cur.execute(DDL_STUDENTS)
    cur.execute(DDL_TEACHERS)
    cur.execute(DDL_FACE_EMB)
    cur.execute(DDL_CERTIFICATES)   # NEW
    cur.execute(DDL_INDEXES)        # NEW
    conn.commit(); conn.close()



# ====== TIỆN ÍCH ======
def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def create_user(role: str, username: str, email: str, school_code: str, person_id: str, password_hash: str, advisor_teacher_id: str | None = None):
    conn = get_conn(); cur = conn.cursor()
    if role == "Học sinh":
        face_key = f"{school_code}_{person_id}"
        cur.execute("""
            INSERT INTO students (student_id, school_code, username, email, password_hash, face_key, advisor_teacher_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (username) DO NOTHING
            RETURNING id;
        """, (person_id, school_code, username, email, password_hash, face_key, advisor_teacher_id))
    else:
        cur.execute("""
            INSERT INTO teachers (teacher_id, school_code, username, email, password_hash)
            VALUES (%s,%s,%s,%s,%s)
            ON CONFLICT (username) DO NOTHING
            RETURNING id;
        """, (person_id, school_code, username, email, password_hash))
    row = cur.fetchone()
    conn.commit(); conn.close()
    return row is not None

def find_user(role: str, username: str):
    """Trả về (row_dict or None, table_name)"""
    conn = get_conn()
    cur = conn.cursor()
    if role == "Học sinh":
        cur.execute("SELECT id, student_id, school_code, username, email, password_hash, face_key, public_key FROM students WHERE username=%s", (username,))
        row = cur.fetchone()
        table = "students"
    else:
        cur.execute("SELECT id, teacher_id, school_code, username, email, password_hash, public_key FROM teachers WHERE username=%s", (username,))
        row = cur.fetchone()
        table = "teachers"
    conn.close()
    if not row:
        return None, table
    cols = ["id","person_id","school_code","username","email","password_hash","face_key","public_key"] if table=="students" \
        else ["id","person_id","school_code","username","email","password_hash","public_key"]
    data = dict(zip(cols, row))
    return data, table



def update_public_key(role: str, username: str, public_key_pem: bytes):
    conn = get_conn()
    cur = conn.cursor()
    if role == "Học sinh":
        cur.execute("UPDATE students SET public_key=%s WHERE username=%s", (public_key_pem, username))
    else:
        cur.execute("UPDATE teachers SET public_key=%s WHERE username=%s", (public_key_pem, username))
    conn.commit()
    conn.close()


# ====== 2FA đơn giản ======
def send_otp_simulated(email: str) -> str:
    """Demo: sinh OTP ngẫu nhiên, in ra console và trả về để so sánh."""
    otp = str(random.randint(100000, 999999))
    print(f"[2FA] Gửi OTP tới {email}: {otp}")
    return otp


def upsert_certificate(identifier: str, school_code: str, student_id: str,
                       certificate_text: str, cleaned_text: str, message_bytes: bytes,
                       signature: bytes, public_key_pem: bytes):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO certificates (identifier, school_code, student_id, certificate_text, cleaned_text, message, signature, public_key)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (identifier) DO UPDATE SET
            certificate_text=EXCLUDED.certificate_text,
            cleaned_text=EXCLUDED.cleaned_text,
            message=EXCLUDED.message,
            signature=EXCLUDED.signature,
            public_key=EXCLUDED.public_key,
            created_at=CURRENT_TIMESTAMP;
    """, (identifier, school_code, student_id, certificate_text, cleaned_text, message_bytes, signature, public_key_pem))
    conn.commit(); conn.close()

def delete_certificate(identifier: str):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM certificates WHERE identifier=%s", (identifier,))
    conn.commit(); conn.close()

def search_certificates(keyword: str):
    kw = f"%{keyword}%"
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
        SELECT identifier, school_code, student_id, LEFT(certificate_text,120)
        FROM certificates
        WHERE identifier ILIKE %s OR student_id ILIKE %s OR school_code ILIKE %s OR certificate_text ILIKE %s
        ORDER BY created_at DESC
        LIMIT 200
    """, (kw, kw, kw, kw))
    rows = cur.fetchall()
    conn.close()
    return rows







# ====================================================================================================================================

# ====== GIAO DIỆN ======
LARGE_FONT = ("Verdana", 16, "bold")
NORMAL_FONT = ("Verdana", 11)
PRIMARY_COLOR = "#f7f7f7"

class ManagementApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Phần Mềm Quản Lý Tài Liệu Số")
        self.geometry("900x650")
        init_schema()

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (StartPage, VerificationPage, LoginPage, RegisterPage,
                  StudentDashboard, TeacherDashboard, TeacherActionsPage,
                  ChangePasswordPage, FaceModifyPage):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(StartPage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()


# ========== Các Page ==========
class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=PRIMARY_COLOR)
        self.controller = controller
        ttk.Label(self, text="Chào mừng đến với hệ thống", font=LARGE_FONT).pack(pady=40)

        ttk.Button(self, text="Xác minh Tài liệu",
                   command=lambda: controller.show_frame(VerificationPage)).pack(pady=10, ipady=5, ipadx=10)
        ttk.Button(self, text="Đăng nhập / Đăng ký",
                   command=lambda: controller.show_frame(LoginPage)).pack(pady=10, ipady=5, ipadx=10)


class VerificationPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=PRIMARY_COLOR)
        self.controller = controller
        ttk.Label(self, text="Tra cứu tài liệu bằng Public Key", font=LARGE_FONT).pack(pady=20)

        in_frame = ttk.Frame(self); in_frame.pack(pady=10, padx=20, fill="x")
        # ttk.Label(in_frame, text="Nhập Public Key:", font=NORMAL_FONT).pack(side="left", padx=5)
        # self.pkey_entry = ttk.Entry(in_frame, font=NORMAL_FONT, width=40)
        # self.pkey_entry.pack(side="left", expand=True, fill="x")

        ttk.Button(self, text="Tra cứu", command=self.search_document).pack(pady=10)

        up_frame = ttk.Frame(self); up_frame.pack(pady=20, padx=20, fill="x")
        ttk.Label(up_frame, text="Chọn file cần xác thực:", font=NORMAL_FONT).pack(side="left", padx=5)
        ttk.Button(up_frame, text="Tải file từ máy", command=self.upload_file).pack(side="left", padx=10)
        id_frame = ttk.Frame(self);
        id_frame.pack(pady=10, padx=20, fill="x")
        ttk.Label(id_frame, text="Nhập Identifier :", font=NORMAL_FONT) \
            .pack(side="left", padx=5)
        self.identifier_entry = ttk.Entry(id_frame, font=NORMAL_FONT, width=40)
        self.identifier_entry.pack(side="left", expand=True, fill="x")

        self.selected_file_label = ttk.Label(self, text="Chưa chọn file nào", font=("Arial", 10, "italic"))
        self.selected_file_label.pack(pady=5)

        ttk.Button(self, text="Quay lại",
                   command=lambda: controller.show_frame(StartPage)).pack(pady=20)

        self.selected_file = None

    def upload_file(self):
        filetypes = [("Tất cả", "*.*"), ("PDF", "*.pdf"), ("Word", "*.docx"), ("Text", "*.txt")]
        path = filedialog.askopenfilename(title="Chọn file từ máy tính", filetypes=filetypes)
        if path:
            self.selected_file = path
            self.selected_file_label.config(text=f"Đã chọn: {os.path.basename(path)}")
        else:
            self.selected_file = None
            self.selected_file_label.config(text="Chưa chọn file nào")

    def search_document(self):
        identifier = self.identifier_entry.get().strip()
        if not identifier:
            messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập Identifier.")
            return
        if not self.selected_file:
            messagebox.showwarning("Thiếu file", "Vui lòng chọn một file để xác thực.")
            return

        try:
            cleaned_text, message = get_clean_content(self.selected_file)  # rsq_mappingid
            # Lấy public_key & signature từ DB theo identifier
            conn = get_conn();
            cur = conn.cursor()
            cur.execute("SELECT public_key, signature FROM certificates WHERE identifier=%s", (identifier,))
            row = cur.fetchone();
            conn.close()
            if not row:
                messagebox.showerror("Không có dữ liệu", "Chưa phát hành certificate cho Identifier này.")
                return
            public_key_pem, signature = row
            ok = verify_signature(public_key_pem, signature, message)
            if ok:
                messagebox.showinfo("✅ Hợp lệ", "Chứng chỉ hợp lệ, nội dung đúng với chữ ký.")
            else:
                messagebox.showerror("❌ Sai", "File hoặc chữ ký không hợp lệ.")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi xác thực: {str(e)}")


class LoginPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=PRIMARY_COLOR)
        self.controller = controller
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)

        ttk.Label(self, text="Đăng nhập hệ thống", font=LARGE_FONT).grid(row=0, column=0, columnspan=3, pady=20)

        ttk.Label(self, text="Bạn là:", font=NORMAL_FONT).grid(row=1, column=0, padx=20, pady=5, sticky="e")
        self.role_var = tk.StringVar(value="Học sinh")
        role_cbx = ttk.Combobox(self, textvariable=self.role_var, state="readonly", font=NORMAL_FONT)
        role_cbx["values"] = ("Học sinh", "Giáo viên/Nhà trường")
        role_cbx.grid(row=1, column=1, columnspan=2, padx=20, pady=5, sticky="we")

        ttk.Label(self, text="Tên đăng nhập:", font=NORMAL_FONT).grid(row=2, column=0, padx=20, pady=5, sticky="e")
        self.user_entry = ttk.Entry(self, font=NORMAL_FONT); self.user_entry.grid(row=2, column=1, columnspan=2, padx=20, pady=5, sticky="we")

        ttk.Label(self, text="Mật khẩu:", font=NORMAL_FONT).grid(row=3, column=0, padx=20, pady=5, sticky="e")
        self.pass_entry = ttk.Entry(self, show="*", font=NORMAL_FONT); self.pass_entry.grid(row=3, column=1, columnspan=2, padx=20, pady=5, sticky="we")

        btnf = ttk.Frame(self); btnf.grid(row=4, column=0, columnspan=3, pady=20)
        ttk.Button(btnf, text="Đăng nhập", command=self.handle_login).pack(side="left", padx=10, ipady=4)
        ttk.Button(btnf, text="Đăng ký", command=lambda: controller.show_frame(RegisterPage)).pack(side="left", padx=10, ipady=4)
        ttk.Button(self, text="Quay lại", command=lambda: controller.show_frame(StartPage)).grid(row=5, column=0, columnspan=3, pady=10)

    def handle_login(self):
        username = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()
        role = self.role_var.get()

        user, table = find_user(role, username)
        if not user:
            messagebox.showerror("Sai thông tin", "Tài khoản không tồn tại.")
            return

        if sha256(password) != user["password_hash"]:
            messagebox.showerror("Sai thông tin", "Mật khẩu không đúng.")
            return

        # Đề nghị xác thực khuôn mặt
        use_face = messagebox.askyesno("Xác thực khuôn mặt", "Bạn có muốn đăng nhập bằng khuôn mặt?")
        if use_face:
            # Chụp ảnh nhanh, xác thực qua verify_person (DeepFace):contentReference[oaicite:8]{index=8}
            img_path = capture_image()  # dùng lại tiện ích từ face_register_pg:contentReference[oaicite:9]{index=9}
            if img_path:
                matched, dist = verify_person(img_path, threshold=10)  # :contentReference[oaicite:10]{index=10}
                # Nếu là học sinh thì matched nên bằng face_key
                if matched and (role != "Học sinh" or matched == user.get("face_key")):
                    messagebox.showinfo("Thành công", f"Đăng nhập bằng khuôn mặt thành công ({matched})")
                    self._go_dashboard(role)
                    return
                else:
                    messagebox.showwarning("Không khớp", "Không nhận diện được khuôn mặt của bạn.")

        # Fallback 2FA
        go_2fa = messagebox.askyesno("2FA", "Dùng xác thực 2 bước (OTP) thay thế?")
        if go_2fa:
            otp = send_otp_simulated(user["email"])
            code = simpledialog.askstring("Nhập OTP", "Nhập mã OTP đã gửi tới email:")
            if code and code.strip() == otp:
                messagebox.showinfo("Thành công", "Đăng nhập bằng 2FA thành công.")
                self._go_dashboard(role)
                return
            else:
                messagebox.showerror("Thất bại", "OTP không đúng.")
        else:
            messagebox.showinfo("Hủy", "Bạn đã hủy đăng nhập.")

    def _go_dashboard(self, role):
        if role == "Học sinh":
            self.controller.show_frame(StudentDashboard)
        else:
            self.controller.show_frame(TeacherDashboard)


class RegisterPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=PRIMARY_COLOR)
        self.controller = controller
        self.columnconfigure(0, weight=1); self.columnconfigure(1, weight=2)

        ttk.Label(self, text="Đăng ký tài khoản mới", font=LARGE_FONT).grid(row=0, column=0, columnspan=2, pady=20)

        fields = ["Đối tượng đăng ký:", "Tên đăng nhập:", "Email:", "Mã trường:", "Mã SV/GV:", "Mật khẩu:", "Nhập lại mật khẩu:"]
        for i, f in enumerate(fields):
            ttk.Label(self, text=f, font=NORMAL_FONT).grid(row=i+1, column=0, padx=10, pady=5, sticky="e")

        self.role_var = tk.StringVar(value="Học sinh")
        role_cbx = ttk.Combobox(self, textvariable=self.role_var, state="readonly", font=NORMAL_FONT)
        role_cbx["values"] = ("Học sinh", "Giáo viên/Nhà trường")
        role_cbx.grid(row=1, column=1, padx=10, pady=5, sticky="we")

        self.entry_username = ttk.Entry(self, font=NORMAL_FONT); self.entry_username.grid(row=2, column=1, padx=10, pady=5, sticky="we")
        self.entry_email = ttk.Entry(self, font=NORMAL_FONT); self.entry_email.grid(row=3, column=1, padx=10, pady=5, sticky="we")
        self.entry_school_id = ttk.Entry(self, font=NORMAL_FONT); self.entry_school_id.grid(row=4, column=1, padx=10, pady=5, sticky="we")
        self.entry_person_id = ttk.Entry(self, font=NORMAL_FONT); self.entry_person_id.grid(row=5, column=1, padx=10, pady=5, sticky="we")
        self.entry_pass1 = ttk.Entry(self, show="*", font=NORMAL_FONT); self.entry_pass1.grid(row=6, column=1, padx=10, pady=5, sticky="we")
        self.entry_pass2 = ttk.Entry(self, show="*", font=NORMAL_FONT); self.entry_pass2.grid(row=7, column=1, padx=10, pady=5, sticky="we")

        ttk.Label(self, text="Mã Giáo viên:", font=NORMAL_FONT).grid(row=8, column=0, padx=10, pady=5, sticky="e")
        self.entry_teacher_id = ttk.Entry(self, font=NORMAL_FONT)
        self.entry_teacher_id.grid(row=8, column=1, padx=10, pady=5, sticky="we")

        ttk.Button(self, text="Đăng ký khuôn mặt", command=self.register_face).grid(row=9, column=0, columnspan=2,  pady=10)
        ttk.Button(self, text="Hoàn tất Đăng ký", command=self.handle_register).grid(row=10, column=0, columnspan=2, pady=5)
        ttk.Button(self, text="Quay lại Đăng nhập", command=lambda: controller.show_frame(LoginPage)).grid(row=11, column=0, columnspan=2, pady=15)

    def register_face(self):
        role = self.role_var.get()
        school_code = self.entry_school_id.get().strip()
        person_id = self.entry_person_id.get().strip()
        if not school_code or not person_id:
            messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập Mã Trường và Mã SV/GV trước.")
            return
        key_id = f"{school_code}_{person_id}"

        if check_existing(key_id):  # :contentReference[oaicite:11]{index=11}
            if not messagebox.askyesno("Đã tồn tại", f"Khuôn mặt {key_id} đã đăng ký. Cập nhật lại?"):
                return

        # Cho phép chọn camera hay file
        if messagebox.askyesno("Nguồn ảnh", "Chụp bằng camera? (No = chọn file)"):
            img_path = capture_image()  # :contentReference[oaicite:12]{index=12}
        else:
            img_path = select_file()    # :contentReference[oaicite:13]{index=13}

        if not img_path:
            messagebox.showwarning("Không có ảnh", "Bạn chưa cung cấp ảnh.")
            return

        emb = get_embedding(img_path)   # :contentReference[oaicite:14]{index=14}
        if emb is None:
            messagebox.showerror("Thất bại", "Không thể trích xuất embedding từ ảnh.")
            return

        # Lưu embedding vào bảng face_embeddings
        insert_embedding(school_code, person_id, key_id, emb, img_path)  # :contentReference[oaicite:15]{index=15}
        messagebox.showinfo("Thành công", f"Đã lưu/cập nhật khuôn mặt: {key_id}")

    def handle_register(self):
        role = self.role_var.get()
        username = self.entry_username.get().strip()
        email = self.entry_email.get().strip()
        if not EMAIL_RE.match(email):
            messagebox.showwarning("Email sai định dạng", "Vui lòng nhập email hợp lệ (vd: name@gmail.com).")
            return
        school_code = self.entry_school_id.get().strip()
        person_id = self.entry_person_id.get().strip()
        p1 = self.entry_pass1.get().strip()
        p2 = self.entry_pass2.get().strip()
        if not all([username, email, school_code, person_id, p1, p2]):
            messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập đầy đủ thông tin.")
            return
        if p1 != p2:
            messagebox.showwarning("Sai khớp", "Mật khẩu nhập lại không trùng khớp.")
            return

        # 0) username chưa tồn tại
        user, _ = find_user(role, username)
        if user:
            messagebox.showwarning("Tồn tại", "Tên đăng nhập đã tồn tại.")
            return

        advisor_teacher_id = self.entry_teacher_id.get().strip()

        # === CHỈ khi là Học sinh mới bắt buộc ràng buộc GV + Face Key ===
        if role == "Học sinh":
            if not advisor_teacher_id:
                messagebox.showwarning("Thiếu GV", "Học sinh phải chọn Mã Giáo viên quản lý.")
                return

            # 1) Check GV tồn tại
            conn = get_conn();
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM teachers WHERE teacher_id=%s", (advisor_teacher_id,))
            if cur.fetchone() is None:
                conn.close()
                messagebox.showerror("Sai Mã GV", "Mã Giáo viên không tồn tại.")
                return

            # 2) Check face key_id đã có
            key_id = f"{school_code}_{person_id}"
            cur.execute("SELECT 1 FROM face_embeddings WHERE key_id=%s", (key_id,))
            if cur.fetchone() is None:
                conn.close()
                messagebox.showerror("Chưa có khuôn mặt", "Vui lòng đăng ký khuôn mặt trước (face key chưa tồn tại).")
                return
            conn.close()

        # 3) TẤT CẢ điều kiện OK -> mới tạo user
        ok = create_user(role, username, email, school_code, person_id, sha256(p1), advisor_teacher_id)
        if not ok:
            messagebox.showerror("Thất bại", "Tên đăng nhập đã tồn tại — không tạo được tài khoản.")
            return

        messagebox.showinfo("Thành công", "Tạo tài khoản thành công.")


class StudentDashboard(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=PRIMARY_COLOR)
        ttk.Label(self, text="Giao diện Học sinh", font=LARGE_FONT).pack(pady=20)
        ttk.Label(self, text="(Hiển thị các chức năng dành cho Học sinh)", font=NORMAL_FONT).pack(pady=10)
        ttk.Button(self, text="Đăng xuất", command=lambda: controller.show_frame(StartPage)).pack(pady=20)

        ttk.Button(self, text="Xem văn bằng của tôi", command=self.view_my_certificate).pack(pady=10)
        self.info = tk.Text(self, height=15, width=90)
        self.info.pack(pady=10)

    def view_my_certificate(self):
        # Hỏi username (demo) hoặc lấy từ session (tuỳ bạn có lưu state đăng nhập không)
        username = simpledialog.askstring("Bạn là ai?", "Nhập username đã đăng ký:")
        if not username:
            return

        # Tìm student
        conn = get_conn();
        cur = conn.cursor()
        cur.execute("SELECT student_id, school_code FROM students WHERE username=%s", (username,))
        row = cur.fetchone()
        if not row:
            conn.close()
            messagebox.showerror("Không thấy", "Không tìm thấy học sinh.")
            return
        student_id, school_code = row
        identifier = f"{school_code}_{student_id}"

        # Lấy certificate + khóa/ chữ ký
        cur.execute("""
                    SELECT certificate_text, public_key, signature
                    FROM certificates
                    WHERE identifier = %s
                    """, (identifier,))
        row2 = cur.fetchone()
        conn.close()

        self.info.delete("1.0", "end")

        if not row2:
            self.info.insert("end", f"Chưa có certificate cho {identifier}\n")
            return

        cert_text, pkey, sig = row2

        # Chuyển memoryview -> bytes (nếu cần)
        def to_bytes(x):
            if x is None:
                return None
            return bytes(x) if isinstance(x, memoryview) else x

        pkey_b = to_bytes(pkey)
        sig_b = to_bytes(sig)

        # Rút gọn hiển thị
        pem_preview = (pkey_b.decode("utf-8", errors="ignore")[:200] + "...") if pkey_b else "(chưa có public key)"
        sig_preview = (sig_b.hex()[:64] + "...") if sig_b else "(chưa có signature)"
        cert_text_safe = cert_text or "(chưa có certificate_text)"

        # Hiển thị đầy đủ: identifier + public key + signature + certificate text
        self.info.insert("end", f"Identifier: {identifier}\n")
        self.info.insert("end", f"Public key (PEM - rút gọn):\n{pem_preview}\n\n")
        self.info.insert("end", f"Signature (hex - rút gọn): {sig_preview}\n\n")
        self.info.insert("end", "Certificate:\n")
        self.info.insert("end", cert_text_safe)

class TeacherDashboard(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=PRIMARY_COLOR)
        ttk.Label(self, text="Giao diện Giáo viên / Nhà trường", font=LARGE_FONT).pack(pady=20)
        ttk.Label(self, text="Chọn chức năng:", font=NORMAL_FONT).pack(pady=10)
        ttk.Button(self, text="Quản lý Tài liệu & Cài đặt", command=lambda: controller.show_frame(TeacherActionsPage)).pack(pady=10, ipady=5, ipadx=10)
        ttk.Button(self, text="Đăng xuất", command=lambda: controller.show_frame(StartPage)).pack(pady=20)


class TeacherActionsPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=PRIMARY_COLOR)
        self.controller = controller
        self.columnconfigure(0, weight=1); self.columnconfigure(1, weight=3)
        self.rowconfigure(1, weight=1)

        ttk.Label(self, text="Chức năng Quản lý Tài liệu & Cài đặt", font=LARGE_FONT).grid(row=0, column=0, columnspan=2, pady=20)

        left = ttk.Frame(self, padding="10"); left.grid(row=1, column=0, padx=10, pady=10, sticky="nsw")
        ttk.Button(left, text="Thêm Tài liệu", command=lambda: self._msg("Thêm Tài liệu")).pack(pady=5, fill="x")
        ttk.Button(left, text="Xóa Tài liệu", command=lambda: self._msg("Xóa Tài liệu")).pack(pady=5, fill="x")
        ttk.Button(left, text="Chỉnh sửa Tài liệu", command=lambda: self._msg("Chỉnh sửa Tài liệu")).pack(pady=5, fill="x")
        ttk.Separator(left, orient="horizontal").pack(fill="x", pady=10)
        ttk.Button(left, text="Đổi Mật khẩu", command=lambda: controller.show_frame(ChangePasswordPage)).pack(pady=5, fill="x")
        ttk.Button(left, text="Face Modify", command=lambda: controller.show_frame(FaceModifyPage)).pack(pady=5, fill="x")
        ttk.Separator(left, orient="horizontal").pack(fill="x", pady=10)
        ttk.Button(left, text="Quay lại", command=lambda: controller.show_frame(TeacherDashboard)).pack(pady=10, fill="x")

        right = ttk.Frame(self, relief=tk.GROOVE, borderwidth=2); right.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")
        right.columnconfigure(0, weight=1); right.rowconfigure(2, weight=1)

        top = ttk.Frame(right, padding="5"); top.grid(row=0, column=0, sticky="ew"); top.columnconfigure(1, weight=1)
        ttk.Label(top, text="Tìm kiếm Tài liệu/Sinh viên:", font=NORMAL_FONT).grid(row=0, column=0, padx=(0,5), pady=5, sticky="w")
        self.search_entry = ttk.Entry(top, font=NORMAL_FONT); self.search_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(top, text="Tìm", command=lambda: self._msg(f"Tìm: {self.search_entry.get()}")).grid(row=0, column=2, padx=(5,0), pady=5)

        sort = ttk.Frame(right, padding="5"); sort.grid(row=1, column=0, sticky="ew")
        ttk.Label(sort, text="Sắp xếp theo:", font=NORMAL_FONT).pack(side="left", padx=(0,5))
        self.sort_var = tk.StringVar(value="Mã sinh viên")
        cbx = ttk.Combobox(sort, textvariable=self.sort_var, state="readonly", font=NORMAL_FONT, width=15)
        cbx["values"] = ("Mã sinh viên", "Tên sinh viên", "Ngày cấp", "Loại tài liệu")
        cbx.pack(side="left", padx=5)
        ttk.Button(sort, text="Áp dụng Sắp xếp", command=lambda: self._msg(f"Sắp xếp: {self.sort_var.get()}")).pack(side="left", padx=5)

        disp = ttk.Frame(right, relief=tk.FLAT, padding="10"); disp.grid(row=2, column=0, sticky="nsew", padx=10, pady=10)
        disp.columnconfigure(0, weight=1); disp.rowconfigure(0, weight=1)
        ttk.Label(disp, text="KẾT QUẢ QUẢN LÝ TÀI LIỆU SỐ\n(Danh sách hiển thị/Data Grid ở đây)", font=NORMAL_FONT,
                  anchor="center", justify=tk.CENTER).grid(row=0, column=0, sticky="nsew")

        # ... giữ nguyên top (search) ...
        self.tree = ttk.Treeview(right, columns=("identifier", "school", "student", "preview"), show="headings")
        for c, w in [("identifier", 180), ("school", 100), ("student", 120), ("preview", 400)]:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        self.tree.grid(row=2, column=0, sticky="nsew", padx=10, pady=10)

        btnbar = ttk.Frame(right);
        btnbar.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))
        ttk.Button(btnbar, text="Thêm/ Cập nhật chứng chỉ", command=self.add_or_update_certificate).pack(side="left",
                                                                                                         padx=5)
        ttk.Button(btnbar, text="Xóa chứng chỉ", command=self.delete_selected_certificate).pack(side="left", padx=5)
        ttk.Button(btnbar, text="Tải danh sách", command=self.reload_table).pack(side="left", padx=5)

        # Sự kiện search
        def do_search():
            kw = self.search_entry.get().strip()
            self.reload_table(kw)

        ttk.Button(top, text="Tìm", command=do_search).grid(row=0, column=2, padx=(5, 0), pady=5)

    def reload_table(self, keyword: str = ""):
        for i in self.tree.get_children():
            self.tree.delete(i)
        rows = search_certificates(keyword)
        for (iden, sch, st, pv) in rows:
            self.tree.insert("", "end", values=(iden, sch, st, pv))

    def delete_selected_certificate(self):
        item = self.tree.selection()
        if not item:
            messagebox.showwarning("Chọn dòng", "Hãy chọn một chứng chỉ để xóa.")
            return
        identifier = self.tree.item(item[0])["values"][0]
        if messagebox.askyesno("Xác nhận", f"Xóa chứng chỉ {identifier}?"):
            delete_certificate(identifier)
            self.reload_table()

    def add_or_update_certificate(self):
        # Hộp thoại giản lược: nhập school_code, student_id, chọn file văn bằng
        school_code = simpledialog.askstring("Mã trường", "Nhập mã trường:")
        student_id = simpledialog.askstring("Mã SV", "Nhập mã sinh viên:")
        if not school_code or not student_id:
            return
        identifier = f"{school_code}_{student_id}"

        # Chọn file văn bằng (txt/pdf/docx). Demo: ưu tiên .txt cho đơn giản
        path = filedialog.askopenfilename(title="Chọn file văn bằng (ưu tiên .txt)",
                                          filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if not path:
            return

        # Lấy nội dung sạch & message theo rsq_mappingid
        cleaned_text, message = get_clean_content(path)  # từ rsq_mappingid.py
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            certificate_text = f.read()

        # Tạo/có public key của Nhà trường/GV ký (demo: ký theo identifier)
        # - Private key lưu local, public key lưu DB
        # Nếu chưa có private, generate:
        try:
            # generate nếu chưa có, trả về (identifier, pem)
            from rsq_mappingid import generate_keys, sign_message
            _, pem_public = generate_keys(school_code, student_id)  # private lưu ./keys
        except Exception:
            # nếu đã có khóa thì chỉ cần đọc public == sẽ ký phía dưới
            from rsq_mappingid import sign_message
            with open(os.path.join("keys", f"{identifier}_private.pem"), "rb") as _:
                pass
            # Lấy public_key hiện có từ teachers (ưu tiên) hay students
            conn = get_conn();
            cur = conn.cursor()
            cur.execute("SELECT public_key FROM teachers WHERE teacher_id=%s", (school_code,))  # tuỳ chính sách
            row = cur.fetchone()
            if row and row[0]:
                pem_public = row[0]
            else:
                # fallback: không có — có thể lấy từ students hoặc generate lại
                from rsq_mappingid import generate_keys as gen2
                _, pem_public = gen2(school_code, student_id)
            conn.close()

        # Ký digital
        signature = sign_message(identifier, message)

        # Lưu certificates
        upsert_certificate(identifier, school_code, student_id, certificate_text, cleaned_text, message, signature,
                           pem_public)
        messagebox.showinfo("OK", f"Đã phát hành/ cập nhật certificate cho {identifier}")
        self.reload_table()

    def _msg(self, text):
        messagebox.showinfo("Thông báo", f"Chức năng '{text}' đang được phát triển.")


class ChangePasswordPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=PRIMARY_COLOR)
        self.controller = controller
        self.columnconfigure(0, weight=1); self.columnconfigure(1, weight=2)
        ttk.Label(self, text="Đổi Mật khẩu", font=LARGE_FONT).grid(row=0, column=0, columnspan=2, pady=20)

        ttk.Label(self, text="Mật khẩu cũ:", font=NORMAL_FONT).grid(row=1, column=0, padx=20, pady=5, sticky="e")
        self.old_pass = ttk.Entry(self, show="*", font=NORMAL_FONT); self.old_pass.grid(row=1, column=1, padx=20, pady=5, sticky="we")

        ttk.Label(self, text="Mật khẩu mới:", font=NORMAL_FONT).grid(row=2, column=0, padx=20, pady=5, sticky="e")
        self.new_pass = ttk.Entry(self, show="*", font=NORMAL_FONT); self.new_pass.grid(row=2, column=1, padx=20, pady=5, sticky="we")

        ttk.Label(self, text="Nhập lại Mật khẩu mới:", font=NORMAL_FONT).grid(row=3, column=0, padx=20, pady=5, sticky="e")
        self.new_pass2 = ttk.Entry(self, show="*", font=NORMAL_FONT); self.new_pass2.grid(row=3, column=1, padx=20, pady=5, sticky="we")

        ttk.Button(self, text="Xác nhận Đổi Mật khẩu", command=self.handle_change_password).grid(row=4, column=0, columnspan=2, pady=20)
        ttk.Button(self, text="Quay lại", command=lambda: controller.show_frame(TeacherActionsPage)).grid(row=5, column=0, columnspan=2, pady=10)

    def handle_change_password(self):
        # TODO: kết nối DB, xác minh user hiện tại rồi update
        messagebox.showinfo("Thông báo", "Yêu cầu đổi mật khẩu đã được gửi (demo).")


class FaceModifyPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=PRIMARY_COLOR)
        ttk.Label(self, text="Face Modify (Đang phát triển)", font=LARGE_FONT).pack(pady=20)
        ttk.Label(self, text="Cập nhật / Xóa / Đăng ký lại khuôn mặt sẽ được thêm tại đây.", font=NORMAL_FONT, wraplength=500).pack(pady=10)
        ttk.Button(self, text="Quay lại", command=lambda: controller.show_frame(TeacherActionsPage)).pack(pady=20)


if __name__ == "__main__":
    app = ManagementApp()
    app.mainloop()
