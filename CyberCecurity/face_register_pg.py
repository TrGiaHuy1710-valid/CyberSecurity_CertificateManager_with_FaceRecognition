import os
import pickle
import psycopg2
import numpy as np
import cv2
from deepface import DeepFace
import tkinter as tk
from tkinter import filedialog, Tk, messagebox
import threading
import traceback
import os

# ================= DATABASE CONFIG =================
DB_CONFIG = {
    "host": "127.0.0.1",
    "user": "postgres",
    "password": "huyyuh",   # đổi theo PostgreSQL của bạn
    "dbname": "cyber_verify_certificate",
    "port": 5432
}

def get_conn():
    return psycopg2.connect(**DB_CONFIG)

# ================= EMBEDDING FUNCTIONS =================
def get_embedding(image_path):
    try:
        rep = DeepFace.represent(img_path=image_path, model_name="Facenet", enforce_detection=False)
        return np.array(rep[0]['embedding'])
    except Exception as e:
        print(f"[❌] Không thể lấy embedding: {e}")
        return None

def check_existing(key_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM face_embeddings WHERE key_id=%s", (key_id,))
    exists = cur.fetchone() is not None
    conn.close()
    return exists

def insert_embedding(ma_truong, ma_sv, key_id, embedding, image_path):
    conn = get_conn()
    cur = conn.cursor()
    emb_blob = pickle.dumps(embedding)
    cur.execute("""
        INSERT INTO face_embeddings (ma_truong, ma_sv, key_id, embedding, image_path)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (key_id) DO UPDATE 
        SET embedding = EXCLUDED.embedding, image_path = EXCLUDED.image_path, created_at = CURRENT_TIMESTAMP;
    """, (ma_truong, ma_sv, key_id, emb_blob, image_path))
    conn.commit()
    conn.close()
    print(f"[✅] Đã lưu hoặc cập nhật embedding cho {key_id}")

def load_all_embeddings():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT key_id, embedding FROM face_embeddings")
    data = {k: pickle.loads(v) for k, v in cur.fetchall()}
    conn.close()
    return data

# ================= IMAGE CAPTURE =================
def capture_image(save_path="temp_capture.jpg"):
    cap = cv2.VideoCapture(0)
    print("Nhấn 's' để chụp, 'q' để thoát.")
    while True:
        ret, frame = cap.read()
        if not ret:
            continue
        cv2.imshow("Camera", frame)
        key = cv2.waitKey(1) & 0xFF
        if key == ord('s'):
            cv2.imwrite(save_path, frame)
            print(f"[📸] Đã lưu ảnh tạm tại {save_path}")
            break
        elif key == ord('q'):
            save_path = None
            break
    cap.release()
    cv2.destroyAllWindows()
    return save_path

def select_file():
    try:
        root = tk.Tk()
        root.withdraw()

        file_path = filedialog.askopenfilename(
            title="Chọn file",
            filetypes=[
                ("Tất cả các loại file", "*.*"),
                ("Ảnh", "*.jpg *.jpeg *.png *.bmp *.gif"),
                ("Văn bản", "*.txt *.pdf *.docx")
            ]
        )

        root.destroy()  # ✅ Giải phóng cửa sổ gốc

        if not file_path:
            print("[⚠️] Bạn chưa chọn file nào.")
            return None

        if not os.path.exists(file_path):
            print("[❌] File không tồn tại hoặc đã bị xóa.")
            return None

        print(f"[✅] File bạn đã chọn: {file_path}")
        return file_path

    except tk.TclError:
        print("[❌] Lỗi giao diện Tkinter (có thể không hỗ trợ GUI).")
        return None

    except Exception as e:
        print("[❌] Đã xảy ra lỗi không mong muốn:")
        traceback.print_exc()
        messagebox.showerror("Lỗi", f"Đã xảy ra lỗi: {str(e)}")
        return None

# ================= MAIN MENU =================
if __name__ == "__main__":
    print("=== ĐĂNG KÝ KHUÔN MẶT SINH VIÊN ===")
    ma_truong = input("Nhập mã trường: ").strip()
    ma_sv = input("Nhập mã sinh viên: ").strip()
    key_id = f"{ma_truong}_{ma_sv}"

    if check_existing(key_id):
        print(f"[ℹ️] Sinh viên {key_id} đã đăng ký trước đó.")
        choice = input("Bạn có muốn cập nhật lại khuôn mặt? (y/n): ")
        if choice.lower() != 'y':
            exit()

    print("Chọn nguồn ảnh:")
    print("1. Mở camera chụp trực tiếp")
    print("2. Tải ảnh từ máy tính")
    option = input("Lựa chọn (1/2): ").strip()

    if option == "1":
        image_path = capture_image()
    elif option == "2":
        image_path = select_file()
        if image_path:
            print(f"Bạn đã chọn file: {image_path}")
        else:
            print("Không có file nào được chọn hoặc xảy ra lỗi.")
    else:
        print("❌ Lựa chọn không hợp lệ.")
        exit()

    embedding = get_embedding(image_path)
    if embedding is not None:
        insert_embedding(ma_truong, ma_sv, key_id, embedding, image_path)
    else:
        print("❌ Không thể sinh embedding từ ảnh này.")
