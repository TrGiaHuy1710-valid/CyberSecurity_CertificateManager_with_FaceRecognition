import psycopg2
import pickle
import numpy as np
import cv2
import os
from deepface import DeepFace

# ========== DATABASE CONFIG ==========
DB_CONFIG = {
    "host": "127.0.0.1",
    "user": "postgres",
    "password": "huyyuh",   # đổi theo PostgreSQL của bạn
    "dbname": "cyber_verify_certificate",
    "port": 5432
}

def get_conn():
    return psycopg2.connect(**DB_CONFIG)

# ========== EMBEDDING UTILS ==========
def get_embedding(image_path):
    try:
        rep = DeepFace.represent(img_path=image_path, model_name="Facenet", enforce_detection=False)
        return np.array(rep[0]['embedding'])
    except Exception as e:
        print(f"[❌] Không thể lấy embedding: {e}")
        return None

def load_embeddings_from_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT key_id, embedding FROM face_embeddings")
    data = {key: pickle.loads(emb) for key, emb in cur.fetchall()}
    conn.close()
    return data

# ========== VERIFY LOGIC ==========
def verify_person(image_path, threshold=10):
    """
    So sánh embedding từ ảnh mới với embeddings trong database.
    threshold: khoảng cách Euclidean (nhỏ hơn threshold → cùng người)
    """
    known_embeddings = load_embeddings_from_db()
    if not known_embeddings:
        print("❌ Database trống, chưa có người đăng ký.")
        return

    print(f"[ℹ️] Có {len(known_embeddings)} embeddings trong database.")

    emb_new = get_embedding(image_path)
    if emb_new is None:
        print("❌ Không lấy được embedding từ ảnh.")
        return

    min_dist = float('inf')
    matched_id = None

    for key_id, emb_ref in known_embeddings.items():
        dist = np.linalg.norm(emb_new - emb_ref)
        if dist < min_dist:
            min_dist = dist
            matched_id = key_id

    print(f"🔍 So sánh gần nhất: {matched_id} (Khoảng cách = {min_dist:.2f})")
    if min_dist < threshold:
        print(f"[✅] Xác thực thành công! Ảnh khớp với {matched_id}")
        return matched_id, min_dist
    else:
        print("[❌] Không khớp với bất kỳ người nào trong database.")
        return None, min_dist

# ========== CAMERA CAPTURE ==========
def capture_image(save_path="temp_verify.jpg"):
    cap = cv2.VideoCapture(0)
    print("Nhấn 's' để chụp, 'q' để thoát.")
    while True:
        ret, frame = cap.read()
        if not ret:
            continue
        cv2.imshow("Xác thực khuôn mặt", frame)
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

# ========== MAIN ==========
if __name__ == "__main__":
    print("=== XÁC THỰC KHUÔN MẶT ===")
    print("Chọn nguồn ảnh:")
    print("1. Mở camera")
    print("2. Dùng ảnh từ máy tính")

    choice = input("Lựa chọn (1/2): ").strip()
    if choice == "1":
        image_path = capture_image()
    elif choice == "2":
        image_path = input("Nhập đường dẫn tới ảnh: ").strip()
    else:
        print("❌ Lựa chọn không hợp lệ.")
        exit()

    if image_path is None or not os.path.exists(image_path):
        print("❌ Không có ảnh hợp lệ.")
        exit()

    verify_person(image_path, threshold=10)
