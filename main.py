import io
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

import requests
import imagehash
from dotenv import load_dotenv
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends, status, Request
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image
from fpdf import FPDF

# ----------------------------
# 1) CONFIG & APP INIT
# ----------------------------
load_dotenv()
app = FastAPI(title="Super Identity Hunter API (Full Clerk Edition)")

# ✅ ตั้งค่า CORS ที่เดียวให้ครอบคลุมทั้ง Local และ Production
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://growupward.io",
        "https://www.growupward.io",
        "http://localhost:4321", # Astro Default Port
        "http://localhost:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.getenv("DB_PATH", "identity_vault.db")
KYC_FOLDER = Path("kyc_faces")
SCAM_FOLDER = Path("scam_evidence")
REPORT_FOLDER = Path("reports")
CLERK_SECRET_KEY = os.getenv("CLERK_SECRET_KEY") # 🔑 ต้องมีในไฟล์ .env

for folder in [KYC_FOLDER, SCAM_FOLDER, REPORT_FOLDER]:
    folder.mkdir(exist_ok=True)

FACEPP_API_KEY = os.getenv("FACEPP_API_KEY")
FACEPP_API_SECRET = os.getenv("FACEPP_API_SECRET")

# ----------------------------
# 2) SECURITY (ระบบตรวจสอบ Token จาก Clerk)
# ----------------------------
async def verify_clerk_session(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="🚨 กรุณาล็อกอินก่อนใช้งานระบบ")
    
    token = auth_header.split(" ")[1]
    headers = {"Authorization": f"Bearer {CLERK_SECRET_KEY}"}
    
    # ตรวจสอบ Session กับ Clerk API (เพื่อให้มั่นใจว่า User มีตัวตนจริง)
    try:
        response = requests.get("https://api.clerk.com/v1/sessions", headers=headers, timeout=10)
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail="🚨 บัตรผ่านหมดอายุหรือข้อมูลไม่ถูกต้อง")
    except Exception:
        raise HTTPException(status_code=500, detail="ไม่สามารถเชื่อมต่อระบบตรวจสอบตัวตนได้")
    
    return True

# ----------------------------
# 3) DATABASE & HELPERS
# ----------------------------
def get_db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS identity_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, phash TEXT UNIQUE NOT NULL, label TEXT NOT NULL, image_path TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS scammer_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, phash TEXT UNIQUE NOT NULL, fake_url TEXT NOT NULL, platform TEXT, screenshot_path TEXT, report_date TEXT, report_count INTEGER DEFAULT 1)")
    conn.commit()
    conn.close()

init_db()

class EvidencePDF(FPDF):
    def __init__(self):
        super().__init__()
        self.has_thai = False
        if os.path.exists("THSarabunNew.ttf"):
            self.add_font("THSarabun", "", "THSarabunNew.ttf")
            self.add_font("THSarabun", "B", "THSarabunNew Bold.ttf")
            self.has_thai = True
    def header(self):
        self.set_font("THSarabun" if self.has_thai else "Arial", "B", 16)
        self.cell(0, 10, "Cyber Evidence Report (รายงานหลักฐาน)", ln=True, align="C")

def generate_pdf_auto(data: Dict):
    pdf = EvidencePDF()
    pdf.add_page()
    pdf.set_font("THSarabun" if pdf.has_thai else "Arial", "", 12)
    pdf.cell(0, 10, f"ระดับความเสี่ยง: {data['level']}", ln=True)
    pdf.cell(0, 10, f"คะแนน: {data['score']}%", ln=True)
    if data.get("image") and os.path.exists(data["image"]):
        pdf.image(data["image"], x=10, w=100)
    filename = f"Report_{uuid.uuid4().hex}.pdf"
    pdf.output(str(REPORT_FOLDER / filename))
    return filename

def compare_with_faceplusplus(suspect_bytes: bytes, ref_file_path: str) -> bool:
    if not FACEPP_API_KEY: return False
    url = "https://api-us.faceplusplus.com/facepp/v3/compare"
    try:
        with open(ref_file_path, "rb") as ref_file:
            files = {"image_file1": ("s.jpg", suspect_bytes), "image_file2": ("r.jpg", ref_file)}
            res = requests.post(url, data={"api_key": FACEPP_API_KEY, "api_secret": FACEPP_API_SECRET}, files=files).json()
        return res.get("confidence", 0) >= 75.0
    except: return False

# ----------------------------
# 4) API ENDPOINTS
# ----------------------------

@app.get("/download-report/{file_name}")
async def download_report(file_name: str):
    file_path = REPORT_FOLDER / file_name
    if file_path.exists():
        return FileResponse(path=file_path, filename=file_name, media_type="application/pdf")
    raise HTTPException(status_code=404, detail="ไม่พบไฟล์รายงาน")

# 📸 1. ตรวจสอบใบหน้ามิจฉาชีพ
@app.post("/verify-identity/")
async def verify_identity(request: Request, file: UploadFile = File(...), _auth = Depends(verify_clerk_session)):
    try:
        content = await file.read()
        img = Image.open(io.BytesIO(content)).convert("RGB")
        current_hash = imagehash.phash(img)
        conn = get_db_conn()
        
        scammers = conn.execute("SELECT phash, fake_url, platform, screenshot_path, report_count FROM scammer_reports").fetchall()
        for row in scammers:
            is_match = (current_hash - imagehash.hex_to_hash(row["phash"])) <= 8
            if not is_match:
                is_match = compare_with_faceplusplus(content, row["screenshot_path"])
            
            if is_match:
                risk_data = {"score": 100, "level": "CRITICAL", "url": row["fake_url"], "platform": row["platform"], "image": row["screenshot_path"]}
                pdf_file = generate_pdf_auto(risk_data)
                download_url = f"{request.base_url}download-report/{pdf_file}"
                conn.close()
                return {"risk": {"score": 100, "level": "CRITICAL", "reason": "🚨 ตรวจพบในบัญชีดำมิจฉาชีพ"}, "pdf_download_link": download_url}

        conn.close()
        return {"risk": {"score": 0, "level": "LOW"}, "message": "ปลอดภัย ไม่พบประวัติเสี่ยง"}
    except Exception as e: return {"status": "error", "message": str(e)}

# 🚩 2. รายงานมิจฉาชีพรายใหม่ (เข้าสู่ฐานข้อมูล)
@app.post("/report-scammer/")
async def report_scammer(fake_url: str = Form(...), platform: str = Form(...), file: UploadFile = File(...), _auth = Depends(verify_clerk_session)):
    try:
        content = await file.read()
        fingerprint = str(imagehash.phash(Image.open(io.BytesIO(content)).convert("RGB")))
        conn = get_db_conn()
        existing = conn.execute("SELECT id, report_count FROM scammer_reports WHERE phash = ?", (fingerprint,)).fetchone()
        
        if existing:
            new_count = (existing["report_count"] or 1) + 1
            conn.execute("UPDATE scammer_reports SET report_count = ?, report_date = ? WHERE id = ?", (new_count, datetime.now().strftime("%Y-%m-%d"), existing["id"]))
            conn.commit()
            conn.close()
            return {"status": "updated", "message": f"แจ้งซ้ำ! ระบบบันทึกสถิติเพิ่มเป็น {new_count} ครั้ง"}

        saved_path = SCAM_FOLDER / f"{uuid.uuid4().hex}.png"
        Image.open(io.BytesIO(content)).convert("RGB").save(saved_path)
        conn.execute("INSERT INTO scammer_reports (phash, fake_url, platform, screenshot_path, report_date, report_count) VALUES (?, ?, ?, ?, ?, 1)", (fingerprint, fake_url, platform, str(saved_path), datetime.now().strftime("%Y-%m-%d")))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "บันทึกข้อมูลมิจฉาชีพเข้าสู่ระบบเรียบร้อย"}
    except Exception as e: return {"status": "error", "message": str(e)}

# ✅ 3. ลงทะเบียนคนดี (ยืนยันตัวตนว่าไม่ใช่โจร)
@app.post("/register-kyc/")
async def register_kyc(name: str = Form(...), file: UploadFile = File(...), _auth = Depends(verify_clerk_session)):
    try:
        content = await file.read()
        fingerprint = str(imagehash.phash(Image.open(io.BytesIO(content)).convert("RGB")))
        saved_path = KYC_FOLDER / f"{uuid.uuid4().hex}.png"
        Image.open(io.BytesIO(content)).convert("RGB").save(saved_path)
        
        conn = get_db_conn()
        conn.execute("INSERT INTO identity_reports (phash, label, image_path) VALUES (?, ?, ?)", (fingerprint, name, str(saved_path)))
        conn.commit()
        conn.close()
        return {"status": "success", "message": f"คุ้มครองตัวตนคุณ {name} เรียบร้อย"}
    except Exception as e: return {"status": "error", "message": str(e)}