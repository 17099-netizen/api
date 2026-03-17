from fastapi import FastAPI, Header, Request, HTTPException
from fastapi.responses import JSONResponse
from bs4 import BeautifulSoup
import requests
import hmac
import hashlib
import time
from collections import defaultdict

app = FastAPI(title="DoGrade Ultimate API", version="3.0.0")

# ==========================================
# 1. การตั้งค่าความปลอดภัย (Security Config)
# ==========================================
SECRET_API_KEY = "DKtIsmp3/1/68" # รหัสลับ (ตรงกับฝั่งแอป)
MAX_TIMESTAMP_DIFF = 60 # ลายเซ็นหมดอายุใน 60 วินาที
MAX_FAILS = 5           # พิมพ์ผิดได้ 5 ครั้ง
COOLDOWN_TIME = 30      # โดนแบน 30 วินาที
MAX_REQ_PER_SEC = 3     # กัน Bot ยิงรัวเกิน 3 ครั้ง/วิ

ip_fail_tracker = defaultdict(lambda: {"count": 0, "lockout_until": 0})
ip_request_tracker = defaultdict(list)

# ปุ่มดึงข้อมูลแต่ละเทอม
TERM_MAP = {
    "ปี1ภาค1": "ButtonX1", "ปี1ภาค2": "ButtonX2",
    "ปี2ภาค1": "ButtonX3", "ปี2ภาค2": "ButtonX4",
    "ปี3ภาค1": "ButtonX5", "ปี3ภาค2": "ButtonX6"
}

# ==========================================
# 2. ระบบป้องกันด่านหน้า (Middleware)
# ==========================================
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    client_ip = request.client.host
    current_time = time.time()

    # เช็ค Cooldown
    if current_time < ip_fail_tracker[client_ip]["lockout_until"]:
        rem = int(ip_fail_tracker[client_ip]["lockout_until"] - current_time)
        return JSONResponse(status_code=429, content={"error": f"ถูกระงับชั่วคราว กรุณารอ {rem} วินาที"})

    # เช็ค Anti-Bot ยิงรัว
    ip_request_tracker[client_ip] = [t for t in ip_request_tracker[client_ip] if current_time - t < 1]
    if len(ip_request_tracker[client_ip]) >= MAX_REQ_PER_SEC:
        return JSONResponse(status_code=429, content={"error": "ตรวจพบพฤติกรรมบอท ยิงรัวเกินไป!"})
    ip_request_tracker[client_ip].append(current_time)

    return await call_next(request)

# ==========================================
# 3. Endpoint สำหรับดึงข้อมูลแบบปลอดภัย
# ==========================================
@app.post("/api/v1/get_full_grade")
async def fetch_full_grade(
    request: Request,
    student_id: str, 
    dob: str, 
    term: str, 
    x_timestamp: str = Header(None),
    x_signature: str = Header(None)
):
    client_ip = request.client.host

    # ตรวจสอบ Header
    if not x_timestamp or not x_signature:
        raise HTTPException(status_code=401, detail="Missing Security Headers")

    # ตรวจสอบเวลาหมดอายุ
    try:
        if abs(int(time.time()) - int(x_timestamp)) > MAX_TIMESTAMP_DIFF:
            raise HTTPException(status_code=401, detail="Request Expired! (ลายเซ็นหมดเวลา)")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Timestamp")

    # ตรวจสอบลายเซ็นดิจิทัล
    payload_string = f"{student_id}:{dob}:{term}:{x_timestamp}"
    expected_sig = hmac.new(SECRET_API_KEY.encode('utf-8'), payload_string.encode('utf-8'), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, x_signature):
        ip_fail_tracker[client_ip]["count"] += 1
        _check_ban(client_ip)
        raise HTTPException(status_code=401, detail="Invalid Signature! (ลายเซ็นไม่ถูกต้อง)")

    # ตรวจสอบรูปแบบเทอม
    term_key = term.replace(" ", "")
    if term_key not in TERM_MAP:
        raise HTTPException(status_code=400, detail="เทอมไม่ถูกต้อง (ต้องเป็น ปี1ภาค1 ถึง ปี3ภาค2)")

    # ดึงข้อมูล
    result = scrape_dograde_full(student_id, dob, term_key, TERM_MAP[term_key])

    if result["status"] == "error":
        ip_fail_tracker[client_ip]["count"] += 1
        _check_ban(client_ip)
        raise HTTPException(status_code=400, detail=result["message"])
    
    ip_fail_tracker[client_ip]["count"] = 0
    return {"status": "success", "data": result["data"]}

def _check_ban(ip):
    if ip_fail_tracker[ip]["count"] >= MAX_FAILS:
        ip_fail_tracker[ip]["lockout_until"] = time.time() + COOLDOWN_TIME
        ip_fail_tracker[ip]["count"] = 0

# ==========================================
# 4. ฟังก์ชันดึงและแยกวิเคราะห์ข้อมูล HTML
# ==========================================
def scrape_dograde_full(student_id: str, dob: str, term_name: str, button_id: str):
    url = "http://www.dograde.online/DANKHUNTHOD/default.aspx"
    session = requests.Session()
    
    try:
        # 1. รับ ViewState เบื้องต้น
        res = session.get(url, timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')
        
        viewstate = soup.find("input", id="__VIEWSTATE")
        if not viewstate:
            return {"status": "error", "message": "เซิร์ฟเวอร์โรงเรียนไม่ตอบสนอง"}
            
        # 2. ส่งข้อมูลเพื่อขอดูเกรด
        payload = {
            "__VIEWSTATE": viewstate["value"],
            "__VIEWSTATEGENERATOR": soup.find("input", id="__VIEWSTATEGENERATOR")["value"] if soup.find("input", id="__VIEWSTATEGENERATOR") else "",
            "__EVENTVALIDATION": soup.find("input", id="__EVENTVALIDATION")["value"] if soup.find("input", id="__EVENTVALIDATION") else "",
            "TxtUser": student_id,
            "txtPassword": dob,
            button_id: term_name
        }
        
        post_res = session.post(url, data=payload, timeout=15)
        soup = BeautifulSoup(post_res.text, 'html.parser')
        
        # เช็คว่าเข้าสู่ระบบสำเร็จไหม (ตรวจสอบจากช่องชื่อนักเรียน)
        fname_input = soup.find("input", id="fName")
        if not fname_input or not fname_input.get("value"):
            return {"status": "error", "message": "รหัสนักเรียนหรือวันเกิดไม่ถูกต้อง"}

        # --- ฟังก์ชันช่วยดึงข้อมูล ---
        def safe_get_val(element_id):
            el = soup.find("input", id=element_id)
            return el["value"].strip() if el and el.has_attr("value") else "-"

        def safe_get_text(element_id):
            el = soup.find("span", id=element_id)
            return el.text.strip() if el else "-"

        # ข้อมูลนักเรียน
        student_info = {
            "id": safe_get_val("fid"),
            "name": safe_get_val("fName"),
            "room": safe_get_val("fRoom"),
            "ordinal": safe_get_val("fOrdinal")
        }

        # ข้อมูลสรุปผล
        summary = {
            "term_title": safe_get_text("LabelHead"),
            "enrolled": {
                "basic": safe_get_text("Label4"),
                "additional": safe_get_text("Label6"),
                "total": safe_get_text("Label8")
            },
            "earned": {
                "basic": safe_get_text("Label5"),
                "additional": safe_get_text("Label7"),
                "total": safe_get_text("Label9")
            },
            "gpa": safe_get_text("Label10")
        }

        # ข้อมูลตารางเรียน (รองรับ 13 คอลัมน์แบบตรงเป๊ะจากไฟล์ HTML)
        grades = []
        grade_table = soup.find("table", id="GridView0")
        if grade_table:
            rows = grade_table.find_all("tr")
            for row in rows[1:]: # ข้ามหัวตาราง
                cols = [td.text.strip() for td in row.find_all("td")]
                if len(cols) >= 13:
                    grades.append({
                        "code": cols[0],              # รหัสวิชา
                        "name": cols[1],              # รายวิชา
                        "type": cols[2],              # ประเภท
                        "credit": cols[3],            # หน่วยกิต
                        "raw_score": cols[4],         # คะแนนรวมหน่วย
                        "midterm": cols[5],           # กลางภาค
                        "final": cols[6],             # ปลายภาค
                        "total_score": cols[7],       # รวมคะแนน
                        "grade": cols[8],             # ระดับคะแนน (เกรด)
                        "retake": cols[9],            # แก้ตัว
                        "character": cols[10],        # คุณลักษณะ
                        "read_think": cols[11],       # อ่านคิดวิเคราะห์
                        "teacher": cols[12]           # ครูผู้สอน
                    })

        return {"status": "success", "data": {"student": student_info, "summary": summary, "grades": grades}}
    except Exception as e:
        return {"status": "error", "message": f"ระบบเซิร์ฟเวอร์หลังบ้านขัดข้อง"}
