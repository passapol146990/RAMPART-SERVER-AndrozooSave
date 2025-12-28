import os
import requests
from tqdm import tqdm
from dotenv import load_dotenv
from pathlib import Path
import time
import zipfile
from pathlib import Path
# ===================== CONFIG =====================
load_dotenv()

# โฟลเดอร์ชั่วคราว (จะลบหลังอัปโหลดสำเร็จ)
BASE_DIR = Path("./temp")
MALWARE_DIR = BASE_DIR / "malware"
REPORT_DIR = BASE_DIR / "reports"

# Environment Variables
ANDROZOO_API_KEY = os.getenv("ANDROZOO_API_KEY")
MOBSF_HOST = os.getenv("MOBSF_HOST", "http://localhost:8000")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY")
API_SERVER = os.getenv("API_SERVER", "http://localhost:8000")

# สร้างโฟลเดอร์
for folder in [BASE_DIR, MALWARE_DIR, REPORT_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

# ===================== FUNCTION: 1. ดึง HASH จาก API SERVER =====================
def get_hash_from_server():
    """
    ดึง hash และ tag จาก API server
    GET {API_SERVER}/get
    Response: {"hash": "sha256", "tag": "benign/malware", "id": 123} or null
    Returns: (hash_value, tag) tuple or (None, None)
    """
    try:
        response = requests.get(f"{API_SERVER}/get", timeout=30)
        if response.status_code == 200:
            data = response.json()
            hash_value = data.get("hash")
            tag = data.get("tag", "unknown")  # Default to "unknown" if not provided
            if hash_value:
                print(f"📥 Received hash: {hash_value} [Tag: {tag}]")
                return hash_value, tag
            else:
                return None, None
        else:
            print(f"⚠️ API server response: {response.status_code}")
            return None, None
    except requests.exceptions.Timeout:
        print(f"⏱️ API server timeout")
        return None, None
    except requests.exceptions.ConnectionError:
        print(f"🔌 Cannot connect to API server")
        return None, None
    except requests.exceptions.RequestException as e:
        print(f"❌ API server error: {e}")
        return None, None
    except Exception as e:
        print(f"💥 Unexpected error in get_hash_from_server: {e}")
        return None, None

# ===================== FUNCTION: 2. ดาวน์โหลด APK จาก AndroZoo =====================
def download_apk(sha256, output_path, max_retries=3):
    """
    ดาวน์โหลด APK จาก AndroZoo พร้อม retry mechanism
    รองรับไฟล์ขนาดใหญ่และจัดการ error ต่างๆ
    """
    if output_path.exists():
        file_size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"✅ File already exists: {output_path.name} ({file_size_mb:.2f} MB)")
        return True

    url = f"https://androzoo.uni.lu/api/download?apikey={ANDROZOO_API_KEY}&sha256={sha256}"

    for attempt in range(1, max_retries + 1):
        try:
            print(f"⬇️ Downloading from AndroZoo (attempt {attempt}/{max_retries})...")

            r = requests.get(url, stream=True, timeout=600)  # เพิ่ม timeout เป็น 10 นาที

            if r.status_code == 200:
                total_size = int(r.headers.get("content-length", 0))
                total_size_mb = total_size / (1024 * 1024)
                print(f"   File size: {total_size_mb:.2f} MB")

                # ดาวน์โหลดแบบ streaming พร้อม progress bar
                downloaded = 0
                with open(output_path, "wb") as f, tqdm(
                    total=total_size, unit="B", unit_scale=True,
                    desc=f"   Downloading {output_path.name[:30]}", leave=False
                ) as bar:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            bar.update(len(chunk))

                # ตรวจสอบว่าได้ไฟล์ครบหรือไม่
                if total_size > 0 and downloaded < total_size:
                    print(f"⚠️ Incomplete download: {downloaded}/{total_size} bytes")
                    output_path.unlink(missing_ok=True)
                    if attempt < max_retries:
                        time.sleep(5)
                        continue
                    return False

                print(f"✅ Downloaded: {output_path.name} ({total_size_mb:.2f} MB)")
                return True

            elif r.status_code == 404:
                print(f"❌ APK not found in AndroZoo: {sha256}")
                return False  # ไม่ retry ถ้าไฟล์ไม่มีในระบบ

            elif r.status_code == 403:
                print(f"❌ Access denied (check API key)")
                return False  # ไม่ retry ถ้า API key ไม่ถูกต้อง

            else:
                print(f"⚠️ Download failed: HTTP {r.status_code}")
                if attempt < max_retries:
                    time.sleep(5)

        except requests.exceptions.Timeout:
            print(f"⏱️ Download timeout (attempt {attempt}/{max_retries})")
            output_path.unlink(missing_ok=True)  # ลบไฟล์ที่ดาวน์โหลดไม่สมบูรณ์
            if attempt < max_retries:
                wait_time = attempt * 10
                print(f"⏳ Retrying in {wait_time}s...")
                time.sleep(wait_time)

        except requests.exceptions.ConnectionError as e:
            print(f"🔌 Connection error: {e}")
            output_path.unlink(missing_ok=True)
            if attempt < max_retries:
                time.sleep(10)

        except OSError as e:
            print(f"💾 Disk error: {e}")
            output_path.unlink(missing_ok=True)
            return False  # ไม่ retry ถ้ามีปัญหาเรื่อง disk

        except Exception as e:
            print(f"💥 Download error: {type(e).__name__} - {e}")
            output_path.unlink(missing_ok=True)
            if attempt < max_retries:
                time.sleep(5)

    print(f"❌ Download failed after {max_retries} attempts")
    return False

# ===================== FUNCTION: 3. UPLOAD & SCAN ด้วย MobSF =====================
def scan_with_mobsf(apk_path, max_retries=2):
    """
    Upload และ Static Scan APK ใน MobSF (ไม่ใช้ Dynamic Analysis)
    รองรับไฟล์ขนาดใหญ่และจัดการ error ต่างๆ
    Returns: mobsf_hash (MD5) หรือ None ถ้าล้มเหลว
    """
    api_headers = {"Authorization": MOBSF_API_KEY}

    file_size_mb = apk_path.stat().st_size / (1024 * 1024)
    print(f"📤 Preparing to upload to MobSF: {apk_path.name} ({file_size_mb:.2f} MB)")

    for attempt in range(1, max_retries + 1):
        try:
            # Upload
            with open(apk_path, "rb") as f:
                print(f"   Uploading (attempt {attempt}/{max_retries})...")

                # Dynamic timeout based on file size (minimum 10 min)
                upload_timeout = max(600, int(file_size_mb * 5))

                upload_res = requests.post(
                    f"{MOBSF_HOST}/api/v1/upload",
                    headers=api_headers,
                    files={"file": (apk_path.name, f, "application/vnd.android.package-archive")},
                    timeout=upload_timeout
                )

            if upload_res.status_code != 200:
                print(f"⚠️ Upload failed: HTTP {upload_res.status_code}")
                try:
                    error_detail = upload_res.json()
                    print(f"   Error: {error_detail}")
                except:
                    print(f"   Response: {upload_res.text[:200]}")

                if attempt < max_retries:
                    time.sleep(10)
                    continue
                return None

            data = upload_res.json()
            mobsf_hash = data.get("hash")
            scan_type = data.get("scan_type", "apk")
            file_name = data.get("file_name")

            if not mobsf_hash:
                print(f"❌ No hash returned from MobSF")
                return None

            # Static Scan only (ไม่ต้องการ dynamic analysis)
            print(f"🔍 Static scanning {file_name}...")

            # Dynamic timeout based on file size (minimum 30 min, max 2 hours)
            scan_timeout = max(1800, min(7200, int(file_size_mb * 20)))

            scan_res = requests.post(
                f"{MOBSF_HOST}/api/v1/scan",
                headers=api_headers,
                data={
                    "scan_type": scan_type,
                    "hash": mobsf_hash,
                    "re_scan": "0"  # ไม่ต้อง rescan ถ้ามี scan แล้ว
                }
            )

            if scan_res.status_code == 200:
                print(f"✅ Static scan completed: {file_name}")
                return mobsf_hash
            else:
                print(f"⚠️ Scan failed: HTTP {scan_res.status_code}")
                try:
                    error_detail = scan_res.json()
                    print(f"   Error: {error_detail}")
                except:
                    print(f"   Response: {scan_res.text[:200]}")

                if attempt < max_retries:
                    time.sleep(10)
                    continue
                return None

        except requests.exceptions.Timeout as e:
            print(f"⏱️ Timeout error (attempt {attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                time.sleep(15)

        except requests.exceptions.ConnectionError as e:
            print(f"🔌 Connection error: {e}")
            if attempt < max_retries:
                time.sleep(10)

        except FileNotFoundError:
            print(f"📁 APK file not found: {apk_path}")
            return None

        except Exception as e:
            print(f"💥 MobSF error: {type(e).__name__} - {e}")
            if attempt < max_retries:
                time.sleep(10)

    print(f"❌ MobSF scan failed after {max_retries} attempts")
    return None

# ===================== FUNCTION: 4a. ดาวน์โหลด REPORT =====================
def download_report(mobsf_hash, output_path):
    """ดาวน์โหลด JSON report จาก MobSF"""
    api_headers = {"Authorization": MOBSF_API_KEY}

    try:
        response = requests.post(
            f"{MOBSF_HOST}/api/v1/report_json",
            headers=api_headers,
            data={"hash": mobsf_hash},
            timeout=300
        )

        if response.status_code == 200:
            report_data = response.json()
            with open(output_path, 'w', encoding='utf-8') as f:
                import json
                json.dump(report_data, f, ensure_ascii=False, indent=4)
            print(f"✅ Downloaded report: {output_path.name}")
            return True
        else:
            print(f"❌ Failed to get report: {response.status_code}")
            return False
    except Exception as e:
        print(f"💥 Report download error: {e}")
        return False

# ===================== FUNCTION: 4b. POST STATUS ไปยัง API SERVER =====================
def post_status(sha256, status):
    """
    POST hash และ status ไปที่ API server
    POST {API_SERVER}/post
    Body: {"hash": "sha256", "status": "success/failed"}
    """
    try:
        payload = {"hash": sha256, "status": status}
        response = requests.post(
            f"{API_SERVER}/post",
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            print(f"✅ Status posted: {sha256} -> {status}")
            return True
        else:
            print(f"⚠️ Failed to post status: {response.status_code}")
            return False
    except Exception as e:
        print(f"💥 Error posting status: {e}")
        return False

# ===================== FUNCTION: 5. UPLOAD FILES ไปยัง API SERVER =====================
def upload_files_to_server(sha256, apk_path, report_path, tag="unknown", max_retries=3):
    """
    PUT/Upload ZIP (ที่บรรจุ APK) และ report ไปที่ API server (LAN)
    PUT {API_SERVER}/put
    Files: apk_zip, report
    Data: hash, tag
    """
    url = f"{API_SERVER}/put"

    apk_path = Path(apk_path)
    report_path = Path(report_path)
    zip_path = apk_path.with_suffix(".zip")

    # ✅ สร้าง zip จาก apk
    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(apk_path, apk_path.name)
        print(f"🗜️ Created ZIP: {zip_path.name}")
    except Exception as e:
        print(f"❌ Failed to zip APK: {e}")
        return False

    success = False

    for attempt in range(1, max_retries + 1):
        try:
            print(f"📤 Uploading files (attempt {attempt}/{max_retries})...")

            with open(zip_path, "rb") as zip_file, open(report_path, "rb") as report_file:
                files = {
                    "file": (zip_path.name, zip_file, "application/zip"),
                    "report": (report_path.name, report_file, "application/json")
                }
                data = {"hash": sha256, "tag": tag}

                file_size_mb = zip_path.stat().st_size / (1024 * 1024)
                timeout = max(300, int(file_size_mb * 10))  # Min 5 min, +10s per MB

                print(f"   File size: {file_size_mb:.2f} MB, Timeout: {timeout}s")

                response = requests.put(url, files=files, data=data, timeout=timeout)

                if response.status_code == 200:
                    print(f"✅ Files uploaded: {sha256} [Tag: {tag}]")
                    success = True
                    break
                else:
                    print(f"⚠️ Upload failed: HTTP {response.status_code}")
                    try:
                        print(f"   Error details: {response.json()}")
                    except:
                        print(f"   Response: {response.text[:200]}")

        except requests.exceptions.Timeout:
            print(f"⏱️ Upload timeout (attempt {attempt}/{max_retries})")
            if attempt < max_retries:
                wait_time = attempt * 10
                print(f"⏳ Retrying in {wait_time}s...")
                time.sleep(wait_time)
        except requests.exceptions.ConnectionError as e:
            print(f"🔌 Connection error: {e}")
            if attempt < max_retries:
                time.sleep(5)
        except FileNotFoundError as e:
            print(f"📁 File not found: {e}")
            break
        except OSError as e:
            print(f"💾 OS error: {e}")
            if attempt < max_retries:
                time.sleep(5)
        except Exception as e:
            print(f"💥 Upload error: {type(e).__name__} - {e}")
            if attempt < max_retries:
                time.sleep(5)

    # 🧹 ลบเฉพาะ ZIP ที่สร้างไว้
    for file_path in [zip_path, apk_path]:
        try:
            if file_path.exists():
                file_path.unlink()
                print(f"🧹 Deleted: {file_path.name}")
        except Exception as e:
            print(f"⚠️ Failed to delete {file_path.name}: {e}")

    if success:
        print("✅ Upload complete.")
        return True
    else:
        print(f"❌ Upload failed after {max_retries} attempts")
        return False
# ===================== FUNCTION: 6a. ลบ SCAN จาก MobSF =====================
def delete_scan_from_mobsf(mobsf_hash):
    """
    ลบ scan results จาก MobSF
    POST {MOBSF_HOST}/api/v1/delete_scan
    Data: hash
    """
    api_headers = {"Authorization": MOBSF_API_KEY}

    try:
        response = requests.post(
            f"{MOBSF_HOST}/api/v1/delete_scan",
            headers=api_headers,
            data={"hash": mobsf_hash},
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            if result.get("deleted") == "yes":
                print(f"🗑️ Deleted scan from MobSF: {mobsf_hash[:16]}...")
                return True
            else:
                print(f"⚠️ Scan not found in MobSF")
                return False
        else:
            print(f"❌ Failed to delete scan: {response.status_code}")
            return False
    except Exception as e:
        print(f"💥 Error deleting scan: {e}")
        return False

# ===================== FUNCTION: 6b. ลบไฟล์ LOCAL =====================
def cleanup_local_files(apk_path, report_path):
    """ลบไฟล์ APK และ report จาก local"""
    try:
        deleted = []
        if apk_path.exists():
            apk_path.unlink()
            deleted.append(f"APK: {apk_path.name}")

        if report_path.exists():
            report_path.unlink()
            deleted.append(f"Report: {report_path.name}")

        if deleted:
            print(f"🗑️ Deleted: {', '.join(deleted)}")
        return True
    except Exception as e:
        print(f"💥 Cleanup error: {e}")
        return False

# ===================== MAIN FUNCTION =====================
def main():
    """Main loop - ประมวลผล APK ทีละตัว"""
    while True:
        sha256 = None
        tag = None
        apk_path = None
        report_path = None
        mobsf_hash = None

        try:
            # 1. ดึง hash และ tag จาก API server
            sha256, tag = get_hash_from_server()
            if not sha256:
                print("⏸️ No task available, waiting 10s...")
                time.sleep(10)
                continue

            print(f"\n{'='*70}")
            print(f"🎯 Processing: {sha256} [Tag: {tag}]")
            print(f"{'='*70}")

            apk_path = MALWARE_DIR / f"{sha256}.apk"
            report_path = REPORT_DIR / f"{sha256}.json"

            # 2. ดาวน์โหลด APK
            if not download_apk(sha256, apk_path):
                post_status(sha256, "download_failed")
                continue

            # 3. Scan ด้วย MobSF
            mobsf_hash = scan_with_mobsf(apk_path)
            if not mobsf_hash:
                post_status(sha256, "scan_failed")
                cleanup_local_files(apk_path, report_path)
                continue

            # 4. ดาวน์โหลด report และ POST status
            if not download_report(mobsf_hash, report_path):
                post_status(sha256, "report_failed")
                delete_scan_from_mobsf(mobsf_hash)
                cleanup_local_files(apk_path, report_path)
                continue

            post_status(sha256, "success")

            # 5. Upload files ไปยัง API server (พร้อม tag)
            upload_success = upload_files_to_server(sha256, apk_path, report_path, tag=tag)

            # 6. Cleanup (ลบไฟล์ local และ MobSF scan)
            if upload_success:
                delete_scan_from_mobsf(mobsf_hash)
                cleanup_local_files(apk_path, report_path)
                print(f"✅ ✅ ✅ COMPLETED: {sha256} [Tag: {tag}]\n")
            else:
                print(f"⚠️ Upload failed, keeping local files")
                post_status(sha256, "upload_failed")

        except KeyboardInterrupt:
            print("\n🛑 Stopped by user")
            break
        except Exception as e:
            print(f"💥 Unexpected error in main loop: {type(e).__name__} - {e}")
            if sha256:
                post_status(sha256, "error")
            # เพิ่ม delay เพื่อป้องกัน infinite error loop
            time.sleep(5)

# ===================== ENTRY POINT =====================
if __name__ == "__main__":
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║          MobSF Auto Scanner - Refactored Version             ║
║              (Optimized for Kali Linux 80GB)                 ║
╚═══════════════════════════════════════════════════════════════╝

📋 Configuration:
   - API Server:  {API_SERVER}
   - MobSF Host:  {MOBSF_HOST}
   - Mode:        Single-threaded (1 APK at a time)
   - Temp Dir:    {BASE_DIR.absolute()}

🔄 Workflow:
   1. Get hash from API server
   2. Download APK from AndroZoo
   3. Scan with MobSF
   4. Download report & POST status
   5. Upload APK + report to API server
   6. Delete local files & MobSF scan (to save space)

🚀 Starting scanner...
    """)

    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down gracefully...")
        print("👋 Goodbye!")
