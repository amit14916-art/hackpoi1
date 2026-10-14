import os
import sys
import uvicorn

# Add current workspace directory to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

if __name__ == "__main__":
    print("==========================================================")
    print("[*] Starting AI-Powered Security Audit & DAST SaaS Platform")
    print("    Dashboard URL: http://localhost:8000")
    print("    API Docs:      http://localhost:8000/docs")
    print("==========================================================")
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)
