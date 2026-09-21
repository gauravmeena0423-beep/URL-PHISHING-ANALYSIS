import subprocess
import time
import sys
import webbrowser  # <-- Naya module jo browser khud kholega

print("🚀 Starting PhishGuard Full-Stack System...\n")

try:
    # 1. Start Backend (FastAPI)
    print("⚙️ Booting up AI Backend Core...")
    backend = subprocess.Popen(
        "uvicorn main:app --reload", 
        cwd="_backend_and_core", 
        shell=True
    )
    
    # 2 seconds wait (taaki backend ready ho jaye)
    time.sleep(2) 
    
    # 2. Start Frontend (React/Vite)
    print("🌐 Booting up React Frontend Dashboard...")
    frontend = subprocess.Popen(
        "npm run dev", 
        cwd="_frontend_web", 
        shell=True
    )

    # 3. AUTO OPEN BROWSER MAGIC 🪄
    time.sleep(1.5)  # Vite ko start hone ke liye 1.5 sec do
    print("🌍 Opening Dashboard in Browser automatically...")
    webbrowser.open("http://localhost:5173/")  # <-- Yeh line browser khud kholegi

    # Dono ko chalte rehne do
    backend.wait()
    frontend.wait()

except KeyboardInterrupt:
    # Jab aap Ctrl+C dabaoge, toh dono ek sath band ho jayenge
    print("\n🛑 Shutting down both servers...")
    backend.terminate()
    frontend.terminate()
    print("✅ Servers safely stopped.")
    sys.exit(0)