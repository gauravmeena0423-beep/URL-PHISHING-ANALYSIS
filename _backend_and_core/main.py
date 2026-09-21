import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from workspace root and current backend folder
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = Path(__file__).resolve().parent

if (ROOT_DIR / ".env").exists():
    load_dotenv(ROOT_DIR / ".env")
elif (BACKEND_DIR / ".env").exists():
    load_dotenv(BACKEND_DIR / ".env")
else:
    load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Database imports
from database.db_config import engine, Base
from api_routes import scan_routes, auth_routes

# 1. Database Table Create karna (Agar phishguard.db file nahi hai toh bana dega)
print("⚙️ Initializing Database...")
Base.metadata.create_all(bind=engine)

# 2. FastAPI Application Banana
app = FastAPI(
    title="PhishGuard Enterprise API",
    description="Multi-layered URL Phishing Analysis Platform",
    version="1.0.0"
)

# 3. CORS Settings (React Frontend aur Chrome Extension ko API access dene ke liye)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Production me yahan Frontend ka URL daalna (e.g., "http://localhost:3000")
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 4. API Routes Jodna (Endpoints)
app.include_router(auth_routes.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scan_routes.router, prefix="/api/scan", tags=["URL Scanner Engine"])

# 5. Base Check Route (Server chal raha hai ya nahi)
@app.get("/", tags=["System Health"])
def system_status():
    return {
        "system": "PhishGuard Multi-Layered AI Engine",
        "status": "Online and Listening 🚀",
        "documentation_url": "/docs"
    }

# Agar file directly run ho rahi hai, toh Uvicorn server start karo
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)