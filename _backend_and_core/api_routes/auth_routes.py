from fastapi import APIRouter

router = APIRouter()

@router.post("/login")
async def login():
    return {"message": "Login API ban rahi hai..."}

@router.post("/register")
async def register():
    return {"message": "Register API ban rahi hai..."}