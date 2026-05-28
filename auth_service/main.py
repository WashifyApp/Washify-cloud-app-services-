# auth_service/main.py

```python
import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from passlib.context import CryptContext
from jose import jwt

import motor.motor_asyncio

# ============================================
# FASTAPI APP
# ============================================

app = FastAPI(title="Washify Auth Service")

# ============================================
# CORS
# ============================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# ENV VARIABLES
# ============================================

MONGODB_URI = os.getenv("MONGODB_URI")
JWT_SECRET = os.getenv("JWT_SECRET", "washify_super_secret")

if not MONGODB_URI:
    raise Exception("MONGODB_URI environment variable not found")

# ============================================
# MONGODB CONNECTION
# ============================================

client = motor.motor_asyncio.AsyncIOMotorClient(
    MONGODB_URI,
    tls=True,
    retryWrites=False
)

db = client.washify_auth
users_collection = db.get_collection("users")

# ============================================
# JWT SETTINGS
# ============================================

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

# ============================================
# MODELS
# ============================================

class UserCreate(BaseModel):
    email: EmailStr
    phone_number: str
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

# ============================================
# PASSWORD FUNCTIONS
# ============================================

def verify_password(
    plain_password,
    hashed_password
):
    return pwd_context.verify(
        plain_password,
        hashed_password
    )

def get_password_hash(password):
    return pwd_context.hash(password)

# ============================================
# JWT TOKEN FUNCTION
# ============================================

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
):
    to_encode = data.copy()

    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta
        else timedelta(minutes=15)
    )

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        to_encode,
        JWT_SECRET,
        algorithm=ALGORITHM
    )

    return encoded_jwt

# ============================================
# REGISTER API
# ============================================

@app.post("/register")
async def register(user: UserCreate):

    existing_user = await users_collection.find_one(
        {"email": user.email}
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    user_dict = user.dict()

    user_dict["password"] = get_password_hash(
        user_dict["password"]
    )

    user_dict["is_verified"] = False

    await users_collection.insert_one(user_dict)

    return {
        "message": "User registered successfully"
    }

# ============================================
# VERIFY OTP API
# ============================================

@app.post("/verify-otp", response_model=Token)
async def verify_otp(data: OTPVerify):

    if data.otp != "123456":
        raise HTTPException(
            status_code=400,
            detail="Invalid OTP"
        )

    db_user = await users_collection.find_one(
        {"email": data.email}
    )

    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    await users_collection.update_one(
        {"email": data.email},
        {
            "$set": {
                "is_verified": True
            }
        }
    )

    access_token = create_access_token(
        data={
            "sub": db_user["email"],
            "role": db_user["role"],
            "id": str(db_user["_id"]),
            "phone_number": db_user.get(
                "phone_number",
                ""
            )
        },
        expires_delta=timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": str(db_user["_id"]),
            "email": db_user["email"],
            "role": db_user["role"],
            "phone_number": db_user.get(
                "phone_number",
                ""
            )
        }
    }

# ============================================
# LOGIN API
# ============================================

@app.post("/login", response_model=Token)
async def login(user: UserLogin):

    db_user = await users_collection.find_one(
        {"email": user.email}
    )

    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if not verify_password(
        user.password,
        db_user["password"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if not db_user.get("is_verified", False):
        raise HTTPException(
            status_code=403,
            detail="Please verify OTP"
        )

    access_token = create_access_token(
        data={
            "sub": db_user["email"],
            "role": db_user["role"],
            "id": str(db_user["_id"]),
            "phone_number": db_user.get(
                "phone_number",
                ""
            )
        },
        expires_delta=timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": str(db_user["_id"]),
            "email": db_user["email"],
            "role": db_user["role"],
            "phone_number": db_user.get(
                "phone_number",
                ""
            )
        }
    }

# ============================================
# HEALTH CHECK
# ============================================

@app.get("/health")
async def health():

    return {
        "status": "healthy",
        "service": "washify-auth-service"
    }

# ============================================
# ROOT API
# ============================================

@app.get("/")
async def root():

    return {
        "message": "Washify Auth Service Running"
    }
```
