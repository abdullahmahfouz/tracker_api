from fastapi import FastAPI, HTTPException, Depends
from sqlmodel import SQLModel, Session, create_engine, select
from passlib.hash import bcrypt
import jwt
import os
from datetime import datetime, timedelta
from pydantic import BaseModel
from dotenv import load_dotenv
from models import User

# Load .env variables
load_dotenv()

# Database URL and JWT secret
DATABASE_URL = "sqlite:///./dev.db"
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")

# Create database engine
engine = create_engine(DATABASE_URL, echo=True)

# Create all database tables
SQLModel.metadata.create_all(engine)

# Initialize FastAPI app
app = FastAPI()

# Dependency: get a database session
def get_session():
    with Session(engine) as session:
        yield session

# Request schema for creating and logging in a user
class UserCreate(BaseModel):
    email: str
    password: str

# Response schema for returning user info
class UserRead(BaseModel):
    id: int
    email: str

# Route: Register a new user
@app.post("/auth/register", response_model=UserRead)
def register(user: UserCreate, session: Session = Depends(get_session)):
    # Check if email already exists
    if session.exec(select(User).where(User.email == user.email)).first():
        raise HTTPException(status_code=409, detail="Email already in use")
    
    # Hash the password
    db_user = User(email=user.email, password=bcrypt.hash(user.password))
    
    # Save to the database
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    
    return db_user

# Route: Login a user and return a JWT token
@app.post("/auth/login")
def login(user: UserCreate, session: Session = Depends(get_session)):
    # Find user by email
    db_user = session.exec(select(User).where(User.email == user.email)).first()
    if not db_user or not bcrypt.verify(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create a JWT token valid for 7 days
    token = jwt.encode(
        {"sub": db_user.id, "exp": datetime.utcnow() + timedelta(days=7)},
        JWT_SECRET,
        algorithm="HS256"
    )
    return {"access_token": token, "token_type": "bearer"}

# Health check route
@app.get("/health")
def health():
    return {"ok": True}
