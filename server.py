from fastapi import FastAPI, HTTPException, Depends
from sqlmodel import SQLModel, Field, create_engine, Session, select
import os
from pydantic import BaseModel
from enum import Enum
import datetime

# Database URL (uses an existing database if available)
DATABASE_FILE = "test.db"
DATABASE_URL = f"sqlite:///{DATABASE_FILE}"

# Create SQLite engine (check_same_thread=False is needed for SQLite with FastAPI)
engine = create_engine(DATABASE_URL, echo=True, connect_args={"check_same_thread": False})

# Define SQLModel Table
class User(SQLModel, table=True):
    username: str = Field(unique=True,primary_key=True,index=True)
    passhash: str
    pb_key: str
class Doc(SQLModel,table=True):
    id: int = Field(primary_key=True,default=None)
    filename : str = Field(index=True)
    file_path: str = Field(unique=True)
    log_file_path: str = Field(unique=True)
    n:int
    o:int
    k:int
    l:int
    accessible: bool

class people_doc(SQLModel,table =True):
    doc_id : int =Field(foreign_key='Doc.id')
    user_id: str =Field(foreign_key='User.username')
    encrypted_secret: str 

class owner_doc(SQLModel,table =True):
    doc_id : int =Field(foreign_key='Doc.id')
    owner_id: str =Field(foreign_key='User.username')
    encrypted_secret: str 
class Req_status(str,Enum):
    LIVE_PENDING="L_P"
    EXPIRED_SUCCESSFUL="E_S"
    EXPIRED_FAILED="E_F"
    LIVE_WAITING="L_W"
    LIVE_WAITING_UPLOAD="L_W_U"
class Requests(SQLModel,table=True):
    id: int =Field(primary_key=True,default=None)
    doc_id : int =Field(foreign_key='Doc.id')
    user_id: str =Field(foreign_key='User.username')
    status: Req_status
    req_time: datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC))
    valid_time: int # validity in no of hours


class User_F(BaseModel):
    username: str
    passhash: str

class User_CF(BaseModel):
    username: str
    oldpasshash: str
    newpasshash: str
    updated_secret: list
    newpb:str

# Create Tables if They Don't Exist
def create_db_and_tables():
    if not os.path.exists(DATABASE_FILE):  # Only create tables if DB doesn't exist
        print("Database file not found. Creating a new one...")
        SQLModel.metadata.create_all(engine)
    else:
        print("Using existing database.")

# Dependency to Get Database Session
def get_db():
    with Session(engine) as session:
        yield session

# Initialize FastAPI App
app = FastAPI()

# Run DB Setup on Startup (Only Creates Tables If Needed)
@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# Route to Create a New User
@app.post("/signup/", response_model=User)
def create_user(user: User, db: Session = Depends(get_db)):
    ruser=db.exec(select(User).where(User.username==user.username)).first()
    if ruser:
        user.username="!"+user.username
        return user
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

# Login route for user
@app.post("/login/", response_model=bool)
def login_users(user:User_F,db: Session = Depends(get_db)):
    ruser=db.exec(select(User).where(User.username==user.username)).first()
    if not ruser:
        return False
    if ruser.passhash!=user.passhash:
        return False
    return True

@app.get("/change_pass/",response_model=list)
def change_password_get(user:User_F,db: Session = Depends(get_db)):
    ruser=db.exec(select(User).where(User.username==user.username)).first()
    if not ruser:
        return [False]
    if ruser.passhash!=user.passhash:
        return [False]
    l=db.exec(select(people_doc).where(people_doc.user_id==user.username)).all()
    l+=db.exec(select(owner_doc).where(owner_doc.owner_id==user.username)).all()
    return l

@app.post("/change_pass/",response_model=bool)
def change_password_post(user:User_F,db: Session = Depends(get_db)):
