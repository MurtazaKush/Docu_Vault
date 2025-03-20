from fastapi import FastAPI, HTTPException, Depends
from sqlmodel import SQLModel, Field, create_engine, Session, select, or_
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
class secret_list(BaseModel):
    owner_secret: list[owner_doc]
    people_secret: list[people_doc]
    valid: bool
class User_CP(BaseModel):
    username: str
    oldpasshash: str
    newpasshash: str
    updated_secret: secret_list
    newpb: str

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
    ruser=db.exec(select(User).where(User.username==user.username)).one()
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
    ruser=db.exec(select(User).where(User.username==user.username)).one()
    if not ruser:
        return False
    if ruser.passhash!=user.passhash:
        return False
    return True

@app.get("/change_pass/",response_model=secret_list)
def change_password_get(user:User_F,db: Session = Depends(get_db)):
    ruser=db.exec(select(User).where(User.username==user.username)).one()
    l=secret_list()
    l.owner_secret=[]
    l.people_secret=[]
    l.valid=False
    if not ruser:
        return l
    if ruser.passhash!=user.passhash:
        return l
    l.owner_secret=db.exec(select(people_doc).where(people_doc.user_id==user.username)).all()
    l.people_secret=db.exec(select(owner_doc).where(owner_doc.owner_id==user.username)).all()
    l.valid=True
    return l

@app.post("/change_pass/",response_model=bool)
def change_password_post(user:User_CP,db: Session = Depends(get_db)):
    u=User_F()
    u.username=user.username
    u.passhash=user.oldpasshash
    if login_users(u,db)==False:
        return False
    user_record=db.exec(select(User).where(User.username == user.username)).one()
    user_record.passhash=user.newpasshash
    user_record.pb_key=user.newpb
    db.add(user_record)
    for o_s in user.updated_secret.owner_secret:
        o_s_record=db.exec(select(owner_doc).where(owner_doc.doc_id==o_s.doc_id,owner_doc.owner_id==o_s.owner_id)).one()
        o_s_record.encrypted_secret=o_s.encrypted_secret
        db.add(o_s_record)
    for p_s in user.updated_secret.people_secret:
        p_s_record=db.exec(select(people_doc).where(people_doc.doc_id==p_s.doc_id,people_doc.user_id==p_s.user_id)).one()
        p_s_record.encrypted_secret=p_s.encrypted_secret
        db.add(p_s_record)
    db.commit()
    return True

