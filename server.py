from fastapi import FastAPI, HTTPException, Depends, File, UploadFile
from sqlmodel import Session, select, or_
from sqlalchemy import func
import os
import datetime
from datetime import timezone
from .models import *
from .database import *
SERVER_FS= "./Server"
SERVER_FILE_STORE=SERVER_FS+"/files"
SERVER_LOG_FILE_STORE=SERVER_FS+"/logs"
MAX_VALID_TIME=24
os.makedirs(SERVER_FS,exist_ok=True)
os.makedirs(SERVER_FILE_STORE,exist_ok=True)
os.makedirs(SERVER_LOG_FILE_STORE,exist_ok=True)

# Initialize FastAPI App
app = FastAPI()

# Run DB Setup on Startup (Only Creates Tables If Needed)
@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# Route to Create a New User
@app.post("/signup/", response_model=User)
def create_user(user: User, db: Session = Depends(get_db)):
    ruser=db.exec(select(User).where(User.username==user.username)).one_or_none()
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
    ruser=db.exec(select(User).where(User.username==user.username)).one_or_none()
    if ruser is None:
        return False
    if ruser.passhash!=user.passhash:
        return False
    return True
#Get your secrets to change password
@app.post("/change_pass_get/",response_model=secret_list)
def change_password_get(user:User_F,db: Session = Depends(get_db)):
    ruser=db.exec(select(User).where(User.username==user.username)).one_or_none()
    l=secret_list()
    l.owner_secret=[]
    l.people_secret=[]
    l.valid=False
    if ruser is None:
        return l
    if ruser.passhash!=user.passhash:
        return l
    l.owner_secret=db.exec(select(people_doc).where(people_doc.user_id==user.username)).all()
    l.people_secret=db.exec(select(owner_doc).where(owner_doc.owner_id==user.username)).all()
    l.valid=True
    return l
#Change your password by uploading newly encrypted secrets
@app.post("/change_pass/",response_model=bool)
def change_password_post(user:User_CP,db: Session = Depends(get_db)):
    u=User_F()
    u.username=user.username
    u.passhash=user.oldpasshash
    if login_users(u,db)==False:
        return False
    user_record=db.exec(select(User).where(User.username == user.username)).one_or_none()
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

#Get public key of list of users
@app.post("/pbkey/",response_model=list[user_pbkey])
def get_pbkey(users:list[str],db: Session = Depends(get_db)):
    l=[]
    for username in users:
        u_r=db.exec(select(User).where(User.username==username)).one_or_none()
        if u_r is None:
            return []
        o=user_pbkey()
        o.username=u_r.username
        o.pb_key=u_r.pb_key
        l.append(o)
    return l

#Upload a Doc for secure storage
@app.post("/add_doc/",response_model=bool)
async def add_doc(up_doc: Upload_Doc,file: UploadFile ,db: Session = Depends(get_db)):
    u=User_F()
    u.username=up_doc.username
    u.passhash=up_doc.passhash
    if login_users(u,db)==False:
        return False
    doc = Doc()
    doc.filename=up_doc.filename
    doc.description=up_doc.description
    doc.k=up_doc.k
    doc.o=len(up_doc.list_owners)
    doc.n=len(up_doc.list_people)+doc.n
    doc.l=up_doc.l
    doc.accessible=True
    db.add(doc)
    db.commit()
    db.refresh(doc)
    doc.file_path=SERVER_FILE_STORE+f"/{doc.id}"
    doc.log_file_path=SERVER_LOG_FILE_STORE+f"/{doc.id}.log"
    contents=await file.read()
    with open(doc.file_path,"wb") as f:
        f.write(contents)
    with open(doc.log_file_path,"w") as f:
        f.write(f"{doc.filename} created at {datetime.datetime.now(timezone.utc).isoformat()} by {up_doc.username}\n\
                Owners: {", ".join([x.username for x in up_doc.list_owners])}\n\
                People: {", ".join([x.username for x in up_doc.list_people])}\n\
                k: {up_doc.k}\n\
                Description: {up_doc.description}\n\
                \n\n")
    db.commit()
    for p in up_doc.list_people:
        p_r=people_doc()
        p_r.doc_id=doc.id
        p_r.user_id=p.username
        p_r.encrypted_secret=p.user_secret
        db.add(p_r)
        db.commit()
    for o in up_doc.list_owners:
        o_r=owner_doc()
        o_r.doc_id=doc.id
        o_r.owner_id=o.username
        o_r.encrypted_secret=o.user_secret
        db.add(o_r)
        db.commit()
    return True

def gen_Doc_User_View(d: Doc) -> Doc_User_View:
    ans=Doc_User_View()
    ans.accessible=d.accessible
    ans.filename=d.filename
    ans.description=d.description
    ans.k=d.k
    ans.o=d.o
    ans.n=d.n
    ans.id=d.id
    return ans

#Get list of Documents accessible to you
@app.post("/my_docs/",response_model=Doc_User_Response)
def get_my_docs(user: User_F,db: Session = Depends(get_db)):
    if login_users(user,db)==False:
        return []
    my_docs=Doc_User_Response()
    people_id =[x.doc_id for x in db.exec(select(people_doc).where(people_doc.user_id==user.username)).all()]
    owner_id =[x.doc_id for x in db.exec(select(owner_doc).where(owner_doc.owner_id==user.username)).all()]
    for id in people_id:
        d=db.exec(select(Doc).where(Doc.id==id)).one()
        my_docs.people.append(gen_Doc_User_View(d))
    for id in owner_id:
        d=db.exec(select(Doc).where(Doc.id==id)).one()
        my_docs.people.append(gen_Doc_User_View(d))
    return my_docs

def update_req_status(db: Session = Depends(get_db)):
    r=db.exec(select(Requests).where(or_(Requests.status==Req_status.LIVE_WAITING,Requests.status==Req_status.LIVE_PENDING))).all()
    for req in r:
        if req.req_time+datetime.timedelta(hours=req.valid_time) < datetime.datetime.now(datetime.UTC):
            req.status=Req_status.EXPIRED_FAILED
            db.add(req)
    db.commit()
    r=db.exec(select(Requests).where(Requests.status==Req_status.LIVE_WAITING)).all()
    for req in r:
        doc=db.exec(select(Doc).where(Doc.id==req.doc_id)).one()
        if db.exec(select(func.count()).select_from(Permission).where(Permission.req_id==req.id,Permission.p_type==secret_type.OWNER)) == doc.o and\
            db.exec(select(func.count()).select_from(Permission).where(Permission.req_id==req.id,Permission.p_type==secret_type.PEOPLE)) >= doc.k:
            req.status=Req_status.LIVE_PENDING
            db.add(req)
    db.commit()
    

#Create a new read/write request
@app.post("/create_request/",response_model=bool)
def make_request(req:Req_F,db: Session = Depends(get_db)):
    user=User_F()
    user.username=req.user_id
    user.passhash=req.passhash
    if login_users(user,db)==False:
        return False
    doc=db.exec(select(Doc).where(Doc.id==req.doc_id)).one_or_none()
    if doc is None or doc.accessible==False:
        return False
    people_id =[x.user_id for x in db.exec(select(people_doc).where(people_doc.doc_id==req.doc_id)).all()]
    owner_id =[x.owner_id for x in db.exec(select(owner_doc).where(owner_doc.doc_id==req.doc_id)).all()]
    if user.username not in people_id and user.username not in owner_id:
        return False
    req_record = Requests()
    req_record.doc_id=req.doc_id
    req_record.description=req.description
    req_record.valid_time=req.valid_time