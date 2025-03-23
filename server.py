from fastapi import FastAPI, HTTPException, Depends, File, UploadFile
from fastapi.responses import FileResponse
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
            doc=db.exec(select(Doc).where(Doc.id==req.doc_id)).one()
            p=db.exec(select(Permission).where(Permission.req_id==req.id)).all()
            for pp in p:
                db.delete(pp)
            doc.accessible=True
            db.add(doc)
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
    req_record.req_type=req.req_type
    req_record.status=Req_status.LIVE_WAITING
    req_record.user_id=req.user_id
    db.add(req_record)
    doc.accessible=False
    db.add(doc)
    db.commit()
    db.refresh(req_record)
    p=Permission()
    p.req_id=req_record.id
    p.user_id=req_record.user_id
    if p.user_id in owner_id:
        p.p_type=secret_type.OWNER
        p.encrypted_secret=db.exec(select(owner_doc).where(owner_doc.doc_id==req.doc_id,owner_doc.owner_id==req.user_id)).one().encrypted_secret
    else:
        p.p_type=secret_type.PEOPLE
        p.encrypted_secret=db.exec(select(people_doc).where(people_doc.doc_id==req.doc_id,people_doc.user_id==req.user_id)).one().encrypted_secret
    db.add(p)
    db.commit()
    return True

def gen_myRequest_User_View(req: Requests,db: Session = Depends(get_db)):
    ans=myRequest_User_View()
    ans.description=req.description
    ans.req_time=req.req_time
    ans.req_type=req.req_type
    ans.status=req.status
    ans.req_id=req.id
    ans.doc_id=req.doc_id
    doc=db.exec(select(Doc).where(Doc.id==req.doc_id)).one()
    ans.filename=doc.filename
    ans.n=doc.n
    ans.k=doc.k
    ans.o=ans.o
    ans.s_k= [x.user_id for x in db.exec(select(Permission).where(Permission.req_id==req.id,Permission.p_type==secret_type.PEOPLE)).all()]
    ans.s_o= [x.user_id for x in db.exec(select(Permission).where(Permission.req_id==req.id,Permission.p_type==secret_type.OWNER)).all()]
    return ans

def gen_Request_User_View(req: Requests,username:str,db: Session = Depends(get_db)) -> Request_User_View:
    ans=Request_User_View()
    ans.description=req.description
    ans.req_time=req.req_time
    ans.req_type=req.req_type
    ans.req_id=req.id
    ans.doc_id=req.doc_id
    doc=db.exec(select(Doc).where(Doc.id==req.doc_id)).one()
    ans.filename=doc.filename
    p=db.exec(select(Permission).where(Permission.user_id==username,Permission.req_id==req.id)).one_or_none()
    if p is None:
        ans.signed=False
    else:
        ans.signed=True
    ans.status=req.status
    return ans

@app.post("/my_requests/",list[myRequest_User_View])
def get_my_requests(user: User_F,db: Session = Depends(get_db)):
    if login_users(user)==False:
        return []
    update_req_status(db)
    ans=[]
    reqs=db.exec(select(Requests).where(Requests.user_id==user.username)).all()
    for req in reqs:
        ans.append(gen_myRequest_User_View(req,db))
    return ans

@app.post("/other_requests/",response_model=list[Request_User_View])
def get_other_requests(user: User_F,db: Session = Depends(get_db)):
    if login_users(user)==False:
        return []
    update_req_status(db)
    ans=[]
    docs_o=[x.doc_id for x in db.exec(select(owner_doc).where(owner_doc.owner_id==user.username)).all()]
    docs_p=[x.doc_id for x in db.exec(select(people_doc).where(people_doc.user_id==user.username)).all()]
    for d in docs_o:
        r=db.exec(select(Requests).where(Requests.doc_id==d)).all()
        for req in r:
            a=gen_Request_User_View(req,db)
            a.user_type = secret_type.OWNER
            ans.append(a)
    for d in docs_p:
        r=db.exec(select(Requests).where(Requests.doc_id==d)).all()
        for req in r:
            a=gen_Request_User_View(req,db)
            a.user_type = secret_type.PEOPLE
            ans.append(a)
    return ans

@app.post("/get_my_secret/",response_model=str)
def get_secret(req:Doc_Fetch,db: Session = Depends(get_db)):
    user=User_F(username=req.username,passhash=req.passhash)
    if login_users(user)==False:
        return None
    sec=db.exec(select(people_doc).where(people_doc.user_id==req.username,people_doc.doc_id==req.doc_id)).one_or_none()
    if sec is not None:
        return sec.encrypted_secret
    sec=db.exec(select(owner_doc).where(owner_doc.owner_id==req.username,owner_doc.doc_id==req.doc_id)).one_or_none()
    if sec is None:
        return ""
    return sec.encrypted_secret
#Get owner and people of document
@app.post("/get_o_p/",response_model=O_P)
def get_secret(req:Doc_Fetch,db: Session = Depends(get_db)):
    user=User_F(username=req.username,passhash=req.passhash)
    if login_users(user)==False:
        return None
    ans=O_P()
    sec=db.exec(select(people_doc).where(people_doc.doc_id==req.doc_id)).all()
    ans.people=[x.user_id for x in sec]
    sec=db.exec(select(owner_doc).where(owner_doc.doc_id==req.doc_id)).all()
    ans.owners=[x.owner_id for x in sec]
    if user.username in ans.owners or user.username in ans.people:
        return ans
    return O_P()

@app.post("/sign_req/",response_model=bool)
def sign_req(s:sign,db: Session = Depends(get_db)):
    user=User_F(username=s.username,passhash=s.passhash)
    if login_users(user)==False:
        return False
    req=db.exec(select(Requests).where(Requests.id==s.req_id)).one_or_none()
    if req is None:
        return False
    sec=db.exec(select(people_doc).where(people_doc.user_id==s.username,people_doc.doc_id==req.doc_id)).one_or_none()
    p=Permission()
    p.req_id=s.req_id
    p.user_id=s.username
    p.encrypted_secret=s.encrypted_secret
    if sec is not None:
        p.p_type=secret_type.PEOPLE
        db.add(p)
        db.commit()
        return True
    sec=db.exec(select(owner_doc).where(owner_doc.owner_id==s.username,owner_doc.doc_id==req.doc_id)).one_or_none()
    if sec is not None:
        p.p_type=secret_type.OWNER
        db.add(p)
        db.commit()
        return True
    return False

@app.post("/get_file/",response_model=FileResponse)
def fetch_file(req:Doc_Fetch,db: Session = Depends(get_db)):
    user=User_F()
    user.username=req.username
    user.passhash=req.passhash
    if login_users(user)==False:
        return None
    doc=db.exec(select(Doc).where(Doc.id==req.doc_id)).one_or_none()
    if doc is None:
        return None
    return FileResponse(doc.file_path, filename=f"enc_{doc.filename}", media_type="application/octet-stream")

@app.post("/get_secrets/",response_model=doc_secret)
def fetch_secret(s_req:secret_Fetch,db: Session = Depends(get_db)):
    update_req_status(db)
    req=db.exec(select(Requests).where(Requests.id==s_req.req_id)).one_or_none()
    if req is None or req.status!=Req_status.LIVE_PENDING:
        return doc_secret()
    p_list=db.exec(select(Permission).where(Permission.req_id==s_req.req_id)).all()
    ans=doc_secret()
    for p in p_list:
        s=user_secret()
        s.username=p.user_id
        s.user_secret=p.encrypted_secret
        if p.p_type==secret_type.OWNER:
            ans.list_owners.append(s)
        else:
            ans.list_people.append(s)
    req.status=Req_status.LIVE_WAITING_UPLOAD
    db.add(req)
    db.commit()
    return ans


@app.post("/reupload_doc/",response_model=bool)
async def reupload_file(up_doc: reupload_Doc,file: UploadFile ,db: Session = Depends(get_db)):
    req=db.exec(select(Requests).where(Requests.id==up_doc.req_id)).one_or_none()
    if req is None or req.status!=Req_status.LIVE_WAITING_UPLOAD:
        return False
    u=User_F()
    u.username=up_doc.username
    u.passhash=up_doc.passhash
    if login_users(u,db)==False:
        return False
    doc=db.exec(select(Doc).where(Doc.id==req.doc_id)).one()
    for s in up_doc.list_owners:
        ss=db.exec(select(owner_doc).where(owner_doc.doc_id==doc.id,owner_doc.owner_id==s.username)).one_or_none()
        if ss is None:
            return False
        ss.encrypted_secret=s.user_secret
        db.add(ss)
    for s in up_doc.list_people:
        ss=db.exec(select(people_doc).where(people_doc.doc_id==doc.id,people_doc.user_id==s.username)).one_or_none()
        if ss is None:
            return False
        ss.encrypted_secret=s.user_secret
        db.add(ss)
    doc.l=up_doc.l
    people=[x.user_id for x in db.exec(select(Permission).where(Permission.req_id==req.id,Permission.p_type==secret_type.PEOPLE)).all()]
    contents=await file.read()
    with open(doc.file_path,"wb") as f:
        f.write(contents)
    with open(doc.log_file_path,"a") as f:
        f.write(f"{doc.filename} Uploaded at {datetime.datetime.now(timezone.utc).isoformat()} by {up_doc.username}\n\
                Edited: {"Yes" if req.req_type==Req_type.WRITE else "No"}\n\
                Permitting People: {", ".join(people)}\n\
                \n\n")
    db.add(doc)
    req.status=Req_status.EXPIRED_SUCCESSFUL
    db.add(req)
    db.commit()
    return True