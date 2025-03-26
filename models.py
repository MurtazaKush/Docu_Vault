from sqlmodel import SQLModel, Field, create_engine, Session
from pydantic import BaseModel
from enum import Enum
from datetime import datetime
from sqlalchemy import Column, TIMESTAMP, text

class User(SQLModel, table=True):
    username: str = Field(unique=True,primary_key=True,index=True,default="")
    passhash: str=""
    pb_key: str=""
class Doc(SQLModel,table=True):
    id: int = Field(primary_key=True,default=None)
    filename : str = Field(index=True,default="")
    file_path: str = Field(unique=True,default="")
    log_file_path: str = Field(unique=True,default="")
    description: str=""
    n:int=0
    o:int=0
    k:int=0
    l:int=0
    accessible: bool=True

class people_doc(SQLModel,table =True):
    doc_id : int =Field(foreign_key='doc.id',primary_key=True)
    user_id: str =Field(foreign_key='user.username',primary_key=True)
    encrypted_secret: str =""

class owner_doc(SQLModel,table =True):
    doc_id : int =Field(foreign_key='doc.id',primary_key=True,default=0)
    owner_id: str =Field(foreign_key='user.username',primary_key=True,default=0)
    encrypted_secret: str =""
class Req_status(str,Enum):
    LIVE_PENDING="L_P"
    EXPIRED_SUCCESSFUL="E_S"
    EXPIRED_FAILED="E_F"
    LIVE_WAITING="L_W"
    LIVE_WAITING_UPLOAD="L_W_U"
class Req_type(str,Enum):
    READ="r"
    WRITE="w"
class secret_type(str,Enum):
    OWNER='o'
    PEOPLE='p'
class Requests(SQLModel,table=True):
    id: int =Field(primary_key=True,default=None)
    doc_id : int =Field(foreign_key='doc.id',default=0)
    user_id: str =Field(foreign_key='user.username',default="")
    status: Req_status=Req_status.LIVE_WAITING
    req_time: datetime = Field(sa_column=Column(TIMESTAMP(timezone=True),
                        nullable=False, server_default=text("CURRENT_TIMESTAMP")))
    valid_time: int =0# validity in no of hours
    req_type: Req_type=Req_type.READ
    description:str=""
    
class Permission(SQLModel, table=True):
    req_id:int =Field(foreign_key='requests.id',primary_key=True,default=None)
    user_id:int =Field(foreign_key='user.username',primary_key=True,default=None)
    encrypted_secret:str = ""
    p_type: secret_type= secret_type.PEOPLE

class Req_F(BaseModel):
    doc_id:int=0
    user_id:str = ""
    passhash:str = ""
    description:str = ""
    valid_time:int =0
    req_type: Req_type = Req_type.READ
class User_F(BaseModel):
    username: str= ""
    passhash: str= ""
class User_doc_req(BaseModel):
    username: str= ""
    passhash: str= ""
    doc_id: int=0
class secret_list(BaseModel):
    owner_secret: list[owner_doc]=[]
    people_secret: list[people_doc]=[]
    valid: bool=True
class User_CP(BaseModel):
    username: str=""
    oldpasshash: str=""
    newpasshash: str=""
    updated_secret: secret_list=secret_list()
    newpb: str=""
class user_secret(BaseModel):
    username: str=""
    user_secret: str=""
class user_pbkey(BaseModel):
    username: str=""
    pb_key: str=""
class Upload_Doc(BaseModel):
    username: str=""
    passhash: str=""
    list_owners: list[user_secret]=[]
    list_people: list[user_secret]=[]
    k: int=0
    filename: str=""
    description: str=""
    l: int=0 #length of key+IV

class reupload_Doc(BaseModel):
    username: str=""
    passhash: str=""
    list_owners: list[user_secret]=[]
    list_people: list[user_secret]=[]
    req_id:int=0
    l: int=0 #length of key+IV

class Doc_User_View(BaseModel):
    filename : str=""
    description: str=""
    n:int=0
    o:int=0
    k:int=0
    accessible: bool=True
    id:int=0

class Doc_User_Response(BaseModel):
    people: list[Doc_User_View]=[]
    owner: list[Doc_User_View]=[]

class myRequest_User_View(BaseModel):
    s_o: list[str]=[] # no of owners that signed
    s_k: list[str]=[] # no of people that signed
    o: int=0
    k: int=0
    n: int=0
    description: str=""
    filename: str=""
    req_time: datetime=datetime.utcnow()
    req_type:Req_type=Req_type.READ
    valid_time: int=0
    status:Req_status=Req_status.EXPIRED_FAILED
    doc_id:int=0
    req_id:int=0

class Request_User_View(BaseModel):
    description: str=""
    filename: str=""
    req_time: datetime=datetime.utcnow()
    req_type:Req_type=Req_type.READ
    valid_time: int=0
    user_id: str=""
    signed: bool=False
    user_type: secret_type=secret_type.PEOPLE
    status: Req_status=Req_status.LIVE_WAITING
    doc_id:int=0
    req_id:int=0

class Doc_Fetch(BaseModel):
    username: str=""
    passhash: str=""
    doc_id: int=0

class doc_secret(BaseModel):
    list_owners: list[user_secret]=[]
    list_people: list[user_secret]=[]

class sign(BaseModel):
    username: str=""
    passhash: str=""
    req_id:int=0
    encrypted_secret:str=""

class secret_Fetch(BaseModel):
    username: str=""
    passhash: str=""
    req_id:int=0

class O_P(BaseModel):
    owners:list[str]=[]
    people:list[str]=[]