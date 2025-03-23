from sqlmodel import SQLModel, Field, create_engine, Session
from pydantic import BaseModel
from enum import Enum
import datetime
from datetime import timezone

class User(SQLModel, table=True):
    username: str = Field(unique=True,primary_key=True,index=True)
    passhash: str
    pb_key: str
class Doc(SQLModel,table=True):
    id: int = Field(primary_key=True,default=None)
    filename : str = Field(index=True)
    file_path: str = Field(unique=True)
    log_file_path: str = Field(unique=True)
    description: str
    n:int
    o:int
    k:int
    l:int
    accessible: bool

class people_doc(SQLModel,table =True):
    doc_id : int =Field(foreign_key='doc.id')
    user_id: str =Field(foreign_key='user.username')
    encrypted_secret: str 

class owner_doc(SQLModel,table =True):
    doc_id : int =Field(foreign_key='doc.id')
    owner_id: str =Field(foreign_key='user.username')
    encrypted_secret: str 
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
    doc_id : int =Field(foreign_key='doc.id')
    user_id: str =Field(foreign_key='user.username')
    status: Req_status
    req_time: datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC))
    valid_time: int # validity in no of hours
    req_type: Req_type
    description:str

class Permission(SQLModel, table=True):
    req_id:int =Field(foreign_key='requests.id')
    user_id:int =Field(foreign_key='user.username')
    encrypted_secret:str
    p_type: secret_type

class Req_F(BaseModel):
    doc_id:int
    user_id:str
    passhash:str
    description:str
    valid_time:int
    req_type: Req_type
class User_F(BaseModel):
    username: str
    passhash: str
class User_doc_req(BaseModel):
    username: str
    passhash: str
    doc_id: int
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
class user_secret(BaseModel):
    username: str
    user_secret: str
class user_pbkey(BaseModel):
    username: str
    pb_key: str
class Upload_Doc(BaseModel):
    username: str
    passhash: str
    list_owners: list[user_secret]
    list_people: list[user_secret]
    k: int
    filename: str
    description: str
    l: int #length of key+IV

class Doc_User_View(BaseModel):
    filename : str
    description: str
    n:int
    o:int
    k:int
    accessible: bool
    id:int

class Doc_User_Response(BaseModel):
    people: list[Doc_User_View]
    owner: list[Doc_User_View]