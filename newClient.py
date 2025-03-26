import requests
import click
import json
import os
import base64
from rich.console import Console
from rich.table import Table
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from .hash_rsa import *
from .Doc_encryption import *
from .SSS import *
from .Doc_Decryption import *
from .models import *

def rsa_encrypt(key_str, message:str):# give only public key in readable format pu.export_key().decode()
    """Encrypt a message using RSA public or private key (PEM format)."""
    key = RSA.import_key(key_str)
    cipher = PKCS1_OAEP.new(key)
    encrypted_message = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted_message).decode()

def rsa_decrypt(key_str, encrypted_message): #give only private key in readable format pr.export_key().decode()
    """Decrypt an RSA-encrypted message using a key in PEM format."""
    key = RSA.import_key(key_str)
    cipher = PKCS1_OAEP.new(key)
    
    try:
        # Ensure Base64 decoding is done properly
        encrypted_bytes = base64.b64decode(encrypted_message)
        decrypted_message = cipher.decrypt(encrypted_bytes)
        return decrypted_message.decode()  # Convert bytes back to string
    except Exception as e:
        print(f"❌ RSA Decryption Error: {e}")
        return None

BASE_URL = "http://127.0.0.1:8000"
username=None
passhash=None
pu=None
pr=None
session = requests.Session()
def login() -> bool:
    global username, passhash,pu,pr
    username=input("Enter Username: ")
    pw=input("Enter password: ")
    passhash = generate_hash(pw)
    user=User_F()
    user.username=username
    user.passhash=passhash
    try:
        response = session.post(
            f"{BASE_URL}/login/",
            data=user.model_dump_json()
        )
        if response.ok and response.json():
            pr,pu=hash_to_rsa_key(username,pw)
            pr=pr.export_key().decode()
            pu=pu.export_key().decode()
        else:
            username=None
            passhash=None
            pr=None
            pu=None
            return False
    except Exception as e:
        print(f"Login error: {str(e)}")
        return False
    post_login_options={"My Documents": show_docs,
                        "My requests": show_my_requests,
                        "Other requests": show_other_requests,
                        "Upload new Document": up_doc,
                        "Logout":None}
    while True:
        for i,op in enumerate(post_login_options.keys()):
            print(f"{i+1} {op}")
        choice=int(input("Enter Choice: "))
        if choice==len(post_login_options.keys()):
            break
        if post_login_options[list(post_login_options.keys())[choice-1]]():
            print("Operation Successful")
    return True

def signup() -> bool:
    try:
        uname=input("Set Username: ")
        pw=input("Set password: ")
        print(uname,pw)
        private_key, public_key = hash_to_rsa_key(uname, pw)
        u=User(username=uname,passhash=generate_hash(pw),pb_key=public_key.export_key().decode())
        response = session.post(
            f"{BASE_URL}/signup/",
            data=u.model_dump_json()
        )
        if not response.json():
            print("Username Taken")
        return response.json()
    except Exception as e:
        print(f"Signup error: {str(e)}")
        return False
def show_my_requests():
    global username, passhash
    u = User_F()
    u.username = username
    u.passhash = passhash
    response = session.post(f"{BASE_URL}/my_requests/", data=u.model_dump_json())

    if response.ok:
        requests = response.json()
        print("\n===== My Requests =====")
        
        if not requests:
            print("No requests found.")
            return False
        lp=[]
        lwu=[]
        for req in requests:
            print(f"Request ID: {req['req_id']}")
            print(f"Filename: {req['filename']}")
            print(f"Description: {req['description']}")
            print(f"Request Type: {req['req_type']}")
            print(f"Valid Time: {req['valid_time']} hours")
            print(f"Owners who signed: {req['s_o']}")
            print(f"People who signed: {req['s_k']}")
            print(f"Status: {req['status']}")
            print("-" * 40)
            if req['status']==Req_status.LIVE_PENDING:
                lp.append(req)
            if req['status']==Req_status.LIVE_WAITING_UPLOAD:
                lwu.append(req)
        if len(lp)>0:
            print(f"Would u like to execute these requests? {[req['req_id'] for req in lp]} (0/1):")
            ch=int(input(""))
            if ch==1:
                execute_request(lp)
        if len(lwu)>0:
            print(f"Would u like to upload file for these requests? {[req['req_id'] for req in lwu]} (0/1):")
            ch=int(input(""))
            if ch==1:
                req_id=int(input("Enter the request id: "))
                R=None
                for req in lwu:
                    if req['req_id']==req_id:
                        R=req
                if R is None:
                    print("Invalid Request ID")
                    return False
                R=myRequest_User_View.model_validate(R)
                return reupload(R)
        return True
    else:
        print("Error fetching your requests.")
        return False

def execute_request(lp):
    req_id=int(input("Enter the request id: "))
    R=None
    for req in lp:
        if req['req_id']==req_id:
            R=req
    if R is None:
        print("Invalid Request ID")
        return False
    R=myRequest_User_View.model_validate(R)
    sf=secret_Fetch(username=username,passhash=passhash,req_id=req_id)
    response = session.post(f"{BASE_URL}/get_secrets/", data=sf.model_dump_json())
    ds=doc_secret.model_validate(response.json())
    o_s=[]
    for ss in ds.list_owners:
        o_s.append(rsa_decrypt(pr,ss.user_secret))
    p_s=[]
    for ss in ds.list_people:
        p_s.append(rsa_decrypt(pr,ss.user_secret))
    sss_in={
        "k":R.k,
        "o":R.o,
        'owner':o_s,
        'people':p_s,
        'l':R.l
    }
    fp=get_file(R.doc_id)
    dfp= decrypt_doc(fp,sss_in)
    os.remove(fp)
    if R.req_type==Req_type.READ:
        reupload(R,dfp)
    return dfp
def reupload(req:myRequest_User_View,dfp=None):
    if dfp is None:
        dfp=input("Enter file path of edited file: ")
    req_B=reupload_Doc()
    req_B.username=username
    req_B.passhash=passhash
    req_B.req_id=req.req_id
    req_B.list_owners=[]
    req_B.list_people=[]
    sf=Doc_Fetch()
    sf.doc_id=req.doc_id
    sf.username=username
    sf.passhash=passhash
    response = session.post(f"{BASE_URL}/get_o_p/", data=sf.model_dump_json())
    op=O_P.model_validate(response.json())
    efp,key=encrypt_doc(dfp)
    req_B.l=len(key)
    sss=spilt_secret(key,len(op.owners),req.k,len(op.owners)+len(op.people))
    keys=get_pbkeys(op.owners+op.people)
    for i,p in enumerate(op.people):
        u=user_secret()
        u.user_secret=rsa_encrypt(keys[p],sss['people'][i])
        u.username=p
        req_B.list_people.append(u)
    for i,p in enumerate(op.owners):
        u=user_secret()
        u.user_secret=rsa_encrypt(keys[p],sss['owner'][i])
        u.username=p
        req_B.list_owners.append(u)
    with open(efp, "rb") as f:
        response = session.post(
            f"{BASE_URL}/reupload_doc/",
            data={"up_doc": json.dumps(req_B.model_dump())},
            files={"file": (efp,f,'application/octet-stream')} # check
        )
        if response.json()==True:
            print("File Reuploaded Successfully")
        else:
            print("File reupload failed")
        return response.json()
def show_other_requests():
    """Fetch and display requests from other users that require action."""
    global username, passhash
    u = User_F()
    u.username = username
    u.passhash = passhash
    response = session.post(f"{BASE_URL}/other_requests/", data=u.model_dump_json())

    if response.ok:
        requests = response.json()
        print("\n===== Other Users' Requests =====")

        if not requests:
            print("No requests require your action.")
            return False
        cnt=[]
        for req in requests:
            print(f"Request ID: {req['req_id']}")
            print(f"Filename: {req['filename']}")
            print(f"Requested By: {req['user_id']}")
            print(f"Description: {req['description']}")
            print(f"Request Type: {req['req_type']}")
            print(f"Status: {req['status']}")
            print(f"Signed: {req['signed']}")
            print("-" * 40)
            if req['signed']==False:
                cnt.append(req['req_id'])
        if len(cnt)>0:
            print(f"{str(cnt)} are waiting for sign would you like to sign? (0/1)")
            ch=int(input(""))
            if ch==1:
                sign_request(requests)
        return True
    else:
        print("Error fetching other users' requests.")
        return False
def sign_request(requests):
    """Sign a request for document access."""
    global username, passhash, pr, pu
    u=None
    d=None
    req_id = int(input("Enter Request ID to sign: "))
    for req in requests:
        if req['req_id']==req_id and req['signed']==False:
            u=req['user_id']
            d=req['doc_id']
            break
    if u is None:
        print("Inappropriate ID")
        return False
    # Fetch the user's encrypted secret
    fetch_data = Doc_Fetch()
    fetch_data.username = username
    fetch_data.passhash = passhash
    fetch_data.doc_id = d

    response = session.post(f"{BASE_URL}/get_my_secret/", data=fetch_data.model_dump_json())

    if not response.ok or  response.json()=="":
        print(f"Failed to fetch your encrypted secret. {response.json()}")
        return False
    encrypted_secret = response.json()
    try:
        # Decrypt the secret using the private key
        decrypted_secret = rsa_decrypt(pr, encrypted_secret)
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return False

    # Re-encrypt the secret with the request's public key
    pb_key = get_pbkeys([u])[u]
    signed_secret = rsa_encrypt(pb_key, decrypted_secret)

    # Send signed request
    sign_data = sign()
    sign_data.username = username
    sign_data.passhash = passhash
    sign_data.req_id = req_id
    sign_data.encrypted_secret = signed_secret

    sign_response = session.post(f"{BASE_URL}/sign_req/", data=sign_data.model_dump_json())

    if sign_response.ok and sign_response.json():
        print("Request signed successfully.")
        return True
    else:
        print("Failed to sign the request.")
        return False

def print_doc(d:Doc_User_View):
    print(f"ID: {d.id}\n\
    Filename: {d.filename}\n\
    Description: {d.description}\nn: {d.n}\nk: {d.k}\nNo of Owners: {d.o}\nAccessible: {d.accessible}")
def show_docs() -> bool:
    u=User_F()
    u.username=username
    u.passhash=passhash
    response = session.post(
        f"{BASE_URL}/my_docs/",
        data=u.model_dump_json()
    )
    docs = Doc_User_Response.model_validate(response.json())
    print("Owner type Documents: ")
    for i,obj in enumerate(docs.owner):
        print_doc(obj)
    if len(docs.owner)==0:
        print("No owner docs")
    print("People type Documents: ")
    for i,obj in enumerate(docs.people):
        print_doc(obj)
    if len(docs.people)==0:
        print("No people docs")
    post_doc_options={"Get log file":get_log_file,"Create Request":create_req,"Back": None}
    while True:
        for i,op in enumerate(post_doc_options.keys()):
            print(f"{i+1} {op}")
        choice=int(input("Enter Choice: "))
        if choice == len(post_doc_options.keys()):
            break
        post_doc_options[list(post_doc_options.keys())[choice-1]]()
    return True
            

def get_log_file():
    """Fetch and display the log file for a given document."""
    global username, passhash
    docid=int(input("Enter docid: "))
    u = Doc_Fetch()
    u.username = username
    u.passhash = passhash
    u.doc_id = docid

    response = session.post(f"{BASE_URL}/get_log_file/", data=u.model_dump_json())

    if response.status_code == 200:
        log_filename = f"log_{docid}.txt"
        with open(log_filename, "wb") as f:
            f.write(response.content)
        print(f"Log file saved as {log_filename}.")
        return True
    else:
        print("Failed to fetch log file.")
        return False
    
def get_file(docid):
    """Fetch and display the log file for a given document."""
    global username, passhash
    u = Doc_Fetch()
    u.username = username
    u.passhash = passhash
    u.doc_id = docid

    response = session.post(f"{BASE_URL}/get_file/", data=u.model_dump_json())

    if response.status_code == 200:
        log_filename = f"enc_{docid}.bin"
        with open(log_filename, "wb") as f:
            f.write(response.content)
        #print(f"Log file saved as {log_filename}.")
        return log_filename
    else:
        print("Failed to fetch encrypted file.")
        return False


def create_req():
    """Create a read/write request for a document."""
    global username, passhash
    docid=int(input("Enter docid: "))
    description = input("Enter request description: ")
    valid_time = int(input("Enter validity time (hours): "))
    req_type = input("Enter request type (r for read, w for write): ").strip().lower()
    
    if req_type not in ["r", "w"]:
        print("Invalid request type.")
        return False
    
    req = Req_F()
    req.doc_id = docid
    req.user_id = username
    req.passhash = passhash
    req.description = description
    req.valid_time = valid_time
    req.req_type = Req_type.READ if req_type == "r" else Req_type.WRITE
    print(req.model_dump_json())
    response = session.post(f"{BASE_URL}/create_request/", data=req.model_dump_json())

    if response.ok and response.json():
        print("Request successfully created.")
        return True
    else:
        print("Failed to create request.")
        return False

def up_doc()->bool:
    global username, passhash,pu,pr
    file_path=input("Enter file path: ")
    description=input("Enter description of file: ")
    while True:
        n=int(input("Enter no of owners: "))
        print("Enter usernames of owners line by line")
        owners=[]
        for i in range(n):
            owners.append(input(""))
        n=int(input("Enter no of people: "))
        print("Enter usernames of people line by line")
        people=[]
        for i in range(n):
            people.append(input(""))
        owners=list(set(owners))
        people=list(set(people))
        if set(owners) & set(people):
            print("No overlap between people and owners allowed\nTry again")
        else:
            break
    if username not in owners and username not in people:
        owners.append(username)
    while True:
        k=int(input("Enter threshold k: "))
        if k>len(people):
            print("Threshold more than no of people")
        else:
            break
    enc_file, key_iv_bits = encrypt_doc(file_path)
    sss_shares = spilt_secret(
        secret=key_iv_bits,
        no_of_owners=len(owners),
        k=k,
        n=len(people) + len(owners)
    )
    keys=get_pbkeys(owners+people)
    upload_data=Upload_Doc()
    upload_data.username=username
    upload_data.passhash=passhash
    upload_data.list_owners=[]
    upload_data.list_people=[]
    upload_data.l=len(key_iv_bits)
    upload_data.filename=os.path.basename(file_path)
    upload_data.k=k
    upload_data.description=description
    for i in range(len(owners)):
        upload_data.list_owners.append(gen_user_secret(sss_shares['owner'][i],owners[i],keys[owners[i]]))
        if owners[i]==username:
            temp=upload_data.list_owners[-1].user_secret
    for i in range(len(people)):
        upload_data.list_people.append(gen_user_secret(sss_shares['people'][i],people[i],keys[people[i]]))
    try:
        print(json.dumps(upload_data.model_dump()), "application/json")
        with open(enc_file, "rb") as f:
            response = session.post(
                f"{BASE_URL}/add_doc/",
                data={"up_doc": json.dumps(upload_data.model_dump())},
                files={"file": (upload_data.filename,f,'application/octet-stream')} # check
            )
            os.remove(enc_file)
        return response.json()
    except IOError as e:
        print(f"File access error: {str(e)}")
        return False
    return True
def gen_user_secret(share,uname,pbkey):
    ans=user_secret()
    ans.user_secret =rsa_encrypt(pbkey,share)
    ans.username=uname
    return ans
def get_pbkeys(usernames: list) -> dict:
    try:
        response = session.post(f"{BASE_URL}/pbkey/", json=usernames)
        return {u.username: u.pb_key for u in [user_pbkey.model_validate(item) for item in response.json()]}
    except:
        return {}
def main():
    initial_options={"Login":login,"Signup":signup}
    while True:
        for i,op in enumerate(initial_options.keys()):
            print(f"{i+1} {op}")
        choice=int(input("Enter Choice: "))
        print(type(initial_options.keys()))
        if initial_options[list(initial_options.keys())[choice-1]]():
            print("Operation Successful")
        else:
            print("Operation Failed")
if __name__=='__main__':
    main()